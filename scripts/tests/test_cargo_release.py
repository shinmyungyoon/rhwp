import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "cargo_release.py"
SPEC = importlib.util.spec_from_file_location("cargo_release", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "LICENSE").write_text("Fixture license.\n")
        self.package = release.Package(self.source, "archive-fixture", "0.1.0", ("LICENSE",))
        self.manifest = (
            '[package]\nname="archive-fixture"\nversion="0.1.0"\nedition="2021"\n'
            'include=["/src/**","/LICENSE","/Cargo.toml"]\n'
        )
        (self.source / "Cargo.toml").write_text(self.manifest)
        (self.source / "src/lib.rs").write_text("pub fn answer() -> u8 { 42 }\n")

    def archive(self, entries):
        archive = self.base / self.package.archive_name
        with tarfile.open(archive, "w:gz") as contents:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                contents.addfile(member, io.BytesIO(data))
        return archive

    def entries(self):
        prefix = "archive-fixture-0.1.0/"
        return [
            (prefix + "Cargo.toml", self.manifest.encode()),
            (prefix + "LICENSE", b"Fixture license.\n"),
            (prefix + "src/lib.rs", b"pub fn answer() -> u8 { 42 }\n"),
        ]

    def test_rejects_missing_notice_before_extracting(self):
        archive = self.archive(self.entries()[::2])
        with self.assertRaisesRegex(release.ReleaseError, "required license"):
            release.unpack_archive(archive, self.base / "unpacked", self.package)
        self.assertFalse((self.base / "unpacked").exists())

    def test_rejects_changed_notice(self):
        entries = self.entries()
        entries[1] = (entries[1][0], b"Removed terms.")
        with self.assertRaisesRegex(release.ReleaseError, "changes the required notice"):
            release.unpack_archive(self.archive(entries), self.base / "unpacked", self.package)

    def test_rejects_extra_file_and_inventory_mismatch(self):
        entries = self.entries() + [("archive-fixture-0.1.0/corpus/input.hwp", b"data")]
        with self.assertRaisesRegex(release.ReleaseError, "unexpected file"):
            release.unpack_archive(self.archive(entries), self.base / "unpacked", self.package)
        with self.assertRaisesRegex(release.ReleaseError, "inventory"):
            release.unpack_archive(
                self.archive(self.entries()), self.base / "unpacked", self.package,
                expected=["Cargo.toml", "LICENSE"],
            )

    def test_rejects_traversal_and_duplicate_files(self):
        for added in [
            ("archive-fixture-0.1.0/../../escaped", b"bad"),
            self.entries()[1],
        ]:
            with self.subTest(added=added[0]), self.assertRaises(release.ReleaseError):
                release.unpack_archive(
                    self.archive(self.entries() + [added]), self.base / "unpacked", self.package,
                )
        self.assertFalse((self.base / "escaped").exists())

    def test_rejects_target_specific_path_or_git_dependency(self):
        for dependency in ('path="../other"', 'git="https://example.invalid/code"'):
            entries = self.entries()
            entries[0] = (
                entries[0][0],
                (self.manifest + '\n[target.\'cfg(unix)\'.dependencies.other]\n'
                 + dependency + '\nversion="1"\n').encode(),
            )
            with self.subTest(dependency=dependency), self.assertRaisesRegex(
                release.ReleaseError, "crates.io",
            ):
                release.unpack_archive(self.archive(entries), self.base / "unpacked", self.package)

    def test_inventory_rejects_an_ignored_or_untracked_source_file(self):
        listing = {"Cargo.toml", "Cargo.lock", "LICENSE", "src/lib.rs", "src/local-data.bin"}
        tracked = {"source/Cargo.toml", "source/LICENSE", "source/src/lib.rs"}
        with self.assertRaisesRegex(release.ReleaseError, "untracked file"):
            release.check_tracked_inventory(self.base, self.package, listing, tracked)
        release.check_tracked_inventory(
            self.base, self.package, listing - {"src/local-data.bin"}, tracked,
        )

    def test_real_package_archive_resolves_from_external_directory_source(self):
        cargo = shutil.which("cargo")
        self.assertIsNotNone(cargo, "Cargo is required for the archive behavior test")
        home = self.base / "home"
        home.mkdir()
        env = release.clean_environment(home, self.base / "target", "1.93.1")
        subprocess.run(
            [cargo, "package", "--offline", "--no-verify", "--allow-dirty"],
            cwd=self.source, env=env, check=True, capture_output=True,
        )
        archive = self.base / "target/package" / self.package.archive_name
        stage = self.base / "registry"
        extracted = release.stage_archive(
            archive, stage, self.package,
            {"Cargo.lock", "Cargo.toml", "Cargo.toml.orig", "LICENSE", "src/lib.rs"},
        )
        checksum = json.loads((extracted / ".cargo-checksum.json").read_text())
        self.assertEqual(checksum["package"], release.digest(archive))
        self.assertEqual(
            checksum["files"]["src/lib.rs"],
            hashlib.sha256((self.source / "src/lib.rs").read_bytes()).hexdigest(),
        )
        (home / "config.toml").write_text(
            '[source.crates-io]\nreplace-with="staged"\n'
            f'[source.staged]\ndirectory={json.dumps(str(stage))}\n',
        )
        consumer = self.base / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(
            '[package]\nname="external-fixture"\nversion="0.0.0"\nedition="2021"\n'
            '[dependencies]\narchive-fixture="=0.1.0"\n',
        )
        (consumer / "src/main.rs").write_text(
            "fn main() { assert_eq!(archive_fixture::answer(), 42); }\n",
        )
        subprocess.run(
            [cargo, "run", "--offline"], cwd=consumer, env=env,
            check=True, capture_output=True,
        )
        (extracted / "src/lib.rs").write_text("pub fn answer() -> u8 { 0 }\n")
        rejected = subprocess.run(
            [cargo, "check", "--offline"], cwd=consumer, env=env,
            check=False, capture_output=True, text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("checksum", rejected.stderr)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.root = release.Package(Path("/source"), "test-root", "1.2.3", ("LICENSE",))
        self.head = "a" * 40
        self.environment = patch.dict(os.environ, {
            "CARGO_REGISTRY_TOKEN": "test-only-credential",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/tags/cargo-v1.2.3",
        }, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def guard(self, **overrides):
        values = {"confirmation": "test-root@1.2.3", "commit": self.head}
        values.update(overrides)
        with patch.object(release, "git", side_effect=["", self.head, self.head]), patch.object(
            release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0),
        ):
            return release.publish_guard(Path("/source"), self.root, **values)

    def test_accepts_exact_tag_confirmation_and_commit(self):
        self.assertEqual(self.guard()[0], self.head)

    def test_rejects_missing_credential_before_building(self):
        os.environ.pop("CARGO_REGISTRY_TOKEN")
        with patch.object(release, "git") as git, self.assertRaisesRegex(
            release.ReleaseError, "required",
        ):
            self.guard()
        git.assert_not_called()

    def test_rejects_pr_other_events_wrong_tag_and_confirmation(self):
        for event in ["pull_request", "pull_request_target", "push", ""]:
            with self.subTest(event=event), patch.dict(os.environ, {"GITHUB_EVENT_NAME": event}):
                with self.assertRaisesRegex(release.ReleaseError, "workflow_dispatch"):
                    self.guard()
        with patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v1.2.3"}):
            with self.assertRaisesRegex(release.ReleaseError, "refs/tags/cargo-v"):
                self.guard()
        for arguments in [{"confirmation": "wrong@1"}, {"commit": "b" * 40}]:
            with self.subTest(arguments=arguments), self.assertRaises(release.ReleaseError):
                self.guard(**arguments)

    def test_rejects_dirty_source_tag_mismatch_and_non_main_commit(self):
        for answers in [["dirty"], ["", self.head, "b" * 40]]:
            with patch.object(release, "git", side_effect=answers), self.assertRaises(
                release.ReleaseError,
            ):
                release.publish_guard(
                    Path("/source"), self.root, "test-root@1.2.3", self.head,
                )
        with patch.object(release, "git", side_effect=["", self.head, self.head]), patch.object(
            release.subprocess, "run", return_value=subprocess.CompletedProcess([], 1),
        ), self.assertRaisesRegex(release.ReleaseError, "origin/main"):
            release.publish_guard(Path("/source"), self.root, "test-root@1.2.3", self.head)

    def test_build_environment_removes_all_cargo_credentials_and_overrides(self):
        os.environ["CARGO_REGISTRIES_CRATES_IO_TOKEN"] = "other-test-credential"
        os.environ["CARGO_REGISTRIES_CRATES_IO_INDEX"] = "https://example.invalid/index"
        env = release.clean_environment(Path("/home"), Path("/target"), "1.93.1")
        self.assertNotIn("CARGO_REGISTRY_TOKEN", env)
        self.assertNotIn("CARGO_REGISTRIES_CRATES_IO_TOKEN", env)
        self.assertNotIn("CARGO_REGISTRIES_CRATES_IO_INDEX", env)
        self.assertEqual(env["CARGO_HOME"], "/home")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.package = release.Package(Path("/source"), "test-leaf", "0.1.0", ("LICENSE",))

    def test_wait_accepts_only_matching_non_yanked_checksum(self):
        self.assertIsNone(release.wait_for_version(
            self.package, "abc", lookup=lambda *a, **k: {"cksum": "abc", "yanked": False},
        ))
        for entry in [{"cksum": "different"}, {"cksum": "abc", "yanked": True}]:
            with self.subTest(entry=entry), self.assertRaises(release.ReleaseError):
                release.wait_for_version(self.package, "abc", lookup=lambda *a, **k: entry)

    def test_wait_has_a_deadline(self):
        now = [0]
        sleeps = []

        def advance(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        with self.assertRaisesRegex(release.ReleaseError, "timed out"):
            release.wait_for_version(
                self.package, "abc", seconds=7, lookup=lambda *a, **k: None,
                clock=lambda: now[0], sleep=advance,
            )
        self.assertEqual(sleeps, [5, 2])

    def test_upload_token_is_not_reused_for_availability_checks(self):
        job = release.Release.__new__(release.Release)
        job.repo, job.head = Path("/source"), "head"
        job.packages, job.confirmation = [self.package], "test-leaf@0.1.0"
        job.env = {"CARGO_HOME": "/isolated"}
        job.records = {"test-leaf": {"sha256": "abc"}}
        commands = []
        job.cargo = lambda *args, **kwargs: commands.append((args, kwargs))
        with patch.object(release, "git", return_value="head"), patch.object(
            release, "publish_guard",
        ), patch.object(release, "registry_version", return_value=None), patch.object(
            release, "wait_for_version",
        ) as wait:
            job.upload(self.package, "test-only-credential")
        self.assertEqual(len(commands), 1)
        args, kwargs = commands[0]
        self.assertEqual(args[0], "publish")
        self.assertIn("--no-verify", args)
        self.assertIn("--locked", args)
        self.assertIn("CARGO_REGISTRY_TOKEN", kwargs["env"])
        self.assertNotIn("CARGO_REGISTRY_TOKEN", job.env)
        wait.assert_called_once_with(self.package, "abc")

    def test_recovery_rejects_mismatch_and_skips_only_exact_archive(self):
        job = release.Release.__new__(release.Release)
        job.repo, job.head = Path("/source"), "head"
        job.packages, job.confirmation = [self.package], "test-leaf@0.1.0"
        job.records = {"test-leaf": {"sha256": "abc"}}
        job.cargo = unittest.mock.Mock()
        for checksum in ["abc", "different"]:
            with self.subTest(checksum=checksum), patch.object(
                release, "git", return_value="head",
            ), patch.object(release, "publish_guard"), patch.object(
                release, "registry_version", return_value={"cksum": checksum, "yanked": False},
            ):
                if checksum == "abc":
                    job.upload(self.package, "test-only-credential")
                else:
                    with self.assertRaisesRegex(release.ReleaseError, "differs"):
                        job.upload(self.package, "test-only-credential")
        job.cargo.assert_not_called()

    def test_default_cli_never_calls_publish(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(
            release, "Release",
        ) as implementation:
            result = release.main(["--output", str(Path(temp) / "output")])
        self.assertEqual(result, 0)
        implementation.return_value.preflight.assert_called_once()
        implementation.return_value.publish.assert_not_called()

    def test_publish_cli_rejects_missing_credentials_without_constructing_release(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(
            release, "Release",
        ) as implementation, patch("sys.stderr", new_callable=io.StringIO):
            result = release.main(["publish", "--confirm", "wrong", "--commit", "wrong"])
        self.assertEqual(result, 1)
        implementation.assert_not_called()

    def test_output_cannot_inherit_ambient_cargo_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            (parent / ".cargo").mkdir()
            (parent / ".cargo/config.toml").write_text("[source.crates-io]\n")
            with self.assertRaisesRegex(release.ReleaseError, "ancestor Cargo"):
                release.Release(Path("/source"), parent / "output", parent / "target")

    def test_publish_checks_all_leaf_uploads_before_real_root_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            job = release.Release.__new__(release.Release)
            job.home = Path(temp)
            (job.home / "config.toml").write_text("staging configuration")
            job.packages = [
                release.Package(Path("/source"), f"leaf-{i}", "0.1.0", ("LICENSE",))
                for i in range(4)
            ] + [self.package]
            job.records = {package.name: {"sha256": "abc"} for package in job.packages}
            job.env = {}
            events = []
            job.preflight = lambda: events.append("preflight")
            job.upload = lambda package, token: events.append("upload-" + package.name)

            def archive(package):
                self.assertFalse((job.home / "config.toml").exists())
                events.append("real-root-archive")
                return Path("archive"), Path("unpacked")

            job.archive = archive
            job.consumer = lambda *args: events.append("real-root-consumer")
            job.report = lambda *args: events.append("report")
            with patch.object(release, "registry_version", return_value=None):
                job.publish("test-only-credential", "root@1")
        self.assertEqual(events, [
            "preflight", "upload-leaf-0", "upload-leaf-1", "upload-leaf-2",
            "upload-leaf-3", "real-root-archive", "real-root-consumer",
            "upload-test-leaf", "report",
        ])

    def test_publish_stops_before_upload_on_any_existing_checksum_mismatch(self):
        job = release.Release.__new__(release.Release)
        job.packages = [self.package]
        job.records = {self.package.name: {"sha256": "abc"}}
        job.preflight = unittest.mock.Mock()
        job.upload = unittest.mock.Mock()
        with patch.object(release, "registry_version", return_value={"cksum": "different"}):
            with self.assertRaisesRegex(release.ReleaseError, "differs"):
                job.publish("test-only-credential", "root@1")
        job.upload.assert_not_called()

    def test_verification_failure_cannot_reach_upload(self):
        job = release.Release.__new__(release.Release)
        job.preflight = unittest.mock.Mock(side_effect=release.ReleaseError("verification failed"))
        job.upload = unittest.mock.Mock()
        with self.assertRaisesRegex(release.ReleaseError, "verification failed"):
            job.publish("test-only-credential", "root@1")
        job.upload.assert_not_called()


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.root = release.Package(Path("/source"), "root-fixture", "1.0.0", ())
        self.pdf = release.Package(Path("/source"), "patched-pdf", "0.13.0", ())
        self.metadata = {
            "packages": [
                {"name": "root-fixture", "id": "root", "manifest_path": "/outside/root/Cargo.toml"},
                {"name": "patched-pdf", "id": "pdf", "manifest_path": "/outside/pdf/Cargo.toml"},
                {"name": "usvg", "id": "usvg", "version": "0.45.1",
                 "manifest_path": "/outside/usvg/Cargo.toml"},
            ],
            "resolve": {"nodes": [{"id": "root", "deps": [
                {"name": "svg2pdf", "pkg": "pdf"}, {"name": "usvg", "pkg": "usvg"},
            ]}]},
        }

    def verify(self):
        return release.verify_metadata(self.metadata, Path("/source"), self.root, self.pdf)

    def test_requires_the_aliased_patched_dependency(self):
        self.assertEqual(self.verify(), "0.45.1")
        self.metadata["resolve"]["nodes"][0]["deps"][0]["pkg"] = "unpatched"
        with self.assertRaisesRegex(release.ReleaseError, "patched package"):
            self.verify()

    def test_rejects_any_repository_source_path(self):
        self.metadata["packages"][1]["manifest_path"] = "/source/vendor/pdf/Cargo.toml"
        with self.assertRaisesRegex(release.ReleaseError, "repository source"):
            self.verify()

    def test_rejects_original_pdf_package(self):
        self.metadata["packages"].append({
            "name": "svg2pdf", "id": "original", "manifest_path": "/outside/original/Cargo.toml",
        })
        with self.assertRaisesRegex(release.ReleaseError, "renamed PDF"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
