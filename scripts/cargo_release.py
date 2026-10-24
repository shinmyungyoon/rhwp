#!/usr/bin/env python3
"""Verify Cargo archives locally. The publish command requires a release tag."""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request


class ReleaseError(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_toml(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Package:
    directory: Path
    name: str
    version: str
    notices: tuple

    @property
    def manifest(self):
        return self.directory / "Cargo.toml"

    @property
    def archive_name(self):
        return f"{self.name}-{self.version}.crate"


def packages(repo):
    locations = [
        ("crates/rhwp-contracts", ("LICENSE",)),
        ("crates/rhwp-ooxml-chart", ("LICENSE",)),
        ("crates/rhwp-password-crypto", ("LICENSE", "NOTICE")),
        ("vendor/svg2pdf", ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE", "RHWP_PATCHES.md")),
        (".", ("LICENSE", "THIRD_PARTY_LICENSES.md")),
    ]
    result = []
    for location, notices in locations:
        directory = repo / location
        data = read_toml(directory / "Cargo.toml")["package"]
        if data.get("publish") != ["crates-io"]:
            raise ReleaseError(f"{location}: publication must be limited to crates-io")
        result.append(Package(directory, data["name"], data["version"], notices))
    if len({p.name for p in result}) != len(result):
        raise ReleaseError("Release package names must be distinct")
    return result


def clean_environment(home, target, toolchain):
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("CARGO_")
    }
    env.update(CARGO_HOME=str(home), CARGO_TARGET_DIR=str(target),
               RUSTUP_TOOLCHAIN=toolchain,
               CARGO_BUILD_JOBS=os.environ.get("CARGO_BUILD_JOBS", "4"))
    return env


def without_cargo_environment():
    return {key: value for key, value in os.environ.items() if not key.startswith("CARGO_")}


def run(args, *, cwd, env, capture=False):
    print("+", " ".join(map(str, args)), flush=True)
    result = subprocess.run(
        list(map(str, args)), cwd=cwd, env=env, text=True, check=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, env=without_cargo_environment(),
    ).strip()


def publish_guard(repo, root, confirmation, commit):
    token = os.environ.get("CARGO_REGISTRY_TOKEN", "")
    if not token.strip():
        raise ReleaseError("CARGO_REGISTRY_TOKEN is required for publish")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event != "workflow_dispatch":
        raise ReleaseError("Only workflow_dispatch can publish packages")
    if confirmation != f"{root.name}@{root.version}":
        raise ReleaseError("--confirm must match the root package name and version")
    tag = f"cargo-v{root.version}"
    if os.environ.get("GITHUB_REF", f"refs/tags/{tag}") != f"refs/tags/{tag}":
        raise ReleaseError(f"Publication requires refs/tags/{tag}")
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise ReleaseError("Publication requires a clean source tree")
    head = git(repo, "rev-parse", "HEAD")
    if commit != head:
        raise ReleaseError("--commit must match the full HEAD commit")
    if git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}") != head:
        raise ReleaseError(f"{tag} must point to HEAD")
    if subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor",
         head, "refs/remotes/origin/main"], check=False, env=without_cargo_environment(),
    ).returncode:
        raise ReleaseError("HEAD must be reachable from fetched origin/main")
    return head, token


def dependency_tables(manifest):
    tables = [manifest]
    tables.extend(manifest.get("target", {}).values())
    for table in tables:
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            yield from table.get(kind, {}).values()


def check_normalized_manifest(manifest, package):
    if manifest["package"]["name"] != package.name:
        raise ReleaseError("Archive package name does not match the manifest")
    if manifest["package"]["version"] != package.version:
        raise ReleaseError("Archive package version does not match the manifest")
    if "patch" in manifest or "replace" in manifest:
        raise ReleaseError("Archive cannot require consumer dependency overrides")
    for dependency in dependency_tables(manifest):
        if isinstance(dependency, dict) and any(
            key in dependency for key in ("path", "git", "registry", "registry-index")
        ):
            raise ReleaseError("Archive dependency must resolve from crates.io")


def check_tracked_inventory(repo, package, listing, tracked):
    generated = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}
    for name in set(listing) - generated:
        relative = (package.directory / name).relative_to(repo).as_posix()
        if relative not in tracked:
            raise ReleaseError(f"Package selects an untracked file: {relative}")


def unpack_archive(archive, destination, package, expected=None):
    prefix = f"{package.name}-{package.version}"
    with tarfile.open(archive, "r:gz") as contents:
        members = contents.getmembers()
        files = {}
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts
                    or not path.parts or path.parts[0] != prefix
                    or not (member.isfile() or member.isdir())):
                raise ReleaseError("Archive contains an unsafe member")
            if member.isfile():
                relative = str(path.relative_to(prefix))
                if relative in files:
                    raise ReleaseError("Archive contains a duplicate file")
                files[relative] = member
        if expected is not None and set(files) != set(expected):
            raise ReleaseError("Archive inventory differs from cargo package --list")
        if not set(package.notices) <= files.keys():
            raise ReleaseError("Archive omits a required license or notice")
        allowed = {
            "Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json",
            "README.md", *package.notices,
        }
        if "THIRD_PARTY_LICENSES.md" in package.notices:
            allowed |= {"README_EN.md", "build.rs", "llms.txt"}
        for relative in files:
            if relative in allowed or relative.startswith("src/"):
                continue
            if "THIRD_PARTY_LICENSES.md" in package.notices:
                if relative == "saved/blank2010.hwp":
                    continue
                if relative.startswith("mydocs/") and (
                    "/" + relative in read_toml(package.manifest)["package"]["include"]
                ):
                    continue
            raise ReleaseError(f"Archive includes an unexpected file: {relative}")
        check_normalized_manifest(
            tomllib.loads(contents.extractfile(files["Cargo.toml"]).read().decode()),
            package,
        )
        for notice in package.notices:
            if contents.extractfile(files[notice]).read() != (package.directory / notice).read_bytes():
                raise ReleaseError(f"Archive changes the required notice: {notice}")
        destination.mkdir(parents=True, exist_ok=True)
        contents.extractall(destination, filter="data")
    return destination / prefix, sorted(files)


def stage_archive(archive, directory, package, expected):
    root, files = unpack_archive(archive, directory, package, expected)
    checksums = {name: digest(root / name) for name in files}
    (root / ".cargo-checksum.json").write_text(
        json.dumps({"files": checksums, "package": digest(archive)}),
        encoding="utf-8",
    )
    return root


def index_path(name):
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def registry_version(package, timeout=20):
    request = urllib.request.Request(
        f"https://index.crates.io/{index_path(package.name)}",
        headers={"User-Agent": "cargo-release-preflight"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(16 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise ReleaseError(f"Registry lookup failed with HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError):
        raise ReleaseError("Registry lookup failed") from None
    if len(body) > 16 * 1024 * 1024:
        raise ReleaseError("Registry index response is too large")
    for line in body.splitlines():
        entry = json.loads(line)
        if entry["vers"] == package.version:
            return entry
    return None


def wait_for_version(package, checksum, *, seconds=180, lookup=registry_version,
                     clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise ReleaseError(f"Registry availability timed out: {package.name}")
        entry = lookup(package, timeout=min(20, remaining))
        if entry is not None:
            if entry.get("cksum") != checksum or entry.get("yanked"):
                raise ReleaseError(f"Registry checksum or status differs: {package.name}")
            return
        sleep(min(5, max(0, deadline - clock())))


def verify_metadata(metadata, repo, root, pdf):
    by_name = {p["name"]: p for p in metadata["packages"]}
    for package in metadata["packages"]:
        if Path(package["manifest_path"]).resolve().is_relative_to(repo.resolve()):
            raise ReleaseError("Consumer resolves a repository source path")
    if "svg2pdf" in by_name or pdf.name not in by_name:
        raise ReleaseError("Consumer does not resolve the renamed PDF package")
    root_id = by_name[root.name]["id"]
    pdf_id = by_name[pdf.name]["id"]
    node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == root_id)
    if not any(d["name"] == "svg2pdf" and d["pkg"] == pdf_id for d in node["deps"]):
        raise ReleaseError("Root PDF dependency does not use the patched package")
    return next(
        p["version"] for p in metadata["packages"]
        if p["id"] == next(d["pkg"] for d in node["deps"] if d["name"] == "usvg")
    )


class Release:
    def __init__(self, repo, output, target):
        self.repo, self.output, self.target = repo, output, target
        for parent in (output, *output.parents):
            if any((parent / ".cargo" / name).exists() for name in ("config", "config.toml")):
                raise ReleaseError("Choose an output directory without ancestor Cargo configuration")
        self.packages = packages(repo)
        self.home = output / "cargo-home"
        self.home.mkdir(parents=True)
        toolchain = read_toml(repo / "rust-toolchain.toml")["toolchain"]["channel"]
        self.env = clean_environment(self.home, target, toolchain)
        self.records = {}
        self.head = git(repo, "rev-parse", "HEAD")
        self.dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=all"))
        self.tracked = set(git(repo, "ls-files", "-z").split("\0"))
        self.confirmation = None

    def cargo(self, *args, cwd=None, env=None, capture=False):
        return run(["cargo", *args], cwd=cwd or self.output,
                   env=env or self.env, capture=capture)

    def archive(self, package, *, env=None):
        common = ["--manifest-path", str(package.manifest), "-p", package.name]
        listing = self.cargo(
            "package", "--list", "--locked", "--allow-dirty", *common, env=env, capture=True,
        ).splitlines()
        check_tracked_inventory(self.repo, package, listing, self.tracked)
        self.cargo("package", "--locked", "--allow-dirty", *common, env=env)
        source = self.target / "package" / package.archive_name
        saved = self.output / "archives" / package.archive_name
        saved.parent.mkdir(exist_ok=True)
        shutil.copyfile(source, saved)
        extracted, files = unpack_archive(saved, self.output / "unpacked", package, listing)
        self.records[package.name] = {
            "version": package.version, "sha256": digest(saved), "files": files,
        }
        return saved, extracted

    def consumer(self, root_path, phase, env):
        root, pdf = self.packages[-1], self.packages[-2]
        consumer = self.output / f"consumer-{phase}"
        (consumer / "src").mkdir(parents=True)
        manifest = (
            '[package]\nname = "cargo-archive-consumer"\nversion = "0.0.0"\n'
            'edition = "2021"\n[workspace]\n[dependencies]\n'
            f'rhwp = {{ package = {json.dumps(root.name)}, path = '
            f'{json.dumps(str(root_path))} }}\n'
        )
        (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")
        (consumer / "src/main.rs").write_text(
            'fn main() {\n'
            '    assert!(rhwp::parser::parse_document_strict(&[]).is_err());\n'
            '    println!("Packaged strict parser rejects empty input.");\n'
            '}\n', encoding="utf-8",
        )
        self.cargo("run", cwd=consumer, env=env)
        self.cargo("check", "--target", "wasm32-unknown-unknown", cwd=consumer, env=env)
        host = run(["rustc", "-vV"], cwd=consumer, env=env, capture=True)
        host = next(line.removeprefix("host: ") for line in host.splitlines() if line.startswith("host: "))
        metadata = json.loads(self.cargo(
            "metadata", "--format-version", "1", "--filter-platform", host,
            cwd=consumer, env=env, capture=True,
        ))
        usvg_version = verify_metadata(metadata, self.repo, root, pdf)
        if phase == "registry" and any(
            Path(package["manifest_path"]).resolve().is_relative_to(self.output / "registry")
            for package in metadata["packages"]
        ):
            raise ReleaseError("Real-registry verification still uses the directory source")
        (self.output / f"metadata-{phase}.json").write_text(
            json.dumps(metadata), encoding="utf-8",
        )
        with (consumer / "Cargo.toml").open("a", encoding="utf-8") as file:
            file.write(
                '\n[dev-dependencies]\nusvg = { version = '
                f'"={usvg_version}", default-features = false, features = ["text"] }}\n'
            )
        (consumer / "tests").mkdir()
        shutil.copyfile(
            self.repo / "tests/cases/issue_7077_pdf_gradient_functions.rs",
            consumer / "tests/pdf_gradient_functions.rs",
        )
        result = self.cargo(
            "test", "--test", "pdf_gradient_functions", cwd=consumer, env=env, capture=True,
        )
        if "test result: ok. 2 passed; 0 failed;" not in result:
            raise ReleaseError("Both packaged PDF gradient regressions must execute")
        print(result, flush=True)

    def preflight(self):
        leaves = []
        for package in self.packages[:-1]:
            archive, _ = self.archive(package)
            leaves.append((package, archive))
        configuration = self.cargo(
            "vendor", "--manifest-path", self.repo / "Cargo.toml",
            "--locked", "--versioned-dirs", self.output / "registry", capture=True,
        )
        (self.home / "config.toml").write_text(configuration, encoding="utf-8")
        for package, archive in leaves:
            stage_archive(archive, self.output / "registry", package,
                          self.records[package.name]["files"])
        isolated = self.env | {"CARGO_NET_OFFLINE": "true"}
        _, root = self.archive(self.packages[-1], env=isolated)
        self.consumer(root, "local", isolated)
        self.report("preflight-passed")

    def report(self, status):
        (self.output / "report.json").write_text(
            json.dumps({"commit": self.head, "dirty": self.dirty, "status": status,
                        "packages": self.records}, indent=2) + "\n",
            encoding="utf-8",
        )

    def upload(self, package, token):
        if git(self.repo, "rev-parse", "HEAD") != self.head:
            raise ReleaseError("Source commit changed during release checks")
        publish_guard(self.repo, self.packages[-1], self.confirmation, self.head)
        checksum = self.records[package.name]["sha256"]
        existing = registry_version(package)
        if existing is not None:
            if existing.get("cksum") != checksum or existing.get("yanked"):
                raise ReleaseError(f"Existing registry version differs: {package.name}")
            print(f"Verified existing archive: {package.name}@{package.version}", flush=True)
            return
        env = self.env | {"CARGO_REGISTRY_TOKEN": token}
        self.cargo(
            "publish", "--registry", "crates-io", "--no-verify", "--locked",
            "--manifest-path", package.manifest, "-p", package.name, env=env,
        )
        wait_for_version(package, checksum)

    def publish(self, token, confirmation):
        self.confirmation = confirmation
        self.preflight()
        for package in self.packages:
            existing = registry_version(package)
            if existing is not None and (
                existing.get("cksum") != self.records[package.name]["sha256"]
                or existing.get("yanked")
            ):
                raise ReleaseError(f"Existing registry version differs: {package.name}")
        (self.home / "config.toml").unlink()
        for package in self.packages[:-1]:
            self.upload(package, token)
        _, root = self.archive(self.packages[-1])
        self.consumer(root, "registry", self.env)
        self.upload(self.packages[-1], token)
        self.report("published")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("preflight", "publish"), default="preflight")
    parser.add_argument("--confirm")
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    try:
        selected = packages(repo)
        token = None
        if args.mode == "publish":
            _, token = publish_guard(repo, selected[-1], args.confirm, args.commit)
        output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="cargo-release-"))
        if output.is_relative_to(repo):
            raise ReleaseError("--output must be outside the repository")
        if args.output:
            output.mkdir()
        target = (args.target_dir or repo / "target/pr-review").resolve()
        release = Release(repo, output, target)
        if args.mode == "publish":
            release.publish(token, args.confirm)
        else:
            release.preflight()
        print(f"Release report: {output / 'report.json'}")
        return 0
    except (ReleaseError, subprocess.CalledProcessError, OSError, ValueError, KeyError,
            tarfile.TarError) as error:
        print(f"Cargo release failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
