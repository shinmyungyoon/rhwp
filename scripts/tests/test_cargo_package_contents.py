import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
PACKAGES = (
    "shin-rhwp",
    "shin-rhwp-contracts",
    "shin-rhwp-ooxml-chart",
    "shin-rhwp-password-crypto",
    "shin-rhwp-svg2pdf",
)
DOCS = {
    "mydocs/manual/agent_knowledge_map.md",
    "mydocs/manual/agent_troubleshooting_guide.md",
    "mydocs/manual/gym_optional_tool.md",
    "mydocs/manual/recipes/01_fill_form_and_submit.md",
    "mydocs/manual/recipes/02_table_csv_roundtrip.md",
    "mydocs/manual/recipes/03_redact_before_sharing.md",
    "mydocs/manual/recipes/04_safety_check_untrusted_doc.md",
    "mydocs/manual/recipes/05_mail_merge_batch_fill.md",
    "mydocs/manual/recipes/06_visual_regression_before_after.md",
    "mydocs/tech/agent_roadmap/atlas_r1_r200.md",
}


class CargoPackageContents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {}
        for package in PACKAGES:
            command = [
                    os.environ.get("CARGO", "cargo"),
                    "package",
                    "--list",
                    "--locked",
                    "--allow-dirty",
                ]
            if package == "shin-rhwp-svg2pdf":
                command += ["--manifest-path", str(ROOT / "vendor/svg2pdf/Cargo.toml")]
            else:
                command += ["-p", package]
            result = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            cls.files[package] = set(result.stdout.splitlines())

    def test_root_has_no_corpus_or_application_packages(self):
        allowed_top = {
            ".cargo_vcs_info.json",
            "Cargo.lock",
            "Cargo.toml",
            "Cargo.toml.orig",
            "LICENSE",
            "README.md",
            "README_EN.md",
            "THIRD_PARTY_LICENSES.md",
            "build.rs",
            "llms.txt",
            "src",
            "saved",
            "mydocs",
        }
        for path in self.files["shin-rhwp"]:
            with self.subTest(path=path):
                self.assertIn(path.split("/")[0], allowed_top)
                if path.startswith("mydocs/"):
                    self.assertIn(path, DOCS)
                if Path(path).suffix.lower() in {".hwp", ".hwpx", ".pdf"}:
                    self.assertEqual(path, "saved/blank2010.hwp")

    def test_known_compile_resources_are_retained(self):
        required = DOCS | {
            "saved/blank2010.hwp",
            "llms.txt",
            "build.rs",
            "LICENSE",
            "THIRD_PARTY_LICENSES.md",
        }
        for directory in (
            "src/parser/hwpx/blank2010_assets",
            "src/serializer/hwpx/templates",
        ):
            required.update(
                path.relative_to(ROOT).as_posix()
                for path in (ROOT / directory).iterdir()
                if path.is_file()
            )
        self.assertFalse(required - self.files["shin-rhwp"])

    def test_shared_crates_keep_the_project_license(self):
        license_bytes = (ROOT / "LICENSE").read_bytes()
        for package in PACKAGES[1:4]:
            with self.subTest(package=package):
                self.assertIn("LICENSE", self.files[package])
                self.assertEqual(
                    (ROOT / "crates" / package.removeprefix("shin-") / "LICENSE").read_bytes(),
                    license_bytes,
                )
                for path in self.files[package]:
                    self.assertTrue(
                        path.startswith("src/")
                        or path
                        in {
                            ".cargo_vcs_info.json",
                            "Cargo.lock",
                            "Cargo.toml",
                            "Cargo.toml.orig",
                            "LICENSE",
                            "NOTICE",
                        },
                        path,
                    )

    def test_password_crypto_keeps_the_bsd_notice(self):
        self.assertIn("NOTICE", self.files["shin-rhwp-password-crypto"])
        notice = (ROOT / "crates/rhwp-password-crypto/NOTICE").read_text()
        self.assertIn("Volexity", notice)
        self.assertIn("e5f8b5e1590dee973630666e687e919fa70da2e2", notice)
        self.assertIn("Redistribution and use in source and binary forms", notice)

    def test_patched_pdf_package_keeps_notices_and_source(self):
        paths = self.files["shin-rhwp-svg2pdf"]
        self.assertTrue({"LICENSE-MIT", "LICENSE-APACHE", "NOTICE", "README.md", "RHWP_PATCHES.md", "src/lib.rs"} <= paths)
        for path in paths:
            self.assertTrue(path.startswith("src/") or path in {
                ".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig",
                "Cargo.lock", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE",
                "README.md", "RHWP_PATCHES.md",
            }, path)


if __name__ == "__main__":
    unittest.main()
