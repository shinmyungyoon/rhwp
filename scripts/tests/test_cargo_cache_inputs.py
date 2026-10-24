import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from scripts.cargo_cache_inputs import digest, record, restore


class CargoInputCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.source = self.root / "lib.rs"
        self.source.write_text("pub fn value() -> u8 { 1 }\n")
        self.old = time.time_ns() - 10_000_000_000
        os.utime(self.source, ns=(self.old, self.old))
        (self.target / "lib.d").write_text(f"output: {self.source}\n")

    def test_identical_source_restores_recorded_timestamp(self):
        self.assertEqual(record(self.root, self.target, "head"), 1)
        self.source.touch()
        self.assertEqual(restore(self.root, self.target, "head"), 1)
        self.assertEqual(self.source.stat().st_mtime_ns, self.old)

    def test_changed_bytes_and_other_commit_never_restore(self):
        record(self.root, self.target, "head")
        self.source.touch()
        fresh = self.source.stat().st_mtime_ns
        self.assertEqual(restore(self.root, self.target, "other"), 0)
        self.assertEqual(self.source.stat().st_mtime_ns, fresh)
        self.source.write_text("pub fn value() -> u8 { 2 }\n")
        changed = self.source.stat().st_mtime_ns
        self.assertEqual(restore(self.root, self.target, "head"), 0)
        self.assertEqual(self.source.stat().st_mtime_ns, changed)

    def test_escaped_spaces_in_compiler_dependencies(self):
        spaced = self.root / "with space.rs"
        spaced.write_text("pub fn other() {}\n")
        (self.target / "lib.d").write_text(
            "output: lib.rs with\\ space.rs\nlib.rs:\nwith\\ space.rs:\n"
        )
        self.assertEqual(record(self.root, self.target, "head"), 2)

    def test_metadata_cannot_touch_target_or_parent_files(self):
        outside = self.root.parent / f"{self.root.name}-outside"
        outside.write_text("outside")
        self.addCleanup(outside.unlink)
        target_file = self.target / "generated.rs"
        target_file.write_text("generated")
        entries = {
            str(outside): {"digest": digest(outside), "mtime_ns": self.old},
            "../" + outside.name: {"digest": digest(outside), "mtime_ns": self.old},
            "target/generated.rs": {"digest": digest(target_file), "mtime_ns": self.old},
        }
        (self.target / ".source-inputs.json").write_text(json.dumps({
            "version": 1, "head": "head", "files": entries,
        }))
        self.assertEqual(restore(self.root, self.target, "head"), 0)

    def test_future_timestamp_and_symlink_are_rejected(self):
        record(self.root, self.target, "head")
        metadata = self.target / ".source-inputs.json"
        data = json.loads(metadata.read_text())
        data["files"]["lib.rs"]["mtime_ns"] = time.time_ns() + 10_000_000_000
        metadata.write_text(json.dumps(data))
        self.assertEqual(restore(self.root, self.target, "head"), 0)
        self.source.unlink()
        self.source.symlink_to(self.target / "lib.d")
        self.assertEqual(restore(self.root, self.target, "head"), 0)


if __name__ == "__main__":
    unittest.main()
