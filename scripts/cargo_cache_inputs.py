"""Restore cached Cargo input timestamps only for identical source bytes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_path(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file():
        return None
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        return None
    return resolved


def record(root, target, head, metadata=None):
    files = {}
    for depfile in target.rglob("*.d"):
        for line in depfile.read_text(errors="replace").splitlines():
            if line.startswith("#") or ": " not in line:
                continue
            try:
                names = shlex.split(line.split(": ", 1)[1])
            except ValueError:
                continue
            for name in names:
                path = source_path(root, name)
                if path is None or path.is_relative_to(target.resolve()):
                    continue
                relative = path.relative_to(root.resolve()).as_posix()
                if relative not in files:
                    files[relative] = {
                        "digest": digest(path),
                        "mtime_ns": path.stat().st_mtime_ns,
                    }
    target.mkdir(parents=True, exist_ok=True)
    metadata = metadata or target / ".source-inputs.json"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps({
        "version": 1, "head": head, "files": files,
    }), encoding="utf-8")
    return len(files)


def restore(root, target, head, metadata=None):
    metadata = metadata or target / ".source-inputs.json"
    try:
        data = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if not isinstance(data, dict) or data.get("version") != 1 or data.get("head") != head:
        return 0
    if not isinstance(data.get("files"), dict):
        return 0
    restored = 0
    now = time.time_ns()
    for name, item in data.get("files", {}).items():
        if not isinstance(item, dict):
            continue
        if Path(name).is_absolute() or ".." in Path(name).parts:
            continue
        path = source_path(root, name)
        if path is None or path.is_relative_to(target.resolve()):
            continue
        timestamp = item.get("mtime_ns")
        if type(timestamp) is not int or not 0 < timestamp <= now:
            continue
        if digest(path) != item.get("digest"):
            continue
        os.utime(path, ns=(path.stat().st_atime_ns, timestamp))
        restored += 1
    return restored


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("record", "restore"))
    parser.add_argument("--target-dir", default="target")
    parser.add_argument("--metadata-file")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    target = Path(args.target_dir).resolve()
    metadata = Path(args.metadata_file).resolve() if args.metadata_file else None
    count = (record if args.command == "record" else restore)(root, target, head, metadata)
    print(f"Cargo input timestamps: {args.command} {count} identical-source files")


if __name__ == "__main__":
    main()
