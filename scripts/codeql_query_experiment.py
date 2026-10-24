"""Prepare and verify a coverage-preserving security-query experiment."""

import argparse
import json
from pathlib import Path

SECURITY_IDS = sorted([
    "rust/access-invalid-pointer",
    "rust/cleartext-logging",
    "rust/cleartext-storage-database",
    "rust/cleartext-transmission",
    "rust/command-line-injection",
    "rust/disabled-certificate-check",
    "rust/hard-coded-cryptographic-value",
    "rust/insecure-cookie",
    "rust/non-https-url",
    "rust/path-injection",
    "rust/regex-injection",
    "rust/request-forgery",
    "rust/sql-injection",
    "rust/uncontrolled-allocation-size",
    "rust/weak-cryptographic-algorithm",
    "rust/weak-sensitive-data-hashing",
    "rust/xss",
])


def selected_ids(group):
    if group not in ("a", "b"):
        raise ValueError("Unknown query group")
    return set(SECURITY_IDS[0 if group == "a" else 1::2])


def prepare_config(source, group):
    excluded = set(SECURITY_IDS) - selected_ids(group)
    return source.rstrip() + "\n" + "".join(
        f"  - exclude:\n      id: {query}\n" for query in sorted(excluded)
    )


def verify_results(directory, group):
    files = sorted(Path(directory).glob("*.sarif"))
    if len(files) != 1:
        raise ValueError("Expected one Rust SARIF file")
    runs = json.loads(files[0].read_text())["runs"]
    rules = {
        rule["id"]
        for run in runs
        for component in [run["tool"]["driver"], *run["tool"].get("extensions", [])]
        for rule in component.get("rules", [])
    }
    security = rules.intersection(SECURITY_IDS)
    if security != selected_ids(group):
        raise ValueError(f"Security query coverage mismatch: all observed rules={sorted(rules)}")
    return {
        "group": group,
        "security_queries": sorted(security),
        "all_rules": sorted(rules),
        "alerts": [
            {
                "rule": result.get("ruleId"),
                "locations": result.get("locations", []),
                "fingerprints": result.get("partialFingerprints", {}),
            }
            for run in runs
            for result in run.get("results", [])
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("group", choices=("a", "b"))
    parser.add_argument("path")
    args = parser.parse_args()
    if args.command == "prepare":
        original = Path(".github/codeql/rust-pr.yml").read_text()
        Path(args.path).write_text(prepare_config(original, args.group))
    else:
        print(json.dumps(verify_results(args.path, args.group), sort_keys=True))


if __name__ == "__main__":
    main()
