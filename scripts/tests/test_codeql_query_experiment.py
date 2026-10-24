import json
from pathlib import Path
import tempfile
import unittest

from scripts.codeql_query_experiment import (
    SECURITY_IDS, prepare_config, selected_ids, verify_results,
)


class QueryExperimentTests(unittest.TestCase):
    def test_groups_preserve_every_security_query_without_overlap(self):
        a, b = selected_ids("a"), selected_ids("b")
        self.assertFalse(a & b)
        self.assertEqual(a | b, set(SECURITY_IDS))
        self.assertEqual((len(a), len(b)), (9, 8))

    def test_original_source_and_diagnostic_policy_is_preserved(self):
        original = Path(".github/codeql/rust-pr.yml").read_text()
        for group in ("a", "b"):
            config = prepare_config(original, group)
            self.assertTrue(config.startswith(original.rstrip() + "\n"))
            additions = config[len(original.rstrip()) + 1:]
            excluded = set(SECURITY_IDS) - selected_ids(group)
            self.assertEqual(
                additions,
                "".join(f"  - exclude:\n      id: {query}\n" for query in sorted(excluded)),
            )

    def test_sarif_must_include_exact_group_security_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rust.sarif"
            expected = selected_ids("a")
            def write(ids):
                path.write_text(json.dumps({"runs": [{
                    "tool": {"driver": {"rules": [{"id": query} for query in ids]}},
                    "results": [],
                }]}))
            write(expected)
            self.assertEqual(verify_results(temporary, "a")["security_queries"], sorted(expected))
            for invalid in (set(), expected - {min(expected)}, set(SECURITY_IDS)):
                write(invalid)
                with self.assertRaises(ValueError):
                    verify_results(temporary, "a")

    def test_missing_sarif_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                verify_results(temporary, "a")

    def test_query_pack_rules_in_extensions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rust.sarif"
            expected = selected_ids("b")
            path.write_text(json.dumps({"runs": [{
                "tool": {
                    "driver": {"rules": []},
                    "extensions": [{"rules": [{"id": query} for query in expected]}],
                },
                "results": [],
            }]}))
            self.assertEqual(verify_results(temporary, "b")["security_queries"], sorted(expected))
            with self.assertRaises(ValueError):
                verify_results(temporary, "a")


if __name__ == "__main__":
    unittest.main()
