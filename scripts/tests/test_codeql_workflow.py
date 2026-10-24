"""CodeQL 보안 판정 재사용과 Rust no-prebuild의 장기 workflow 계약."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CODEQL_WORKFLOW = REPO_ROOT / ".github/workflows/codeql.yml"
RUST_PR_CODEQL_CONFIG = REPO_ROOT / ".github/codeql/rust-pr.yml"


def job_body(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"codeql.yml에 {job_name} job이 없다")
    return match.group(0)


class CodeQLWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = CODEQL_WORKFLOW.read_text(encoding="utf-8")
        script = cls.workflow.split("script: |\n", maxsplit=1)[1].split(
            "\n      # 기준선 병합을 fast-pass bridge로", maxsplit=1
        )[0]
        cls.preflight_script = "\n".join(
            line.removeprefix("            ") for line in script.splitlines()
        )
        language_step = cls.workflow.split(
            "      - name: Finalize CodeQL language selection\n", maxsplit=1
        )[1].split("\n      - name: Summarize CodeQL impact classification", maxsplit=1)[0]
        language_script = language_step.split("        run: |\n", maxsplit=1)[1]
        cls.language_script = "\n".join(
            line.removeprefix("          ") for line in language_script.splitlines()
        )

    def test_reused_result_requires_candidate_bound_security_check(self) -> None:
        workflow = self.workflow
        self.assertIn("github.rest.checks.listForRef", workflow)
        self.assertIn("ref: candidateSha", workflow)
        self.assertIn("check.app?.slug === 'github-advanced-security'", workflow)
        self.assertIn("check.name === 'CodeQL'", workflow)
        self.assertIn("check.head_sha === candidateSha", workflow)
        self.assertIn("workflowRun.run_started_at || workflowRun.created_at", workflow)
        self.assertIn("Date.parse(securityCheck.started_at)", workflow)
        self.assertIn("securityCheckStartedAt < runAttemptStartedAt", workflow)
        self.assertNotIn("check.created_at", workflow)
        self.assertNotIn("securityCheck.created_at", workflow)
        self.assertNotIn("check.started_at || check.created_at || 0", workflow)
        self.assertNotIn(
            "securityCheck.started_at || securityCheck.created_at || 0", workflow
        )
        self.assertNotIn("security-check-workflow-identity-mismatch", workflow)
        self.assertIn("missing-security-check:CodeQL:${candidateSha}", workflow)
        self.assertIn("security-check-not-completed:CodeQL:${securityCheck.status}", workflow)
        self.assertIn("security-check-not-green:CodeQL:${securityCheck.conclusion}", workflow)
        self.assertIn(
            "const allowedSecurityConclusions = new Set(['success', 'neutral']);",
            workflow,
        )
        self.assertIn(
            "!allowedSecurityConclusions.has(securityCheck.conclusion)", workflow
        )
        self.assertNotIn("securityCheck.conclusion !== 'success'", workflow)
        self.assertLess(
            workflow.index("!allowedSecurityConclusions.has(securityCheck.conclusion)"),
            workflow.index("return { state: 'green' };"),
        )

    def test_trusted_postmerge_reuse_receives_original_caller_identity(self) -> None:
        trusted_reuse = job_body(self.workflow, "trusted_postmerge_reuse")
        self.assertIn("caller_event_name: ${{ github.event_name }}", trusted_reuse)
        self.assertIn("caller_ref: ${{ github.ref }}", trusted_reuse)
        self.assertIn("caller_sha: ${{ github.sha }}", trusted_reuse)

    def test_green_analyze_jobs_cannot_reuse_a_failed_security_check(self) -> None:
        outputs = self._run_preflight("failure")
        self.assertEqual(outputs["fast_pass"], "false")
        self.assertEqual(outputs["candidate_sha"], "cccccccccccccccccccccccccccccccccccccccc")
        self.assertEqual(
            outputs["reason"],
            "security-check-not-green:CodeQL:failure",
        )

    def test_green_analyze_jobs_and_early_security_check_remain_reusable(self) -> None:
        outputs = self._run_preflight("success")
        self.assertEqual(outputs["fast_pass"], "true")
        self.assertEqual(outputs["candidate_sha"], "cccccccccccccccccccccccccccccccccccccccc")
        self.assertEqual(outputs["reason"], "codeql-checks-green")

    def test_green_analyze_jobs_and_neutral_security_summary_remain_reusable(self) -> None:
        outputs = self._run_preflight("neutral")
        self.assertEqual(outputs["fast_pass"], "true")
        self.assertEqual(outputs["candidate_sha"], "cccccccccccccccccccccccccccccccccccccccc")
        self.assertEqual(outputs["reason"], "codeql-checks-green")

    def test_green_analyze_jobs_cannot_reuse_a_skipped_security_summary(self) -> None:
        outputs = self._run_preflight("skipped")
        self.assertEqual(outputs["fast_pass"], "false")
        self.assertEqual(outputs["candidate_sha"], "cccccccccccccccccccccccccccccccccccccccc")
        self.assertEqual(
            outputs["reason"],
            "security-check-not-green:CodeQL:skipped",
        )

    def test_security_check_from_an_earlier_run_attempt_is_not_reused(self) -> None:
        outputs = self._run_preflight(
            "success",
            run_started_at="2026-08-09T00:18:00Z",
            security_started_at="2026-08-09T00:15:00Z",
            security_completed_at="2026-08-09T00:15:02Z",
        )
        self.assertEqual(outputs["fast_pass"], "false")
        self.assertEqual(outputs["reason"], "no-green-codeql-candidate")

    def test_security_check_without_started_at_is_not_reused(self) -> None:
        outputs = self._run_preflight("success", security_started_at=None)
        self.assertEqual(outputs["fast_pass"], "false")
        self.assertEqual(outputs["reason"], "no-green-codeql-candidate")

    def test_preflight_uses_trusted_classifier_and_fails_closed_to_all_languages(
        self,
    ) -> None:
        workflow = self.workflow
        preflight = job_body(workflow, "preflight")
        self.assertIn("permissions:\n      actions: read", preflight)
        self.assertIn(
            "codeql_languages: ${{ steps.languages.outputs.codeql_languages "
            "|| 'javascript-typescript,python,rust' }}",
            workflow,
        )
        self.assertIn(
            "ref: ${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.base.sha || github.sha }}",
            workflow,
        )
        self.assertIn("sparse-checkout: scripts/ci-impact-classifier.cjs", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("forceFullReason: 'non-pull-request'", workflow)
        self.assertIn("forceFullReason: 'collection-error'", workflow)
        self.assertIn("id: languages", workflow)
        self.assertIn("IMPACT_OUTCOME: ${{ steps.impact.outcome }}", workflow)
        self.assertIn("fail-closed:impact-unavailable", workflow)
        self.assertIn("fail-closed:invalid-codeql-languages", workflow)
        for selection in (
            "none",
            "javascript-typescript",
            "python",
            "rust",
            "javascript-typescript,python",
            "javascript-typescript,rust",
            "python,rust",
            "javascript-typescript,python,rust",
        ):
            self.assertIn(f"'{selection}')", workflow)

    def test_analysis_steps_follow_selection_while_check_names_stay_stable(self) -> None:
        analyze = job_body(self.workflow, "analyze")
        selected = (
            "contains(format(',{0},', env.SELECTED_LANGUAGES), "
            "format(',{0},', matrix.language))"
        )
        self.assertIn(
            "SELECTED_LANGUAGES: ${{ needs.preflight.outputs.codeql_languages "
            "|| 'javascript-typescript,python,rust' }}",
            analyze,
        )
        self.assertIn("language: [javascript-typescript, python, rust]", analyze)
        self.assertIn("name: Analyze (${{ matrix.language }})", analyze)
        self.assertIn("name: Skip unselected language", analyze)
        self.assertIn(f"if: ${{{{ !{selected} }}}}", analyze)
        self.assertEqual(analyze.count(f"if: ${{{{ {selected} }}}}"), 2)
        self.assertIn(
            "if: ${{ matrix.language != 'rust' && " + selected + " }}",
            analyze,
        )
        self.assertIn(
            "if: ${{ matrix.language == 'rust' && "
            + selected
            + " && github.event_name == 'pull_request' }}",
            analyze,
        )
        self.assertIn(
            "if: ${{ matrix.language == 'rust' && "
            + selected
            + " && github.event_name != 'pull_request' && !(github.event_name == 'push' && github.ref == 'refs/heads/devel') }}",
            analyze,
        )
        job_if = next(
            line.strip() for line in analyze.splitlines() if line.strip().startswith("if:")
        )
        self.assertNotIn("codeql_languages", job_if)

    def test_fast_pass_summary_marks_language_classification_not_applicable(
        self,
    ) -> None:
        summary = self.workflow.split(
            "      - name: Summarize CodeQL impact classification\n", maxsplit=1
        )[1].split("\n  analyze:", maxsplit=1)[0]
        self.assertIn("if [[ \"${FAST_PASS}\" == 'true' ]]; then", summary)
        self.assertIn("IMPACT_AUTHORITY='n/a (fast-pass)'", summary)
        self.assertIn("CODEQL_LANGUAGES='n/a (fast-pass)'", summary)
        self.assertIn("CLASSIFICATION_STATUS='n/a (fast-pass)'", summary)
        self.assertIn('IMPACT_REASON="fast-pass:${FAST_PASS_REASON}"', summary)

    def test_language_finalizer_preserves_valid_selection(self) -> None:
        outputs = self._run_language_finalizer(
            outcome="success",
            languages="javascript-typescript",
            status="classified",
            reason="classified:studio-unit",
        )
        self.assertEqual(outputs["codeql_languages"], "javascript-typescript")
        self.assertEqual(outputs["classification_status"], "classified")
        self.assertEqual(outputs["reason"], "classified:studio-unit")

    def test_language_finalizer_rejects_invalid_or_failed_classification(self) -> None:
        invalid = self._run_language_finalizer(
            outcome="success",
            languages="javascript-typescript,ruby",
            status="classified",
            reason="classified:unexpected",
        )
        unavailable = self._run_language_finalizer(
            outcome="failure",
            languages="javascript-typescript",
            status="classified",
            reason="classified:studio-unit",
        )
        inconsistent_full = self._run_language_finalizer(
            outcome="success",
            languages="rust",
            status="full",
            reason="fail-closed:unexpected",
        )
        for outputs, reason in (
            (invalid, "fail-closed:invalid-codeql-languages"),
            (unavailable, "fail-closed:impact-unavailable"),
            (inconsistent_full, "fail-closed:invalid-codeql-languages"),
        ):
            self.assertEqual(
                outputs["codeql_languages"],
                "javascript-typescript,python,rust",
            )
            self.assertEqual(outputs["classification_status"], "full")
            self.assertEqual(outputs["reason"], reason)

    def test_rust_lane_uses_explicit_none_build_mode_without_manual_prebuild(self) -> None:
        analyze = job_body(self.workflow, "analyze")
        self.assertIn("language: [javascript-typescript, python, rust]", analyze)
        self.assertIn("languages: ${{ matrix.language }}", analyze)
        self.assertIn("security-events: write", analyze)
        self.assertIn("contents: read", analyze)
        self.assertIn("Perform CodeQL Analysis", analyze)
        rust_init = analyze.split("      - name: Initialize CodeQL (Rust)\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("languages: rust", rust_init)
        self.assertIn("build-mode: none", rust_init)
        self.assertIn("config-file: .github/codeql/rust-pr.yml", rust_init)
        rust_full_init = analyze.split(
            "      - name: Initialize CodeQL (Rust full scan)\n", 1
        )[1].split("\n      - name:", 1)[0]
        self.assertIn("languages: rust", rust_full_init)
        self.assertIn("build-mode: none", rust_full_init)
        self.assertNotIn("config-file:", rust_full_init)
        self.assertEqual(analyze.count("uses: actions/cache/"), 2)
        self.assertNotIn("uses: actions/cache@", analyze)
        self.assertNotIn("cargo build", analyze)
        self.assertNotIn("rust-blocking-results", analyze)
        self.assertNotIn("actions/upload-artifact", analyze)

    def _rust_cache_step(self, name: str) -> str:
        return job_body(self.workflow, "analyze").split(
            f"      - name: {name}\n", 1
        )[1].split("\n      - name:", 1)[0]

    def _run_rust_cache_identity(self, root: Path, **overrides: str) -> tuple[int, str]:
        workspace = root / "workspace"
        tools = root / "codeql/rust/tools"
        commands = root / "bin"
        for directory in (workspace, tools, commands, root / "temp"):
            directory.mkdir(parents=True, exist_ok=True)
        extractor = tools / "extractor"
        if not extractor.exists():
            extractor.write_bytes(b"fixed extractor compiler")
        for command, variable in (
            ("git", "FAKE_HEAD"), ("rustc", "FAKE_COMPILER"), ("rustup", "FAKE_TOOLCHAIN")
        ):
            executable = commands / command
            executable.write_text(
                f"#!{sys.executable}\nimport os\nprint(os.environ[{variable!r}])\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
        output = root / "output"
        output.write_text("", encoding="utf-8")
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CODEQL_EXTRACTOR_RUST_")
        }
        environment.update({
            "PATH": str(commands) + os.pathsep + os.environ["PATH"],
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/12/merge",
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(root / "temp"),
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "GITHUB_OUTPUT": str(output),
            "CACHE_PR": "12",
            "CACHE_REPOSITORY": "123",
            "SOURCE_SHA": "a" * 40,
            "FAKE_HEAD": "a" * 40,
            "CODEQL_PATH": str(root / "codeql/codeql"),
            "CODEQL_VERSION": "2.27.3",
            "FAKE_COMPILER": "rustc fixture\nhost: fixture-linux",
            "FAKE_TOOLCHAIN": "stable-fixture-linux",
            "CODEQL_EXTRACTOR_RUST_OPTION_CARGO_TARGET_DIR":
                str(root / "temp/codeql-rust-cargo-target"),
        })
        environment.update(overrides)
        step = self._rust_cache_step("Identify Rust extractor Cargo cache")
        script = step.split("          python3 - <<'PY'\n", 1)[1].split(
            "\n          PY", 1
        )[0]
        script = "\n".join(line.removeprefix("          ") for line in script.splitlines())
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=workspace, env=environment,
            capture_output=True, text=True, check=False,
        )
        return result.returncode, output.read_text(encoding="utf-8").strip()

    def test_rust_cache_identity_is_stable_and_invalidates_every_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status, baseline = self._run_rust_cache_identity(root)
            self.assertEqual(status, 0)
            self.assertRegex(baseline, r"^key=codeql-rust-cargo-v1-[0-9a-f]{64}$")
            self.assertEqual(self._run_rust_cache_identity(root), (0, baseline))
            for changes in (
                {"CODEQL_VERSION": "2.27.4"},
                {"FAKE_COMPILER": "rustc changed compiler"},
                {"FAKE_TOOLCHAIN": "nightly-fixture-linux"},
                {"SOURCE_SHA": "b" * 40, "FAKE_HEAD": "b" * 40},
                {"CODEQL_EXTRACTOR_RUST_OPTION_CARGO_FEATURES": "changed option"},
                {"CACHE_REPOSITORY": "456"},
                {"CACHE_PR": "13", "GITHUB_REF": "refs/pull/13/merge"},
                {"RUNNER_ARCH": "ARM64"},
            ):
                with self.subTest(changes=changes):
                    status, changed = self._run_rust_cache_identity(root, **changes)
                    self.assertEqual(status, 0)
                    self.assertNotEqual(changed, baseline)
            (root / "codeql/rust/tools/extractor").write_bytes(b"changed fixed compiler")
            status, changed = self._run_rust_cache_identity(root)
            self.assertEqual(status, 0)
            self.assertNotEqual(changed, baseline)

    def test_rust_cache_rejects_untrusted_context_or_workspace_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for changes in (
                {"GITHUB_EVENT_NAME": "pull_request_target"},
                {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"},
                {"GITHUB_REF": "refs/pull/99/merge"},
                {"SOURCE_SHA": "b" * 40},
                {"CODEQL_EXTRACTOR_RUST_OPTION_CARGO_TARGET_DIR": str(root / "workspace/target")},
                {"CODEQL_VERSION": ""},
                {"CODEQL_PATH": str(root / "missing/codeql")},
            ):
                with self.subTest(changes=changes):
                    status, output = self._run_rust_cache_identity(root, **changes)
                    self.assertNotEqual(status, 0)
                    self.assertEqual(output, "")

    def test_rust_cache_is_exact_pr_only_and_saves_only_successful_analysis(self) -> None:
        selection = "contains(format(',{0},', env.SELECTED_LANGUAGES), format(',{0},', matrix.language))"
        names = (
            "Identify Rust extractor Cargo cache", "Restore Rust extractor Cargo cache",
            "Save Rust extractor Cargo cache",
        )
        for name in names:
            step = self._rust_cache_step(name)
            condition = re.search(r"if: \$\{\{ (.*?) \}\}", step).group(1)
            for event in ("pull_request", "pull_request_target", "push", "schedule", "workflow_dispatch"):
                for language in ("rust", "python"):
                    for selected in (True, False):
                        for successful in (True, False):
                            for hit in ("true", "false", ""):
                                expression = condition.replace(selection, str(selected))
                                for variable, value in (
                                    ("matrix.language", language), ("github.event_name", event),
                                    ("steps.codeql-analyze.outcome", "success" if successful else "failure"),
                                    ("steps.rust-cargo-restore.outputs.cache-hit", hit),
                                ):
                                    expression = expression.replace(variable, repr(value))
                                expression = expression.replace("success()", str(successful))
                                expression = expression.replace("&&", " and ").replace("||", " or ")
                                actual = eval(expression, {"__builtins__": {}}, {})
                                expected = event == "pull_request" and language == "rust" and selected
                                if name.startswith("Save"):
                                    expected = expected and successful and hit != "true"
                                self.assertEqual(actual, expected, (name, event, language, hit))
        analyze = job_body(self.workflow, "analyze")
        for name in (names[0], "Perform CodeQL Analysis"):
            self.assertIn(
                "CODEQL_EXTRACTOR_RUST_OPTION_CARGO_TARGET_DIR: ${{ runner.temp }}/codeql-rust-cargo-target",
                self._rust_cache_step(name),
            )
        for name, action in ((names[1], "restore"), (names[2], "save")):
            step = self._rust_cache_step(name)
            self.assertIn(
                f"actions/cache/{action}@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", step,
            )
            self.assertIn("path: ${{ runner.temp }}/codeql-rust-cargo-target", step)
            self.assertIn("key: ${{ steps.rust-cargo-key.outputs.key }}", step)
            self.assertNotIn("restore-keys:", step)
        self.assertLess(analyze.index(names[1]), analyze.index("Perform CodeQL Analysis"))
        self.assertGreater(analyze.index(names[2]), analyze.index("Perform CodeQL Analysis"))

    def test_pr_rust_config_limits_scanning_to_production_paths(self) -> None:
        config = RUST_PR_CODEQL_CONFIG.read_text(encoding="utf-8")
        self.assertIn("paths:\n", config)
        for path in ("src/**", "crates/**", "rhwp-desk/src/**", "build.rs"):
            self.assertIn(f"  - {path}\n", config)

    def test_postmerge_metrics_keep_full_source_scope_and_security_defaults(self) -> None:
        config = (REPO_ROOT / ".github/codeql/rust-postmerge.yml").read_text(encoding="utf-8")
        active = "\n".join(line for line in config.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(active, r"(?m)^\s*(paths|paths-ignore|queries|packs|disable-default-queries):")
        self.assertEqual(re.findall(r"id: (\S+)", active), [
            "rust/summary/summary-statistics",
            "rust/summary/reduced-summary-statistics",
            "rust/summary/query-sink-counts",
        ])
        self.assertEqual(active.count("kind: metric"), 3)
        self.assertEqual(active.count("- exclude:"), 3)

    def test_rust_initializers_are_exclusive_for_every_event_and_language(self) -> None:
        analyze = job_body(self.workflow, "analyze")
        blocks = re.findall(r"(?ms)^      - name: Initialize CodeQL \(Rust[^\n]*\n.*?(?=^      - name:|\Z)", analyze)
        self.assertEqual(len(blocks), 3)
        conditions = [re.search(r"if: \$\{\{ (.*?) \}\}", block).group(1) for block in blocks]
        selection = "contains(format(',{0},', env.SELECTED_LANGUAGES), format(',{0},', matrix.language))"
        for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
            for ref in ("refs/heads/devel", "refs/heads/main"):
                for language in ("rust", "python"):
                    for selected in (True, False):
                        values = []
                        for condition in conditions:
                            expression = condition.replace(selection, str(selected))
                            expression = expression.replace("matrix.language", repr(language))
                            expression = expression.replace("github.event_name", repr(event))
                            expression = expression.replace("github.ref", repr(ref))
                            expression = expression.replace("&&", " and ").replace("||", " or ")
                            expression = re.sub(r"!(?!=)", "not ", expression)
                            values.append(eval(expression, {"__builtins__": {}}, {}))
                        expected = (0 if event == "pull_request" else
                                    1 if event == "push" and ref == "refs/heads/devel" else 2)
                        self.assertEqual(values, [language == "rust" and selected and i == expected for i in range(3)])
        self.assertIn("config-file: .github/codeql/rust-postmerge.yml", blocks[1])
        self.assertNotIn("config-file:", blocks[2])

    def test_temporary_measurement_jobs_and_artifacts_are_absent(self) -> None:
        workflow = self.workflow
        self.assertNotIn("rust-no-prebuild-shadow:", workflow)
        self.assertNotIn("Rust no-prebuild shadow", workflow)
        self.assertNotIn("rust-no-prebuild-results", workflow)
        self.assertNotIn("rust-blocking-results", workflow)
        self.assertNotIn("rust-blocking-sarif-", workflow)
        self.assertNotIn("rust-no-prebuild-sarif-", workflow)

    def _run_preflight(
        self,
        security_conclusion: str,
        *,
        run_started_at: str = "2026-08-09T00:10:00Z",
        security_started_at: str | None = "2026-08-09T00:11:00Z",
        security_completed_at: str = "2026-08-09T00:11:02Z",
    ) -> dict[str, str]:
        harness = """
const outputs = {};
const endpoints = {
  listWorkflowRuns: Symbol('listWorkflowRuns'),
  listJobsForWorkflowRun: Symbol('listJobsForWorkflowRun'),
  listFiles: Symbol('listFiles'),
  listCommits: Symbol('listCommits'),
  listForRef: Symbol('listForRef'),
};
const commits = {
  'dddddddddddddddddddddddddddddddddddddddd': {
    parents: [{ sha: 'cccccccccccccccccccccccccccccccccccccccc' }],
    files: [{ filename: 'mydocs/working/review.md', status: 'modified' }],
  },
  'cccccccccccccccccccccccccccccccccccccccc': {
    parents: [{ sha: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }],
    files: [{ filename: 'src/lib.rs', status: 'modified' }],
  },
};
const github = {
  rest: {
    actions: {
      listWorkflowRuns: endpoints.listWorkflowRuns,
      listJobsForWorkflowRun: endpoints.listJobsForWorkflowRun,
    },
    pulls: {
      listFiles: endpoints.listFiles,
      listCommits: endpoints.listCommits,
    },
    checks: { listForRef: endpoints.listForRef },
    repos: {
      getCommit: async ({ ref }) => ({ data: { sha: ref, ...commits[ref] } }),
    },
  },
  paginate: async (endpoint, params) => {
    if (endpoint === endpoints.listFiles) {
      return [
        { filename: 'src/lib.rs', status: 'modified' },
        { filename: 'mydocs/working/review.md', status: 'modified' },
      ];
    }
    if (endpoint === endpoints.listCommits) {
      return [{ sha: 'cccccccccccccccccccccccccccccccccccccccc' }, { sha: 'dddddddddddddddddddddddddddddddddddddddd' }];
    }
    if (endpoint === endpoints.listWorkflowRuns) {
      return [{
        id: 3790,
        path: '.github/workflows/codeql.yml',
        event: 'pull_request',
        head_sha: 'cccccccccccccccccccccccccccccccccccccccc',
        head_branch: 'feature-3790',
        head_repository: { id: 7 },
        status: 'completed',
        conclusion: 'success',
        created_at: '2026-08-09T00:10:00Z',
        run_started_at: RUN_STARTED_AT,
        completed_at: '2026-08-09T00:20:00Z',
      }];
    }
    if (endpoint === endpoints.listJobsForWorkflowRun) {
      return [
        { name: 'Analyze (python)', completed_at: '2026-08-09T00:12:00Z' },
        {
          name: 'Analyze (javascript-typescript)',
          completed_at: '2026-08-09T00:14:00Z',
        },
        { name: 'Analyze (rust)', completed_at: '2026-08-09T00:19:00Z' },
      ].map((job) => ({
        ...job,
        status: 'completed',
        conclusion: 'success',
      }));
    }
    if (endpoint === endpoints.listForRef) {
      return [{
        name: 'CodeQL',
        app: { slug: 'github-advanced-security' },
        head_sha: params.ref,
        status: 'completed',
        conclusion: SECURITY_CONCLUSION,
        started_at: SECURITY_STARTED_AT,
        completed_at: SECURITY_COMPLETED_AT,
      }];
    }
    throw new Error('unexpected paginate endpoint');
  },
};
const context = {
  eventName: 'pull_request',
  repo: { owner: 'edwardkim', repo: 'rhwp' },
  payload: {
    pull_request: {
      number: 4310,
      created_at: '2026-08-09T00:00:00Z',
      base: { sha: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
      head: { sha: 'dddddddddddddddddddddddddddddddddddddddd', ref: 'feature-3790', repo: { id: 7 } },
    },
  },
};
const core = {
  setOutput: (name, value) => { outputs[name] = String(value); },
  info: () => {},
  warning: () => {},
};
(async () => {
PREFLIGHT_SCRIPT
})().then(() => {
  process.stdout.write(JSON.stringify(outputs));
}).catch((error) => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
""".replace("SECURITY_CONCLUSION", json.dumps(security_conclusion)).replace(
            "RUN_STARTED_AT", json.dumps(run_started_at)
        ).replace("SECURITY_STARTED_AT", json.dumps(security_started_at)).replace(
            "SECURITY_COMPLETED_AT", json.dumps(security_completed_at)
        ).replace(
            "PREFLIGHT_SCRIPT", self.preflight_script
        )
        completed = subprocess.run(
            ["node"],
            input=harness,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def _run_language_finalizer(
        self,
        *,
        outcome: str,
        languages: str,
        status: str,
        reason: str,
    ) -> dict[str, str]:
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as output:
            env = os.environ.copy()
            env.update(
                {
                    "GITHUB_OUTPUT": output.name,
                    "IMPACT_OUTCOME": outcome,
                    "RAW_LANGUAGES": languages,
                    "RAW_STATUS": status,
                    "RAW_REASON": reason,
                }
            )
            completed = subprocess.run(
                ["bash"],
                # Windows text pipes translate LF to CRLF.  Feed Bash bytes so
                # the YAML shell block keeps its POSIX line endings.
                input=self.language_script.encode("utf-8"),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            output.seek(0)
            return dict(
                line.rstrip("\n").split("=", maxsplit=1)
                for line in output
                if "=" in line
            )


if __name__ == "__main__":
    unittest.main()
