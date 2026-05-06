"""Tests for core.orchestration.agentic_passes.

Mocks subprocess.run (lifecycle/build_checklist helpers) and sandbox_run
(claude -p dispatch) so tests don't spawn real processes. The dispatcher
routes by argv[0] program name — lifecycle helpers go through
subprocess.run, claude calls through sandbox_run.
"""

import contextlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from core.orchestration.agentic_passes import (
    PostpassResult,
    PrepassResult,
    _enrich_agentic_checklist,
    _select_findings_for_validate,
    run_understand_prepass,
    run_validate_postpass,
)

# Assume interactive for all tests except RuleOfTwoTests (which patches
# is_interactive explicitly). Without this, every test that exercises the
# full pass path fails in CI/pytest (no TTY).
_interactive_patch = None

def setUpModule():
    global _interactive_patch
    _interactive_patch = patch(
        "core.security.rule_of_two.is_interactive", return_value=True,
    )
    _interactive_patch.start()

def tearDownModule():
    _interactive_patch.stop()


@contextlib.contextmanager
def _patch_passes(dispatcher):
    """Patch both subprocess.run and sandbox_run in agentic_passes.

    sandbox_run receives the claude -p calls (keyword-heavy signature);
    subprocess.run receives lifecycle/build_checklist calls. Both route
    through the same dispatcher. Returns a combined mock whose
    call_args_list merges both targets so existing assertions work.
    """
    combined = MagicMock()

    def _subprocess_side_effect(cmd, *args, **kwargs):
        result = dispatcher(cmd, *args, **kwargs)
        combined(cmd, *args, **kwargs)
        return result

    def _sandbox_side_effect(cmd, *args, **kwargs):
        result = dispatcher(cmd, *args, **kwargs)
        combined(cmd, *args, **kwargs)
        return result

    with patch("core.orchestration.agentic_passes.subprocess.run",
               side_effect=_subprocess_side_effect), \
         patch("core.orchestration.agentic_passes.sandbox_run",
               side_effect=_sandbox_side_effect):
        yield combined


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(returncode=0, stdout="", stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def _make_lifecycle_dispatcher(start_dir=None, claude_writes=None,
                                start_returncode=0, claude_returncode=0,
                                build_returncode=0):
    """Return a side_effect callable that simulates subprocess.run for the
    lifecycle/claude/build_checklist calls.

    - start_dir: Path the lifecycle 'start' should claim it created (and on
      first claude -p call, the directory will be created and any
      claude_writes files dropped into it).
    - claude_writes: dict of {filename: content} written into start_dir
      when claude -p is invoked.
    """
    state = {"started": False}

    def dispatcher(cmd, *args, **kwargs):
        argv = cmd if isinstance(cmd, list) else [cmd]
        program = Path(argv[0]).name

        if program == "raptor-run-lifecycle":
            action = argv[1] if len(argv) > 1 else ""
            if action == "start":
                if start_returncode == 0 and start_dir is not None:
                    Path(start_dir).mkdir(parents=True, exist_ok=True)
                    state["started"] = True
                    return _ok(stdout=f"OUTPUT_DIR={start_dir}\n")
                return _ok(returncode=start_returncode, stderr="lifecycle failed")
            return _ok()  # complete / fail / cancel — best-effort, we don't assert

        if program == "raptor-build-checklist":
            if build_returncode == 0 and start_dir is not None:
                (Path(start_dir) / "checklist.json").write_text('{"files": []}')
            return _ok(returncode=build_returncode)

        # Otherwise: claude -p invocation
        if claude_writes and start_dir is not None and claude_returncode == 0:
            for name, content in claude_writes.items():
                (Path(start_dir) / name).write_text(content)
        return _ok(returncode=claude_returncode)

    return dispatcher


# ---------------------------------------------------------------------------
# Selection logic
# ---------------------------------------------------------------------------


class SelectFindingsTests(unittest.TestCase):

    def _write_report(self, dir_: Path, results: list) -> Path:
        path = dir_ / "report.json"
        path.write_text(json.dumps({"results": results}))
        return path

    def test_picks_exploitable_findings(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "a", "is_exploitable": True},
                {"id": "b", "is_exploitable": False},
            ])
            self.assertEqual(
                [f["id"] for f in _select_findings_for_validate(report)], ["a"])

    def test_picks_high_confidence_findings(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "a", "confidence": "high"},
                {"id": "b", "confidence": "medium"},
                {"id": "c", "confidence": "low"},
            ])
            self.assertEqual(
                [f["id"] for f in _select_findings_for_validate(report)], ["a"])

    def test_picks_either_qualifier(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "a", "is_exploitable": True, "confidence": "low"},
                {"id": "b", "is_exploitable": False, "confidence": "high"},
                {"id": "c", "is_exploitable": False, "confidence": "medium"},
            ])
            self.assertEqual(
                {f["id"] for f in _select_findings_for_validate(report)}, {"a", "b"})

    def test_case_folded_and_whitespace_tolerant(self):
        # Pre-fix this asserted strict equality and only "c" matched.
        # Post-fix the comparison strip+lowers so all three (and the
        # leading/trailing-space variants common in spliced outputs)
        # qualify. Schema-enforced canonical lowercase still produces
        # the same outcome; the relaxation only adds robustness for
        # non-orchestrated dispatch paths and external producers.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "a", "confidence": "High"},
                {"id": "b", "confidence": "HIGH"},
                {"id": "c", "confidence": "high"},
                {"id": "d", "confidence": "  high  "},
            ])
            self.assertEqual(
                {f["id"] for f in _select_findings_for_validate(report)},
                {"a", "b", "c", "d"},
            )

    def test_skips_null_or_missing_fields(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "a"},
                {"id": "b", "is_exploitable": None, "confidence": None},
                {"id": "c", "confidence": "high"},
            ])
            self.assertEqual(
                [f["id"] for f in _select_findings_for_validate(report)], ["c"])

    def test_empty_results(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [])
            self.assertEqual(_select_findings_for_validate(report), [])

    def test_malformed_json_returns_empty(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            path = tmp / "bad.json"
            path.write_text("not json{")
            self.assertEqual(_select_findings_for_validate(path), [])

    def test_picks_legacy_exploitable_key_from_sequential_mode(self):
        # Sequential-mode and prep-only findings emit "exploitable" (legacy
        # key from VulnerabilityContext.to_dict()), not the schema's
        # "is_exploitable". Both must qualify or --validate silently does
        # nothing in --sequential mode.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._write_report(tmp, [
                {"id": "seq", "exploitable": True},                # sequential
                {"id": "orch", "is_exploitable": True},            # orchestrated
                {"id": "neither", "exploitable": False, "is_exploitable": False},
            ])
            ids = {f["id"] for f in _select_findings_for_validate(report)}
            self.assertEqual(ids, {"seq", "orch"})

    def test_non_list_results_returns_empty(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            path = tmp / "weird.json"
            path.write_text(json.dumps({"results": "not a list"}))
            self.assertEqual(_select_findings_for_validate(path), [])


# ---------------------------------------------------------------------------
# Pre-pass
# ---------------------------------------------------------------------------


class UnderstandPrepassTests(unittest.TestCase):

    def test_skips_when_block_cc_dispatch(self):
        with TemporaryDirectory() as tmp:
            result = run_understand_prepass(
                target=Path(tmp), agentic_out_dir=Path(tmp),
                block_cc_dispatch=True,
            )
        self.assertFalse(result.ran)
        self.assertIn("cc_trust", result.skipped_reason)

    def test_skips_when_claude_not_on_path(self):
        with TemporaryDirectory() as tmp, \
             patch("core.orchestration.agentic_passes.shutil.which", return_value=None):
            result = run_understand_prepass(
                target=Path(tmp), agentic_out_dir=Path(tmp),
            )
        self.assertFalse(result.ran)
        self.assertIn("claude not on PATH", result.skipped_reason)

    def test_skips_when_lifecycle_start_fails(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dispatcher = _make_lifecycle_dispatcher(start_returncode=1)
            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("lifecycle start failed", result.skipped_reason)

    def test_skips_when_checklist_build_fails(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir, build_returncode=1,
            )
            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("checklist build failed", result.skipped_reason)
        # Lifecycle should still hold the dir (we marked it failed best-effort).
        self.assertEqual(result.understand_dir, understand_dir.resolve())

    def test_happy_path_runs_lifecycle_builds_checklist_invokes_claude(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                claude_writes={"context-map.json": '{"sources": [], "sinks": []}'},
            )
            with _patch_passes(dispatcher) as mock_run:
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.understand_dir, understand_dir.resolve())
            self.assertEqual(result.context_map_path,
                             understand_dir.resolve() / "context-map.json")

            # Verify the call sequence: lifecycle start, build_checklist,
            # claude -p, lifecycle complete (4 subprocess calls minimum).
            programs = [Path(call.args[0][0]).name for call in mock_run.call_args_list]
            self.assertIn("raptor-run-lifecycle", programs)
            self.assertIn("raptor-build-checklist", programs)
            # claude_bin is /fake/claude so its name is "claude"
            self.assertIn("claude", programs)

    def test_happy_path_invokes_claude_with_expected_args(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                claude_writes={"context-map.json": "{}"},
            )
            with _patch_passes(dispatcher) as mock_run:
                run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )

            # Find the claude -p call.
            claude_call = next(c for c in mock_run.call_args_list
                               if Path(c.args[0][0]).name == "claude")
            cmd = claude_call.args[0]
            self.assertIn("-p", cmd)
            self.assertIn("--no-session-persistence", cmd)
            self.assertIn("--allowed-tools", cmd)
            self.assertIn("Write", cmd[cmd.index("--allowed-tools") + 1])

            # RAPTOR_DIR must be in --add-dir so the subprocess can read
            # .claude/skills/code-understanding/SKILL.md.
            from core.orchestration.agentic_passes import _RAPTOR_DIR
            add_dirs = {cmd[i + 1] for i, a in enumerate(cmd) if a == "--add-dir"}
            self.assertIn(str(_RAPTOR_DIR), add_dirs)
            self.assertIn(str(understand_dir.resolve()), add_dirs)

    def test_claude_dispatch_uses_sandbox_with_egress_proxy(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                claude_writes={"context-map.json": "{}"},
            )
            sandbox_calls = []

            def _sandbox_capture(cmd, *args, **kwargs):
                sandbox_calls.append(kwargs)
                return dispatcher(cmd, *args, **kwargs)

            with patch("core.orchestration.agentic_passes.subprocess.run",
                       side_effect=dispatcher), \
                 patch("core.orchestration.agentic_passes.sandbox_run",
                       side_effect=_sandbox_capture):
                run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )

            self.assertEqual(len(sandbox_calls), 1)
            kw = sandbox_calls[0]
            self.assertTrue(kw.get("use_egress_proxy"))
            self.assertEqual(kw.get("proxy_hosts"), ["api.anthropic.com"])
            self.assertEqual(kw.get("caller_label"), "agentic-understand")

    def test_happy_path_enriches_agentic_checklist(self):
        # End-to-end: pre-pass writes context-map.json into the understand
        # run dir, then enriches the agentic checklist with priority markers
        # so the analysis prompt can surface them.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            agentic_out = tmp / "agentic"
            agentic_out.mkdir()
            agentic_checklist = {
                "files": [{
                    "path": "src/handler.py",
                    "items": [{"name": "handle_request", "line": 10}],
                }],
            }
            (agentic_out / "checklist.json").write_text(json.dumps(agentic_checklist))

            understand_dir = tmp / "understand_run"
            ctx_map = json.dumps({
                "entry_points": [{"file": "src/handler.py", "name": "handle_request"}],
                "sink_details": [],
            })
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                claude_writes={"context-map.json": ctx_map},
            )
            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertTrue(result.checklist_enriched)

            # Verify the enrichment landed on the function entry. agent.py
            # copies these into per-finding metadata so the prompt builder
            # can render them.
            enriched = json.loads((agentic_out / "checklist.json").read_text())
            func = enriched["files"][0]["items"][0]
            self.assertEqual(func.get("priority"), "high")
            self.assertEqual(func.get("priority_reason"), "entry_point")

    def test_reuses_agentic_checklist_when_present(self):
        # If the agentic pipeline has already built a checklist, the pre-pass
        # should copy it into the understand dir rather than spending another
        # parse pass via raptor-build-checklist.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            agentic_out = tmp / "agentic"
            agentic_out.mkdir()
            agentic_checklist = {"target_path": str(tmp), "files": []}
            (agentic_out / "checklist.json").write_text(json.dumps(agentic_checklist))

            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                claude_writes={"context-map.json": "{}"},
            )
            with _patch_passes(dispatcher) as mock_run:
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)

            # Assert raptor-build-checklist was NOT invoked (checklist was copied).
            programs = [Path(c.args[0][0]).name for c in mock_run.call_args_list]
            self.assertNotIn("raptor-build-checklist", programs)

            # Copy landed in the understand dir.
            self.assertTrue((understand_dir / "checklist.json").exists())

    def test_warns_when_context_map_not_written(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir,
                # No claude_writes — context-map.json won't appear.
            )
            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("missing", result.skipped_reason)

    def test_handles_claude_subprocess_failure(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            dispatcher = _make_lifecycle_dispatcher(
                start_dir=understand_dir, claude_returncode=2,
            )
            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("returned 2", result.skipped_reason)


# ---------------------------------------------------------------------------
# Post-pass
# ---------------------------------------------------------------------------


class ValidatePostpassTests(unittest.TestCase):

    def _make_report(self, dir_: Path, results: list) -> Path:
        path = dir_ / "autonomous_analysis_report.json"
        path.write_text(json.dumps({"results": results}))
        return path

    def test_skips_when_no_findings_qualify(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [
                {"id": "a", "is_exploitable": False, "confidence": "low"},
            ])
            result = run_validate_postpass(
                target=tmp, agentic_out_dir=tmp, analysis_report=report,
                claude_bin="/fake/claude",
            )
        self.assertFalse(result.ran)
        self.assertIn("no findings matched", result.skipped_reason)

    def test_skips_when_block_cc_dispatch(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [{"id": "a", "is_exploitable": True}])
            result = run_validate_postpass(
                target=tmp, agentic_out_dir=tmp, analysis_report=report,
                block_cc_dispatch=True, claude_bin="/fake/claude",
            )
        self.assertFalse(result.ran)

    def test_skips_when_report_missing(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            result = run_validate_postpass(
                target=tmp, agentic_out_dir=tmp,
                analysis_report=tmp / "missing.json",
                claude_bin="/fake/claude",
            )
        self.assertFalse(result.ran)
        self.assertIn("not found", result.skipped_reason)

    def test_happy_path_runs_lifecycle_and_writes_selection_file(self):
        # IDs deliberately use a hyphen + uppercase prefix so
        # `assertNotIn(...)` below isn't a substring-collision risk
        # against tempfile.mkdtemp's 8-char alphanumeric random suffix
        # (CI ran into "f1" appearing inside "/tmp/tmpfef1_buh" and
        # falsely failing the inline-injection check).
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [
                {"finding_id": "FINDING-F1", "is_exploitable": True},
                {"finding_id": "FINDING-F2", "confidence": "high"},
                {"finding_id": "FINDING-F3", "is_exploitable": False, "confidence": "low"},
            ])
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher) as mock_run:
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, 2)
            self.assertEqual(result.validate_dir, validate_dir.resolve())

            # Selection file persisted into the validate dir, not the prompt.
            # After format conversion the records are in /validate Finding
            # shape — finding_id has been renamed to id.
            selection_file = validate_dir / "selected-findings.json"
            self.assertTrue(selection_file.exists())
            data = json.loads(selection_file.read_text())
            self.assertEqual({f["id"] for f in data["findings"]}, {"FINDING-F1", "FINDING-F2"})
            # Container metadata is /validate-shaped.
            self.assertIn("target_path", data)

            # Find the claude call and verify finding_ids do NOT appear inline.
            claude_call = next(c for c in mock_run.call_args_list
                               if Path(c.args[0][0]).name == "claude")
            prompt = claude_call.kwargs["input"]
            self.assertIn("selected-findings.json", prompt)
            self.assertNotIn("FINDING-F1", prompt)
            self.assertNotIn("FINDING-F2", prompt)
            self.assertNotIn("FINDING-F3", prompt)

    def test_validate_dispatch_uses_sandbox_with_egress_proxy(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [
                {"finding_id": "FINDING-F1", "is_exploitable": True},
            ])
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            sandbox_calls = []

            def _sandbox_capture(cmd, *args, **kwargs):
                sandbox_calls.append(kwargs)
                return dispatcher(cmd, *args, **kwargs)

            with patch("core.orchestration.agentic_passes.subprocess.run",
                       side_effect=dispatcher), \
                 patch("core.orchestration.agentic_passes.sandbox_run",
                       side_effect=_sandbox_capture):
                run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )

            self.assertEqual(len(sandbox_calls), 1)
            kw = sandbox_calls[0]
            self.assertTrue(kw.get("use_egress_proxy"))
            self.assertEqual(kw.get("proxy_hosts"), ["api.anthropic.com"])
            self.assertEqual(kw.get("caller_label"), "agentic-validate")

    def test_skips_when_lifecycle_start_fails(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [{"finding_id": "FINDING-F1", "is_exploitable": True}])
            dispatcher = _make_lifecycle_dispatcher(start_returncode=1)
            with _patch_passes(dispatcher):
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("lifecycle start failed", result.skipped_reason)

    def test_truncates_selection_above_cap(self):
        from core.orchestration.agentic_passes import _MAX_VALIDATE_FINDINGS
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            many = [{"finding_id": f"f{i}", "is_exploitable": True}
                    for i in range(_MAX_VALIDATE_FINDINGS + 10)]
            report = self._make_report(tmp, many)
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
            self.assertEqual(result.selected_count, _MAX_VALIDATE_FINDINGS)


# ---------------------------------------------------------------------------
# Backstop and prompt builders
# ---------------------------------------------------------------------------


class BackstopTests(unittest.TestCase):
    """Unexpected exceptions must not break the base agentic pipeline."""

    def test_prepass_swallows_unexpected_exception(self):
        with patch("core.orchestration.agentic_passes._run_understand_prepass_unsafe",
                   side_effect=RuntimeError("boom")):
            result = run_understand_prepass(
                target=Path("/tmp/x"), agentic_out_dir=Path("/tmp/y"),
            )
        self.assertFalse(result.ran)
        self.assertIn("RuntimeError", result.skipped_reason)
        self.assertIn("boom", result.skipped_reason)

    def test_postpass_swallows_unexpected_exception(self):
        with patch("core.orchestration.agentic_passes._run_validate_postpass_unsafe",
                   side_effect=ValueError("kaboom")):
            result = run_validate_postpass(
                target=Path("/tmp/x"), agentic_out_dir=Path("/tmp/y"),
                analysis_report=Path("/tmp/y/r.json"),
            )
        self.assertFalse(result.ran)
        self.assertIn("ValueError", result.skipped_reason)


class PromptBuildTests(unittest.TestCase):

    def test_understand_prompt_includes_paths(self):
        from core.orchestration.agentic_passes import _build_understand_prompt
        prompt = _build_understand_prompt(Path("/repo/x"), Path("/run/u"))
        self.assertIn("/repo/x", prompt)
        self.assertIn("/run/u", prompt)
        self.assertIn("context-map.json", prompt)
        # Lifecycle is owned by the launcher; subprocess should NOT call helpers.
        self.assertIn("Do not call libexec/raptor-run-lifecycle", prompt)

    def test_validate_prompt_references_selection_file(self):
        from core.orchestration.agentic_passes import _build_validate_prompt
        prompt = _build_validate_prompt(
            target=Path("/repo/x"),
            agentic_out_dir=Path("/run/a"),
            validate_dir=Path("/run/v"),
            analysis_report=Path("/run/a/autonomous_analysis_report.json"),
            selection_file=Path("/run/v/selected-findings.json"),
            selected_count=3,
        )
        self.assertIn("selected-findings.json", prompt)
        self.assertIn("3", prompt)
        # The launcher owns the lifecycle; subprocess should not touch it.
        self.assertIn("libexec/raptor-run-lifecycle", prompt)
        # The field-mapping block is the bridge between /agentic and /validate
        # schemas — without it claude has to guess. Surface as a literal
        # check so prompt edits that drop the mapping section get caught.
        self.assertIn("agentic", prompt.lower())
        self.assertIn("validate", prompt.lower())
        self.assertIn("ruling", prompt)


# ---------------------------------------------------------------------------
# Checklist enrichment helper
# ---------------------------------------------------------------------------


class TruncationOrderTests(unittest.TestCase):
    """When >_MAX_VALIDATE_FINDINGS qualify, we should keep the strongest
    signal — not just the first ones in iteration order."""

    def test_truncation_keeps_exploitable_over_high_confidence(self):
        # If we're capped at N and have N+1 qualifying findings, the one we
        # drop should be the weakest signal (high-confidence-only), not a
        # confirmed-exploitable. Otherwise truncation silently degrades the
        # post-pass on large reports.
        from core.orchestration.agentic_passes import _MAX_VALIDATE_FINDINGS
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # First N: confidence=high only (weaker signal)
            # Last 1: is_exploitable=True (strongest signal)
            findings = [
                {"finding_id": f"hc-{i}", "confidence": "high"}
                for i in range(_MAX_VALIDATE_FINDINGS)
            ]
            findings.append({"finding_id": "exploitable-1",
                             "is_exploitable": True})

            report = tmp / "report.json"
            report.write_text(json.dumps({"results": findings}))
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
            selection = json.loads(
                (validate_dir / "selected-findings.json").read_text()
            )
            ids = {f["id"] for f in selection["findings"]}
            self.assertIn(
                "exploitable-1", ids,
                msg="truncation dropped the is_exploitable=True finding because "
                    "it was last in iteration order — should have kept it as the "
                    "strongest signal",
            )


class NaNScoreTests(unittest.TestCase):
    """exploitability_score=NaN must not produce non-deterministic ordering."""

    def test_truncation_handles_nan_score_deterministically(self):
        # Python sort with NaN keys leaves NaN findings at undefined positions
        # because NaN compares False to everything. The cap-at-N truncation
        # then keeps or drops them randomly. Treat NaN as 0 so behaviour is
        # deterministic across runs.
        from core.orchestration.agentic_passes import _MAX_VALIDATE_FINDINGS
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            findings = []
            # N findings with score=NaN
            findings.append({"finding_id": "nan-only", "is_exploitable": True,
                             "exploitability_score": float("nan")})
            # N findings with valid high score
            for i in range(_MAX_VALIDATE_FINDINGS):
                findings.append({"finding_id": f"valid-{i}",
                                 "is_exploitable": True,
                                 "exploitability_score": 0.9})
            report = tmp / "report.json"
            # NaN can't be JSON-encoded by default; force allow_nan via raw write
            import json as _json
            report.write_text(_json.dumps({"results": findings}))
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, _MAX_VALIDATE_FINDINGS)
            # The NaN finding should be dropped — the N valid 0.9-score
            # findings are strictly stronger signal.
            selection = json.loads(
                (validate_dir / "selected-findings.json").read_text()
            )
            ids = {f["id"] for f in selection["findings"]}
            self.assertNotIn(
                "nan-only", ids,
                msg="NaN-scored finding should be sorted as 0 (weakest), not "
                    "left in undefined position",
            )


class MalformedContextMapStructureTests(unittest.TestCase):
    """Pre-pass should fail on structurally-invalid context-map, not just
    on unparseable JSON."""

    def test_pre_pass_rejects_non_list_entry_points(self):
        # context-map parses as JSON object (passes my earlier check) but
        # entry_points is a string instead of a list. The bridge would then
        # crash with AttributeError when iterating; backstop catches but the
        # lifecycle has already been marked complete and the user sees a
        # misleading "ran=True" result.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            calls = []

            def dispatcher(cmd, *args, **kwargs):
                calls.append(cmd)
                program = Path(cmd[0]).name
                if program == "raptor-run-lifecycle":
                    if cmd[1] == "start":
                        Path(understand_dir).mkdir(parents=True, exist_ok=True)
                        return _ok(stdout=f"OUTPUT_DIR={understand_dir}\n")
                    return _ok()
                if program == "raptor-build-checklist":
                    return _ok()
                # claude wrote a structurally-broken context-map (string for
                # what should be a list) — passes JSON parse but not shape.
                (understand_dir / "context-map.json").write_text(
                    json.dumps({"entry_points": "not-a-list"}))
                return _ok()

            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
            self.assertFalse(
                result.ran,
                msg="structurally-invalid context-map should fail the pre-pass; "
                    "would otherwise mark run complete and let enrichment crash "
                    "downstream with backstop-only handling",
            )


class CorruptContextMapTests(unittest.TestCase):
    """Pre-pass must not call claude -p a success when the output is unparseable."""

    def test_pre_pass_treats_corrupt_context_map_as_failure(self):
        # If claude -p was killed mid-write, context-map.json could exist but
        # be non-JSON. Existence check passes, lifecycle gets marked complete,
        # bridge later silently treats it as "no context". The pre-pass
        # should detect unparseable output and mark the lifecycle FAILED.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            calls = []

            def dispatcher(cmd, *args, **kwargs):
                calls.append(cmd)
                program = Path(cmd[0]).name
                if program == "raptor-run-lifecycle":
                    if cmd[1] == "start":
                        Path(understand_dir).mkdir(parents=True, exist_ok=True)
                        return _ok(stdout=f"OUTPUT_DIR={understand_dir}\n")
                    return _ok()
                if program == "raptor-build-checklist":
                    return _ok()
                # Simulate claude -p crashing mid-write — file exists but
                # contains a JSON syntax error.
                (understand_dir / "context-map.json").write_text(
                    '{"sources": [partial-json-no-close')
                return _ok()

            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
            # Run must NOT be reported as successful — the artefact is junk.
            self.assertFalse(
                result.ran,
                msg="corrupt/unparseable context-map should fail the pre-pass; "
                    "marking it ran=True would deceive callers and silently "
                    "leave a 'completed' run dir with garbage in it",
            )
            self.assertIn("context-map", (result.skipped_reason or "").lower())


class SortKeyTypeSafetyTests(unittest.TestCase):
    """Selection sort must not crash on malformed exploitability_score values."""

    def test_sort_handles_string_exploitability_score_gracefully(self):
        # Schema declares exploitability_score as a number, but if some path
        # bypasses validation and the LLM returns a string description,
        # float() raises and our truncation sort would crash mid-post-pass.
        from core.orchestration.agentic_passes import _MAX_VALIDATE_FINDINGS
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # Force the truncation path with one bad apple.
            findings = [
                {"finding_id": f"f-{i}", "is_exploitable": True,
                 "exploitability_score": 0.5}
                for i in range(_MAX_VALIDATE_FINDINGS)
            ]
            findings.append({
                "finding_id": "bad-score", "is_exploitable": True,
                "exploitability_score": "high",  # not a number — would crash float()
            })
            report = tmp / "report.json"
            report.write_text(json.dumps({"results": findings}))
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                # Must not raise — backstop would catch it but the user would
                # see "unexpected ValueError" instead of a clean post-pass.
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, _MAX_VALIDATE_FINDINGS)


class SelfCopyTests(unittest.TestCase):
    """When agentic_out_dir == understand_dir, checklist copy must not raise."""

    def test_provision_checklist_handles_same_source_and_dest(self):
        # Defensive: shutil.copyfile raises SameFileError when src and dest
        # resolve to the same file. _provision_understand_checklist must
        # handle this rather than letting it propagate.
        from core.orchestration.agentic_passes import _provision_understand_checklist
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text('{"files": []}')
            # Source and dest are literally the same file.
            self.assertTrue(
                _provision_understand_checklist(tmp, tmp, tmp),
                msg="self-copy must not crash; should treat as already-present",
            )


class AdversarialBugsTests(unittest.TestCase):
    """Adversarial pass — bugs that surface only under unusual conditions.

    Each test demonstrates a real defect; the fixes live in agentic_passes.py.
    """

    def test_keyboard_interrupt_during_claude_marks_lifecycle_failed(self):
        # If the user Ctrl-Cs during the long claude -p run, the pre-pass
        # must mark the lifecycle FAILED before propagating the interrupt.
        # Otherwise the run dir stays in "running" state forever and the
        # bridge tier-2 search will keep finding it as a candidate.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"
            calls = []

            def dispatcher(cmd, *args, **kwargs):
                calls.append(cmd)
                program = Path(cmd[0]).name
                if program == "raptor-run-lifecycle":
                    if cmd[1] == "start":
                        Path(understand_dir).mkdir(parents=True, exist_ok=True)
                        return _ok(stdout=f"OUTPUT_DIR={understand_dir}\n")
                    return _ok()
                if program == "raptor-build-checklist":
                    return _ok()
                # claude -p: simulate the user Ctrl-C-ing the parent process.
                raise KeyboardInterrupt()

            with _patch_passes(dispatcher):
                with self.assertRaises(KeyboardInterrupt):
                    run_understand_prepass(
                        target=tmp, agentic_out_dir=tmp,
                        claude_bin="/fake/claude",
                    )
            # Lifecycle "fail" must have been invoked.
            fail_called = any(
                Path(c[0]).name == "raptor-run-lifecycle" and "fail" in c
                for c in calls
            )
            self.assertTrue(
                fail_called,
                msg="lifecycle 'fail' should be invoked even when claude -p is "
                    "interrupted via KeyboardInterrupt",
            )

    def test_empty_context_map_does_not_claim_enrichment_succeeded(self):
        # If claude -p writes an empty {} for context-map.json (zero entry
        # points, zero sinks), enrich_checklist marks zero functions. We
        # currently return checklist_enriched=True regardless — misleading.
        # Should return False or at least log loudly so the caller knows
        # the enrichment was a no-op.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text(json.dumps({
                "files": [{"path": "a.py", "items": [{"name": "f"}]}],
            }))
            (tmp / "context-map.json").write_text("{}")
            from core.orchestration.agentic_passes import _enrich_agentic_checklist
            result = _enrich_agentic_checklist(tmp, tmp / "context-map.json")
            # Current behaviour returns True with zero matches — that's the bug.
            # After fix: empty context-map should return False (nothing to enrich).
            self.assertFalse(
                result,
                msg="empty context-map.json should NOT claim enrichment success "
                    "(no entry_points/sinks means no enrichment is possible)",
            )

    def test_complete_lifecycle_subprocess_nonzero_return_is_logged(self):
        # _complete_lifecycle ignores the subprocess returncode silently.
        # If the helper failed internally (e.g. couldn't write metadata),
        # we'd never know — the run dir stays in "running" state.
        from core.orchestration.agentic_passes import _complete_lifecycle
        import logging
        with patch("core.orchestration.agentic_passes.subprocess.run",
                   return_value=_ok(returncode=1, stderr="permission denied")):
            with self.assertLogs(
                "core.orchestration.agentic_passes", level="WARNING"
            ) as cm:
                _complete_lifecycle(Path("/tmp/whatever"))
            self.assertTrue(
                any("complete" in m.lower() and ("returned" in m.lower()
                                                  or "failed" in m.lower())
                    for m in cm.output),
                msg=f"non-zero return from lifecycle complete should warn; got: {cm.output}",
            )


class LifecycleHelperResilienceTests(unittest.TestCase):
    """Lifecycle helper failures must not cascade into the pass results."""

    def test_complete_lifecycle_failure_does_not_raise(self):
        # If raptor-run-lifecycle complete itself errors after the work
        # succeeded, we should still return a successful PrepassResult —
        # the analytical work is done, the housekeeping just didn't tick.
        from core.orchestration.agentic_passes import _complete_lifecycle
        with patch("core.orchestration.agentic_passes.subprocess.run",
                   side_effect=OSError("disk full")):
            # Should swallow the OSError, not raise.
            _complete_lifecycle(Path("/tmp/whatever"))

    def test_fail_lifecycle_handles_none_gracefully(self):
        # _fail_lifecycle is called from error paths where the dir might
        # not have been created. None must be a no-op, not a crash.
        from core.orchestration.agentic_passes import _fail_lifecycle
        _fail_lifecycle(None, "anything")  # must not raise

    def test_fail_lifecycle_swallows_subprocess_errors(self):
        from core.orchestration.agentic_passes import _fail_lifecycle
        with patch("core.orchestration.agentic_passes.subprocess.run",
                   side_effect=OSError("no such file")):
            _fail_lifecycle(Path("/tmp/whatever"), "test")  # must not raise


class TimeoutTests(unittest.TestCase):
    """Subprocess timeout paths must mark the lifecycle failed cleanly."""

    def test_prepass_timeout_marks_lifecycle_failed(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            understand_dir = tmp / "understand_run"

            calls = []

            def dispatcher(cmd, *args, **kwargs):
                calls.append([Path(cmd[0]).name, *cmd[1:]])
                program = Path(cmd[0]).name
                if program == "raptor-run-lifecycle":
                    if cmd[1] == "start":
                        Path(understand_dir).mkdir(parents=True, exist_ok=True)
                        return _ok(stdout=f"OUTPUT_DIR={understand_dir}\n")
                    return _ok()  # complete / fail
                if program == "raptor-build-checklist":
                    return _ok()
                # claude -p -> simulate timeout
                from subprocess import TimeoutExpired
                raise TimeoutExpired(cmd, kwargs.get("timeout", 0))

            with _patch_passes(dispatcher):
                result = run_understand_prepass(
                    target=tmp, agentic_out_dir=tmp,
                    claude_bin="/fake/claude",
                )
            self.assertFalse(result.ran)
            self.assertIn("timeout", result.skipped_reason)
            # Lifecycle 'fail' must have been invoked so the run dir isn't
            # left in 'running' state forever.
            fail_called = any(
                c[0] == "raptor-run-lifecycle" and "fail" in c
                for c in calls
            )
            self.assertTrue(fail_called,
                            "lifecycle fail should be called on timeout")


class EnrichmentTests(unittest.TestCase):

    def test_enrichment_returns_false_when_no_agentic_checklist(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ctx_map = tmp / "context-map.json"
            ctx_map.write_text("{}")
            self.assertFalse(_enrich_agentic_checklist(tmp, ctx_map))

    def test_enrichment_returns_false_on_malformed_inputs(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text("not json{")
            ctx_map = tmp / "context-map.json"
            ctx_map.write_text("{}")
            self.assertFalse(_enrich_agentic_checklist(tmp, ctx_map))

    def test_enrichment_does_not_raise_on_non_list_files_in_checklist(self):
        # The marked-counter inside _enrich_agentic_checklist iterates
        # checklist["files"] and each file's items/functions. If any of
        # those is a non-list (corrupt LLM-built checklist), the previous
        # `or []` fallback would crash with `for x in 42`. Defensive
        # guard means we degrade to "0 marked" with a warning rather than
        # blowing up the post-pass.
        import json
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for bad_files in (42, "string", {"obj": True}):
                (tmp / "checklist.json").write_text(json.dumps({
                    "target_path": str(tmp),
                    "files": bad_files,
                }))
                (tmp / "context-map.json").write_text(json.dumps({
                    "entry_points": [{"file": "x.py", "name": "f"}],
                    "sink_details": [],
                }))
                # Must not raise. Returns False because nothing got marked.
                _enrich_agentic_checklist(tmp, tmp / "context-map.json")

    def test_enrichment_does_not_raise_on_non_list_items_in_file_entry(self):
        # Same gap, deeper iteration: file entry has items/functions as
        # non-list.
        import json
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(tmp),
                "files": [
                    {"path": "a.py", "items": "not a list"},
                    {"path": "b.py", "functions": 42},
                ],
            }))
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "a.py", "name": "f"}],
                "sink_details": [],
            }))
            # Must not raise.
            _enrich_agentic_checklist(tmp, tmp / "context-map.json")

    def test_enrichment_marks_multiple_files_and_reasons(self):
        # Both entry-points and sinks across multiple files must all land on
        # their corresponding checklist functions.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text(json.dumps({
                "files": [
                    {"path": "src/api.py", "items": [{"name": "endpoint", "line": 1}]},
                    {"path": "src/db.py", "items": [{"name": "execute", "line": 1}]},
                    {"path": "src/util.py", "items": [{"name": "helper", "line": 1}]},
                ],
            }))
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "src/api.py", "name": "endpoint"}],
                "sink_details": [{"file": "src/db.py", "name": "execute"}],
                # src/util.py is in checklist but NOT in context-map; should
                # remain unmarked.
            }))
            self.assertTrue(_enrich_agentic_checklist(tmp, tmp / "context-map.json"))

            enriched = json.loads((tmp / "checklist.json").read_text())
            by_path = {f["path"]: f["items"][0] for f in enriched["files"]}
            self.assertEqual(by_path["src/api.py"].get("priority_reason"), "entry_point")
            self.assertEqual(by_path["src/db.py"].get("priority_reason"), "sink")
            # Unmarked function should not have the priority field at all.
            self.assertNotIn("priority", by_path["src/util.py"])

    def test_enrichment_warns_when_path_conventions_mismatch(self):
        # Context map with 1 entry point against a checklist that has the
        # same logical file under a different path (absolute vs relative)
        # should fire the "0 marked despite N entry-points" warning.
        import logging
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checklist.json").write_text(json.dumps({
                "files": [{"path": "/abs/src/handler.py",
                           "items": [{"name": "handle", "line": 1}]}],
            }))
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "src/handler.py"}],
            }))
            with self.assertLogs(
                "core.orchestration.agentic_passes", level="WARNING"
            ) as cm:
                result = _enrich_agentic_checklist(tmp, tmp / "context-map.json")
            # Zero matches with non-empty context-map = no useful enrichment
            # AND a loud warning so the caller can investigate.
            self.assertFalse(result)
            self.assertTrue(any("path-convention mismatch" in m for m in cm.output))


class FormatConverterTests(unittest.TestCase):
    """convert_agentic_to_validate must produce records that /validate's
    FindingsContainer.from_dict / Finding.from_dict can consume directly."""

    def test_renames_finding_id_to_id(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f-1", "is_exploitable": True}], target_path="/repo")
        self.assertEqual(out["findings"][0]["id"], "f-1")
        self.assertNotIn("finding_id", out["findings"][0])

    def test_renames_file_path_and_start_line(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "file_path": "src/db.py", "start_line": 42}],
            target_path="/repo")
        f = out["findings"][0]
        self.assertEqual(f["file"], "src/db.py")
        self.assertEqual(f["line"], 42)

    def test_renames_reasoning_to_description(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "reasoning": "tainted from req.body to db.execute"}],
            target_path="/repo")
        self.assertEqual(out["findings"][0]["description"],
                         "tainted from req.body to db.execute")

    def test_wraps_string_ruling_into_object(self):
        # /agentic emits ruling as a string verdict; /validate wants an object
        # {"status": ..., ...}. The converter must wrap, not pass through.
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "ruling": "validated"}], target_path="/repo")
        ruling = out["findings"][0]["ruling"]
        self.assertIsInstance(ruling, dict)
        self.assertEqual(ruling["status"], "validated")
        # Original verbatim verdict preserved alongside.
        self.assertEqual(ruling["agentic_ruling"], "validated")

    def test_ruling_object_passes_through_unchanged(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        already = {"status": "exploitable", "disqualifier": None}
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "ruling": already}], target_path="/repo")
        self.assertEqual(out["findings"][0]["ruling"], already)

    def test_false_positive_reason_lifts_into_ruling(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "ruling": "false_positive",
              "false_positive_reason": "test_only"}], target_path="/repo")
        ruling = out["findings"][0]["ruling"]
        self.assertEqual(ruling["status"], "false_positive")
        self.assertEqual(ruling["reason"], "test_only")

    def test_legacy_exploitable_normalises_to_is_exploitable(self):
        # --sequential mode emits "exploitable" (no is_ prefix). The
        # converter should normalise so /validate sees the canonical name.
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f", "exploitable": True}], target_path="/repo")
        self.assertIs(out["findings"][0]["is_exploitable"], True)

    def test_passes_through_shared_fields(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        agentic = {
            "finding_id": "f",
            "vuln_type": "sql_injection", "cwe_id": "CWE-89",
            "severity_assessment": "high",
            "cvss_vector": "CVSS:3.1/AV:N/...", "cvss_score_estimate": 9.8,
            "confidence": "high",
            "attack_scenario": "...", "dataflow_summary": "...",
            "remediation": "use parameters", "tool": "semgrep",
            "rule_id": "py/sql-injection",
        }
        f = convert_agentic_to_validate([agentic], target_path="/r")["findings"][0]
        for k in ("vuln_type", "cwe_id", "severity_assessment",
                  "cvss_vector", "cvss_score_estimate", "confidence",
                  "attack_scenario", "dataflow_summary", "remediation",
                  "tool", "rule_id"):
            self.assertEqual(f[k], agentic[k], msg=f"field {k} not passed through")

    def test_marks_origin_as_agentic_postpass(self):
        # /validate uses origin to decide stage behaviour; mark these so
        # downstream knows they came pre-analysed.
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f"}], target_path="/r")
        self.assertEqual(out["findings"][0]["origin"], "agentic-postpass")

    def test_container_has_validate_metadata(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "f"}], target_path="/repo/myapp")
        self.assertEqual(out["target_path"], "/repo/myapp")
        self.assertIn("findings", out)
        self.assertIn("timestamp", out)
        self.assertIn("source", out)

    def test_skips_non_dict_findings_safely(self):
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        out = convert_agentic_to_validate(
            [{"finding_id": "good"}, "not-a-dict", None,
             {"finding_id": "also-good"}], target_path="/r")
        ids = [f["id"] for f in out["findings"]]
        self.assertEqual(ids, ["good", "also-good"])

    def test_round_trips_through_validate_finding_dataclass(self):
        # The strongest contract test: feed converted output into the
        # actual /validate Finding.from_dict and verify it loads cleanly
        # with our renamed fields landing in the right places.
        from core.orchestration.agentic_passes import convert_agentic_to_validate
        from packages.exploitability_validation.models import (
            Finding, FindingsContainer,
        )
        out = convert_agentic_to_validate([{
            "finding_id": "vuln-1",
            "file_path": "src/handler.py", "start_line": 42,
            "reasoning": "user input flows to SQL",
            "attack_scenario": "POST /search?q=' OR 1=1 --",
            "ruling": "validated",
            "is_exploitable": True, "confidence": "high",
            "vuln_type": "sql_injection",
        }], target_path="/repo")

        container = FindingsContainer.from_dict(out)
        self.assertEqual(len(container.findings), 1)
        finding = container.findings[0]
        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.id, "vuln-1")
        self.assertEqual(finding.file, "src/handler.py")
        self.assertEqual(finding.line, 42)
        self.assertEqual(finding.description, "user input flows to SQL")
        self.assertEqual(finding.ruling.status, "validated")
        self.assertEqual(finding.is_exploitable, True)
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.vuln_type, "sql_injection")


class MockContractTests(unittest.TestCase):
    """Sanity-check that our subprocess.run mock path is the right one.

    Tests do `patch("core.orchestration.agentic_passes.subprocess.run", ...)`.
    If a future refactor changes the import to `from subprocess import run`
    at module level, the patch path becomes wrong but tests still pass
    (mocking nothing) — silent test rot.
    """

    def test_subprocess_module_is_imported_as_module_not_attr(self):
        # The patch target only works if subprocess is imported as a module
        # ("import subprocess") and used as subprocess.run, not as
        # ("from subprocess import run") which would need a different patch
        # path.
        import core.orchestration.agentic_passes as ap
        import subprocess as sp
        self.assertIs(ap.subprocess, sp,
                      msg="agentic_passes must keep `import subprocess` so "
                          "tests' patch paths stay valid")


class RuleOfTwoTests(unittest.TestCase):
    """Agentic passes blocked in non-interactive mode (Rule of Two)."""

    def test_understand_blocked_in_ci(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            result = run_understand_prepass(
                target=Path("/tmp/fake-target"),
                agentic_out_dir=Path("/tmp/fake-out"),
                claude_bin="/fake/claude",
            )
        self.assertFalse(result.ran)
        self.assertIn("not allowed in non-interactive", result.skipped_reason)

    def test_validate_blocked_in_ci(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = tmp / "report.json"
            report.write_text('{"results": []}')
            with patch("core.security.rule_of_two.is_interactive", return_value=False):
                result = run_validate_postpass(
                    target=Path("/tmp/fake-target"),
                    agentic_out_dir=tmp,
                    analysis_report=report,
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertIn("not allowed in non-interactive", result.skipped_reason)

    def test_understand_passes_gate_when_interactive(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=True), \
             patch("core.orchestration.agentic_passes.shutil.which",
                   return_value=None):
            result = run_understand_prepass(
                target=Path("/tmp/nonexistent-target"),
                agentic_out_dir=Path("/tmp/nonexistent-out"),
            )
        # Gets past the Rule of Two gate, fails at next check
        self.assertFalse(result.ran)
        self.assertNotIn("non-interactive", result.skipped_reason)

    def test_validate_passes_gate_when_interactive(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = tmp / "report.json"
            report.write_text('{"results": []}')
            with patch("core.security.rule_of_two.is_interactive", return_value=True), \
                 patch("core.orchestration.agentic_passes.shutil.which",
                       return_value=None):
                result = run_validate_postpass(
                    target=Path("/tmp/nonexistent-target"),
                    agentic_out_dir=tmp,
                    analysis_report=report,
                )
        self.assertFalse(result.ran)
        self.assertNotIn("non-interactive", result.skipped_reason)


if __name__ == "__main__":
    unittest.main()
