"""Tests for core.orchestration.skill_dispatch — the shared runner.

The caller-level behaviour (agentic pre/post passes) is covered by
test_agentic_passes*.py; the audit-side caller by
core/audit/tests/test_validate.py. This file covers the runner's own
contract: gate order, StageError abort, output validation, truncation
policy, and the settled-lifecycle pattern.
"""

import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

# The tests below patch core.orchestration.skill_dispatch.subprocess.run
# — that target resolves through the SHARED subprocess module object, so
# the patch is global for its duration. The honest-fake sandboxes spawn
# real child processes and must reach the genuine implementation, so it
# is bound here at import time, before any patch is active.
_REAL_SUBPROCESS_RUN = subprocess.run

from core.orchestration.skill_dispatch import (
    MAX_VALIDATE_FINDINGS,
    StageError,
    missing_validation_report,
    run_skill_dispatch,
    truncate_findings_by_signal,
)

import pytest

# Dispatch here is mocked (run_untrusted_networked patched throughout)
# — the gate/staging logic is under test, so the transport kill switch
# the root conftest sets is cleared for this module.
pytestmark = pytest.mark.usefixtures("cc_spawn_machinery_enabled")

_FIRST_PARTY_PROVIDER_ENV = {
    "CLAUDE_CODE_USE_BEDROCK": "",
    "CLAUDE_CODE_USE_VERTEX": "",
    "CLAUDE_CODE_USE_FOUNDRY": "",
}

_interactive_patch = None


def setUpModule():
    global _interactive_patch
    _interactive_patch = patch(
        "core.security.rule_of_two._session_has_human_terminal",
        return_value=True,
    )
    _interactive_patch.start()


def tearDownModule():
    _interactive_patch.stop()


def _ok(returncode=0, stdout="", stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def _faithful_ok(kwargs: dict, *, returncode: int = 0, stdout: str = "",
                 stderr: str = "") -> MagicMock:
    """CompletedProcess-shaped result honouring the runner's capture
    contract: streams exist ONLY when the dispatch requested
    ``capture_output`` (the sandbox runner defaults it to False, under
    which both streams are ``None``). A fake that hands streams back
    unconditionally is exactly how the missing-capture defect stayed
    invisible to a green suite — every stream-consuming double in this
    file must route through here.
    """
    if kwargs.get("capture_output"):
        return _ok(returncode=returncode, stdout=stdout, stderr=stderr)
    return _ok(returncode=returncode, stdout=None, stderr=None)


#: Static program text for the honest-fake dispatch child. Never
#: interpolated: every emitted byte rides as hex argv DATA so hostile
#: and invalid-UTF-8 sequences survive the argv boundary without ever
#: appearing inside program text (the instruction-file `python3 -c`
#: census rule, applied to test children).
#: argv: <stdout_hex> <stderr_hex> <exit_code> [<sleep_s>]
_CHILD_SCRIPT_SOURCE = """\
import sys
import time

sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))
sys.stdout.buffer.flush()
sys.stderr.buffer.write(bytes.fromhex(sys.argv[2]))
sys.stderr.buffer.flush()
if len(sys.argv) > 4:
    time.sleep(float(sys.argv[4]))
sys.exit(int(sys.argv[3]))
"""


def _lifecycle_dispatcher(start_dir):
    def dispatcher(cmd, *args, **kwargs):
        argv = cmd if isinstance(cmd, list) else [cmd]
        program = Path(argv[0]).name
        if program == "raptor-run-lifecycle":
            action = argv[1] if len(argv) > 1 else ""
            if action == "start":
                Path(start_dir).mkdir(parents=True, exist_ok=True)
                return _ok(stdout=f"OUTPUT_DIR={start_dir}\n")
            return _ok()
        return _ok()
    return dispatcher


def _run(tmp, run_dir, *, sandbox=None, probe_result="fake-model", **overrides):
    dispatcher = _lifecycle_dispatcher(run_dir)
    kwargs = {
        "command": "validate",
        "target": Path(tmp),
        "tools": "Read",
        "budget_usd": "1.00",
        "timeout_s": 60,
        "caller_label": "test-dispatch",
        "log_label": "test pass",
        "build_prompt": lambda d: "prompt",
        "claude_bin": "/fake/claude",
    }
    kwargs.update(overrides)
    with patch("core.orchestration.skill_dispatch.subprocess.run",
               side_effect=dispatcher), \
         patch("core.orchestration.skill_dispatch.run_untrusted_networked",
               side_effect=sandbox or dispatcher), \
         patch("core.llm.cc_probe.probe_cc_session_model",
               return_value=probe_result), \
         patch.dict("os.environ", _FIRST_PARTY_PROVIDER_ENV):
        return run_skill_dispatch(**kwargs)


class GateOrderTests(unittest.TestCase):

    def test_block_cc_dispatch_wins_over_everything(self):
        # Even with claude missing AND a failing preflight, the
        # cc-trust block reports first (defense-in-depth ordering).
        with TemporaryDirectory() as tmp:
            result = _run(
                tmp, Path(tmp) / "run",
                block_cc_dispatch=True,
                claude_bin=None,
                preflight=lambda: "preflight says no",
            )
        self.assertFalse(result.ran)
        self.assertIn("cc_trust", result.skipped_reason)
        self.assertIsNone(result.run_dir)

    def test_transport_kill_switch_skips_before_resolution(self):
        # This lane is a billed spawn that never passes
        # run_cc_streaming, so it honours RAPTOR_CC_TRANSPORT_DISABLED
        # itself — before binary resolution, with the gate-chain skip
        # shape. (The module-level opt-out fixture deletes the var;
        # setting it inside the test wins.)
        import os
        with TemporaryDirectory() as tmp, \
                patch.dict(os.environ,
                           {"RAPTOR_CC_TRANSPORT_DISABLED": "1"}):
            result = _run(tmp, Path(tmp) / "run")
        self.assertFalse(result.ran)
        self.assertIn("transport disabled", result.skipped_reason)
        self.assertIsNone(result.run_dir)

    def test_claude_missing(self):
        # Resolution moved to cc_adapter.resolve_claude_cli (realpath
        # at the seam); missing CLI still gates the dispatch off.
        with TemporaryDirectory() as tmp, \
             patch("core.llm.cc_adapter.resolve_claude_cli",
                   return_value=None):
            result = _run(tmp, Path(tmp) / "run", claude_bin=None)
        self.assertFalse(result.ran)
        self.assertIn("claude not on PATH", result.skipped_reason)

    def test_symlinked_claude_dispatches_via_realpath(self):
        # The mount-ns visibility check realpaths cmd[0]; execing the
        # symlink silently downgraded isolation. The dispatch must
        # exec the REAL binary path (selftest-05 precedent).
        with TemporaryDirectory() as tmp:
            real = Path(tmp) / "versions" / "1.0" / "claude"
            real.parent.mkdir(parents=True)
            real.write_text("#!/bin/sh\n")
            link = Path(tmp) / "bin" / "claude"
            link.parent.mkdir()
            link.symlink_to(real)
            seen_cmds = []
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox_spy(cmd, *args, **kwargs):
                seen_cmds.append(list(cmd))
                return dispatcher(cmd, *args, **kwargs)

            result = _run(tmp, run_dir, claude_bin=str(link),
                          sandbox=_sandbox_spy)
        self.assertTrue(result.ran)
        self.assertTrue(seen_cmds, "sandboxed dispatch never spawned")
        self.assertEqual(seen_cmds[0][0], str(real.resolve()))

    def test_preflight_skip_reason_propagates(self):
        with TemporaryDirectory() as tmp:
            result = _run(tmp, Path(tmp) / "run",
                          preflight=lambda: "nothing to do")
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "nothing to do")
        self.assertIsNone(result.run_dir)

    def test_preflight_runs_before_lifecycle(self):
        # A skipping preflight must not create a run dir.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            _run(tmp, run_dir, preflight=lambda: "skip")
            self.assertFalse(run_dir.exists())


class DispatchFlowTests(unittest.TestCase):

    def test_happy_path(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            staged = []
            result = _run(tmp, run_dir,
                          stage=lambda d: staged.append(d))
        self.assertTrue(result.ran)
        self.assertEqual(result.run_dir, run_dir)
        self.assertEqual(staged, [run_dir])
        self.assertIsNone(result.skipped_reason)

    def test_stage_error_fails_lifecycle_with_reason(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            lifecycle_calls = []
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _tracking(cmd, *args, **kwargs):
                argv = cmd if isinstance(cmd, list) else [cmd]
                if Path(argv[0]).name == "raptor-run-lifecycle":
                    lifecycle_calls.append(argv[1])
                return dispatcher(cmd, *args, **kwargs)

            def _stage(d):
                raise StageError("staging exploded")

            with patch("core.orchestration.skill_dispatch.subprocess.run",
                       side_effect=_tracking), \
                 patch("core.orchestration.skill_dispatch."
                       "run_untrusted_networked", side_effect=dispatcher), \
                 patch("core.llm.cc_probe.probe_cc_session_model",
                       return_value="fake-model"):
                result = run_skill_dispatch(
                    command="validate", target=Path(tmp), tools="Read",
                    budget_usd="1.00", timeout_s=60,
                    caller_label="t", log_label="t",
                    build_prompt=lambda d: "p", claude_bin="/fake/claude",
                    stage=_stage,
                )
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "staging exploded")
        self.assertEqual(result.run_dir, run_dir)
        self.assertIn("fail", lifecycle_calls)
        self.assertNotIn("complete", lifecycle_calls)

    def test_timeout_reports_and_fails_lifecycle(self):
        import subprocess as sp
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"

            def _sandbox(cmd, *args, **kwargs):
                raise sp.TimeoutExpired(cmd="claude", timeout=60)

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "timeout after 60s")
        self.assertEqual(result.run_dir, run_dir)

    def test_launch_oserror_reports_and_fails_lifecycle(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"

            def _sandbox(cmd, *args, **kwargs):
                raise OSError("exec format error")

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertIn("launch failed", result.skipped_reason)
        self.assertIn("exec format error", result.skipped_reason)

    def test_nonzero_returncode(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                return _ok(returncode=3)

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "subprocess returned 3")

    def test_unauthenticated_claude_skips_cleanly(self):
        # claude on PATH but NOT logged in: the child exits non-zero with
        # a "Not logged in" message. That must become a clean SKIP (login
        # guidance) — NOT a noisy "subprocess returned N" failure — so a
        # login-free box isn't spammed with false failures. Detection is a
        # substring match on the child's own output (no extra probe).
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                return _ok(returncode=1,
                           stderr="Not logged in · Please run /login")

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertIn("not logged in", result.skipped_reason.lower())
        self.assertNotIn("subprocess returned", result.skipped_reason)

    def test_other_nonzero_still_reports_as_failure(self):
        # Two-direction guard: a non-zero exit WITHOUT the login signature
        # keeps the "subprocess returned N" failure shape.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                return _ok(returncode=2, stderr="some other crash")

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "subprocess returned 2")

    def test_raptor_no_claude_skips_cleanly(self):
        # Operator-forced local-only posture: skip the claude-bound pass
        # up front with a clear reason (not an error).
        import os
        with TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"RAPTOR_NO_CLAUDE": "1"}):
            result = _run(tmp, Path(tmp) / "run")
        self.assertFalse(result.ran)
        self.assertIn("RAPTOR_NO_CLAUDE", result.skipped_reason)
        self.assertIsNone(result.run_dir)

    def test_cc_probe_unusable_skips_before_lifecycle(self):
        # cc-probe returns None → skip cleanly BEFORE start_lifecycle
        # creates a run dir. No lifecycle calls, no wasted work.
        with TemporaryDirectory() as tmp:
            result = _run(tmp, Path(tmp) / "run", probe_result=None)
        self.assertFalse(result.ran)
        self.assertIn("not usable", result.skipped_reason)
        self.assertIsNone(result.run_dir)

    def test_sandbox_setup_error_reason_is_classifiable(self):
        """A SandboxSetupError skip must classify via
        is_sandbox_setup_skip so callers can bound-retry the launch
        (the child never executed — nothing billed to double-run);
        every other skip shape must not classify."""
        from core.orchestration.skill_dispatch import is_sandbox_setup_skip
        from core.sandbox.errors import SandboxSetupError
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"

            def _sandbox(cmd, *args, **kwargs):
                raise SandboxSetupError("mount namespace could not engage")

            result = _run(tmp, run_dir, sandbox=_sandbox)
        self.assertFalse(result.ran)
        self.assertTrue(is_sandbox_setup_skip(result.skipped_reason))
        self.assertIn("mount namespace could not engage",
                      result.skipped_reason)
        for other in ("timeout after 60s", "subprocess returned 3",
                      "launch failed: exec format error", "", None):
            self.assertFalse(is_sandbox_setup_skip(other), other)

    def test_validate_outputs_error_fails_run(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            result = _run(tmp, run_dir,
                          validate_outputs=lambda d: "artefact missing")
        self.assertFalse(result.ran)
        self.assertEqual(result.skipped_reason, "artefact missing")

    def test_validate_outputs_none_means_success(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            result = _run(tmp, run_dir, validate_outputs=lambda d: None)
        self.assertTrue(result.ran)

    def test_zero_verdict_child_exit0_fails_the_pass(self):
        """A /validate child that exits 0 WITHOUT writing the
        pipeline's terminal artifact must fail the pass with the
        no-verdicts reason — the child's exit status alone used to
        record the pass as ran/completed while every selected finding
        stayed pending."""
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            result = _run(tmp, run_dir,
                          validate_outputs=missing_validation_report)
        self.assertFalse(result.ran)
        self.assertIn("produced no verdicts", result.skipped_reason)

    def test_report_written_by_child_counts_as_ran(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def sandbox(cmd, *args, **kwargs):
                (Path(run_dir) / "validation-report.md").write_text(
                    "# Exploitability Validation Report\n")
                return dispatcher(cmd, *args, **kwargs)

            result = _run(tmp, run_dir, sandbox=sandbox,
                          validate_outputs=missing_validation_report)
        self.assertTrue(result.ran)
        self.assertIsNone(result.skipped_reason)

    def test_keyboard_interrupt_marks_lifecycle_failed(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            lifecycle_calls = []
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _tracking(cmd, *args, **kwargs):
                argv = cmd if isinstance(cmd, list) else [cmd]
                if Path(argv[0]).name == "raptor-run-lifecycle":
                    lifecycle_calls.append(argv[1:])
                return dispatcher(cmd, *args, **kwargs)

            def _sandbox(cmd, *args, **kwargs):
                raise KeyboardInterrupt()

            with patch("core.orchestration.skill_dispatch.subprocess.run",
                       side_effect=_tracking), \
                 patch("core.orchestration.skill_dispatch."
                       "run_untrusted_networked", side_effect=_sandbox), \
                 patch("core.llm.cc_probe.probe_cc_session_model",
                       return_value="fake-model"), \
                 self.assertRaises(KeyboardInterrupt):
                run_skill_dispatch(
                    command="validate", target=Path(tmp), tools="Read",
                    budget_usd="1.00", timeout_s=60,
                    caller_label="t", log_label="t",
                    build_prompt=lambda d: "p", claude_bin="/fake/claude",
                )
            fails = [argv for argv in lifecycle_calls if argv[0] == "fail"]
            self.assertTrue(fails, "lifecycle must be marked failed")
            self.assertEqual(fails[-1][-1], "interrupted")

    def test_context_dirs_reach_sandbox(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            ctx = Path(tmp) / "artefacts"
            ctx.mkdir()
            dispatcher = _lifecycle_dispatcher(run_dir)
            captured = {}

            def _sandbox(cmd, *args, **kwargs):
                captured["cmd"] = cmd
                captured["kwargs"] = kwargs
                return dispatcher(cmd, *args, **kwargs)

            with patch.dict("os.environ", _FIRST_PARTY_PROVIDER_ENV):
                result = _run(tmp, run_dir, sandbox=_sandbox,
                              context_dirs=(ctx,))
            self.assertTrue(result.ran)
            paths = captured["kwargs"].get("readable_paths") or []
            self.assertIn(str(ctx.resolve()), paths)
            cmd = captured["cmd"]
            add_dirs = {cmd[i + 1] for i, a in enumerate(cmd)
                        if a == "--add-dir"}
            self.assertIn(str(ctx.resolve()), add_dirs)


class TruncationTests(unittest.TestCase):

    def test_no_op_within_cap(self):
        findings = [{"id": i} for i in range(5)]
        self.assertIs(truncate_findings_by_signal(findings, 5), findings)

    def test_exploitable_kept_over_confidence_only(self):
        findings = ([{"id": f"c{i}", "confidence": "high"} for i in range(4)]
                    + [{"id": "x", "is_exploitable": True}])
        kept = truncate_findings_by_signal(findings, 2)
        self.assertEqual(kept[0]["id"], "x")

    def test_score_orders_within_class(self):
        findings = [
            {"id": "low", "exploitability_score": 0.1},
            {"id": "high", "exploitability_score": 0.9},
            {"id": "mid", "exploitability_score": 0.5},
        ]
        kept = truncate_findings_by_signal(findings, 2)
        self.assertEqual([f["id"] for f in kept], ["high", "mid"])

    def test_garbage_scores_do_not_crash(self):
        findings = [
            {"id": "nan", "exploitability_score": float("nan")},
            {"id": "str", "exploitability_score": "high"},
            {"id": "num", "exploitability_score": 0.4},
        ]
        kept = truncate_findings_by_signal(findings, 2)
        self.assertEqual(kept[0]["id"], "num")

    def test_signal_free_entries_keep_input_order(self):
        findings = [{"id": i} for i in range(10)]
        kept = truncate_findings_by_signal(findings, 4)
        self.assertEqual([f["id"] for f in kept], [0, 1, 2, 3])

    def test_sarif_level_ranks_when_signals_absent(self):
        findings = [
            {"ruleId": "a", "level": "note"},
            {"ruleId": "b", "level": "warning"},
            {"ruleId": "c", "level": "error"},
            {"ruleId": "d"},  # absent level == SARIF default (warning)
        ]
        kept = truncate_findings_by_signal(findings, 3)
        self.assertEqual([f["ruleId"] for f in kept], ["c", "b", "d"])

    def test_sarif_level_never_outranks_signal_fields(self):
        findings = [
            {"id": "noisy-error", "level": "error"},
            {"id": "exploitable-note", "level": "note",
             "is_exploitable": True},
        ]
        kept = truncate_findings_by_signal(findings, 1)
        self.assertEqual(kept[0]["id"], "exploitable-note")

    def test_default_cap_matches_constant(self):
        findings = [{"id": i} for i in range(MAX_VALIDATE_FINDINGS + 7)]
        self.assertEqual(len(truncate_findings_by_signal(findings)),
                         MAX_VALIDATE_FINDINGS)


if __name__ == "__main__":
    unittest.main()


class TrustMarkerPropagationTests(unittest.TestCase):
    """A4: the CC skill child operates on the operator-approved run and
    must see the trusted-parent context; an untrusted parent propagates
    nothing."""

    def _dispatch_kwargs(self, parent_env):
        captured = {}

        def sandbox(cmd, **kwargs):
            captured.update(kwargs)
            return _ok()

        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with patch.dict("os.environ", parent_env):
                result = _run(tmp, run_dir, sandbox=sandbox)
            self.assertTrue(result.ran)
        return captured

    def test_dispatch_opts_into_trust_marker_keep(self):
        captured = self._dispatch_kwargs({"CLAUDECODE": "1"})
        self.assertIs(captured.get("keep_trust_markers"), True)

    def test_trusted_parent_marker_reaches_child_env(self):
        captured = self._dispatch_kwargs({"CLAUDECODE": "1"})
        env = captured.get("env") or {}
        self.assertEqual(env.get("CLAUDECODE"), "1")

    def test_untrusted_parent_stays_refused(self):
        # Parent holds neither marker: nothing to propagate — the
        # child env carries no trust marker and libexec preambles
        # refuse it exactly as before.
        captured = self._dispatch_kwargs(
            {"CLAUDECODE": "", "_RAPTOR_TRUSTED": ""},
        )
        env = captured.get("env") or {}
        self.assertFalse(env.get("CLAUDECODE"))
        self.assertFalse(env.get("_RAPTOR_TRUSTED"))


class SpawnContextTests(unittest.TestCase):
    """S4 launch-path regression: the CC skill child must not inherit
    the operator's cwd (an arbitrary project root whose workspace-trust
    posture the CLI then ignores), and — being sandboxed away from
    ~/.aws and IMDS — must get AWS credentials minted at the parent's
    trust boundary."""

    def _dispatch_kwargs(self, parent_env, run_dir_holder=None):
        captured = {}

        def sandbox(cmd, **kwargs):
            captured.update(kwargs)
            return _ok()

        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            if run_dir_holder is not None:
                run_dir_holder.append(run_dir)
            with patch.dict("os.environ", parent_env):
                result = _run(tmp, run_dir, sandbox=sandbox)
            self.assertTrue(result.ran)
        return captured

    def test_child_cwd_is_the_run_dir(self):
        holder = []
        captured = self._dispatch_kwargs({"CLAUDECODE": "1"}, holder)
        self.assertEqual(captured.get("cwd"), str(holder[0]))

    def test_spawn_opts_into_credential_minting(self):
        """The spawn site passes mint_aws_credentials=True — wiring
        check via a recording stand-in for cc_subprocess_env."""
        seen = {}

        def fake_env(**kwargs):
            seen.update(kwargs)
            return {"PATH": "/usr/bin"}

        def sandbox(cmd, **kwargs):
            return _ok()

        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with patch("core.llm.cc_adapter.cc_subprocess_env",
                       side_effect=fake_env), \
                 patch.dict("os.environ", {"CLAUDECODE": "1"}):
                result = _run(tmp, run_dir, sandbox=sandbox)
            self.assertTrue(result.ran)
        self.assertIs(seen.get("mint_aws_credentials"), True)


class MissingValidationReportTests(unittest.TestCase):
    """missing_validation_report — the /validate outcome probe. The
    pipeline's terminal artifact (a non-empty validation-report.md) is
    the success evidence; a child exit status of 0 is not (an in-child
    pipeline crash leaves the CC child free to narrate the failure and
    exit cleanly)."""

    def test_missing_report_is_an_error(self):
        with TemporaryDirectory() as tmp:
            reason = missing_validation_report(Path(tmp))
        self.assertIsNotNone(reason)
        self.assertIn("produced no verdicts", reason)

    def test_empty_report_is_an_error(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "validation-report.md").write_text("")
            self.assertIsNotNone(missing_validation_report(Path(tmp)))

    def test_nonempty_report_is_success(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "validation-report.md").write_text("# Report\n")
            self.assertIsNone(missing_validation_report(Path(tmp)))

    def test_probe_reason_is_not_a_sandbox_setup_skip(self):
        """The zero-verdict reason must never classify as a
        sandbox-setup skip: setup skips are retried once (unbilled),
        while a zero-verdict pass already spent its budget and must
        not be re-dispatched by that machinery."""
        from core.orchestration.skill_dispatch import is_sandbox_setup_skip
        with TemporaryDirectory() as tmp:
            reason = missing_validation_report(Path(tmp))
        self.assertFalse(is_sandbox_setup_skip(reason))


class ChildTailTests(unittest.TestCase):
    """A failed child's narrative must survive: the CC child
    multiplexes its errors onto stdout, so the old stderr-only excerpt
    went blank exactly when the operator needed it."""

    def _fail_sandbox(self, run_dir: Path, *, returncode: int,
                      stdout: str = "", stderr: str = "",
                      ) -> Callable[..., MagicMock]:
        # Capture-faithful (via _faithful_ok): these tests pin tail
        # content and quoting, but their double must not hand streams
        # back unconditionally — that shape kept the suite green while
        # the dispatch never requested capture at all.
        dispatcher = _lifecycle_dispatcher(run_dir)

        def _sandbox(cmd: object, *args: object,
                     **kwargs: object) -> MagicMock:
            dispatcher(cmd, *args, **kwargs)
            return _faithful_ok(kwargs, returncode=returncode,
                                stdout=stdout, stderr=stderr)
        return _sandbox

    def test_nonzero_exit_surfaces_stdout_when_stderr_empty(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                result = _run(
                    tmp, run_dir,
                    sandbox=self._fail_sandbox(
                        run_dir, returncode=1,
                        stdout="Stage A written\nTypeError: boom\n",
                        stderr=""),
                )
            self.assertFalse(result.ran)
            joined = "\n".join(logs.output)
            self.assertIn("stdout tail", joined)
            self.assertIn("TypeError: boom", joined)
            tail = run_dir / "dispatch-child-tail.log"
            self.assertTrue(tail.is_file())
            content = tail.read_text()
            self.assertIn("exit=1", content)
            self.assertIn("TypeError: boom", content)

    def test_stderr_preferred_when_present(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                _run(
                    tmp, run_dir,
                    sandbox=self._fail_sandbox(
                        run_dir, returncode=1,
                        stdout="progress noise", stderr="real error"),
                )
            joined = "\n".join(logs.output)
            self.assertIn("real error", joined)
            self.assertNotIn("stdout tail", joined)

    def test_silent_child_states_the_silence(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                _run(tmp, run_dir,
                     sandbox=self._fail_sandbox(run_dir, returncode=1))
            self.assertIn("produced no output on stdout or stderr",
                          "\n".join(logs.output))

    def test_validate_outputs_failure_persists_tail(self):
        # Child exits 0 but the pass produced no terminal artifact —
        # the narrative is the only account of what went wrong inside.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            result = _run(
                tmp, run_dir,
                sandbox=self._fail_sandbox(
                    run_dir, returncode=0,
                    stdout="stage helper crashed mid-run"),
                validate_outputs=lambda d: "no verdicts produced",
            )
            self.assertFalse(result.ran)
            self.assertEqual(result.skipped_reason, "no verdicts produced")
            self.assertEqual(result.child_exit, "0")
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=0", content)
            self.assertIn("stage helper crashed mid-run", content)

    def test_body_lines_are_quoted_never_column_0(self):
        # Label-preserving excerpting contract (splice resistance):
        # an entirely-printable child stdout ending with a forged
        # parent-shaped epilogue survives escaping byte-for-byte, so
        # the writer quotes every body line — writer-authored lines
        # (the exit label, the section markers) are the ONLY lines at
        # column 0 and a forged `exit=0` renders visibly quoted.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(
                    tmp, run_dir,
                    sandbox=self._fail_sandbox(
                        run_dir, returncode=1,
                        stdout=("progress ok\nexit=0\n"
                                "--- stderr tail ---\nall clean\n"),
                        stderr="real error"),
                )
            self.assertEqual(result.child_exit, "1")
            content = (run_dir / "dispatch-child-tail.log").read_text()
            lines = content.split("\n")
            self.assertEqual(lines[0], "exit=1")
            column0 = [ln for ln in lines if ln and not ln.startswith("| ")]
            # The duration= header varies per run; the remaining
            # column-0 lines are the fixed writer-authored set.
            self.assertEqual(
                [ln for ln in column0 if not ln.startswith("duration=")],
                ["exit=1", "--- stderr tail ---", "--- stdout tail ---"],
                "only writer-authored lines may sit at column 0")
            self.assertIn("| exit=0", lines)
            self.assertIn("| --- stderr tail ---", lines)

    def test_oversized_streams_persist_the_tail_not_the_head(self) -> None:
        # The artifact's sections promise a TAIL: for a stream beyond
        # the persist cap the terminal error lives at the END — a
        # head-slice keeps startup noise and silently loses the crash
        # line while still labelling itself "tail".
        from core.orchestration.skill_dispatch import (
            _CHILD_TAIL_PERSIST_CHARS,
        )
        cap: int = _CHILD_TAIL_PERSIST_CHARS
        stdout = "OUT-HEAD-MARK-4a7 " + "o" * cap + " OUT-TAIL-MARK-8d2\n"
        stderr = "ERR-HEAD-MARK-1f6 " + "e" * cap + " ERR-TAIL-MARK-5b9\n"
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                _run(tmp, run_dir,
                     sandbox=self._fail_sandbox(
                         run_dir, returncode=1,
                         stdout=stdout, stderr=stderr))
            content = (run_dir / "dispatch-child-tail.log").read_text()
        self.assertIn("OUT-TAIL-MARK-8d2", content)
        self.assertIn("ERR-TAIL-MARK-5b9", content)
        self.assertNotIn("OUT-HEAD-MARK-4a7", content,
                         "capped stdout must keep the tail, not the head")
        self.assertNotIn("ERR-HEAD-MARK-1f6", content,
                         "capped stderr must keep the tail, not the head")

    def test_exact_cap_stream_survives_in_full(self) -> None:
        # Boundary pin on the persist cap: a 64 KiB stream must land
        # whole — an off-by-one shaves the stream's first characters
        # off exactly at the boundary. The length is the LITERAL
        # 65536, deliberately NOT the imported constant: a stream
        # sized from the constant tracks any off-by-one in the
        # constant itself and can never witness it. Both directions:
        # raising the cap keeps this green (stream fits under it);
        # lowering it below 64 KiB fails here and must be a conscious
        # retune of this literal alongside it.
        head = "ERR-FIRST-MARK-2c8 "
        tail = " ERR-LAST-MARK-6e3"
        stderr = head + "e" * (65536 - len(head) - len(tail)) + tail
        self.assertEqual(len(stderr), 65536)
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                _run(tmp, run_dir,
                     sandbox=self._fail_sandbox(
                         run_dir, returncode=1, stderr=stderr))
            content = (run_dir / "dispatch-child-tail.log").read_text()
        self.assertIn("ERR-FIRST-MARK-2c8", content,
                      "an exactly-cap stream must persist in full")
        self.assertIn("ERR-LAST-MARK-6e3", content)

    def test_warning_excerpt_is_the_stdout_tail_not_head(self) -> None:
        # The WARNING line advertises a "stdout tail" — for a stdout
        # narrative longer than its 500-char excerpt the crash line at
        # the END must be the part that survives, not the head noise.
        stdout = "OUT-HEAD-MARK-3e1 " + "x" * 600 + " OUT-TAIL-MARK-9c4\n"
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                _run(tmp, run_dir,
                     sandbox=self._fail_sandbox(
                         run_dir, returncode=1, stdout=stdout))
        joined = "\n".join(logs.output)
        self.assertIn("stdout tail", joined)
        self.assertIn("OUT-TAIL-MARK-9c4", joined,
                      "the excerpt must end with the stream's tail")
        self.assertNotIn("OUT-HEAD-MARK-3e1", joined,
                         "a head-slice excerpt loses the crash line")

    def test_timeout_persists_partial_capture(self):
        # The kill's partial capture is the only account of what the
        # multi-minute child was doing when the clock ran out — the
        # arm previously returned without writing the artifact.
        import subprocess as sp
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                raise sp.TimeoutExpired(
                    cmd="claude", timeout=60,
                    output=b"Stage A written\nstill grinding \x1b[2J...\n",
                    stderr="partial stderr line")

            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(tmp, run_dir, sandbox=_sandbox)
            self.assertFalse(result.ran)
            self.assertIn("timeout", result.skipped_reason)
            self.assertEqual(result.child_exit, "timeout after 60s")
            tail = run_dir / "dispatch-child-tail.log"
            self.assertTrue(
                tail.is_file(),
                "timeout kill's partial capture must persist")
            content = tail.read_text()
            self.assertIn("exit=timeout after 60s", content)
            self.assertIn("still grinding", content)
            self.assertIn("partial stderr line", content)
            # Hostile bytes escaped at write (newlines kept).
            self.assertNotIn("\x1b", content)

    def test_timeout_with_no_capture_still_fails_cleanly(self):
        import subprocess as sp
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                raise sp.TimeoutExpired(cmd="claude", timeout=60)

            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(tmp, run_dir, sandbox=_sandbox)
            self.assertFalse(result.ran)
            self.assertIn("timeout", result.skipped_reason)
            # Nothing captured: the artifact still records the exit
            # label with empty tails — forensics never raises.
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=timeout after 60s", content)


class ChildStreamCaptureTests(unittest.TestCase):
    """The dispatch must REQUEST stream capture from the sandbox.

    The sandbox runner's ``capture_output`` defaults to False, under
    which the returned CompletedProcess carries ``stdout=None`` /
    ``stderr=None`` — the child's narrative goes to the parent's
    inherited stdio and is never persisted. A dispatch that omits the
    kwarg makes every failure-path artifact (dispatch-child-tail.log,
    the WARNING excerpt, the postpass record's embedded tail) EMPTY
    for every failing child: a multi-minute billed pass exits nonzero
    with nothing diagnosable in the run dir. The fakes here mirror
    the real runner's capture contract instead of unconditionally
    handing streams back.
    """

    def _faithful_sandbox(self, run_dir, *, returncode,
                          stdout="", stderr="", seen=None):
        """run()-faithful fake: streams exist ONLY when capture was
        requested (mirrors the runner's capture_output=False default,
        under which both CompletedProcess streams are None)."""
        dispatcher = _lifecycle_dispatcher(run_dir)

        def _sandbox(cmd, *args, **kwargs):
            dispatcher(cmd, *args, **kwargs)
            if seen is not None:
                seen.update(kwargs)
            if kwargs.get("capture_output"):
                return _ok(returncode=returncode,
                           stdout=stdout, stderr=stderr)
            return _ok(returncode=returncode, stdout=None, stderr=None)
        return _sandbox

    def test_dispatch_requests_capture_with_replacing_decode(self):
        # The kwargs ARE the contract: capture on, hostile bytes
        # decoded with replacement instead of raising in the parent.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            seen = {}
            result = _run(
                tmp, run_dir,
                sandbox=self._faithful_sandbox(
                    run_dir, returncode=0, seen=seen))
        self.assertTrue(result.ran)
        self.assertIs(seen.get("capture_output"), True)
        self.assertEqual(seen.get("errors"), "replace")
        # text=True must be explicit: the sandbox fork backend decodes
        # streams keyed solely on `text` (genuine run() would mask its
        # omission because errors= alone enables text mode there).
        self.assertIs(seen.get("text"), True)

    def test_failing_child_leaves_a_nonempty_diagnostic(self):
        # The regression this class exists for: under a run()-faithful
        # sandbox, a failing child's narrative must reach the tail
        # artifact — a dispatch that never asked for capture persisted
        # `exit=1` over two empty tails.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                result = _run(
                    tmp, run_dir,
                    sandbox=self._faithful_sandbox(
                        run_dir, returncode=1,
                        stdout="Stage C helper: TypeError: boom\n"))
            self.assertFalse(result.ran)
            self.assertEqual(result.child_exit, "1")
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=1", content)
            self.assertIn("TypeError: boom", content,
                          "failing child's narrative must be persisted")
            self.assertIn("TypeError: boom", "\n".join(logs.output))

    def test_silent_failing_child_gets_a_loud_artifact(self):
        # A child that dies before logging anything must still leave
        # a diagnosable record: exit label, duration, and an explicit
        # streams=empty disclosure — never two silent empty tails.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(
                    tmp, run_dir,
                    sandbox=self._faithful_sandbox(
                        run_dir, returncode=1, stdout="", stderr=""))
            self.assertFalse(result.ran)
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=1", content)
            self.assertIn("duration=", content)
            self.assertIn("streams=empty", content)
            self.assertIn("produced no output on stdout or stderr",
                          content)

    def test_uncaptured_streams_are_disclosed_in_the_artifact(self):
        # Belt-and-braces on the artifact writer itself: a result
        # whose streams were never captured (both None) must say so
        # instead of rendering as a silent child — the two cases were
        # indistinguishable on disk, which is how the missing capture
        # went undiagnosed.
        import subprocess as sp
        from core.orchestration.skill_dispatch import _persist_child_tail
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            proc = sp.CompletedProcess(
                args=["claude"], returncode=1, stdout=None, stderr=None)
            _persist_child_tail(run_dir, proc, duration_s=12.5)
            content = (run_dir / "dispatch-child-tail.log").read_text()
        self.assertIn("exit=1", content)
        self.assertIn("duration=12.5s", content)
        self.assertIn("capture=missing", content)
        self.assertIn("not captured", content)

    def test_uncaptured_streams_are_disclosed_in_the_warning(self):
        import subprocess as sp
        from core.orchestration.skill_dispatch import _child_failure_tail
        proc = sp.CompletedProcess(
            args=["claude"], returncode=1, stdout=None, stderr=None)
        line = _child_failure_tail(proc)
        self.assertIn("not captured", line)
        self.assertNotIn("produced no output on stdout or stderr", line)

    def test_captured_but_silent_child_is_not_a_capture_failure(self):
        # Empty-string streams mean capture worked and the child said
        # nothing — that must NOT read as a plumbing failure.
        import subprocess as sp
        from core.orchestration.skill_dispatch import (
            _child_failure_tail,
            _persist_child_tail,
        )
        proc = sp.CompletedProcess(
            args=["claude"], returncode=1, stdout="", stderr="")
        self.assertIn("produced no output on stdout or stderr",
                      _child_failure_tail(proc))
        self.assertNotIn("not captured", _child_failure_tail(proc))
        with TemporaryDirectory() as tmp:
            _persist_child_tail(Path(tmp), proc)
            content = (
                Path(tmp) / "dispatch-child-tail.log").read_text()
        self.assertNotIn("capture=missing", content)
        self.assertIn("streams=empty", content)


class RealChildStreamCaptureTests(unittest.TestCase):
    """Capture pins that bite on a REAL subprocess child.

    The doubles above pin the kwargs contract and the artifact writer;
    none of them exercises actual stream capture — a hand-written fake
    decides what streams look like, so it can never catch a decode
    posture or plumbing regression the fake's author didn't imagine.
    These tests spawn a real child process through a runner-shaped shim
    that forwards the dispatch's stream-plumbing kwargs VERBATIM
    (present-or-absent — never defaulted by the shim) to the genuine
    ``subprocess.run``: real pipes, real nonzero exits, real
    invalid-UTF-8 bytes on both streams, a real timeout kill. If the
    dispatch stops requesting capture the streams come back ``None``
    from the OS-level run, and if it drops ``errors="replace"`` a
    hostile byte raises ``UnicodeDecodeError`` in the parent — either
    way these tests fail on the real mechanism, not on a double's
    say-so.
    """

    #: The dispatch kwargs that ARE the stream-plumbing contract with
    #: the runner. Sandbox-only kwargs (target/output/env/cwd/...) are
    #: dropped: the shim stands in for the sandbox, not for isolation.
    #: `stdin` is deliberately absent: proxy-credential mode transports
    #: a stdin file handle, but that leg exists only on the fork/netns
    #: backend — a genuine-run() shim cannot exercise it honestly.
    _STREAM_KWARGS = ("capture_output", "text", "errors", "input",
                      "timeout")

    def _write_child(self, tmp: Path) -> Path:
        child = Path(tmp) / "dispatch-child.py"
        child.write_text(_CHILD_SCRIPT_SOURCE)
        return child

    def _real_child_sandbox(
        self, run_dir: Path, child: Path, *,
        stdout: bytes = b"", stderr: bytes = b"",
        exit_code: int = 0, sleep_s: float = 0.0,
    ) -> Callable[..., subprocess.CompletedProcess]:
        child_argv: list[str] = [
            sys.executable, str(child),
            stdout.hex(), stderr.hex(), str(exit_code), str(sleep_s),
        ]

        def _sandbox(cmd: object, *args: object,
                     **kwargs: object) -> subprocess.CompletedProcess:
            # text=True is pinned HERE because the genuine run() below
            # cannot witness its omission: errors= alone still enables
            # text mode. The real sandbox fork backend decodes keyed
            # SOLELY on `text` — without it every stream comes back as
            # bytes and both failure-path consumers crash before any
            # artifact lands.
            if kwargs.get("text") is not True:
                raise AssertionError(
                    "dispatch must pass text=True explicitly: the "
                    "sandbox fork backend decodes streams keyed on it")
            run_kwargs: dict = {k: kwargs[k] for k in self._STREAM_KWARGS
                                if k in kwargs}
            # _REAL_SUBPROCESS_RUN: subprocess.run itself is patched
            # module-globally while the dispatch runs (see the import-
            # time binding at the top of this file).
            return _REAL_SUBPROCESS_RUN(child_argv, check=False,
                                        **run_kwargs)

        return _sandbox

    def test_failing_child_narrative_survives_end_to_end(self) -> None:
        # The parent defect, replayed with a real child: a nonzero-exit
        # child's stdout narrative must reach the tail artifact AND the
        # WARNING excerpt via real pipes — not via a fake that hands
        # streams back regardless of capture.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                result = _run(
                    tmp, run_dir,
                    sandbox=self._real_child_sandbox(
                        run_dir, child,
                        stdout=b"Stage C helper: TypeError: boom\n",
                        exit_code=3))
            self.assertFalse(result.ran)
            self.assertEqual(result.skipped_reason,
                             "subprocess returned 3")
            self.assertEqual(result.child_exit, "3")
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=3", content)
            self.assertIn("TypeError: boom", content,
                          "real child's narrative must be persisted")
            self.assertNotIn("capture=missing", content,
                             "capture must actually be active")
            joined = "\n".join(logs.output)
            self.assertIn("stdout tail", joined)
            self.assertIn("TypeError: boom", joined)

    def test_streams_land_in_their_own_sections(self) -> None:
        # Real interleaved output on BOTH pipes: each stream's bytes
        # must land under its own section marker (a swapped or
        # swallowed stream renders under the wrong header), and the
        # WARNING excerpt must prefer stderr when it is non-empty.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING") as logs:
                result = _run(
                    tmp, run_dir,
                    sandbox=self._real_child_sandbox(
                        run_dir, child,
                        stdout=b"OUT-MARKER-7f3\n",
                        stderr=b"ERR-MARKER-2c9\n",
                        exit_code=1))
            self.assertFalse(result.ran)
            content = (run_dir / "dispatch-child-tail.log").read_text()
            stderr_section = content.split(
                "--- stderr tail ---\n", 1)[1].split(
                "--- stdout tail ---\n", 1)[0]
            stdout_section = content.split(
                "--- stdout tail ---\n", 1)[1]
            self.assertIn("ERR-MARKER-2c9", stderr_section)
            self.assertNotIn("OUT-MARKER-7f3", stderr_section)
            self.assertIn("OUT-MARKER-7f3", stdout_section)
            self.assertNotIn("ERR-MARKER-2c9", stdout_section)
            joined = "\n".join(logs.output)
            self.assertIn("ERR-MARKER-2c9", joined)
            self.assertNotIn("stdout tail", joined)

    def test_hostile_bytes_replace_decoded_never_raise(self) -> None:
        # errors="replace" is load-bearing: a real child emitting
        # invalid UTF-8 on both streams must produce a clean failure
        # record — under a strict decode the parent raises
        # UnicodeDecodeError and loses the very narrative capture
        # exists to keep. The raw bytes must never be persisted;
        # U+FFFD stands in for them.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(
                    tmp, run_dir,
                    sandbox=self._real_child_sandbox(
                        run_dir, child,
                        stdout=b"pre-marker \xff\xfe post-marker\n",
                        stderr=b"err-marker \x80 tail\n",
                        exit_code=1))
            self.assertFalse(result.ran)
            self.assertEqual(result.skipped_reason,
                             "subprocess returned 1")
            raw = (run_dir / "dispatch-child-tail.log").read_bytes()
            self.assertNotIn(b"\xff", raw,
                             "hostile byte must never persist raw")
            content = raw.decode("utf-8")
            self.assertIn("pre-marker", content)
            self.assertIn("post-marker", content)
            self.assertIn("err-marker", content)
            self.assertIn("�", content,
                          "invalid bytes must decode to U+FFFD")

    def test_silent_failing_child_yields_streams_empty(self) -> None:
        # A real child that exits nonzero without writing a byte:
        # capture is ACTIVE (empty-string streams, not None), so the
        # artifact must carry the streams=empty disclosure — never
        # capture=missing, and never two silent empty tails.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(
                    tmp, run_dir,
                    sandbox=self._real_child_sandbox(
                        run_dir, child, exit_code=1))
            self.assertFalse(result.ran)
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=1", content)
            self.assertIn("duration=", content)
            self.assertIn("streams=empty", content)
            self.assertIn("produced no output on stdout or stderr",
                          content)
            self.assertNotIn("capture=missing", content)

    def test_success_child_output_captured_and_discarded(self) -> None:
        # Success-path semantics under real capture: a chatty exit-0
        # child completes the pass and leaves no tail artifact.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            result = _run(
                tmp, run_dir,
                sandbox=self._real_child_sandbox(
                    run_dir, child,
                    stdout=b"result narrative\n", exit_code=0))
            self.assertTrue(result.ran)
            self.assertIsNone(result.skipped_reason)
            self.assertEqual(result.child_exit, "0")
            self.assertFalse(
                (run_dir / "dispatch-child-tail.log").exists(),
                "success must not write a failure artifact")

    def test_timeout_kill_persists_real_partial_capture(self) -> None:
        # A real child writes to both pipes (stdout carrying an
        # invalid-UTF-8 byte: the kill precedes decoding, so this leg
        # decodes bytes itself), flushes, then outlives the dispatch
        # timeout. The genuine TimeoutExpired must carry the partial
        # capture into the artifact — with capture off it carries
        # nothing and the artifact goes empty.
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            child = self._write_child(Path(tmp))
            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(
                    tmp, run_dir,
                    sandbox=self._real_child_sandbox(
                        run_dir, child,
                        stdout=b"Stage A written \xff mid-flight\n",
                        stderr=b"partial err line\n",
                        exit_code=0, sleep_s=30.0),
                    timeout_s=1)
            self.assertFalse(result.ran)
            self.assertEqual(result.skipped_reason, "timeout after 1s")
            self.assertEqual(result.child_exit, "timeout after 1s")
            raw = (run_dir / "dispatch-child-tail.log").read_bytes()
            self.assertNotIn(b"\xff", raw)
            content = raw.decode("utf-8")
            self.assertIn("exit=timeout after 1s", content)
            self.assertIn("Stage A written", content,
                          "partial capture must reach the artifact")
            self.assertIn("partial err line", content)


class ChildTailPlantTests(unittest.TestCase):
    """run_dir is child-writable by design: a planted symlink at the
    artifact name must never steer the parent's write."""

    def test_symlink_plant_never_clobbers_the_target(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            victim = Path(tmp) / "victim.json"
            victim.write_text('{"verdict": "untouched"}')
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd: object, *args: object,
                         **kwargs: object) -> MagicMock:
                dispatcher(cmd, *args, **kwargs)
                # The child plants the symlink inside its writable
                # run dir, then fails.
                link = run_dir / "dispatch-child-tail.log"
                if not link.exists() and not link.is_symlink():
                    link.symlink_to(victim)
                return _faithful_ok(kwargs, returncode=1,
                                    stdout="attacker narrative")

            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                result = _run(tmp, run_dir, sandbox=_sandbox)
            self.assertFalse(result.ran)
            # Victim untouched; artifact name now a REGULAR file with
            # the parent's content (rename replaced the symlink).
            self.assertEqual(victim.read_text(),
                             '{"verdict": "untouched"}')
            tail = run_dir / "dispatch-child-tail.log"
            self.assertFalse(tail.is_symlink())
            self.assertIn("attacker narrative", tail.read_text())

    def test_artifact_mode_is_owner_only(self):
        import stat as _stat
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd: object, *args: object,
                         **kwargs: object) -> MagicMock:
                dispatcher(cmd, *args, **kwargs)
                return _faithful_ok(kwargs, returncode=1, stdout="boom")

            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                _run(tmp, run_dir, sandbox=_sandbox)
            mode = _stat.S_IMODE(
                (run_dir / "dispatch-child-tail.log").stat().st_mode)
            self.assertEqual(mode, 0o600)


class ParentPinThreadingTests(unittest.TestCase):
    """start_lifecycle threads the PARENT RUN's project pin.

    A child pass's lifecycle stub re-resolves the project ambiently
    unless the argv carries the pin; the parent run's own pin is the
    authority for a child phase — the machine-wide last-activated
    default can be re-pointed mid-run by another session.
    """

    def _start(self, parent_run_dir: Path | None = None,
               process_project: str | None = None,
               containment: str | None = None,
               witness: tuple[bool, str | None, str | None] | None = None,
               project_target: str | None = "/target",
               project_missing: bool = False,
               ) -> list:
        from contextlib import ExitStack
        from types import SimpleNamespace

        from core.orchestration.skill_dispatch import start_lifecycle
        captured: dict = {}

        def dispatcher(cmd, *args, **kwargs):
            captured["argv"] = list(cmd)
            return _ok(stdout="OUTPUT_DIR=/nonexistent-run\n")

        # Hermetic registry for the pin-target vet, modelling the REAL
        # load() seams only: the pinned project's registered target is
        # what the test declares ("/target" — the child target — by
        # default, so pre-vet tests keep their matching shape);
        # project_missing = load() returns None (the real load never
        # raises for file-level failures — load_json strict=False
        # funnels missing/unreadable/corrupt entries to None);
        # project_target=None = the project loads with ``target: null``
        # (the predicate then raises inside the vet).
        class _FakeMgr:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def load(self, name: str):
                if project_missing:
                    return None
                return SimpleNamespace(name=name, target=project_target)

        patches = [
            patch("core.orchestration.skill_dispatch.subprocess.run",
                  side_effect=dispatcher),
            # Hermetic pin resolution: the registry probe answers yes
            # for the marker's project, containment inference answers
            # what the test declares — nothing by default (the host
            # registry must not leak in).
            patch("core.run.pin._project_exists", lambda name: True),
            patch("core.run.pin._containment_project",
                  lambda d: containment),
            patch("core.run.pin._process_project", process_project),
            patch("core.run.pin._process_project_set",
                  process_project is not None),
            patch("core.project.project.ProjectManager", _FakeMgr),
        ]
        if witness is not None:
            # Pin the ledger witness outcome (found, project, source)
            # so the host's live session ledger cannot leak in.
            patches.append(
                patch("core.project.sessions.ledger_pin_witness",
                      lambda run_dir, pid=None: witness))
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            start_lifecycle("validate", Path("/target"),
                            parent_run_dir=parent_run_dir)
        return captured["argv"]

    def _parent(self, tmp, meta_extra):
        import json as _json
        parent = Path(tmp) / "audit-run"
        parent.mkdir()
        meta = {"version": 2, "command": "audit", "status": "running",
                "timestamp": "2026-01-01T00:00:00+00:00"}
        meta.update(meta_extra)
        (parent / ".raptor-run.json").write_text(_json.dumps(meta))
        return parent

    def test_parent_pin_is_threaded(self):
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            argv = self._start(parent_run_dir=parent)
            self.assertIn("--project", argv)
            self.assertEqual(argv[argv.index("--project") + 1], "p1")

    def test_projectless_parent_threads_explicit_none(self):
        # Bound-to-none is authoritative: the child must not fall
        # through to the ambient layers.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": None,
                                        "project_source": "argv"})
            argv = self._start(parent_run_dir=parent)
            self.assertIn("--project", argv)
            self.assertEqual(argv[argv.index("--project") + 1], "-")

    def test_process_override_wins_over_parent_pin(self):
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            argv = self._start(parent_run_dir=parent,
                               process_project="p2")
            self.assertEqual(argv[argv.index("--project") + 1], "p2")

    def test_legacy_parent_threads_nothing(self):
        # Pre-series marker (no ``project`` key): containment
        # inference authorizes reads only — never an argv pin.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {})
            argv = self._start(parent_run_dir=parent)
            self.assertNotIn("--project", argv)

    def test_no_parent_run_dir_threads_nothing(self):
        argv = self._start(parent_run_dir=None)
        self.assertNotIn("--project", argv)

    def test_named_containment_never_threads(self) -> None:
        # Pre-series marker (no ``project`` key) sitting inside a
        # registered project's output dir: containment inference
        # resolves a NAME, but it authorizes reads only — the name
        # must still never become an argv pin.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {})
            argv = self._start(parent_run_dir=parent,
                               containment="legacyproj")
            self.assertNotIn("--project", argv)

    def test_unwitnessed_parent_pin_warns_and_still_threads(self) -> None:
        # No session-ledger witness (the sessionless/detached parent):
        # the pin threads exactly as before — gating on the witness
        # would strand that parent back on the ambient layers — but a
        # loud warning marks the marker-only provenance.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            with self.assertLogs("core.orchestration.skill_dispatch",
                                 level="WARNING") as logs:
                argv = self._start(parent_run_dir=parent,
                                   witness=(False, None, None))
            self.assertIn("--project", argv)
            self.assertEqual(argv[argv.index("--project") + 1], "p1")
            self.assertTrue(any("NO session-ledger witness" in line
                                for line in logs.output))

    def test_witnessed_parent_pin_threads_without_warning(self) -> None:
        # An agreeing witness is the verified path: no warning.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            with self.assertNoLogs("core.orchestration.skill_dispatch",
                                   level="WARNING"):
                argv = self._start(parent_run_dir=parent,
                                   witness=(True, "p1", "argv"))
            self.assertIn("--project", argv)
            self.assertEqual(argv[argv.index("--project") + 1], "p1")

    def test_mismatching_parent_pin_demotes_to_standalone(self) -> None:
        # Poisoned-pin shape: the parent marker pins a project whose
        # registered target does NOT contain the child target (a
        # --out parent records its ambient pin unvetted). Threading
        # it verbatim would deterministically refuse the child start
        # at the helper's target-match gate — the vet must demote to
        # the explicit projectless pin, loudly.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "symlink"})
            with self.assertLogs("core.orchestration.skill_dispatch",
                                 level="WARNING") as logs:
                argv = self._start(parent_run_dir=parent,
                                   witness=(True, "p1", "symlink"),
                                   project_target="/elsewhere")
            self.assertIn("--project", argv)
            self.assertEqual(argv[argv.index("--project") + 1], "-")
            joined = "\n".join(logs.output)
            self.assertIn("not threading project pin", joined)
            self.assertIn("'p1'", joined)

    def test_mismatching_process_override_demotes_too(self) -> None:
        # The same poisoned shape via the process-scoped override (a
        # --project X --out parent keeps X set in-process): the child
        # helper would refuse identically, so the vet applies to
        # whatever pin is about to thread, regardless of source.
        with self.assertLogs("core.orchestration.skill_dispatch",
                             level="WARNING"):
            argv = self._start(process_project="p2",
                               project_target="/elsewhere")
        self.assertEqual(argv[argv.index("--project") + 1], "-")

    def test_child_target_inside_project_target_still_threads(self) -> None:
        # Containment (not just equality) satisfies the vet — the
        # same rule as the helper's gate.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            argv = self._start(parent_run_dir=parent,
                               witness=(True, "p1", "argv"),
                               project_target="/")
            self.assertEqual(argv[argv.index("--project") + 1], "p1")

    def test_vetting_failure_keeps_the_pin(self) -> None:
        # Unknown arm, exception shape: the project loads but the
        # target-match predicate raises (a registry entry with
        # ``target: null`` TypeErrors inside the gate). Not a verdict
        # on the target — keep the pin; the helper's own gate is the
        # backstop and its refusal is recorded. The real
        # ProjectManager.load never raises for file-level failures
        # (load_json strict=False funnels them to None), so the raise
        # seam is exactly in-vet crashes like this one.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            with self.assertLogs("core.orchestration.skill_dispatch",
                                 level="WARNING") as logs:
                argv = self._start(parent_run_dir=parent,
                                   witness=(True, "p1", "argv"),
                                   project_target=None)
            self.assertEqual(argv[argv.index("--project") + 1], "p1")
            joined = "\n".join(logs.output)
            self.assertIn("could not be vetted", joined)
            self.assertIn("keeping the pin", joined)
            self.assertNotIn("outside the project's target", joined)

    def test_missing_project_pin_is_kept_for_the_helper(self) -> None:
        # Unknown arm, load-returns-None shape: a missing, unreadable,
        # or corrupt registry entry all funnel to load() -> None
        # (load_json strict=False). That is not a mismatch verdict —
        # demoting would strip project placement from a healthy
        # pinned run on a transient read error. Keep the pin: the
        # helper's gate adjudicates ms later and its refusal now
        # rides back as the recorded skip detail.
        with TemporaryDirectory() as tmp:
            parent = self._parent(tmp, {"project": "p1",
                                        "project_source": "argv"})
            with self.assertLogs("core.orchestration.skill_dispatch",
                                 level="WARNING") as logs:
                argv = self._start(parent_run_dir=parent,
                                   witness=(True, "p1", "argv"),
                                   project_missing=True)
            self.assertEqual(argv[argv.index("--project") + 1], "p1")
            joined = "\n".join(logs.output)
            self.assertIn("could not be loaded for vetting", joined)
            self.assertIn("keeping the pin", joined)
            self.assertNotIn("outside the project's target", joined)

    def test_demotion_warning_is_escaped_and_bounded(self) -> None:
        # The demotion warning interpolates the child target and the
        # project's registered target — attacker-influenceable
        # strings (checkout dir names). Hostile bytes must never
        # reach the log stream raw: ESC would drive the terminal,
        # a newline forges log lines, a bidi override reorders what
        # the operator reads, and an unbounded path floods the
        # terminal. Escaped forms only, bounded.
        from types import SimpleNamespace

        from core.orchestration.skill_dispatch import _vet_threaded_pin
        hostile_target = ("/tmp/evil\x1b[2J\ninjected line\u202egnp"
                          + "A" * 4000)
        hostile_proj_target = "/proj\x1b]0;t\x07dir" + "B" * 4000

        class _Mgr:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def load(self, name: str):
                return SimpleNamespace(name=name,
                                       target=hostile_proj_target)

        with patch("core.project.project.ProjectManager", _Mgr), \
             self.assertLogs("core.orchestration.skill_dispatch",
                             level="WARNING") as logs:
            pin = _vet_threaded_pin("p1", Path(hostile_target),
                                    "validate")
        self.assertEqual(pin, "-")
        demotions = [rec for rec in logs.output
                     if "not threading project pin" in rec]
        self.assertEqual(len(demotions), 1)
        rec = demotions[0]
        self.assertNotIn("\x1b", rec)
        self.assertNotIn("\x07", rec)
        self.assertNotIn("\u202e", rec)
        # The injected newline must not mint a second log line.
        self.assertNotIn("\n", rec)
        self.assertIn("\\x1b", rec)
        # Both %s values bounded (300 + elision marker each) — the
        # 4000-char hostile components must not ride through.
        self.assertIn("chars]", rec)
        self.assertLess(len(rec), 1000)


class StartLifecycleFailureDetailTests(unittest.TestCase):
    """start_lifecycle's failure contract: LifecycleStart.error carries
    a one-line, escaped, bounded detail — helper stderr interpolates
    target paths and project names, so raw bytes must never reach the
    skip record."""

    def _start(self, dispatcher):
        from core.orchestration.skill_dispatch import start_lifecycle
        with patch("core.orchestration.skill_dispatch.subprocess.run",
                   side_effect=dispatcher), \
             patch("core.run.pin._process_project", None), \
             patch("core.run.pin._process_project_set", False), \
             self.assertLogs("core.orchestration.skill_dispatch",
                             level="WARNING"):
            return start_lifecycle("validate", Path("/target"))

    def test_error_line_is_extracted(self) -> None:
        stderr = ("usage noise\n"
                  "ERROR: target /t is outside project p (/pt)\n"
                  "  A project tracks one target.\n")
        result = self._start(
            lambda *a, **k: _ok(returncode=1, stderr=stderr))
        self.assertIsNone(result.run_dir)
        self.assertEqual(
            result.error, "ERROR: target /t is outside project p (/pt)")

    def test_detail_is_escaped_and_bounded(self) -> None:
        hostile = "ERROR: target /t\x1b[2J\x07 " + "A" * 4000
        result = self._start(
            lambda *a, **k: _ok(returncode=1, stderr=hostile))
        self.assertIsNone(result.run_dir)
        self.assertNotIn("\x1b", result.error)
        self.assertNotIn("\x07", result.error)
        self.assertIn("\\x1b", result.error)
        self.assertLess(len(result.error), 400)
        self.assertIn("chars]", result.error)  # explicit elision marker
        self.assertNotIn("\n", result.error)

    def test_no_stderr_reports_exit_code(self) -> None:
        result = self._start(lambda *a, **k: _ok(returncode=7))
        self.assertIsNone(result.run_dir)
        self.assertEqual(result.error, "helper exited 7 with no stderr")

    def test_missing_sentinel_reports_it(self) -> None:
        result = self._start(
            lambda *a, **k: _ok(returncode=0, stdout="no sentinel\n"))
        self.assertIsNone(result.run_dir)
        self.assertEqual(result.error, "helper did not emit OUTPUT_DIR=")

    def test_success_has_no_error(self) -> None:
        from core.orchestration.skill_dispatch import start_lifecycle
        with patch("core.orchestration.skill_dispatch.subprocess.run",
                   side_effect=lambda *a, **k: _ok(
                       stdout="OUTPUT_DIR=/nonexistent-run\n")), \
             patch("core.run.pin._process_project", None), \
             patch("core.run.pin._process_project_set", False):
            result = start_lifecycle("validate", Path("/target"))
        self.assertEqual(result.run_dir, Path("/nonexistent-run"))
        self.assertIsNone(result.error)

    def test_spawn_failure_detail_is_sanitised(self) -> None:
        def _boom(*a, **k):
            raise OSError("exec\x1bfailed")
        result = self._start(_boom)
        self.assertIsNone(result.run_dir)
        self.assertTrue(result.error.startswith("helper spawn failed: "))
        self.assertNotIn("\x1b", result.error)

    def test_dispatch_skip_reason_carries_the_detail(self) -> None:
        # End of the seam: run_skill_dispatch's skip record appends
        # the helper detail to the stable constant prefix.
        with TemporaryDirectory() as tmp:
            def dispatcher(cmd, *args, **kwargs):
                return _ok(returncode=1,
                           stderr="ERROR: target /t is outside "
                                  "project p (/pt)\n")
            with patch(
                    "core.orchestration.skill_dispatch.subprocess.run",
                    side_effect=dispatcher), \
                 patch("core.orchestration.skill_dispatch."
                       "run_untrusted_networked",
                       side_effect=dispatcher), \
                 patch("core.llm.cc_probe.probe_cc_session_model",
                       return_value="fake-model"), \
                 patch("core.run.pin._process_project", None), \
                 patch("core.run.pin._process_project_set", False), \
                 patch.dict("os.environ", _FIRST_PARTY_PROVIDER_ENV), \
                 self.assertLogs("core.orchestration.skill_dispatch",
                                 level="WARNING"):
                result = run_skill_dispatch(
                    command="validate", target=Path(tmp),
                    tools="Read", budget_usd="1.00", timeout_s=60,
                    caller_label="test-dispatch", log_label="test pass",
                    build_prompt=lambda d: "prompt",
                    claude_bin="/fake/claude",
                )
        self.assertFalse(result.ran)
        self.assertEqual(
            result.skipped_reason,
            "lifecycle start failed: "
            "ERROR: target /t is outside project p (/pt)")
