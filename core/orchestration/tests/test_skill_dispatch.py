"""Tests for core.orchestration.skill_dispatch — the shared runner.

The caller-level behaviour (agentic pre/post passes) is covered by
test_agentic_passes*.py; the audit-side caller by
core/audit/tests/test_validate.py. This file covers the runner's own
contract: gate order, StageError abort, output validation, truncation
policy, and the settled-lifecycle pattern.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

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


def _run(tmp, run_dir, *, sandbox=None, **overrides):
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
                       "run_untrusted_networked", side_effect=dispatcher):
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

    def _fail_sandbox(self, run_dir, *, returncode, stdout="", stderr=""):
        dispatcher = _lifecycle_dispatcher(run_dir)

        def _sandbox(cmd, *args, **kwargs):
            dispatcher(cmd, *args, **kwargs)
            return _ok(returncode=returncode, stdout=stdout, stderr=stderr)
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
            self.assertIn("no output captured", "\n".join(logs.output))

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
            content = (run_dir / "dispatch-child-tail.log").read_text()
            self.assertIn("exit=0", content)
            self.assertIn("stage helper crashed mid-run", content)


class ChildTailPlantTests(unittest.TestCase):
    """run_dir is child-writable by design: a planted symlink at the
    artifact name must never steer the parent's write."""

    def test_symlink_plant_never_clobbers_the_target(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            victim = Path(tmp) / "victim.json"
            victim.write_text('{"verdict": "untouched"}')
            dispatcher = _lifecycle_dispatcher(run_dir)

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                # The child plants the symlink inside its writable
                # run dir, then fails.
                link = run_dir / "dispatch-child-tail.log"
                if not link.exists() and not link.is_symlink():
                    link.symlink_to(victim)
                return _ok(returncode=1, stdout="attacker narrative")

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

            def _sandbox(cmd, *args, **kwargs):
                dispatcher(cmd, *args, **kwargs)
                return _ok(returncode=1, stdout="boom")

            with self.assertLogs(
                    "core.orchestration.skill_dispatch",
                    level="WARNING"):
                _run(tmp, run_dir, sandbox=_sandbox)
            mode = _stat.S_IMODE(
                (run_dir / "dispatch-child-tail.log").stat().st_mode)
            self.assertEqual(mode, 0o600)
