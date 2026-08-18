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
    run_skill_dispatch,
    truncate_findings_by_signal,
)

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
