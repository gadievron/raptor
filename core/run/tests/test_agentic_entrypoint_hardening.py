"""Tests for raptor_agentic.py entry-point hardening helpers.

Covers:
  1. ``_count_dropped_suppressions`` — suppressions.jsonl counters
     count only ``dropped: true`` records (record-only rows with
     ``dropped: false`` describe findings that SURVIVED to the LLM).
  2. ``_replay_reproduced`` — fuzz-crash replay counts a reproduction
     only on real crash evidence, never on a plain usage-error exit
     or a LeakSanitizer report.
  3. ``_kill_process_tree`` — phase-timeout kills reap the whole
     process group, not just the direct child.
  4. run_command_streaming credential-relay failure — the env-direct
     fallback really carries the LLM env, and a failed spawn does not
     leak the relayed token FD.
  5. ``_fail_run_and_exit`` — hard-failure exits stamp the run failed.
  6. sys.path bootstrap uses a resolved path in all three entry
     scripts.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_agentic():
    if str(_RAPTOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor_agentic
    return raptor_agentic


# ---------------------------------------------------------------------------
# _count_dropped_suppressions
# ---------------------------------------------------------------------------


class TestCountDroppedSuppressions:
    def test_counts_only_dropped_true_records(self, tmp_path):
        agentic = _import_agentic()
        f = tmp_path / "suppressions.jsonl"
        f.write_text(
            '{"finding_id": "a", "verdict": "absent", "dropped": true}\n'
            '{"finding_id": "b", "verdict": "candidate_only",'
            ' "dropped": false, "extra": 1}\n'
            "\n"
            "not-json\n"
            '{"finding_id": "c", "verdict": "absent"}\n',
            encoding="utf-8",
        )
        # a (dropped true) + c (legacy record predating the field,
        # which always described a drop) = 2; the record-only b row,
        # the blank line, and the malformed line are all skipped.
        assert agentic._count_dropped_suppressions(f) == 2

    def test_missing_file_counts_zero(self, tmp_path):
        agentic = _import_agentic()
        assert agentic._count_dropped_suppressions(
            tmp_path / "nope.jsonl") == 0


# ---------------------------------------------------------------------------
# _replay_reproduced
# ---------------------------------------------------------------------------


class TestReplayReproduced:
    def test_signal_death_reproduces(self):
        agentic = _import_agentic()
        assert agentic._replay_reproduced(-11, b"") is True
        assert agentic._replay_reproduced(139, b"") is True

    def test_plain_usage_error_does_not_reproduce(self):
        agentic = _import_agentic()
        assert agentic._replay_reproduced(1, b"usage: prog FILE\n") is False

    def test_leak_report_does_not_reproduce(self):
        agentic = _import_agentic()
        stderr = b"==12==ERROR: LeakSanitizer: detected memory leaks\n"
        assert agentic._replay_reproduced(23, stderr) is False

    def test_asan_crash_report_reproduces(self):
        agentic = _import_agentic()
        stderr = b"==7==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        assert agentic._replay_reproduced(1, stderr) is True

    def test_clean_exit_never_reproduces(self):
        agentic = _import_agentic()
        assert agentic._replay_reproduced(0, b"anything") is False

    def test_replay_env_disables_leak_detection(self):
        # The injected ASAN default must not turn benign exit-time
        # leaks into nonzero exits in the first place.
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(encoding="utf-8")
        assert "abort_on_error=1:symbolize=1:detect_leaks=0" in src
        assert "abort_on_error=1:symbolize=1:detect_leaks=1" not in src


# ---------------------------------------------------------------------------
# _kill_process_tree
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="killpg unavailable")
class TestKillProcessTree:
    def test_grandchild_is_reaped(self):
        agentic = _import_agentic()
        # Child leads a new session (as the real spawns do) and forks a
        # grandchild whose pid it reports on stdout.
        proc = subprocess.Popen(
            ["bash", "-c", "sleep 30 & echo $!; wait"],
            stdout=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            grandchild = int(proc.stdout.readline().strip())
            agentic._kill_process_tree(proc)
            proc.wait(timeout=5)
            # Give the kernel a beat to deliver the group SIGKILL.
            for _ in range(50):
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                os.kill(grandchild, 9)
                pytest.fail("grandchild survived the tree kill")
        finally:
            proc.stdout.close()

    def test_already_dead_child_is_harmless(self):
        agentic = _import_agentic()
        proc = subprocess.Popen(["true"], start_new_session=True)
        proc.wait(timeout=5)
        agentic._kill_process_tree(proc)  # must not raise


# ---------------------------------------------------------------------------
# run_command_streaming relay-failure fallback
# ---------------------------------------------------------------------------


class TestRelayFailureFallback:
    def test_env_direct_fallback_carries_llm_env(self, monkeypatch):
        agentic = _import_agentic()
        from core.config import RaptorConfig
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/nonexistent.sock")
        marker_env = {"RAPTOR_TEST_MARKER": "1", "PATH": os.environ.get("PATH", "")}
        with patch("core.llm.dispatcher.client.relay_for_grandchild",
                   side_effect=RuntimeError("relay down")), \
                patch.object(RaptorConfig, "get_llm_env",
                             staticmethod(lambda **kw: dict(marker_env))):
            rc, _stdout, _stderr = agentic.run_command_streaming(
                [sys.executable, "-c",
                 "import os, sys; "
                 "sys.exit(0 if os.environ.get('RAPTOR_TEST_MARKER') == '1' "
                 "else 3)"],
                "fallback probe", timeout=60,
            )
        assert rc == 0

    def test_no_socket_means_no_llm_env(self, monkeypatch):
        # Direction two: without a dispatcher session the safe env is
        # used as before — the keys-bearing env is never built.
        agentic = _import_agentic()
        from core.config import RaptorConfig
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        with patch.object(RaptorConfig, "get_llm_env") as get_llm_env:
            rc, _stdout, _stderr = agentic.run_command_streaming(
                [sys.executable, "-c", "raise SystemExit(0)"],
                "safe-env probe", timeout=60,
            )
        assert rc == 0
        assert not get_llm_env.called

    def test_failed_spawn_closes_relayed_token_fd(self, monkeypatch):
        agentic = _import_agentic()
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/nonexistent.sock")
        r, w = os.pipe()
        os.close(w)
        with patch("core.llm.dispatcher.client.relay_for_grandchild",
                   return_value=("/nonexistent.sock", r)):
            rc, _stdout, _stderr = agentic.run_command_streaming(
                ["/nonexistent-binary-xyz"], "spawn failure", timeout=60,
            )
        assert rc == -1
        # The parent's copy of the relayed FD must be closed even when
        # Popen itself raised (one leaked fd per failed spawn otherwise).
        with pytest.raises(OSError):
            os.fstat(r)


# ---------------------------------------------------------------------------
# _fail_run_and_exit
# ---------------------------------------------------------------------------


class TestFailRunAndExit:
    def test_stamps_failed_then_exits_nonzero(self, tmp_path):
        agentic = _import_agentic()
        calls = []
        with patch("core.run.fail_run",
                   side_effect=lambda out_dir, reason: calls.append(
                       (out_dir, reason))), \
                pytest.raises(SystemExit) as exc:
            agentic._fail_run_and_exit(tmp_path, "boom")
        assert exc.value.code == 1
        assert calls == [(tmp_path, "boom")]

    def test_marker_failure_never_masks_the_exit(self, tmp_path):
        agentic = _import_agentic()
        with patch("core.run.fail_run",
                   side_effect=OSError("disk full")), \
                pytest.raises(SystemExit) as exc:
            agentic._fail_run_and_exit(tmp_path, "boom")
        assert exc.value.code == 1

    def test_hard_failure_sites_use_the_helper(self):
        # The post-start_run hard exits must stamp the run: a direct
        # invocation has no wrapper backstop, and a bare sys.exit(1)
        # leaves a phantom status="running" run behind.
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(encoding="utf-8")
        assert '_fail_run_and_exit(out_dir, "no SARIF files generated from scanning")' in src
        assert '_fail_run_and_exit(out_dir, "CodeQL-only mode failed")' in src


# ---------------------------------------------------------------------------
# Phase 2 / Phase 3 failure capture
# ---------------------------------------------------------------------------


class TestValidationPhaseChecked:
    def test_crash_fails_the_run_and_exits(self, tmp_path):
        agentic = _import_agentic()
        calls = []
        with patch("packages.exploitability_validation."
                   "run_validation_phase",
                   side_effect=ValueError("bad sarif")), \
                patch("core.run.fail_run",
                      side_effect=lambda out_dir, reason: calls.append(
                          (out_dir, reason))), \
                pytest.raises(SystemExit) as exc:
            agentic._run_validation_phase_checked(
                tmp_path, repo_path="x", out_dir=tmp_path)
        assert exc.value.code == 1
        assert calls and calls[0][0] == tmp_path
        assert "ValueError" in calls[0][1]

    def test_success_passes_result_through(self, tmp_path):
        agentic = _import_agentic()
        sentinel = ({"completed": True}, 7)
        with patch("packages.exploitability_validation."
                   "run_validation_phase", return_value=sentinel), \
                patch("core.run.fail_run") as fail_run:
            result = agentic._run_validation_phase_checked(
                tmp_path, repo_path="x", out_dir=tmp_path)
        assert result == sentinel
        assert not fail_run.called

    def test_sandbox_error_keeps_propagating(self, tmp_path):
        # SandboxSetupError has its own actionable handler and exit
        # code at the entry point — never converted to a plain fail.
        agentic = _import_agentic()
        from core.sandbox import SandboxSetupError
        with patch("packages.exploitability_validation."
                   "run_validation_phase",
                   side_effect=SandboxSetupError("m", "hint")), \
                pytest.raises(SandboxSetupError):
            agentic._run_validation_phase_checked(
                tmp_path, repo_path="x", out_dir=tmp_path)

    def test_call_site_uses_the_checked_wrapper(self):
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert "_run_validation_phase_checked(\n        out_dir," in src


class TestMissingAnalysisReport:
    def test_nonzero_rc_fails_the_run(self, tmp_path, capsys):
        agentic = _import_agentic()
        calls = []
        with patch("core.run.fail_run",
                   side_effect=lambda out_dir, reason: calls.append(
                       (out_dir, reason))), \
                pytest.raises(SystemExit) as exc:
            agentic._fail_or_warn_missing_analysis(tmp_path, 2, "boom")
        assert exc.value.code == 1
        assert calls and "exited 2" in calls[0][1]

    def test_zero_rc_keeps_the_degrade_path(self, tmp_path, capsys):
        # Direction two: a clean subprocess with nothing to report
        # still degrades with a warning — completed runs stay rc 0.
        agentic = _import_agentic()
        with patch("core.run.fail_run") as fail_run:
            agentic._fail_or_warn_missing_analysis(tmp_path, 0, "")
        assert not fail_run.called
        assert "produced no output" in capsys.readouterr().err


class TestReportWithNonzeroRc:
    """Phase 3 wrote its report but exited nonzero (post-report
    teardown window). The run deliberately proceeds on the written
    report and exits 0 — but the child rc must surface as a warning,
    never be silently absorbed into "Analysis complete"."""

    def test_nonzero_rc_warns_and_returns(self, capsys):
        agentic = _import_agentic()
        agentic._warn_analysis_rc_with_report(3)
        err = capsys.readouterr().err
        assert "exited 3" in err
        assert "written report" in err

    def test_zero_rc_stays_silent(self, capsys):
        agentic = _import_agentic()
        agentic._warn_analysis_rc_with_report(0)
        assert capsys.readouterr().err == ""

    def test_call_site_guards_the_report_branch(self):
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert ("if analysis_report.exists():\n"
                "            _warn_analysis_rc_with_report(rc)") in src


# ---------------------------------------------------------------------------
# _cli_entry lifecycle backstop
# ---------------------------------------------------------------------------


class TestCliEntryBackstop:
    """Uncaught exceptions and Ctrl-C at the entry point must close the
    lifecycle — pre-fix only SandboxSetupError was handled and the run
    marker stayed at "running" forever on a direct invocation."""

    def test_uncaught_exception_stamps_failed_and_reraises(
            self, tmp_path):
        agentic = _import_agentic()
        calls = []
        with patch.object(agentic, "main",
                          side_effect=RuntimeError("phase exploded")), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run",
                      side_effect=lambda out_dir, reason: calls.append(
                          (out_dir, reason))), \
                pytest.raises(RuntimeError):
            agentic._cli_entry()
        assert calls and calls[0][0] == tmp_path
        assert "RuntimeError" in calls[0][1]

    def test_keyboard_interrupt_cancels_and_exits_130(self, tmp_path):
        agentic = _import_agentic()
        calls = []
        with patch.object(agentic, "main",
                          side_effect=KeyboardInterrupt), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.cancel_run",
                      side_effect=lambda out_dir: calls.append(out_dir)), \
                pytest.raises(SystemExit) as exc:
            agentic._cli_entry()
        assert exc.value.code == 130
        assert calls == [tmp_path]

    def test_nonzero_system_exit_stamps_failed(self, tmp_path):
        # A bare sys.exit(N) deep in a phase is not an Exception — it
        # sailed through the handler chain with the marker "running".
        agentic = _import_agentic()
        calls = []
        with patch.object(agentic, "main",
                          side_effect=SystemExit(3)), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run",
                      side_effect=lambda out_dir, reason: calls.append(
                          (out_dir, reason))), \
                pytest.raises(SystemExit) as exc:
            agentic._cli_entry()
        assert exc.value.code == 3
        assert calls and "3" in calls[0][1]

    def test_zero_system_exit_never_stamps(self, tmp_path):
        agentic = _import_agentic()
        with patch.object(agentic, "main",
                          side_effect=SystemExit(0)), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run") as fail_run, \
                pytest.raises(SystemExit) as exc:
            agentic._cli_entry()
        assert exc.value.code == 0
        assert not fail_run.called

    def test_backstop_never_clobbers_a_specific_reason(self, tmp_path):
        # _fail_run_and_exit stamps a precise reason then sys.exit(1);
        # the SystemExit backstop must not overwrite it with the
        # generic "exited with code 1".
        import json
        agentic = _import_agentic()
        from core.run.metadata import RUN_METADATA_FILE
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "status": "failed", "extra": {"error": "specific reason"},
        }), encoding="utf-8")
        with patch.object(agentic, "main",
                          side_effect=SystemExit(1)), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run") as fail_run, \
                pytest.raises(SystemExit):
            agentic._cli_entry()
        assert not fail_run.called

    def test_base_exception_stamps_failed_and_reraises(self, tmp_path):
        agentic = _import_agentic()

        class Escape(BaseException):
            pass

        calls = []
        with patch.object(agentic, "main", side_effect=Escape("gone")), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run",
                      side_effect=lambda out_dir, reason: calls.append(
                          reason)), \
                pytest.raises(Escape):
            agentic._cli_entry()
        assert calls == ["uncaught Escape: gone"]

    def test_raising_dunder_str_still_stamps(self, tmp_path):
        # A hostile/broken __str__ on the escaping exception must not
        # defeat the marker write.
        agentic = _import_agentic()

        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("nope")

        calls = []
        with patch.object(agentic, "main", side_effect=Hostile()), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", tmp_path), \
                patch("core.run.fail_run",
                      side_effect=lambda out_dir, reason: calls.append(
                          reason)), \
                pytest.raises(Hostile):
            agentic._cli_entry()
        assert calls == ["uncaught Hostile"]

    def test_unarmed_backstop_never_touches_a_marker(self):
        # Failure BEFORE start_run (argparse, git init): there is no
        # run to close; the backstop must stay quiet.
        agentic = _import_agentic()
        with patch.object(agentic, "main",
                          side_effect=RuntimeError("pre-lifecycle")), \
                patch.object(agentic, "_LIFECYCLE_OUT_DIR", None), \
                patch("core.run.fail_run") as fail_run, \
                pytest.raises(RuntimeError):
            agentic._cli_entry()
        assert not fail_run.called

    def test_clean_return_exits_zero_without_backstop(self):
        agentic = _import_agentic()
        with patch.object(agentic, "main", return_value=0), \
                patch("core.run.fail_run") as fail_run, \
                patch("core.run.cancel_run") as cancel_run, \
                pytest.raises(SystemExit) as exc:
            agentic._cli_entry()
        assert exc.value.code == 0
        assert not fail_run.called and not cancel_run.called

    def test_subprocess_crash_leaves_no_running_marker(self, tmp_path):
        # End-to-end shape of the original defect: a direct invocation
        # whose pipeline raises after start_run must leave the marker
        # terminal, not "running".
        import json
        out = tmp_path / "agentic_run"
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(_RAPTOR_ROOT)!r})\n"
            "import raptor_agentic as ra\n"
            "from pathlib import Path\n"
            f"out = Path({str(out)!r})\n"
            "def boom():\n"
            "    out.mkdir(parents=True, exist_ok=True)\n"
            "    from core.run import start_run\n"
            "    start_run(out, 'agentic', target=str(out))\n"
            "    ra._LIFECYCLE_OUT_DIR = out\n"
            "    raise RuntimeError('phase exploded')\n"
            "ra.main = boom\n"
            "ra._cli_entry()\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_RAPTOR_ROOT, capture_output=True, text=True,
            timeout=120,
        )
        assert proc.returncode != 0
        marker = json.loads(
            (out / ".raptor-run.json").read_text(encoding="utf-8"))
        assert marker["status"] == "failed"
        assert "RuntimeError" in marker.get("extra", {}).get("error", "")


# ---------------------------------------------------------------------------
# sys.path bootstrap
# ---------------------------------------------------------------------------


class TestSysPathBootstrap:
    def test_entry_scripts_resolve_their_parent(self):
        # A symlinked (or, on interpreters that don't absolutise
        # __file__, relative) invocation must still put THIS tree on
        # sys.path — the unresolved parent points at the wrong tree.
        for name in ("raptor_agentic.py", "raptor_codeql.py",
                     "raptor_fuzzing.py"):
            src = (_RAPTOR_ROOT / name).read_text(encoding="utf-8")
            assert ("sys.path.insert(0, "
                    "str(Path(__file__).resolve().parent))") in src, name
            assert ("sys.path.insert(0, "
                    "str(Path(__file__).parent))") not in src, name
