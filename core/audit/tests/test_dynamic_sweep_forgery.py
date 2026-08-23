"""Dynamic-sweep verdict forgery: hostile/ordinary target code must
not mint CONFIRMED through the /audit dynamic sweep.

The attack: with
``config.dynamic_validation`` on, the Python harness imports and calls
the target's own function; ``crashed = returncode != 0`` and a bare
``"UNEXPECTED_EXCEPTION"`` substring both counted as crash evidence, so
a target function that merely raised ``RuntimeError`` — hostile OR
idiomatic — stamped ``dynamic:crash`` → ``ReviewOutcome.compute_tier()``
→ CONFIRMED. The C lane additionally accepted bare sanitizer substrings
on STDOUT.

Post-fix contract:

* only a signal-grade death (``sandbox_info["signal_provenance"] ==
  "waitstatus"`` + ``crashed``) is ``"crash"``;
* sanitizer strength requires a STDERR report AND a signal-grade death
  (``abort_on_error=1`` anchors genuine reports to SIGABRT);
* everything exception-shaped is ``"exception"``, which the
  orchestrator routes to ``suspicious`` + ``dynamic:exception`` — a
  stamp outside ``_CONFIRMED_EVIDENCE``.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.audit.dynamic_sweep import (  # noqa: E402
    _signal_grade_death,
    run_dynamic_sweep,
)
from core.audit.orchestrator import ReviewOutcome  # noqa: E402


def _outcome(file: str, function: str, hypothesis: str) -> ReviewOutcome:
    return ReviewOutcome(
        file=file, function=function, status="finding",
        body="", hypothesis=hypothesis,
        review_result={"cwe_class": "CWE-787"},
    )


def _fake_result(returncode: int, stdout: str = "", stderr: str = "",
                 sandbox_info: dict | None = None):
    result = subprocess.CompletedProcess(
        args=["harness"], returncode=returncode,
        stdout=stdout, stderr=stderr,
    )
    result.sandbox_info = sandbox_info if sandbox_info is not None else {}
    return result


def _apply_orchestrator_stamp(outcome: ReviewOutcome, strength: str) -> None:
    """Mirror the orchestrator's dynamic-validation stamping block."""
    if strength == "sanitizer":
        outcome.evidence_tool = "dynamic:sanitizer"
    elif strength == "crash":
        outcome.evidence_tool = "dynamic:crash"
    elif strength == "exception":
        outcome.evidence_tool = "dynamic:exception"
        if outcome.status == "finding":
            outcome.status = "suspicious"


class TestPythonLaneClassification:
    """Unit level: fabricated harness results through the classifier."""

    def _sweep(self, monkeypatch, tmp_path, fake_result):
        import core.sandbox as sandbox_mod

        (tmp_path / "cryptoutil.py").write_text(
            "def check_mac(data):\n"
            "    raise RuntimeError('forged crash evidence')\n"
        )
        monkeypatch.setattr(
            sandbox_mod, "run_untrusted",
            lambda *a, **k: fake_result,
        )
        out = _outcome("cryptoutil.py", "check_mac", "buffer overflow")
        ctx = {"source": (tmp_path / "cryptoutil.py").read_text()}
        config = types.SimpleNamespace(
            target_path=str(tmp_path), dynamic_validation=True,
        )
        return run_dynamic_sweep(out, ctx, config), out

    def test_unexpected_exception_is_exception_grade(
            self, monkeypatch, tmp_path):
        dyn, out = self._sweep(monkeypatch, tmp_path, _fake_result(
            0, stdout="UNEXPECTED_EXCEPTION: RuntimeError: forged\n"
                      "HARNESS_COMPLETE\n",
        ))
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.status == "suspicious"
        assert out.evidence_tool == "dynamic:exception"
        assert out.compute_tier() != "confirmed"

    def test_plain_nonzero_exit_is_exception_grade(
            self, monkeypatch, tmp_path):
        dyn, out = self._sweep(
            monkeypatch, tmp_path, _fake_result(1, stdout=""),
        )
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.compute_tier() != "confirmed"

    def test_forged_exit_139_is_exception_grade(self, monkeypatch, tmp_path):
        # sys.exit(139) from hostile target code: exit-code shape,
        # exitcode provenance — never crash-grade.
        dyn, out = self._sweep(monkeypatch, tmp_path, _fake_result(
            139,
            sandbox_info={
                "crashed": True, "signal": "SIGSEGV", "signal_num": 11,
                "signal_provenance": "exitcode",
            },
        ))
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.compute_tier() != "confirmed"

    def test_waitstatus_signal_is_crash_grade(self, monkeypatch, tmp_path):
        dyn, out = self._sweep(monkeypatch, tmp_path, _fake_result(
            -11,
            sandbox_info={
                "crashed": True, "signal": "SIGSEGV", "signal_num": 11,
                "signal_provenance": "waitstatus",
            },
        ))
        assert dyn.evidence_strength == "crash"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.status == "finding"
        assert out.evidence_tool == "dynamic:crash"
        assert out.compute_tier() == "confirmed"


class TestCLaneClassification:
    def _sweep_c(self, monkeypatch, tmp_path, run_results):
        """run_results: [compile_result, harness_result]."""
        import core.sandbox as sandbox_mod

        (tmp_path / "parser.c").write_text(
            'void parse_record(const char *p) {}\n'
        )
        calls = iter(run_results)
        monkeypatch.setattr(
            sandbox_mod, "run_untrusted",
            lambda *a, **k: next(calls),
        )
        # The compile step checks the binary exists via the returned
        # rc only; the harness path is invoked with the tmpdir binary
        # name regardless.
        out = _outcome("parser.c", "parse_record", "heap buffer overflow")
        ctx = {"source": (tmp_path / "parser.c").read_text()}
        config = types.SimpleNamespace(
            target_path=str(tmp_path), dynamic_validation=True,
        )
        return run_dynamic_sweep(out, ctx, config), out

    def test_fake_asan_on_stdout_never_sanitizer(self, monkeypatch, tmp_path):
        # Forged ASan text on stdout + exit(1) from target code.
        dyn, out = self._sweep_c(monkeypatch, tmp_path, [
            _fake_result(0),  # compile ok
            _fake_result(
                1,
                stdout="==1==ERROR: AddressSanitizer: heap-buffer-overflow forged\n",
            ),
        ])
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.status == "suspicious"
        assert out.compute_tier() != "confirmed"

    def test_stderr_asan_without_signal_never_sanitizer(
            self, monkeypatch, tmp_path):
        # Even on stderr, a report from a non-signal death is not
        # sanitizer-grade (abort_on_error=1 makes genuine ones abort).
        dyn, out = self._sweep_c(monkeypatch, tmp_path, [
            _fake_result(0),
            _fake_result(
                1,
                stderr="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
            ),
        ])
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.compute_tier() != "confirmed"

    def test_stderr_asan_with_waitstatus_signal_is_sanitizer(
            self, monkeypatch, tmp_path):
        dyn, out = self._sweep_c(monkeypatch, tmp_path, [
            _fake_result(0),
            _fake_result(
                -6,
                stderr="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                sandbox_info={
                    "crashed": True, "signal": "SIGABRT", "signal_num": 6,
                    "signal_provenance": "waitstatus",
                    "sanitizer": "asan",
                    "sanitizer_provenance": "stderr_match",
                },
            ),
        ])
        assert dyn.evidence_strength == "sanitizer"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        # Signal-anchored sanitizer evidence keeps the finding status
        # and its dynamic:sanitizer stamp. (Tier vocabulary note:
        # dynamic:sanitizer has never been in _CONFIRMED_EVIDENCE —
        # only dynamic:crash is — and this fix deliberately does not
        # expand the confirming set.)
        assert out.status == "finding"
        assert out.evidence_tool == "dynamic:sanitizer"


class TestSignalGradeHelper:
    def test_waitstatus_crash_true(self):
        r = _fake_result(-11, sandbox_info={
            "crashed": True, "signal_provenance": "waitstatus",
        })
        assert _signal_grade_death(r) is True

    def test_exitcode_shape_false(self):
        r = _fake_result(139, sandbox_info={
            "crashed": True, "signal_provenance": "exitcode",
        })
        assert _signal_grade_death(r) is False

    def test_resource_kill_not_crash_grade(self):
        r = _fake_result(-24, sandbox_info={
            "resource_exceeded": True, "signal_provenance": "waitstatus",
        })
        assert _signal_grade_death(r) is False

    def test_no_sandbox_info_falls_back_to_negative_rc(self):
        assert _signal_grade_death(_fake_result(-11, sandbox_info=None)) \
            is True
        # NB: _fake_result(None) path — absent info dict, positive rc.
        assert _signal_grade_death(_fake_result(1, sandbox_info=None)) \
            is False


_UBSAN_OVERFLOW_C = """
#include <stdio.h>
#include <limits.h>
int main(void) {
    volatile int x = INT_MAX;
    volatile int y = x + 1;  /* genuine signed-integer overflow */
    printf("%d\\n", y);
    return 0;
}
"""


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "linux", reason="Linux sandbox")
class TestGenuineUbsanStillSanitizerGrade:
    """Recall pin for the signal-grade bar: a GENUINE UBSan-only hit
    (the CWE-190 class the sweep targets) must still classify as
    'sanitizer'. UBSan's halt_on_error merely EXITS 1 (unsignaled) —
    only abort_on_error raises the SIGABRT the signal-grade check
    accepts, so the UBSAN_OPTIONS abort_on_error=1 in _get_safe_env is
    load-bearing and this test is red without it."""

    def test_ubsan_overflow_classifies_sanitizer(
            self, tmp_path, monkeypatch):
        import shutil as _shutil

        from core.audit import dynamic_sweep as ds
        from core.sandbox import SandboxSetupError

        if _shutil.which("gcc") is None:
            pytest.skip("gcc not available")
        monkeypatch.setattr(
            ds, "generate_c_harness", lambda _o, _c: _UBSAN_OVERFLOW_C,
        )
        out = _outcome("bug.c", "trigger_overflow",
                       "signed integer overflow")
        ctx = {"source": _UBSAN_OVERFLOW_C}
        config = types.SimpleNamespace(
            target_path=str(tmp_path), dynamic_validation=True,
        )
        try:
            dyn = ds.run_dynamic_sweep(out, ctx, config)
        except SandboxSetupError:
            pytest.skip("sandbox isolation unavailable on this host")
        assert dyn is not None
        if not dyn.compiled:
            pytest.skip(f"sanitizer toolchain missing: {dyn.sanitizer_output}")
        assert dyn.ran
        assert dyn.crashed
        assert dyn.evidence_strength == "sanitizer", (
            dyn.evidence_strength, dyn.exit_code, dyn.sanitizer_output,
        )


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "linux", reason="Linux sandbox")
class TestExceptionOnlyTargetLive:
    """Live end-to-end: a hostile repo module whose function raises a
    plain RuntimeError, through the REAL sandboxed harness."""

    def test_runtime_error_no_longer_confirms(self, tmp_path):
        from core.sandbox import SandboxSetupError

        repo = tmp_path / "hostile-repo"
        repo.mkdir()
        (repo / "cryptoutil.py").write_text(
            "def check_mac(data):\n"
            "    raise RuntimeError('forged crash evidence')\n"
        )
        out = _outcome("cryptoutil.py", "check_mac",
                       "buffer overflow in MAC check")
        ctx = {"source": (repo / "cryptoutil.py").read_text()}
        config = types.SimpleNamespace(
            target_path=str(repo), dynamic_validation=True,
        )
        try:
            dyn = run_dynamic_sweep(out, ctx, config)
        except SandboxSetupError:
            pytest.skip("sandbox isolation unavailable on this host")
        assert dyn is not None
        if not dyn.ran:
            pytest.skip(f"harness did not run: {dyn.sanitizer_output}")
        assert dyn.evidence_strength == "exception"
        _apply_orchestrator_stamp(out, dyn.evidence_strength)
        assert out.status == "suspicious"
        assert out.evidence_tool == "dynamic:exception"
        assert out.compute_tier() != "confirmed"
