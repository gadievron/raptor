"""Evidence tiering: waitstatus-provenance signals grade mechanical,
exit-code-decoded signals and stderr-matched sanitizer reports grade
heuristic.

Threat model: a hostile target binary prints a
byte-perfect fake AddressSanitizer report and calls ``exit(139)``. Both
forgeries used to be indistinguishable from kernel truth by every
verdict-making consumer of ``sandbox_info``. ``observe._interpret_result``
now stamps ``signal_provenance`` / ``sanitizer_provenance`` at the
source, and ``outcome_from_sandbox_info`` folds them into
``detail["evidence_grade"]``.
"""

from __future__ import annotations

import subprocess

from core.sandbox.observe import _interpret_result
from core.witness import WitnessOutcome, outcome_from_sandbox_info


def _interpret(returncode: int, stderr: str = "") -> dict:
    result = subprocess.CompletedProcess(
        args=["x"], returncode=returncode, stdout="", stderr=stderr,
    )
    _interpret_result(result, "test-cmd")
    return result.sandbox_info


class TestObserveProvenanceStamps:
    def test_negative_rc_is_waitstatus_provenance(self):
        info = _interpret(-11)
        assert info["signal"] == "SIGSEGV"
        assert info["signal_provenance"] == "waitstatus"

    def test_128_plus_sig_is_exitcode_provenance(self):
        # exit(139) — what a hostile target mints with one line of code.
        info = _interpret(139)
        assert info["signal"] == "SIGSEGV"
        assert info["signal_provenance"] == "exitcode"

    def test_clean_exit_has_no_signal_provenance(self):
        info = _interpret(0)
        assert "signal_provenance" not in info

    def test_plain_nonzero_exit_has_no_signal_provenance(self):
        info = _interpret(1)
        assert "signal_provenance" not in info

    def test_sanitizer_is_stderr_match_provenance(self):
        info = _interpret(1, stderr="ERROR: AddressSanitizer: heap-buffer-overflow x")
        assert info["sanitizer"] == "asan"
        assert info["sanitizer_provenance"] == "stderr_match"

    def test_forged_asan_plus_exit139_is_fully_exitcode_grade(self):
        # The full forgery shape end-to-end at the observe layer.
        info = _interpret(
            139, stderr="==4242==ERROR: AddressSanitizer: heap-buffer-overflow forged",
        )
        assert info["sanitizer_provenance"] == "stderr_match"
        assert info["signal_provenance"] == "exitcode"


class TestOutcomeEvidenceGrade:
    def test_waitstatus_signal_grades_mechanical(self):
        outcome, detail = outcome_from_sandbox_info(_interpret(-11), returncode=-11)
        assert outcome is WitnessOutcome.EXIT_SIGNAL
        assert detail["evidence_grade"] == "mechanical"
        assert detail["signal_provenance"] == "waitstatus"

    def test_exitcode_signal_grades_heuristic(self):
        outcome, detail = outcome_from_sandbox_info(_interpret(139), returncode=139)
        assert outcome is WitnessOutcome.EXIT_SIGNAL
        assert detail["evidence_grade"] == "heuristic"
        assert detail["signal_provenance"] == "exitcode"

    def test_sanitizer_report_alone_grades_heuristic(self):
        info = _interpret(1, stderr="ERROR: AddressSanitizer: heap-buffer-overflow x")
        outcome, detail = outcome_from_sandbox_info(info, returncode=1)
        assert outcome is WitnessOutcome.SANITIZER_REPORT
        assert detail["evidence_grade"] == "heuristic"
        assert detail["sanitizer_provenance"] == "stderr_match"

    def test_sanitizer_with_waitstatus_signal_grades_mechanical(self):
        # Genuine ASan under abort_on_error=1: report + SIGABRT via
        # the parent's own waitpid.
        info = _interpret(-6, stderr="ERROR: AddressSanitizer: heap-buffer-overflow x")
        outcome, detail = outcome_from_sandbox_info(info, returncode=-6)
        assert outcome is WitnessOutcome.SANITIZER_REPORT
        assert detail["evidence_grade"] == "mechanical"

    def test_legacy_info_without_stamps_grades_heuristic(self):
        # Tolerant reader: stored/older sandbox_info dicts carry no
        # provenance — they must never silently grade mechanical.
        outcome, detail = outcome_from_sandbox_info(
            {"crashed": True, "signal": "SIGSEGV", "signal_num": 11},
            returncode=139,
        )
        assert outcome is WitnessOutcome.EXIT_SIGNAL
        assert detail["evidence_grade"] == "heuristic"
        assert "signal_provenance" not in detail

    def test_no_obvious_effect_carries_no_grade(self):
        outcome, detail = outcome_from_sandbox_info({}, returncode=0)
        assert outcome is WitnessOutcome.NO_OBVIOUS_EFFECT
        assert "evidence_grade" not in detail

    def test_crashed_without_signal_grades_heuristic(self):
        outcome, detail = outcome_from_sandbox_info({"crashed": True})
        assert outcome is WitnessOutcome.EXIT_SIGNAL
        assert detail["evidence_grade"] == "heuristic"
