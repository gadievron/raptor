"""Tests for ``core.witness.outcome_from_sandbox_info``.

These pin the precedence semantics (sanitizer > signal > blocked-only >
clean-exit) and the detail-extraction shape (absent → omitted).
"""

from __future__ import annotations

import sys
from pathlib import Path


# core/witness/tests/test_sandbox_outcome.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    sys.path.insert(0, str(REPO))

from core.witness import (  # noqa: E402
    WitnessOutcome,
    outcome_from_sandbox_info,
)


# ----------------------------------------------------------------------
# Crash signal — EXIT_SIGNAL
# ----------------------------------------------------------------------


def test_sigsegv_crash_to_exit_signal():
    info = {
        "signal": "SIGSEGV",
        "signal_num": 11,
        "crashed": True,
        "evidence": "Process crashed with SIGSEGV",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["signal"] == "SIGSEGV"
    assert detail["signal_num"] == 11
    assert detail["crashed"] is True
    assert detail["evidence"] == "Process crashed with SIGSEGV"


def test_sigabrt_crash_to_exit_signal():
    info = {"signal": "SIGABRT", "signal_num": 6, "crashed": True}
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["signal"] == "SIGABRT"


def test_returncode_threads_into_detail():
    info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
    _, detail = outcome_from_sandbox_info(info, returncode=-11)
    assert detail["returncode"] == -11


# ----------------------------------------------------------------------
# Sanitizer — SANITIZER_REPORT
# ----------------------------------------------------------------------


def test_asan_with_crash_to_sanitizer_report():
    """Sanitizer takes precedence over signal — even when the
    process died, the SANITIZER_REPORT outcome carries the
    more specific bug-class signal."""
    info = {
        "signal": "SIGABRT",
        "signal_num": 6,
        "crashed": True,
        "sanitizer": "asan",
        "evidence": "AddressSanitizer: heap-buffer-overflow",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.SANITIZER_REPORT
    assert detail["sanitizer"] == "asan"
    assert detail["crashed"] is True
    assert detail["signal"] == "SIGABRT"
    assert "heap-buffer-overflow" in detail["evidence"]


def test_asan_without_crash_still_sanitizer_report():
    """ASan with ``halt_on_error=0`` reports without aborting.
    The outcome must still be SANITIZER_REPORT — the bug was
    observed even though exit was clean."""
    info = {
        "sanitizer": "asan",
        "evidence": "AddressSanitizer: stack-use-after-return",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.SANITIZER_REPORT
    assert detail["sanitizer"] == "asan"
    assert "crashed" not in detail


def test_ubsan_to_sanitizer_report():
    info = {"sanitizer": "ubsan", "evidence": "UBSAN triggered"}
    outcome, _ = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.SANITIZER_REPORT


def test_msan_to_sanitizer_report():
    info = {"sanitizer": "msan", "crashed": True}
    outcome, _ = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.SANITIZER_REPORT


def test_tsan_to_sanitizer_report():
    info = {"sanitizer": "tsan"}
    outcome, _ = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.SANITIZER_REPORT


# ----------------------------------------------------------------------
# Resource / seccomp — still EXIT_SIGNAL with disambiguating flags
# ----------------------------------------------------------------------


def test_sigxcpu_resource_exceeded():
    info = {
        "signal": "SIGXCPU",
        "signal_num": 24,
        "resource_exceeded": True,
        "evidence": "Process killed by SIGXCPU — CPU time exhausted",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["resource_exceeded"] is True
    assert detail["signal"] == "SIGXCPU"


def test_sigsys_seccomp_killed():
    info = {
        "signal": "SIGSYS",
        "signal_num": 31,
        "seccomp_killed": True,
        "evidence": "Process killed by SIGSYS — seccomp blocked a syscall",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["seccomp_killed"] is True


# ----------------------------------------------------------------------
# `crashed` without explicit signal (defensive — observe could add this)
# ----------------------------------------------------------------------


def test_crashed_without_signal_to_exit_signal():
    info = {"crashed": True, "evidence": "abnormal exit"}
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["crashed"] is True


# ----------------------------------------------------------------------
# Sandbox enforcement only — NO_OBVIOUS_EFFECT
# ----------------------------------------------------------------------


def test_blocked_only_to_no_obvious_effect():
    """Sandbox stopped the process from doing something else; no
    target-bug evidence. ``blocked`` lands in detail so operators
    can see what was attempted."""
    info = {
        "blocked": [
            {"kind": "network", "detail": "Connection refused"},
        ],
        "evidence": "Network connection blocked",
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.NO_OBVIOUS_EFFECT
    assert detail["blocked"][0]["kind"] == "network"


def test_blocked_with_signal_keeps_exit_signal():
    """The process died by signal — that's the primary outcome.
    blocked still rides along in detail for diagnosis."""
    info = {
        "signal": "SIGSEGV",
        "signal_num": 11,
        "crashed": True,
        "blocked": [{"kind": "write", "detail": "Read-only file system"}],
    }
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.EXIT_SIGNAL
    assert detail["blocked"][0]["kind"] == "write"


# ----------------------------------------------------------------------
# Clean exit / nothing observed
# ----------------------------------------------------------------------


def test_empty_sandbox_info_to_no_obvious_effect():
    outcome, detail = outcome_from_sandbox_info({})
    assert outcome is WitnessOutcome.NO_OBVIOUS_EFFECT
    assert detail == {}


def test_none_sandbox_info_to_no_obvious_effect():
    """The sandbox attached no info (e.g. unsandboxed fallback).
    Defensive default: nothing observed, no detail to surface."""
    outcome, detail = outcome_from_sandbox_info(None)
    assert outcome is WitnessOutcome.NO_OBVIOUS_EFFECT
    assert detail == {}


def test_clean_exit_with_evidence_still_no_obvious_effect():
    """``crashed=False`` with some evidence text doesn't escalate
    — the bug-class signals are what trigger non-default outcomes."""
    info = {"crashed": False}
    outcome, detail = outcome_from_sandbox_info(info)
    assert outcome is WitnessOutcome.NO_OBVIOUS_EFFECT
    assert detail == {}


# ----------------------------------------------------------------------
# Detail-shape invariants
# ----------------------------------------------------------------------


def test_absent_fields_are_omitted_not_nulled():
    """Convention: absent in input → absent in detail (no None
    values cluttering downstream consumers)."""
    info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
    _, detail = outcome_from_sandbox_info(info)
    for k in ("sanitizer", "blocked", "resource_exceeded",
              "seccomp_killed", "evidence"):
        assert k not in detail


def test_blocked_list_is_copied_not_aliased():
    """Mutating the returned detail must not back-mutate
    sandbox_info — safer for callers that reuse the dict."""
    blocked = [{"kind": "network"}]
    info = {"blocked": blocked}
    _, detail = outcome_from_sandbox_info(info)
    detail["blocked"].append({"kind": "write"})
    assert len(blocked) == 1


# ----------------------------------------------------------------------
# Floor-refusal chokepoint — refusal_detail / refusal_summary_line
# ----------------------------------------------------------------------


def _floor_error(remedies: str = "install uidmap; re-run"):
    from core.sandbox.errors import SandboxFloorError
    from core.sandbox.tiers import ContainmentTier

    return SandboxFloorError(
        "sandbox containment floor violated",
        remedies,
        achievable=ContainmentTier.LANDLOCK_ONLY,
        floor=ContainmentTier.MOUNT_NS,
        setup_category="U",
    )


def test_refusal_detail_maps_floor_error_to_canonical_payload():
    from core.witness import UNVERIFIABLE_ENVIRONMENT, refusal_detail

    detail = refusal_detail(_floor_error())
    assert detail == {
        "status": UNVERIFIABLE_ENVIRONMENT,
        "floor": "mount-ns",
        "achievable": "landlock",
        "remedies": "install uidmap; re-run",
        "failure_mode": "constrained_by_env",
    }


def test_refusal_detail_payload_is_flat_json_safe_strings():
    import json

    from core.witness import refusal_detail

    detail = refusal_detail(_floor_error())
    assert all(isinstance(v, str) for v in detail.values())
    json.dumps(detail)  # must not raise


def test_refusal_detail_failure_mode_matches_labeled_attempts_enum():
    """The payload's failure_mode string must stay in lockstep with
    FailureMode.CONSTRAINED_BY_ENV so attempt-record writers can pass
    it through verbatim."""
    from core.labeled_attempts.types import FailureMode
    from core.witness import refusal_detail

    detail = refusal_detail(_floor_error())
    assert detail["failure_mode"] == FailureMode.CONSTRAINED_BY_ENV.value


def test_refusal_detail_none_for_plain_setup_error():
    """Only the typed floor subtype maps — a generic SandboxSetupError
    keeps its existing fail-loud flight path (caller re-raises)."""
    from core.sandbox.errors import SandboxSetupError
    from core.witness import refusal_detail

    assert refusal_detail(SandboxSetupError("engage failed", "fix")) is None


def test_refusal_detail_none_for_ordinary_exceptions():
    from core.witness import refusal_detail

    assert refusal_detail(ValueError("nope")) is None
    assert refusal_detail(OSError("nope")) is None


def test_refusal_detail_empty_remedies_stay_empty_string():
    from core.witness import refusal_detail

    detail = refusal_detail(_floor_error(remedies=""))
    assert detail["remedies"] == ""


def test_refusal_detail_unknown_tier_falls_back_to_str():
    """A floor error carrying a non-lattice value (defensive: a test
    double or a future field widening) must not crash the mapping."""
    from core.sandbox.errors import SandboxFloorError
    from core.witness import refusal_detail

    exc = SandboxFloorError(
        "violated", "fix", achievable="weird", floor="weirder",
    )
    detail = refusal_detail(exc)
    assert detail["achievable"] == "weird"
    assert detail["floor"] == "weirder"


def test_refusal_summary_line_shape():
    from core.witness import refusal_detail, refusal_summary_line

    line = refusal_summary_line(refusal_detail(_floor_error()))
    assert line == (
        "1 execution(s) refused: environment cannot meet the "
        "containment floor (mount-ns required, landlock achievable) "
        "— remedies: install uidmap; re-run"
    )


def test_refusal_summary_line_empty_remedies_named_honestly():
    from core.witness import refusal_summary_line

    line = refusal_summary_line({"floor": "mount-ns", "achievable": "none",
                                 "remedies": ""})
    assert "(none recorded)" in line
