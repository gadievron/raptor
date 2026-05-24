"""Tests for ``packages.zkpox.eligibility`` — witness → ZKPoX
candidacy classification (the free Tier 0/1 layer)."""

from __future__ import annotations

import sys
from pathlib import Path


# packages/zkpox/tests/test_eligibility.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness.types import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)
from packages.zkpox.eligibility import (  # noqa: E402
    is_zkpox_eligible,
    render_eligibility_summary,
    summarize_eligibility,
)


def _w(
    *,
    outcome: WitnessOutcome,
    target_binary_hash=None,
    target_source_hash=None,
    bytes_len=10,
    data: bytes = b"witness",
) -> Witness:
    return Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=bytes_len,
        source=WitnessSource.LLM_EMIT_RUN,
        observed_outcome=outcome,
        outcome_detail={},
        target_binary_hash=target_binary_hash,
        target_source_hash=target_source_hash,
    )


# ----------------------------------------------------------------------
# Provable-outcome gate
# ----------------------------------------------------------------------


def test_exit_signal_with_binary_is_eligible():
    w = _w(outcome=WitnessOutcome.EXIT_SIGNAL,
           target_binary_hash="a" * 64)
    v = is_zkpox_eligible(w)
    assert v.eligible is True
    assert v.max_tier_from_record == "0/1"


def test_sanitizer_report_with_source_is_eligible():
    w = _w(outcome=WitnessOutcome.SANITIZER_REPORT,
           target_source_hash="b" * 64)
    assert is_zkpox_eligible(w).eligible is True


def test_flag_captured_is_eligible():
    w = _w(outcome=WitnessOutcome.FLAG_CAPTURED,
           target_binary_hash="c" * 64)
    assert is_zkpox_eligible(w).eligible is True


def test_not_run_is_ineligible():
    w = _w(outcome=WitnessOutcome.NOT_RUN, target_binary_hash="a" * 64)
    v = is_zkpox_eligible(w)
    assert v.eligible is False
    assert "not provable" in v.reason


def test_no_obvious_effect_is_ineligible():
    w = _w(outcome=WitnessOutcome.NO_OBVIOUS_EFFECT,
           target_binary_hash="a" * 64)
    assert is_zkpox_eligible(w).eligible is False


def test_unknown_is_ineligible():
    w = _w(outcome=WitnessOutcome.UNKNOWN, target_binary_hash="a" * 64)
    assert is_zkpox_eligible(w).eligible is False


# ----------------------------------------------------------------------
# Target-artefact gate
# ----------------------------------------------------------------------


def test_provable_outcome_no_target_is_ineligible():
    """A real outcome but no target hash → nothing to prove
    against."""
    w = _w(outcome=WitnessOutcome.EXIT_SIGNAL)  # no target
    v = is_zkpox_eligible(w)
    assert v.eligible is False
    assert "no target artefact" in v.reason


def test_either_target_hash_suffices():
    w_bin = _w(outcome=WitnessOutcome.EXIT_SIGNAL,
               target_binary_hash="a" * 64)
    w_src = _w(outcome=WitnessOutcome.EXIT_SIGNAL,
               target_source_hash="b" * 64)
    assert is_zkpox_eligible(w_bin).eligible is True
    assert is_zkpox_eligible(w_src).eligible is True


# ----------------------------------------------------------------------
# Edge cases
# ----------------------------------------------------------------------


def test_zero_length_witness_eligible_but_noted():
    """Empty input that triggers a crash is valid but flagged for
    eyeballing."""
    w = _w(outcome=WitnessOutcome.EXIT_SIGNAL,
           target_binary_hash="a" * 64, bytes_len=0)
    v = is_zkpox_eligible(w)
    assert v.eligible is True
    assert "zero-length" in v.reason


# ----------------------------------------------------------------------
# Aggregate summary
# ----------------------------------------------------------------------


def test_summarize_counts():
    witnesses = [
        _w(outcome=WitnessOutcome.EXIT_SIGNAL,
           target_binary_hash="a" * 64, data=b"1"),
        _w(outcome=WitnessOutcome.SANITIZER_REPORT,
           target_binary_hash="a" * 64, data=b"2"),
        _w(outcome=WitnessOutcome.NOT_RUN,
           target_binary_hash="a" * 64, data=b"3"),
        _w(outcome=WitnessOutcome.NO_OBVIOUS_EFFECT,
           target_binary_hash="a" * 64, data=b"4"),
        _w(outcome=WitnessOutcome.EXIT_SIGNAL, data=b"5"),  # no target
    ]
    s = summarize_eligibility(witnesses)
    assert s["total"] == 5
    assert s["eligible"] == 2
    assert s["ineligible"] == 3
    assert s["by_reason"]["provable"] == 2
    assert s["by_reason"]["outcome_not_provable"] == 2
    assert s["by_reason"]["no_target"] == 1
    assert len(s["eligible_hashes"]) == 2


def test_summarize_empty():
    s = summarize_eligibility([])
    assert s["total"] == 0
    assert s["eligible"] == 0
    assert s["eligible_hashes"] == []


# ----------------------------------------------------------------------
# Render
# ----------------------------------------------------------------------


def test_render_none_when_empty():
    assert render_eligibility_summary([]) is None


def test_render_shows_ratio_and_breakdown():
    witnesses = [
        _w(outcome=WitnessOutcome.EXIT_SIGNAL,
           target_binary_hash="a" * 64, data=b"1"),
        _w(outcome=WitnessOutcome.NOT_RUN,
           target_binary_hash="a" * 64, data=b"2"),
    ]
    out = render_eligibility_summary(witnesses)
    assert "ZKPoX-eligible witnesses: 1 / 2" in out
    assert "provable: 1" in out
    assert "outcome_not_provable: 1" in out
