"""Tests for the confidence aggregator — design's strict invariant:
"confidence capped at strongest individual signal; no multiplicative
inflation"."""

from __future__ import annotations

from packages.source_intel.render import (
    Mitigation,
    aggregate_confidence,
)


def _mit(name: str, confidence: str) -> Mitigation:
    return Mitigation(
        name=name, axis="axis_x",
        confidence=confidence, detail="x",
    )


def test_empty_returns_none():
    assert aggregate_confidence([]) == "none"


def test_single_high():
    assert aggregate_confidence([_mit("a", "high")]) == "high"


def test_single_medium():
    assert aggregate_confidence([_mit("a", "medium")]) == "medium"


def test_single_low():
    assert aggregate_confidence([_mit("a", "low")]) == "low"


def test_two_mediums_do_not_inflate_to_high():
    """Strict invariant: confidence capped at strongest individual
    signal — TWO mediums DO NOT combine into high."""
    result = aggregate_confidence([
        _mit("a", "medium"), _mit("b", "medium"),
    ])
    assert result == "medium"


def test_five_lows_do_not_inflate():
    """Even five lows shouldn't combine to medium or high."""
    result = aggregate_confidence(
        [_mit(f"m{i}", "low") for i in range(5)]
    )
    assert result == "low"


def test_strongest_wins():
    """Mixed bag — strongest (high) wins."""
    result = aggregate_confidence([
        _mit("a", "low"), _mit("b", "medium"),
        _mit("c", "high"), _mit("d", "low"),
    ])
    assert result == "high"


def test_unknown_confidence_treated_as_zero():
    """A bogus confidence string shouldn't crash; treat as 0."""
    bogus = Mitigation(
        name="x", axis="axis_x",
        confidence="ultra", detail="",
    )
    assert aggregate_confidence([bogus]) == "none"
    assert aggregate_confidence([bogus, _mit("y", "low")]) == "low"
