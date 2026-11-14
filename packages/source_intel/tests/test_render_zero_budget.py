"""Prompt line budgets avoid unnecessary evidence rendering."""

import pytest

from packages.source_intel import render
from packages.source_intel.analyze import NullGuardEvidence, SourceIntelResult


def _result():
    return SourceIntelResult(null_guards=tuple(
        NullGuardEvidence(kind="bang", location=("owned.c", line)) for line in range(1, 4)
    ))


def test_zero_budget_does_not_render_observations(monkeypatch):
    calls = []
    monkeypatch.setattr(render, "_render_null_guard_line", lambda *args: calls.append(args) or "owned")
    assert render.derive_evidence_strings(_result(), max_lines=0) == []
    assert calls == []


def test_positive_budget_retains_first_line(monkeypatch):
    monkeypatch.setattr(render, "_render_null_guard_line", lambda record, style: f"owned:{record.location[1]}")
    assert render.derive_evidence_strings(_result(), max_lines=1) == ["owned:1"]


def test_zero_budget_still_validates_style():
    with pytest.raises(ValueError, match="unknown style"):
        render.derive_evidence_strings(_result(), max_lines=0, style="invalid")
