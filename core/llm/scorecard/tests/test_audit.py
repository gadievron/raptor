"""Tests for ``core.llm.scorecard.audit`` — the Phase 1a sufficiency audit.

Seeds a scorecard via the public ``ModelScorecard.record_event`` API
(no JSON manipulation) so the audit walks data laid down through the
same path real runs use, and the v2 age-bucket flattening is exercised.

Four verdict regimes are covered: missing file, red, amber, green.
Each fixture is sized just past the relevant ratio boundary so the
verdict logic is not over-fitted to a single sample count.
"""
from __future__ import annotations

import json

import pytest

from core.llm.scorecard import EventType, ModelScorecard
from core.llm.scorecard import audit as audit_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _populate(sc: ModelScorecard, *, model: str, decision_class: str,
              event_type: str, n: int, correct_fraction: float = 1.0) -> None:
    """Record ``n`` events on one cell; ``correct_fraction`` chooses the
    correct / incorrect split."""
    n_correct = int(round(n * correct_fraction))
    for _ in range(n_correct):
        sc.record_event(decision_class, model, event_type, "correct")
    for _ in range(n - n_correct):
        sc.record_event(decision_class, model, event_type, "incorrect")


@pytest.fixture
def red_scorecard(tmp_path):
    """A scorecard with 10 multi_model_consensus cells; only 0 reach N=30,
    so the green/amber/red ratio is 0/10 = 0% — red verdict."""
    path = tmp_path / "red.json"
    sc = ModelScorecard(path)
    for i in range(10):
        _populate(sc, model=f"m{i}",
                  decision_class=f"codeql:py/rule-{i}",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=5)
    return path


@pytest.fixture
def amber_scorecard(tmp_path):
    """20 cells, 4 reach N=30 → 20% → amber (between 10% and 50%)."""
    path = tmp_path / "amber.json"
    sc = ModelScorecard(path)
    for i in range(4):
        _populate(sc, model=f"m{i}",
                  decision_class=f"codeql:py/rule-{i}",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=40)
    for i in range(16):
        _populate(sc, model=f"m{i + 4}",
                  decision_class=f"codeql:py/rule-{i + 4}",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=5)
    return path


@pytest.fixture
def green_scorecard(tmp_path):
    """10 cells, 6 reach N=30 → 60% → green."""
    path = tmp_path / "green.json"
    sc = ModelScorecard(path)
    for i in range(6):
        _populate(sc, model=f"m{i}",
                  decision_class=f"codeql:py/rule-{i}",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=40)
    for i in range(4):
        _populate(sc, model=f"m{i + 6}",
                  decision_class=f"codeql:py/rule-{i + 6}",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=5)
    return path


# ---------------------------------------------------------------------------
# Verdict-regime tests
# ---------------------------------------------------------------------------


def test_no_data_when_file_missing(tmp_path):
    missing = tmp_path / "nope.json"
    report = audit_mod.audit(missing)
    assert report.verdict == "no-data"
    assert report.total_models == 0
    assert report.total_cells == 0
    assert "not found" in report.verdict_reason


def test_red_verdict(red_scorecard):
    report = audit_mod.audit(red_scorecard)
    assert report.verdict == "red"
    assert report.total_models == 10
    assert report.total_decision_classes == 10
    # Primary event-type summary: 10 cells exist, none cross N=30.
    primary = next(
        s for s in report.event_type_summaries
        if s.event_type == EventType.MULTI_MODEL_CONSENSUS
    )
    assert primary.total_cells == 10
    assert primary.cells_at_thresholds[30] == 0


def test_amber_verdict(amber_scorecard):
    report = audit_mod.audit(amber_scorecard)
    assert report.verdict == "amber"
    primary = next(
        s for s in report.event_type_summaries
        if s.event_type == EventType.MULTI_MODEL_CONSENSUS
    )
    assert primary.cells_at_thresholds[30] == 4
    assert primary.total_cells == 20


def test_green_verdict(green_scorecard):
    report = audit_mod.audit(green_scorecard)
    assert report.verdict == "green"
    primary = next(
        s for s in report.event_type_summaries
        if s.event_type == EventType.MULTI_MODEL_CONSENSUS
    )
    assert primary.cells_at_thresholds[30] == 6


# ---------------------------------------------------------------------------
# Renderer + CLI tests
# ---------------------------------------------------------------------------


def test_markdown_renderer_includes_verdict(green_scorecard):
    report = audit_mod.audit(green_scorecard)
    md = audit_mod.render_markdown(report)
    assert "VERDICT" not in md  # not a header label
    assert "## Verdict — **GREEN**" in md
    assert "multi_model_consensus" in md
    # Per-decision-class table populated for green.
    assert "## Per-decision-class coverage" in md


def test_json_renderer_round_trips(amber_scorecard):
    report = audit_mod.audit(amber_scorecard)
    payload = json.loads(audit_mod.render_json(report))
    assert payload["verdict"] == "amber"
    assert payload["primary_event_type"] == EventType.MULTI_MODEL_CONSENSUS
    assert payload["total_models"] == 20


def test_cli_exit_codes(red_scorecard, amber_scorecard, green_scorecard, tmp_path, capsys):
    # red → 2, amber → 1, green → 0, no-data → 3
    assert audit_mod.main(["--path", str(red_scorecard), "--json"]) == 2
    assert audit_mod.main(["--path", str(amber_scorecard), "--json"]) == 1
    assert audit_mod.main(["--path", str(green_scorecard), "--json"]) == 0
    assert audit_mod.main(["--path", str(tmp_path / "missing.json"),
                           "--json"]) == 3


# ---------------------------------------------------------------------------
# Per-event-type and per-decision-class summaries
# ---------------------------------------------------------------------------


def test_event_type_breakdown_isolates_primary(tmp_path):
    """Populating a non-primary event type (cheap_short_circuit) must
    NOT influence the multi_model_consensus verdict — the audit
    partitions cleanly by event type."""
    path = tmp_path / "mixed.json"
    sc = ModelScorecard(path)
    # 100 cheap_short_circuit events → would be green on its own
    for i in range(10):
        _populate(sc, model=f"m{i}",
                  decision_class=f"codeql:py/rule-{i}",
                  event_type=EventType.CHEAP_SHORT_CIRCUIT, n=100)
    # No multi_model_consensus events
    report = audit_mod.audit(path)
    # Verdict is no-data because primary event type is empty.
    assert report.verdict == "no-data"
    cheap = next(
        s for s in report.event_type_summaries
        if s.event_type == EventType.CHEAP_SHORT_CIRCUIT
    )
    assert cheap.cells_at_thresholds[100] == 10
    primary = next(
        s for s in report.event_type_summaries
        if s.event_type == EventType.MULTI_MODEL_CONSENSUS
    )
    # ``total_cells`` is "cells with the event_type key", which is every
    # cell in the scorecard because ``_empty_events()`` seeds all known
    # types. The semantically meaningful "no data on this type" check is
    # ``cells_with_any_data``.
    assert primary.cells_with_any_data == 0
    assert primary.total_observations == 0


def test_decision_class_summary_counts_models_per_class(tmp_path):
    """Per-decision-class summary should count distinct models — D–S
    identifiability depends on this."""
    path = tmp_path / "multi-model.json"
    sc = ModelScorecard(path)
    # 3 models on the same decision_class
    for model in ("m1", "m2", "m3"):
        _populate(sc, model=model, decision_class="codeql:py/sql-injection",
                  event_type=EventType.MULTI_MODEL_CONSENSUS, n=50)
    report = audit_mod.audit(path)
    dcs = report.decision_class_summaries
    assert len(dcs) == 1
    assert dcs[0].distinct_models == 3
    assert dcs[0].median_obs_primary == 50.0
