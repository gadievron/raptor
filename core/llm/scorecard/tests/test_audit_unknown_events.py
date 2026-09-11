"""Audit coverage for sidecar event types the stats view cannot carry.

``ModelScorecard.get_stats()`` materialises only ``ALL_EVENT_TYPES``,
so an event type written by a newer schema never reaches the stats
walk — the audit must surface it from the raw sidecar instead of
silently dropping it.
"""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard import EventType, ModelScorecard
from core.llm.scorecard.audit import audit


def _seed(tmp_path: Path, *, extra_events: dict | None = None) -> Path:
    """One known-type cell via the public API; ``extra_events`` are
    merged into the same cell through the scorecard's own locked
    write path — the same way a newer producer would lay them down
    (keeps the integrity stamp valid)."""
    path = tmp_path / "llm_scorecard.json"
    sc = ModelScorecard(path)
    sc.record_events([
        {"decision_class": "audit:hypothesis", "model": "model-a",
         "event_type": EventType.MULTI_MODEL_CONSENSUS,
         "outcome": outcome}
        for outcome in (["correct"] * 3 + ["incorrect"])
    ])
    if extra_events:
        with sc._with_lock(write=True) as data:
            cell = data["models"]["model-a"]["audit:hypothesis"]
            cell["events"].update(extra_events)
    return path


def test_unknown_event_type_surfaces_in_report(tmp_path):
    path = _seed(tmp_path, extra_events={
        "novel_future_signal": {
            "2026-01": {"correct": 30, "incorrect": 5},
        },
    })
    report = audit(path)
    by_type = {s.event_type: s for s in report.event_type_summaries}

    novel = by_type["novel_future_signal"]
    assert novel.total_cells == 1
    assert novel.cells_with_any_data == 1
    assert novel.total_observations == 35
    assert novel.cells_at_thresholds[30] == 1


def test_known_event_types_not_double_counted(tmp_path):
    path = _seed(tmp_path)
    report = audit(path)
    by_type = {s.event_type: s for s in report.event_type_summaries}

    known = by_type[EventType.MULTI_MODEL_CONSENSUS]
    # One cell in the sidecar — the raw walk must not add a second.
    assert known.total_cells == 1
    assert known.total_observations == 4


def test_flat_v1_bucket_shape_counted(tmp_path):
    path = _seed(tmp_path, extra_events={
        "novel_future_signal": {"correct": 2, "incorrect": 1},
    })
    report = audit(path)
    by_type = {s.event_type: s for s in report.event_type_summaries}
    assert by_type["novel_future_signal"].total_observations == 3
