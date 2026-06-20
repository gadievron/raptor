"""Tests for ``core.llm.multi_model.panel_log`` — Phase 2a loader.

Synthetic ``orchestrated_report.json`` fixtures covering the data
shapes the orchestrator actually emits:

* Multi-model finding with usable verdicts → records emitted.
* Single-model finding (no ``multi_model_analyses``) → skipped.
* Mixed valid / error entries within one finding → valid ones kept,
  finding kept iff ≥2 valid remain.
* Missing or non-boolean ``is_exploitable`` → record dropped.
* Missing ``rule_id`` → bucketed under ``agentic:unknown``.
* Multiple report files → records concatenated in path order.

No real orchestrator is invoked. We write JSON directly, mirroring the
on-disk shape documented in panel_log.py's module docstring.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.llm.multi_model.panel_log import (
    discover_reports,
    distinct_models,
    group_by_decision_class,
    group_by_finding,
    load_from_orchestrated_report,
    load_from_paths,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _finding(
    fid: str, rule_id: str, *,
    analyses: list,
    extra: dict = None,
) -> dict:
    base = {
        "finding_id": fid,
        "rule_id": rule_id,
        "multi_model_analyses": analyses,
    }
    if extra:
        base.update(extra)
    return base


def _entry(model: str, is_exploitable, **extra) -> dict:
    """One ``multi_model_analyses`` entry mirroring the
    ``FindingAdapter.extract_analysis_record`` shape."""
    out = {
        "model": model,
        "is_exploitable": is_exploitable,
        "exploitability_score": 0.5,
        "ruling": "verdict-text",
        "reasoning": "rationale",
    }
    out.update(extra)
    return out


def _write_report(path: Path, findings: list) -> Path:
    payload = {"results": findings}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Load: happy path
# ---------------------------------------------------------------------------


def test_two_model_finding_emits_two_records(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "py/sql-injection", analyses=[
            _entry("haiku", True),
            _entry("sonnet", False),
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert len(records) == 2
    assert {r.model for r in records} == {"haiku", "sonnet"}
    assert all(r.finding_id == "F1" for r in records)
    assert all(r.decision_class == "agentic:py/sql-injection" for r in records)
    assert any(r.verdict is True for r in records)
    assert any(r.verdict is False for r in records)


def test_three_model_finding_emits_three_records(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "py/sql-injection", analyses=[
            _entry("m1", True),
            _entry("m2", True),
            _entry("m3", False),
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert len(records) == 3
    assert {r.model for r in records} == {"m1", "m2", "m3"}


# ---------------------------------------------------------------------------
# Load: skip / drop rules
# ---------------------------------------------------------------------------


def test_single_model_finding_skipped(tmp_path):
    """Findings without ``multi_model_analyses`` (single-model runs)
    contribute nothing — D–S needs ≥2 panel members."""
    path = _write_report(tmp_path / "rep.json", [
        {"finding_id": "F1", "rule_id": "x", "is_exploitable": True},
    ])
    assert load_from_orchestrated_report(path) == []


def test_finding_with_one_valid_entry_skipped(tmp_path):
    """Even with ``multi_model_analyses`` present, if only one entry
    survives the validity filter the finding is dropped."""
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("m1", True),
            _entry("m2", "yes"),  # non-bool — dropped
        ]),
    ])
    assert load_from_orchestrated_report(path) == []


def test_error_entries_dropped(tmp_path):
    """``{"error": ...}`` entries are dropped; siblings survive."""
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("m1", True),
            _entry("m2", False),
            {"error": "rate limit", "model": "m3"},
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert len(records) == 2
    assert {r.model for r in records} == {"m1", "m2"}


def test_missing_model_dropped(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("m1", True),
            _entry("m2", False),
            {"is_exploitable": True, "ruling": "x"},  # no model
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert len(records) == 2


def test_none_is_exploitable_dropped(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("m1", True),
            _entry("m2", False),
            _entry("m3", None),  # explicit None — schema failure
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert len(records) == 2
    assert "m3" not in {r.model for r in records}


# ---------------------------------------------------------------------------
# Edge: decision_class derivation
# ---------------------------------------------------------------------------


def test_missing_rule_id_buckets_as_unknown(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        {
            "finding_id": "F1",
            "multi_model_analyses": [
                _entry("m1", True), _entry("m2", False),
            ],
        },
    ])
    records = load_from_orchestrated_report(path)
    assert all(r.decision_class == "agentic:unknown" for r in records)


def test_custom_decision_class_prefix(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("m1", True), _entry("m2", False),
        ]),
    ])
    records = load_from_orchestrated_report(
        path, decision_class_prefix="codeql",
    )
    assert all(r.decision_class == "codeql:x" for r in records)


# ---------------------------------------------------------------------------
# Edge: file IO
# ---------------------------------------------------------------------------


def test_missing_file_returns_empty(tmp_path):
    assert load_from_orchestrated_report(tmp_path / "nope.json") == []


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot parse"):
        load_from_orchestrated_report(path)


def test_results_not_a_list_returns_empty(tmp_path):
    path = tmp_path / "rep.json"
    path.write_text(json.dumps({"results": "broken"}), encoding="utf-8")
    assert load_from_orchestrated_report(path) == []


# ---------------------------------------------------------------------------
# Multi-file loading + discovery
# ---------------------------------------------------------------------------


def test_load_from_paths_concatenates_in_order(tmp_path):
    a = _write_report(tmp_path / "a.json", [
        _finding("F1", "x", analyses=[_entry("m1", True), _entry("m2", False)]),
    ])
    b = _write_report(tmp_path / "b.json", [
        _finding("F2", "y", analyses=[_entry("m1", False), _entry("m2", False)]),
    ])
    records = load_from_paths([a, b])
    finding_ids = [r.finding_id for r in records]
    # File a's records first, then file b's — load order is preserved.
    assert finding_ids[:2] == ["F1", "F1"]
    assert finding_ids[2:] == ["F2", "F2"]


def test_same_finding_across_runs_kept(tmp_path):
    """If the same finding_id appears in two reports (re-run), both
    panels are kept — they're independent observations."""
    a = _write_report(tmp_path / "a.json", [
        _finding("F1", "x", analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    b = _write_report(tmp_path / "b.json", [
        _finding("F1", "x", analyses=[_entry("m1", False), _entry("m2", False)]),
    ])
    records = load_from_paths([a, b])
    assert len(records) == 4
    grouped = group_by_finding(records)
    assert len(grouped["F1"]) == 4


def test_discover_reports_finds_nested(tmp_path):
    nested = tmp_path / "run1" / "subdir"
    nested.mkdir(parents=True)
    p1 = _write_report(nested / "orchestrated_report.json", [
        _finding("F1", "x", analyses=[_entry("m1", True), _entry("m2", False)]),
    ])
    p2 = _write_report(tmp_path / "run2" / "orchestrated_report.json", [
        _finding("F2", "y", analyses=[_entry("m1", False), _entry("m2", False)]),
    ]) if (tmp_path / "run2").mkdir() or True else None  # ensure dir
    # Re-do p2 cleanly now that the dir exists.
    p2 = _write_report(
        tmp_path / "run2" / "orchestrated_report.json",
        [_finding("F2", "y", analyses=[_entry("m1", False), _entry("m2", False)])],
    )
    found = discover_reports(tmp_path)
    assert p1 in found
    assert p2 in found
    # Sorted output is deterministic.
    assert found == sorted(found)


def test_discover_reports_missing_root_returns_empty(tmp_path):
    assert discover_reports(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# Groupers
# ---------------------------------------------------------------------------


def test_group_by_finding(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[_entry("m1", True), _entry("m2", False)]),
        _finding("F2", "y", analyses=[_entry("m1", False), _entry("m2", False)]),
    ])
    records = load_from_orchestrated_report(path)
    grouped = group_by_finding(records)
    assert set(grouped.keys()) == {"F1", "F2"}
    assert len(grouped["F1"]) == 2
    assert len(grouped["F2"]) == 2


def test_group_by_decision_class(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[_entry("m1", True), _entry("m2", False)]),
        _finding("F2", "y", analyses=[_entry("m1", False), _entry("m2", False)]),
        _finding("F3", "x", analyses=[_entry("m1", True), _entry("m2", True)]),
    ])
    records = load_from_orchestrated_report(path)
    grouped = group_by_decision_class(records)
    assert set(grouped.keys()) == {"agentic:x", "agentic:y"}
    assert len(grouped["agentic:x"]) == 4  # F1 + F3
    assert len(grouped["agentic:y"]) == 2  # F2


def test_distinct_models_sorted(tmp_path):
    path = _write_report(tmp_path / "rep.json", [
        _finding("F1", "x", analyses=[
            _entry("zeta", True), _entry("alpha", False), _entry("mu", True),
        ]),
    ])
    records = load_from_orchestrated_report(path)
    assert distinct_models(records) == ["alpha", "mu", "zeta"]
