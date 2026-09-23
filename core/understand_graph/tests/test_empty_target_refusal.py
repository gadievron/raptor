"""Every findings-shaped ingest lane refuses an empty target.

A snapshot with ``target_path=''`` is unmatchable by every
target-scoped query (the inference helper's own docstring names the
harm) — the scan lane refused, but the codeql / validate / audit
siblings minted the unmatchable snapshot anyway.
"""

import json

import pytest

from core.json import save_json
from core.understand_graph import (
    ingest_audit_hypotheses,
    ingest_codeql_sarif,
    ingest_scan_findings,
    ingest_validation_outcomes,
)


def _bare_run_dir(tmp_path):
    """A run dir with NO inferable target (no metadata, no checklist)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return run_dir


def _assert_refused(run_dir, result, capsys):
    assert result is None
    graph = run_dir / "graph" / "raptor.graph.sqlite"
    assert not graph.exists(), (
        "an unmatchable target_path='' snapshot store was still created"
    )
    assert "skip" in capsys.readouterr().err.lower()


def test_scan_lane_refuses_empty_target(tmp_path, capsys):
    run_dir = _bare_run_dir(tmp_path)
    save_json(run_dir / "findings.json",
              [{"rule_id": "r", "file": "a.c", "function": "f"}])
    _assert_refused(run_dir, ingest_scan_findings(run_dir), capsys)


def test_codeql_lane_refuses_empty_target(tmp_path, capsys):
    run_dir = _bare_run_dir(tmp_path)
    save_json(run_dir / "results.sarif", {"runs": [{"results": [{
        "ruleId": "q",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.c"}}}],
    }]}]})
    _assert_refused(run_dir, ingest_codeql_sarif(run_dir), capsys)


def test_validate_lane_refuses_empty_target(tmp_path, capsys):
    run_dir = _bare_run_dir(tmp_path)
    save_json(run_dir / "validation-outcomes.json",
              [{"finding_id": "x", "status": "confirmed"}])
    _assert_refused(run_dir, ingest_validation_outcomes(run_dir), capsys)


def test_audit_lane_refuses_empty_target(tmp_path, capsys):
    from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso

    run_dir = _bare_run_dir(tmp_path)
    append_entry(run_dir, ReviewJournalEntry(
        ts=now_iso(), run_id="r1", file="a.c", function="f",
        verdict="suspicious", source_hash="ab" * 8,
        hypotheses=[{"mechanism": "m", "confidence": "high"}],
    ))
    _assert_refused(run_dir, ingest_audit_hypotheses(run_dir), capsys)


@pytest.mark.parametrize("lane", [
    ingest_scan_findings, ingest_codeql_sarif,
    ingest_validation_outcomes, ingest_audit_hypotheses,
])
def test_explicit_target_still_ingests(tmp_path, lane):
    """The refusal binds ONLY when no target resolves — explicit and
    metadata-inferred targets keep ingesting."""
    from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"target_path": str(target)}), encoding="utf-8")
    save_json(run_dir / "findings.json",
              [{"rule_id": "r", "file": "a.c", "function": "f"}])
    save_json(run_dir / "results.sarif", {"runs": [{"results": [{
        "ruleId": "q",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.c"}}}],
    }]}]})
    save_json(run_dir / "validation-outcomes.json",
              [{"finding_id": "x", "status": "confirmed"}])
    append_entry(run_dir, ReviewJournalEntry(
        ts=now_iso(), run_id="r1", file="a.c", function="f",
        verdict="suspicious", source_hash="ab" * 8,
        hypotheses=[{"mechanism": "m", "confidence": "high"}],
    ))
    assert lane(run_dir) is not None


def test_annotation_lane_refuses_empty_target(tmp_path, capsys):
    from core.understand_graph import ingest_annotations

    run_dir = tmp_path / "run"
    ann_dir = run_dir / "annotations"
    ann_dir.mkdir(parents=True)
    (ann_dir / "a.c.md").write_text(
        "## f\n<!-- status=clean source=human -->\nok\n", encoding="utf-8")
    _assert_refused(run_dir, ingest_annotations(run_dir, ""), capsys)
