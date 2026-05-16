"""Tests for ``core.dataflow.finding_diff``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow.finding_diff import (
    FindingDiff,
    _sarif_finding_ids,
    diff_sarif_data,
    diff_sarif_files,
)


# ---------------------------------------------------------------------
# SARIF fixtures
# ---------------------------------------------------------------------


def _sarif_step(uri: str, line: int, snippet: str = "x", label: str = "step") -> dict:
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {
                    "startLine": line,
                    "startColumn": 1,
                    "snippet": {"text": snippet},
                },
            },
            "message": {"text": label},
        }
    }


def _sarif_result(
    rule_id: str = "py/sql-injection",
    source_uri: str = "app.py",
    source_line: int = 1,
    sink_uri: str = "db.py",
    sink_line: int = 5,
) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": "test"},
        "codeFlows": [{
            "threadFlows": [{
                "locations": [
                    _sarif_step(source_uri, source_line, "src", "source"),
                    _sarif_step(sink_uri, sink_line, "snk", "sink"),
                ]
            }]
        }]
    }


def _sarif_doc(*results: dict) -> dict:
    return {"runs": [{"results": list(results)}]}


# ---------------------------------------------------------------------
# Empty / degenerate cases
# ---------------------------------------------------------------------


def test_both_empty_yields_empty_diff():
    d = diff_sarif_data(_sarif_doc(), _sarif_doc())
    assert d.suppressed_ids == ()
    assert d.still_flagged_ids == ()
    assert d.new_ids == ()
    assert d.baseline_count == 0
    assert d.augmented_count == 0
    assert d.suppression_rate == 0.0


def test_missing_runs_key_handled():
    d = diff_sarif_data({}, {})
    assert d.baseline_count == 0


def test_null_runs_handled():
    d = diff_sarif_data({"runs": None}, {"runs": None})
    assert d.baseline_count == 0


def test_runs_with_no_results_key_handled():
    d = diff_sarif_data({"runs": [{}]}, {"runs": [{}]})
    assert d.baseline_count == 0


# ---------------------------------------------------------------------
# Suppression detection
# ---------------------------------------------------------------------


def test_finding_in_baseline_not_in_augmented_is_suppressed():
    baseline = _sarif_doc(_sarif_result())
    augmented = _sarif_doc()
    d = diff_sarif_data(baseline, augmented)
    assert len(d.suppressed_ids) == 1
    assert d.still_flagged_ids == ()
    assert d.new_ids == ()
    assert d.baseline_count == 1
    assert d.augmented_count == 0
    assert d.suppression_rate == 1.0


def test_finding_in_both_is_still_flagged():
    r = _sarif_result()
    d = diff_sarif_data(_sarif_doc(r), _sarif_doc(r))
    assert d.suppressed_ids == ()
    assert len(d.still_flagged_ids) == 1
    assert d.suppression_rate == 0.0


def test_finding_only_in_augmented_is_new():
    """A finding appearing only in the augmented run shouldn't
    happen — sanitizer models should suppress, not introduce. Track
    it as a regression signal."""
    augmented = _sarif_doc(_sarif_result())
    d = diff_sarif_data(_sarif_doc(), augmented)
    assert d.suppressed_ids == ()
    assert d.still_flagged_ids == ()
    assert len(d.new_ids) == 1


# ---------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------


def test_partial_suppression_yields_correct_rate():
    """3 baseline findings, augmented suppresses 2 → rate 2/3."""
    findings = [
        _sarif_result(source_uri=f"f{i}.py", source_line=i + 1)
        for i in range(3)
    ]
    baseline = _sarif_doc(*findings)
    augmented = _sarif_doc(findings[0])  # only first survives augmented run
    d = diff_sarif_data(baseline, augmented)
    assert d.baseline_count == 3
    assert d.augmented_count == 1
    assert len(d.suppressed_ids) == 2
    assert len(d.still_flagged_ids) == 1
    assert d.suppression_rate == pytest.approx(2 / 3)


def test_different_findings_with_same_source_but_different_sink():
    """Two findings sharing source but different sinks produce
    different finding_ids — they're separate paths."""
    a = _sarif_result(sink_line=5)
    b = _sarif_result(sink_line=10)
    d = diff_sarif_data(_sarif_doc(a, b), _sarif_doc(a))
    assert len(d.suppressed_ids) == 1
    assert len(d.still_flagged_ids) == 1


def test_different_rule_ids_count_as_different_findings():
    """Same code path flagged under two different rule_ids = two
    findings. Sanitizer models target specific kinds, so a model
    that covers sql-injection won't suppress a command-injection
    flag on the same code."""
    a = _sarif_result(rule_id="py/sql-injection")
    b = _sarif_result(rule_id="py/command-injection")
    d = diff_sarif_data(_sarif_doc(a, b), _sarif_doc(b))
    assert len(d.suppressed_ids) == 1
    assert len(d.still_flagged_ids) == 1


def test_duplicate_results_in_same_sarif_collapse_to_one_id():
    """SARIF may emit the same finding twice (e.g., one per
    code-flow variant). Set-based identity collapses them."""
    r = _sarif_result()
    baseline = _sarif_doc(r, r, r)
    d = diff_sarif_data(baseline, _sarif_doc())
    assert d.baseline_count == 1
    assert len(d.suppressed_ids) == 1


# ---------------------------------------------------------------------
# Non-dataflow results filtered out
# ---------------------------------------------------------------------


def test_non_dataflow_results_excluded_from_diff():
    """A SARIF result without ``codeFlows`` is a rule alert, not a
    dataflow path — outside the scope of sanitizer-modeling
    measurement."""
    non_dataflow = {"ruleId": "py/something", "message": {"text": "alert"}}
    baseline = _sarif_doc(non_dataflow, _sarif_result())
    augmented = _sarif_doc(_sarif_result())
    d = diff_sarif_data(baseline, augmented)
    # Only the dataflow result counts.
    assert d.baseline_count == 1
    assert d.augmented_count == 1


def test_malformed_result_filtered_out():
    """A SARIF result that looks like a dataflow but has an empty
    URI / line=0 will fail Step validation in from_sarif_result;
    treat that as not-a-finding rather than raising."""
    bad = {
        "ruleId": "x",
        "message": {"text": "y"},
        "codeFlows": [{"threadFlows": [{"locations": [
            _sarif_step("", 0, "x", "source"),  # empty URI
            _sarif_step("b.py", 1, "y", "sink"),
        ]}]}],
    }
    d = diff_sarif_data(_sarif_doc(bad), _sarif_doc())
    # Bad result doesn't contribute to baseline.
    assert d.baseline_count == 0


# ---------------------------------------------------------------------
# File-based wrapper
# ---------------------------------------------------------------------


def test_diff_sarif_files_reads_both_files(tmp_path: Path):
    baseline_path = tmp_path / "baseline.sarif"
    augmented_path = tmp_path / "augmented.sarif"
    baseline_path.write_text(json.dumps(_sarif_doc(_sarif_result())))
    augmented_path.write_text(json.dumps(_sarif_doc()))
    d = diff_sarif_files(baseline_path, augmented_path)
    assert d.suppression_rate == 1.0


# ---------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------


def test_to_dict_records_all_fields():
    d = FindingDiff(
        suppressed_ids=("a", "b"),
        still_flagged_ids=("c",),
        new_ids=(),
        baseline_count=3,
        augmented_count=1,
    )
    blob = d.to_dict()
    assert blob["suppressed_ids"] == ["a", "b"]
    assert blob["still_flagged_ids"] == ["c"]
    assert blob["new_ids"] == []
    assert blob["baseline_count"] == 3
    assert blob["augmented_count"] == 1
    assert blob["suppression_rate"] == pytest.approx(2 / 3)


def test_diff_ids_are_sorted_for_determinism():
    """Outputs sorted so downstream csv/json reports are stable —
    important for snapshot tests + commit-friendly metric files."""
    findings = [
        _sarif_result(source_uri=u) for u in ("z.py", "a.py", "m.py")
    ]
    d = diff_sarif_data(_sarif_doc(*findings), _sarif_doc())
    assert list(d.suppressed_ids) == sorted(d.suppressed_ids)


# ---------------------------------------------------------------------
# Helper: _sarif_finding_ids
# ---------------------------------------------------------------------


def test_finding_ids_extracted_via_stable_adapter_id():
    """Two identical SARIF results parsed independently should
    produce the same id — that's the foundation of the diff."""
    r = _sarif_result()
    ids_a = _sarif_finding_ids(_sarif_doc(r))
    ids_b = _sarif_finding_ids(_sarif_doc(r))
    assert ids_a == ids_b
    assert len(ids_a) == 1
