"""Saved per-finding validation failures remain distinct from no attempts."""
from copy import deepcopy
import json

import pytest

from core.json import load_json
from core.reporting.dataflow_summary import render_dataflow_validation_lines


@pytest.mark.parametrize("validated,cached,errors", [(0, 0, 2), (1, 0, 1), (0, 1, 1)],
                         ids=["all-errors", "mixed", "cached"])
def test_saved_dataflow_errors_are_visible_without_changing_record(tmp_path, validated, cached, errors):
    metrics = {"n_eligible": 2, "n_validated": validated, "n_cache_hits": cached,
               "n_errors": errors, "skipped_reason": ""}
    source = tmp_path / "orchestrated_report.json"
    source.write_text(json.dumps({"dataflow_validation": metrics}), encoding="utf-8")
    original_bytes = source.read_bytes()
    report = load_json(source)
    original = deepcopy(report)
    lines = render_dataflow_validation_lines(report["dataflow_validation"], indent="")
    assert f"Dataflow validation errors: {errors}" in lines
    if not validated and not cached:
        assert not any("Dataflow validated:" in line for line in lines)
    else:
        assert lines[0].startswith(f"Dataflow validated: {validated}")
        if cached:
            assert "+1 cache hit" in lines[0]
    assert not any("skipped" in line or "confirmed" in line.lower() for line in lines)
    assert source.read_bytes() == original_bytes and report == original


@pytest.mark.parametrize("errors", [0, False, True, None, -1, "2"])
def test_error_disclosure_requires_a_recorded_positive_integer(errors):
    metrics = {"n_validated": 0, "n_cache_hits": 0, "n_errors": errors}
    original = deepcopy(metrics)
    assert render_dataflow_validation_lines(metrics) == []
    assert metrics == original
