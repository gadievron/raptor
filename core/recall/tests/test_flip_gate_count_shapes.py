"""Recall gate arithmetic requires actual integer measurement counts."""
from copy import deepcopy

import pytest

from core.recall import flip_gate as gate
from core.recall.score import LABEL_CLASS


def owned_pair():
    baseline = {
        "label_class": LABEL_CLASS, "manifest": "owned", "language": "c",
        "profile": "agentic", "pinned_sha": "a" * 40,
        "expected_total": 1, "found_total": 0,
        "missed": [{"id": "owned-label"}], "clean_region_fp_count": 0,
        "clean_region_total": 1, "label_digest": "d" * 64,
    }
    candidate = deepcopy(baseline)
    candidate.update(profile="agentic-taint", found_total=1, missed=[])
    return {"owned": baseline}, {"owned": candidate}


@pytest.fixture(autouse=True)
def no_report_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object gate check attempted report loading")
    monkeypatch.setattr(gate, "load_json", forbidden)


@pytest.mark.parametrize("side", ["baseline", "candidate"])
@pytest.mark.parametrize("field", ["expected_total", "found_total"])
def test_boolean_counts_are_refused(side, field):
    base, cand = owned_pair()
    report = (base if side == "baseline" else cand)["owned"]
    report[field] = bool(report[field])
    before = deepcopy((base, cand))
    with pytest.raises(gate.FlipGateError, match=field):
        gate.evaluate_flip_gate(base, cand)
    assert (base, cand) == before


def test_real_integer_counts_keep_successful_uplift():
    base, cand = owned_pair()
    before = deepcopy((base, cand))
    assert gate.evaluate_flip_gate(base, cand)["passed"]
    assert (base, cand) == before


@pytest.mark.parametrize("field", ["expected_total", "found_total"])
def test_malformed_integer_shaped_reports_reach_refusal(field):
    base, _ = owned_pair()
    report = base["owned"]
    report[field] = bool(report[field])
    # Keep recognizable malformed reports in directory comparisons so the
    # guard refuses them rather than silently discarding a measurement.
    assert gate._is_recall_report(report)
