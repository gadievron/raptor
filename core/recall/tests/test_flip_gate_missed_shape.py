"""Malformed missed records refuse before displacement evaluation."""
from copy import deepcopy

import pytest

from core.recall import flip_gate as gate


def owned_pair():
    baseline = {"profile": "agentic", "pinned_sha": "a" * 40,
                "language": "c", "expected_total": 2, "found_total": 1,
                "missed": [{"id": "owned-label"}],
                "clean_region_fp_count": 0, "clean_region_total": 1,
                "label_digest": "d" * 64}
    candidate = deepcopy(baseline)
    candidate.update(profile="agentic-taint", found_total=2, missed=[])
    return {"owned": baseline}, {"owned": candidate}


@pytest.fixture(autouse=True)
def no_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted report loading")
    monkeypatch.setattr(gate, "load_json", forbidden)


@pytest.mark.parametrize("record", [None, [], "owned-label", 1, True])
@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_non_object_missed_record_refuses(record, side):
    base, cand = owned_pair()
    report = (base if side == "baseline" else cand)["owned"]
    report.update(found_total=1, missed=[record])
    before = deepcopy((base, cand))
    with pytest.raises(gate.FlipGateError, match="missed"):
        gate.evaluate_flip_gate(base, cand)
    assert (base, cand) == before


def test_object_missed_records_keep_valid_uplift():
    base, cand = owned_pair()
    assert gate.evaluate_flip_gate(base, cand)["passed"]


def test_object_missed_records_keep_displacement_check():
    base, cand = owned_pair()
    cand["owned"].update(found_total=1, missed=[{"id": "different-label"}])
    result = gate.evaluate_flip_gate(base, cand)
    assert not result["checks"]["no_displacement"]["passed"]
