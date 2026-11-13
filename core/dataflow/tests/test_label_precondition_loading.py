"""Optional lifecycle metadata distinguishes absence from malformed input."""

import json
from types import MappingProxyType

import pytest

from core.dataflow.label import GroundTruth, LifecyclePrecondition, VERDICT_TRUE_POSITIVE


def test_label_precondition_loading():
    label = GroundTruth("fixture", VERDICT_TRUE_POSITIVE, "fixture", "fixture", "2026-11-13")
    record = label.to_dict()
    assert GroundTruth.from_dict(record).lifecycle_precondition is None
    assert GroundTruth.from_dict({**record, "lifecycle_precondition": None}).lifecycle_precondition is None
    condition = LifecyclePrecondition("state", "initialized", False, "fixture")
    supplied = {**record, "lifecycle_precondition": condition.to_dict()}
    assert GroundTruth.from_json(json.dumps(supplied)).lifecycle_precondition == condition
    supplied["lifecycle_precondition"] = MappingProxyType(condition.to_dict())
    assert GroundTruth.from_dict(supplied).lifecycle_precondition == condition
    for malformed in (False, 0, "", []):
        with pytest.raises(ValueError, match="lifecycle_precondition"):
            GroundTruth.from_json(json.dumps({**record, "lifecycle_precondition": malformed}))
    with pytest.raises(KeyError):
        GroundTruth.from_dict({**record, "lifecycle_precondition": {}})
