"""Optional lifecycle metadata refuses malformed types at construction."""

import pytest

from core.dataflow.label import GroundTruth, LifecyclePrecondition


def test_label_optional_metadata_types():
    def label(condition):
        return GroundTruth("fixture", "true_positive", "fixture", "fixture", "2026-11-13",
                           lifecycle_precondition=condition)

    for invalid in (False, 0, [], {}, "note"):
        with pytest.raises(ValueError, match="lifecycle_precondition"):
            label(invalid)
    for invalid in (False, 0, [], {}):
        with pytest.raises(ValueError, match="notes"):
            LifecyclePrecondition("state", "initialized", False, invalid)
        with pytest.raises(ValueError, match="notes"):
            LifecyclePrecondition.from_dict({"field": "state", "write_site_guard": "initialized",
                                            "read_site_lacks_guard": False, "notes": invalid})
    for note in (None, "", "fixture"):
        condition = LifecyclePrecondition("state", "initialized", False, note)
        original = label(condition)
        restored = GroundTruth.from_json(original.to_json())
        assert restored == original
        assert restored.lifecycle_precondition.read_site_lacks_guard is False
        assert restored.lifecycle_precondition.notes == note
    assert "lifecycle_precondition" not in label(None).to_dict()
