"""Evidence JSON cannot invent source coordinates through coercion."""

import json

import pytest

from core.dataflow.sanitizer_evidence import (
    CandidateValidator,
    PROVENANCE_LLM,
    SEMANTICS_OTHER,
    StepAnnotation,
)


def test_evidence_coordinate_types():
    candidate = CandidateValidator("fixture", "fixture", SEMANTICS_OTHER, "Unverified fixture", 0.5, "fixture.py", 1, PROVENANCE_LLM)
    annotation = StepAnnotation(0)
    for value, field in ((candidate, "source_line"), (annotation, "step_index")):
        cls = type(value)
        record = value.to_dict()
        assert cls.from_dict(json.loads(json.dumps(record))) == value
        for invalid in (True, False, 1.5, "1", "invalid", None):
            with pytest.raises(ValueError, match=field):
                cls.from_dict(json.loads(json.dumps({**record, field: invalid})))
            with pytest.raises(ValueError, match=field):
                cls(**{**record, field: invalid})
    assert StepAnnotation.from_dict({}).step_index == 0
