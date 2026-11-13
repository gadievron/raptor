"""Ambiguous JSON fields cannot bypass strict value-model validation."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.sanitizer_evidence import SanitizerEvidence


def test_value_json_refuses_duplicate_fields_at_every_object_depth():
    step = Step("fixture.py", 1, 0, "value")
    values = (
        Finding("fixture", "fixture", "fixture", "fixture", step, step, raw={"key": "value"}),
        GroundTruth("fixture", "true_positive", "fixture", "fixture", "2026-11-13"),
        SanitizerEvidence(extraction_failures=("duplicate text is ordinary content",)),
    )
    for value in values:
        valid = value.to_json()
        assert type(value).from_json(valid) == value
        for earlier in ("0", "1"):
            ambiguous = '{"schema_version":' + earlier + ',' + valid.lstrip()[1:]
            with pytest.raises(ValueError, match="duplicate"):
                type(value).from_json(ambiguous)
    valid = values[0].to_json(indent=2)
    ambiguous_raw = valid.replace('"key": "value"', '"key": "discarded", "key": "value"')
    assert ambiguous_raw != valid
    with pytest.raises(ValueError, match="duplicate"):
        Finding.from_json(ambiguous_raw)
