"""Typed version discriminators for labels and sanitizer evidence."""

import json

import pytest

from core.dataflow.label import GroundTruth, VERDICT_TRUE_POSITIVE
from core.dataflow.sanitizer_evidence import SanitizerEvidence


def test_value_schema_version_types():
    label = GroundTruth("fixture", VERDICT_TRUE_POSITIVE, "fixture", "fixture", "2026-11-13")
    for value in (label, SanitizerEvidence()):
        cls = type(value)
        record = value.to_dict()
        assert cls.from_json(json.dumps(record)) == value
        for version in (True, False, 1.0, "1", None, 2):
            with pytest.raises(ValueError, match="schema_version"):
                cls.from_json(json.dumps({**record, "schema_version": version}))
