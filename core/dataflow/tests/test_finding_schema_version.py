"""Finding JSON requires an integer schema-version discriminator."""

import json

import pytest

from core.dataflow import SCHEMA_VERSION, Finding, Step


def test_finding_schema_version_type():
    step = Step("fixture.py", 1, 0, "value")
    finding = Finding("fixture", "fixture", "fixture", "fixture", step, step)
    record = finding.to_dict()
    assert Finding.from_json(json.dumps(record)) == finding
    for version in (True, False, 1.0, "1", None, SCHEMA_VERSION + 1):
        malformed = {**record, "schema_version": version}
        with pytest.raises(ValueError, match="schema_version"):
            Finding.from_json(json.dumps(malformed))
