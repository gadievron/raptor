"""Source coordinates retain their integer schema across JSON input."""

import json

import pytest

from core.dataflow import Step


def test_step_coordinate_schema():
    valid = {"file_path": "fixture.py", "line": 1, "column": 0, "snippet": "value"}
    assert Step.from_dict(json.loads(json.dumps(valid))).to_dict()["line"] == 1
    assert Step.from_dict(valid).column == 0
    for field in ("line", "column"):
        for value in (True, False, 1.5, "2", None):
            record = {**valid, field: value}
            with pytest.raises(ValueError, match=field):
                Step.from_dict(json.loads(json.dumps(record)))
