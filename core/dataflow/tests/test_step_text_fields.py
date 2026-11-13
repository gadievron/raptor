"""Step text fields cannot contain mutable JSON containers."""

import json

import pytest

from core.dataflow import Step


def test_step_text_fields_reject_nontext():
    record = {"file_path": "fixture.py", "line": 1, "column": 0, "snippet": "", "label": None}
    for snippet, label in (("", None), ("value = 'é'\n", "source"), ("value", "producer-specific label"), ("value", "")):
        valid = {**record, "snippet": snippet, "label": label}
        assert Step.from_dict(json.loads(json.dumps(valid))).to_dict() == valid
    for field, values in (("snippet", ([], {}, None, True, 1)), ("label", ([], {}, False, 1))):
        for value in values:
            invalid = {**record, field: value}
            with pytest.raises(ValueError, match=field):
                Step.from_dict(json.loads(json.dumps(invalid)))
            with pytest.raises(ValueError, match=field):
                Step(**invalid)
