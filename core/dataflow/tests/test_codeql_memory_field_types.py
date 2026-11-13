"""In-memory CodeQL adaptation preserves malformed types for refusal."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.dataflow.adapters.codeql import from_dataflow_path


def test_memory_adapter_preserves_falsey_invalid_types():
    def step(line):
        return SimpleNamespace(file_path="fixture.py", line=line, column=0, snippet="value", label="")

    valid = SimpleNamespace(source=step(1), sink=step(2), intermediate_steps=[],
                            rule_id="fixture", message="fixture", sanitizers=[])
    for field in ("rule_id", "message", "label"):
        for value in (False, 0, [], {}):
            bad = deepcopy(valid)
            setattr(bad.source if field == "label" else bad, field, value)
            with pytest.raises(ValueError):
                from_dataflow_path(bad)
    for empty in (None, ""):
        admitted = deepcopy(valid)
        admitted.rule_id = admitted.message = admitted.source.label = empty
        finding = from_dataflow_path(admitted)
        assert finding.rule_id == "unknown" and finding.message == "(no message)"
        assert finding.source.label is None
    finding = from_dataflow_path(valid)
    assert finding.rule_id == "fixture" and finding.source.snippet == "value"
