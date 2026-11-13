"""Finding wire containers cannot silently lose or reshape producer data."""

from types import MappingProxyType

import pytest

from core.dataflow.finding import Finding, Step


def test_finding_container_shapes_preserve_valid_inputs():
    step = Step("fixture.py", 1, 0, "value")
    base = Finding("fixture", "fixture", "fixture", "fixture", step, step).to_dict()
    for invalid in ("", b"", {}, {"line": 1}):
        with pytest.raises(ValueError, match="intermediate_steps"):
            Finding.from_dict({**base, "intermediate_steps": invalid})
    for invalid in ([], [["key", "value"]], "", None):
        with pytest.raises(ValueError, match="raw"):
            Finding.from_dict({**base, "raw": invalid})
    for valid in ([], (), iter(())):
        assert Finding.from_dict({**base, "intermediate_steps": valid}).intermediate_steps == ()
    for valid in ({"producer": {"key": [1, 2]}}, MappingProxyType({"key": "value"})):
        assert Finding.from_dict({**base, "raw": valid}).raw == valid
    assert Finding.from_dict({**base, "intermediate_steps": [step.to_dict()]}).intermediate_steps == (step,)
