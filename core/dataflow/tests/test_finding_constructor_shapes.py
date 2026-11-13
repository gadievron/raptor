"""Direct finding construction preserves the declared container shapes."""

from types import MappingProxyType

import pytest

from core.dataflow.finding import Finding, Step


def test_direct_finding_collections_refuse_scalar_and_mapping_coercion():
    step = Step("fixture.py", 1, 0, "value")
    base = dict(finding_id="fixture", producer="fixture", rule_id="fixture", message="fixture", source=step, sink=step)
    for invalid in ("", b"", {}, {"step": step}):
        with pytest.raises(ValueError, match="intermediate_steps"):
            Finding(**base, intermediate_steps=invalid)
    for invalid in ([], [["key", "value"]], "", None):
        with pytest.raises(ValueError, match="raw"):
            Finding(**base, raw=invalid)
    for valid in ([], (), iter(())):
        assert Finding(**base, intermediate_steps=valid).intermediate_steps == ()
    for raw in ({"key": [1, 2]}, MappingProxyType({"key": "value"})):
        finding = Finding(**base, intermediate_steps=iter([step]), raw=raw)
        assert finding.raw is raw
        assert finding.intermediate_steps == (step,)
        assert Finding.from_dict(finding.to_dict()).raw == raw
