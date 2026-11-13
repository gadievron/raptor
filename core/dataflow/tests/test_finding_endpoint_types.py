"""All finding path nodes share the Step instance invariant."""

import pytest

from core.dataflow.finding import Finding, Step


def test_direct_finding_requires_step_endpoints():
    source = Step("fixture.py", 1, 0, "source", "source")
    sink = Step("fixture.py", 2, 0, "sink", "sink")
    base = dict(finding_id="fixture", producer="fixture", rule_id="fixture", message="fixture", source=source, sink=sink)
    for field in ("source", "sink"):
        for invalid in (None, {}, source.to_dict(), "fixture.py", 1):
            with pytest.raises(TypeError, match=field):
                Finding(**{**base, field: invalid})
    finding = Finding(**base)
    assert finding.source is source
    assert finding.sink is sink
    assert Finding.from_json(finding.to_json()) == finding
