"""Allocation-site reports do not establish runtime failure paths."""

import pytest

from packages.source_intel.analyze import AllocationEvidence
from packages.source_intel.render import _render_allocation_line


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_allocation_prose_retains_observation_limits(style):
    record = AllocationEvidence(
        allocator="malloc", location=("owned.c", 7), shape="field", target_field="buf",
        conditional_on="CONFIG_OWNED",
    )
    text = _render_allocation_line(record, style)
    assert "owned.c:7" in text and "`malloc`" in text and "`->buf`" in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "downstream deref crashes" not in text
    assert "does not establish" in text
