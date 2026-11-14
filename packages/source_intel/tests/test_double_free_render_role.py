"""Double-free observations retain the producer's endpoint role."""

import pytest

from packages.source_intel.analyze import DoubleFreeEvidence
from packages.source_intel.render import _render_double_free_line


@pytest.mark.parametrize("role,label", [("first", "First"), ("second", "Second"), ("other", "Matched")])
def test_report_role_controls_location_label(role, label):
    record = DoubleFreeEvidence(role=role, free_fn="kfree", location=("owned.c", 20))
    for style in ("stage_d", "exploit_plan", "agentic_variant"):
        text = _render_double_free_line(record, style)
        assert f"{label} free at owned.c:20" in text
        assert "`kfree`" in text
