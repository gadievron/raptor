"""A noreturn annotation alone does not classify exploitability."""

import pytest

from packages.source_intel.analyze import AttributeEvidence
from packages.source_intel.render import _render_attribute_line


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_noreturn_annotation_does_not_establish_abort_or_dos_only(style):
    record = AttributeEvidence(
        kind="noreturn", function_name="owned", location=("owned.c", 7),
        match_source="literal", raw_match="noreturn",
        conditional_on="CONFIG_OWNED",
    )
    text = _render_attribute_line(record, None, style)
    assert "`owned`" in text and "noreturn" in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "the program aborts before exploitation" not in text
    assert "the bug becomes DoS-only" not in text
    assert "does not establish" in text
