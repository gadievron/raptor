"""An attribute observation does not establish overflow reachability."""

import pytest

from packages.source_intel.analyze import AttributeEvidence
from packages.source_intel.render import _render_attribute_line


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_stack_protector_prose_preserves_annotation_limits(style):
    record = AttributeEvidence(
        kind="no_stack_protector", function_name="owned",
        location=("owned.c", 7), match_source="literal",
        raw_match="no_stack_protector", conditional_on="CONFIG_OWNED",
    )
    text = _render_attribute_line(record, None, style)
    assert "`owned`" in text and "no_stack_protector" in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "saved return address reaches" not in text
    assert "does not establish" in text
    assert "Build-wide stack-protector level unknown" in text


@pytest.mark.parametrize("level", ["strong", "all", "none"])
def test_observed_stack_flags_do_not_assert_binary_instrumentation(level):
    from core.build.build_flags import BuildFlagsContext
    from packages.source_intel.render import _stack_protector_phrase

    flags = BuildFlagsContext(extraction_confidence="best_effort",
                              stack_protector_level=level)
    text = _stack_protector_phrase(flags)
    assert "observed" in text
    assert "does not establish" in text
