"""Observed flags do not establish compiled null-check outcomes."""

import pytest

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import AttributeEvidence
from packages.source_intel.render import _render_attribute_line


@pytest.mark.parametrize("kind", ["nonnull", "returns_nonnull"])
@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_null_annotation_flags_preserve_outcome_limits(kind, flag, style):
    record = AttributeEvidence(
        kind=kind, function_name="owned", location=("owned.c", 7),
        match_source="literal", raw_match=kind, conditional_on="CONFIG_OWNED",
    )
    flags = BuildFlagsContext(extraction_confidence="high",
                              delete_null_pointer_checks=flag)
    text = _render_attribute_line(record, flags, style)
    assert "`owned`" in text
    if kind == "returns_nonnull":
        assert "promises never to return NULL" in text
    else:
        assert "annotated nonnull" in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "-fdelete-null-pointer-checks" in text or "-fno-delete-null-pointer-checks" in text
    assert "does not establish" in text
    assert "are preserved" not in text
    assert "real deref" not in text
    assert "would reach the deref" not in text
