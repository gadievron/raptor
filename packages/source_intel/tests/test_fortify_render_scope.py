"""Annotation and flag observations do not establish runtime bounds checks."""

import pytest

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import AttributeEvidence
from packages.source_intel.render import _render_attribute_line


@pytest.mark.parametrize("kind", ["alloc_size", "access"])
@pytest.mark.parametrize("level,source", [
    (None, "compile_commands.json"), (0, "compile_commands.json"),
    (1, "compile_commands.json"), (2, "compile_commands.json"),
    (1, "kconfig"),
])
@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_fortify_observation_does_not_establish_runtime_checks(kind, level, source, style):
    record = AttributeEvidence(
        kind=kind, function_name="owned", location=("owned.c", 7),
        match_source="literal", raw_match=kind, conditional_on="CONFIG_OWNED",
    )
    flags = BuildFlagsContext(extraction_confidence="high", source=source,
                              fortify_source_level=level)
    text = _render_attribute_line(record, flags, style)
    assert "`owned`" in text and kind in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "does not establish" in text
    assert "would be caught" not in text
    assert "will bounds-check" not in text
    if source == "kconfig":
        assert "CONFIG_FORTIFY_SOURCE" in text
    elif level is not None:
        assert f"_FORTIFY_SOURCE={level}" in text
