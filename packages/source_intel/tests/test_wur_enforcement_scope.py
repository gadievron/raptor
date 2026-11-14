"""Aggregate warning settings do not establish caller compile outcomes."""

import pytest

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import WurEvidence
from packages.source_intel.render import _render_attribute_line


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_wur_observed_flag_does_not_establish_caller_compilation(flag, style):
    record = WurEvidence(
        function_name="owned", location=("owned.c", 7),
        match_source="literal", raw_match="warn_unused_result",
        conditional_on="CONFIG_OWNED",
    )
    flags = BuildFlagsContext(extraction_confidence="high",
                              werror_unused_result=flag)
    text = _render_attribute_line(record, flags, style)
    assert "`owned`" in text and "warn_unused_result" in text
    assert "CONFIG_OWNED" in text and "CONDITIONAL" in text
    assert "does not establish" in text
    assert "would not compile" not in text
    assert "warning suppressed" not in text
