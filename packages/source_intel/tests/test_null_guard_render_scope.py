"""Null-check observations carry no sink-order or dominance proof."""

import pytest

from packages.source_intel.analyze import NullGuardEvidence
from packages.source_intel.render import _render_null_guard_line


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_null_guard_prose_preserves_observation_limits(style):
    record = NullGuardEvidence(kind="bang", location=("owned.c", 100), enclosing_function="owned")
    text = _render_null_guard_line(record, style)
    assert "owned.c:100" in text and "`if (!e)`" in text
    assert "precedes sink" not in text
    assert "Reduces likelihood" not in text
    assert "does not establish" in text
