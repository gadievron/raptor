"""Privilege-site observations retain their scope without becoming verdicts."""

import pytest

from packages.source_intel.analyze import BoundaryEvidence, LsmEvidence, SourceIntelResult
from packages.source_intel.render import (
    _render_lsm_line,
    derive_evidence_strings,
    derive_mitigations_found,
)


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_lsm_name_observation_does_not_claim_sink_path(style):
    record = LsmEvidence(hook_name="security_owned", location=("owned.c", 100))
    text = _render_lsm_line(record, style)
    assert "`security_owned`" in text and "owned.c:100" in text
    assert "on path to sink" not in text
    assert "does not establish" in text


def test_boundary_only_result_renders_existing_observation():
    record = BoundaryEvidence(boundary_fn="copy_from_user", location=("owned.c", 7), enclosing_function="owned")
    result = SourceIntelResult(boundary_crossings=(record,))
    lines = derive_evidence_strings(result, finding_function="owned", max_lines=12)
    assert len(lines) == 1 and "`copy_from_user`" in lines[0] and "owned.c:7" in lines[0]
    assert "does not establish" in lines[0]
    assert derive_mitigations_found(result) == []


@pytest.mark.parametrize("function,retained", [(None, True), ("other", False)])
def test_boundary_function_filter_keeps_unknown_attribution(function, retained):
    record = BoundaryEvidence(boundary_fn="copy_to_user", location=("owned.c", 7), enclosing_function=function)
    lines = derive_evidence_strings(SourceIntelResult(boundary_crossings=(record,)), finding_function="owned")
    assert any("`copy_to_user`" in line for line in lines) is retained
