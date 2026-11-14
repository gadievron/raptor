"""Warning API sites are informational context, never mitigations."""

import pytest

from packages.source_intel.analyze import SourceIntelResult, WarnEvidence
from packages.source_intel.render import derive_evidence_strings, derive_mitigations_found


def _result(function="owned"):
    return SourceIntelResult(warns=(WarnEvidence(
        warn_fn="WARN_ON", location=("owned.c", 7), enclosing_function=function,
    ),))


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_warning_only_result_surfaces_existing_record(style):
    result = _result()
    lines = derive_evidence_strings(result, finding_function="owned", style=style)
    assert len(lines) == 1 and "`WARN_ON`" in lines[0] and "owned.c:7" in lines[0]
    assert "does not establish" in lines[0]
    assert derive_mitigations_found(result) == []


@pytest.mark.parametrize("function,retained", [(None, True), ("other", False)])
def test_warning_function_filter_retains_unknown_attribution(function, retained):
    lines = derive_evidence_strings(_result(function), finding_function="owned")
    assert any("`WARN_ON`" in line for line in lines) is retained


def test_failure_only_result_discloses_incomplete_coverage():
    result = SourceIntelResult(rules_failed=(("owned.cocci", "owned refusal"),))
    lines = derive_evidence_strings(result)
    assert len(lines) == 1 and "1 rule failure" in lines[0]
    assert "incomplete" in lines[0]
    assert "owned refusal" not in lines[0]


def test_failure_disclosure_precedes_warning_under_line_cap():
    result = SourceIntelResult(warns=_result().warns, rules_failed=(("owned.cocci", "owned refusal"),))
    lines = derive_evidence_strings(result, max_lines=1)
    assert len(lines) == 1 and "incomplete" in lines[0]


def test_warning_formatting_stops_at_positive_budget(monkeypatch):
    from packages.source_intel import render

    calls = []
    monkeypatch.setattr(render, "_render_warning_line", lambda *args: calls.append(args) or "owned")
    result = SourceIntelResult(warns=_result().warns * 3)
    assert derive_evidence_strings(result, max_lines=1) == ["owned"]
    assert len(calls) == 1
