"""Saved phase projections retain findings and recorded completeness limits."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.json import load_json
from core.reporting.adapters import stages_from_phases
from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("review,expected_stage,expected_summary", [
    ({"enabled": True, "completed": True}, "completed", "completed"),
    ({"enabled": True, "completed": True, "error": "recorded failure"}, "partial", "partial"),
    ({"enabled": True, "completed": False}, "unknown", "partial"),
], ids=["healthy", "recorded-error", "incomplete"])
def test_saved_phase_adapter_survives_publication_with_independent_findings(
    tmp_path, review, expected_stage, expected_summary,
):
    payload = {"phases": {"scan": {"completed": True},
                          "optional": {"enabled": False, "completed": False}, "review": review},
               "findings": [{"id": "F1", "file": "a.c", "line": 1, "message": "recorded claim"}]}
    source = tmp_path / "saved-phases.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    original_bytes = source.read_bytes()
    captured = load_json(source)
    original = deepcopy(captured)
    stages = stages_from_phases(captured["phases"], producer="agentic", run_id="saved")
    console = StringIO()
    output = tmp_path / "report"
    result = complete_native_result(
        NativeResult("agentic", "captured", "saved", captured, findings=captured["findings"],
                     state="completed", triage=True, stages=stages, artifacts=[{"path": str(source)}]),
        output, stem="phase-report", options=ReportOptions(formats=("json", "markdown")), stream=console,
    )
    assert not result.errors and result.publication is not None and result.publication.committed
    context, document, _ = load_committed_report(output)
    assert {stage.stage_id: stage.state for stage in context.stages} == {
        "scan": "completed", "optional": "skipped", "review": expected_stage,
    }
    for stage in context.stages:
        assert stage.extensions["raptor.phase"] == original["phases"][stage.stage_id]
    assert context.completion_state == result.summary.state == expected_summary
    assert context.extensions["raptor.result"] == captured == original
    assert len(context.findings) == result.summary.total == 1
    assert result.summary.counts == {"Unconfirmed": 1}
    assert context.findings[0]["native"] == original["findings"][0]
    assert document.snapshot_id == context.snapshot_id
    assert json.loads((output / "phase-report.json").read_bytes()) == document.to_dict()
    assert (output / "phase-report.md").is_file()
    assert f"Tool/stage review: {expected_stage}" in console.getvalue()
    if expected_stage == "partial":
        assert context.stages[-1].reason == "recorded failure"
        assert "Phase completion conflicts" in console.getvalue()
    assert source.read_bytes() == original_bytes
