"""Normal retained check publication reaches reports without verdict authority."""
import json

import pytest

from core.audit import check_trace
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.orchestrator import ReviewOutcome
from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.audit.sweep import SweepResult
from core.audit.verification_results import ToolChainResult
from core.reporting.renderers import get_renderer


def _publish(out, *, tools=("fixture-checker",)):
    scope = ToolChainResult(file="owned.c", function="f", line_start=1, hypothesis="retained concern")
    for tool in tools:
        for outcome in ("inconclusive", "error"):
            result = SweepResult(tool=tool, file_path="owned.c", function_name="f",
                                 outcome=outcome, rule_id="fixture-rule", details={"reason": "inert saved output"})
            check_trace.record_check_observation(out, scope, tool=tool, verdict=outcome,
                                                 rule_id="fixture-rule", result=result)
    finding = ReviewOutcome(file="owned.c", function="f", line=1, status="suspicious",
                            body="reviewer judgment", hypothesis="retained concern")
    export = export_findings([finding])
    write_graded_findings(export, out)
    (out / "findings.json").write_text(json.dumps(export["findings"]), encoding="utf-8")
    return export


def test_actual_publisher_observation_counts_reach_report_without_execution_or_verdict_claim(tmp_path):
    export = _publish(tmp_path)
    report = generate_report(tmp_path)
    record = report["analysis_observations"]
    assert record["mode"] == "recorded" and record["authoritative"] is False
    assert record["summary"] == export["verification_summary"]["observations"]["retained"]
    assert record["summary"]["records"] == 2
    assert record["summary"]["by_tool"] == {"fixture-checker": {"inconclusive": 1, "error": 1}}
    assert record["history_complete"] is False
    assert report["findings"][0]["status"] == "suspicious"
    _, document = build_audit_document(report, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Retained checker observations" in markdown
    assert "not distinct executions" in markdown
    assert "Missing records do not mean no check ran" in markdown
    assert "fixture-checker" in markdown and "inconclusive" in markdown
    assert "source freshness" in markdown


def test_absent_checker_artifact_is_unavailable_not_zero_runs(tmp_path):
    record = generate_report(tmp_path)["analysis_observations"]
    assert record["mode"] == "unavailable" and record["authoritative"] is False
    assert "summary" not in record


@pytest.mark.parametrize("change", ["summary", "row", "history"])
def test_malformed_or_inconsistent_saved_checker_projection_is_unavailable(tmp_path, change):
    _publish(tmp_path)
    path = tmp_path / "verification-checks.json"
    data = json.loads(path.read_text())
    if change == "summary":
        data["summary"]["records"] = 900
    elif change == "row":
        data["checks"].append({"scope": None})
    else:
        data["history_complete"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    record = generate_report(tmp_path)["analysis_observations"]
    assert record["mode"] == "unavailable"
    assert "summary" not in record


def test_optional_projection_failure_cannot_replace_report_but_cancellation_propagates(tmp_path, monkeypatch):
    from core.audit import analysis_observation_reporting as consumer

    _publish(tmp_path)

    def allocation_failure(*args, **kwargs):
        raise MemoryError("owned projection seam")

    monkeypatch.setattr(consumer, "load_json", allocation_failure)
    report = generate_report(tmp_path)
    assert report["analysis_observations"]["mode"] == "unavailable"
    assert report["findings"][0]["status"] == "suspicious"

    def cancellation(*args, **kwargs):
        raise KeyboardInterrupt("owned projection cancellation")

    monkeypatch.setattr(consumer, "load_json", cancellation)
    with pytest.raises(KeyboardInterrupt):
        generate_report(tmp_path)


def test_tool_outcome_display_cap_preserves_all_retained_totals(tmp_path):
    _publish(tmp_path, tools=tuple(f"checker-{i}" for i in range(25)))
    report = generate_report(tmp_path)
    assert report["analysis_observations"]["summary"]["records"] == 50
    _, document = build_audit_document(report, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "50 retained checker record(s)" in markdown
    assert "10 further tool/outcome groups retained" in markdown
    assert "record totals include them" in markdown
