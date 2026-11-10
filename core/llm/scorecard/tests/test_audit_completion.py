"""Readiness exports preserve native gates, integrity flags and source bytes."""
from copy import deepcopy
import json

import pytest

from core.llm.scorecard import audit as module
from core.llm.scorecard.audit import DecisionClassSummary, EventTypeSummary, PRIMARY_EVENT_TYPE
from core.llm.scorecard.tests.test_audit_document import _report
from core.reporting.writer import load_committed_report, regenerate


def _capture(tmp_path, monkeypatch, verdict="amber", *, integrity=None):
    source = tmp_path / "scorecard.json"
    source.write_text("owned source bytes")
    report = _report(source)
    report.key_unusable = integrity == "unusable"
    report.sidecar_demoted = integrity == "demoted"
    if integrity == "demoted":
        verdict = "no-data"
        report.schema_version = None
    report.verdict = verdict
    report.verdict_reason = "Recorded " + verdict + " readiness"
    if verdict == "no-data":
        report.total_models = report.total_decision_classes = report.total_cells = 0
        report.event_type_summaries = [EventTypeSummary(PRIMARY_EVENT_TYPE, 0, 0, {10: 0, 30: 0, 100: 0}, 0)]
        report.decision_class_summaries = []
    elif verdict in {"green", "red"}:
        n = 50 if verdict == "green" else 2
        report.event_type_summaries[0] = EventTypeSummary(PRIMARY_EVENT_TYPE, 10, 10,
                                                        {10: 10 if n >= 10 else 0, 30: 10 if n >= 30 else 0, 100: 0}, 10 * n)
        report.decision_class_summaries = [DecisionClassSummary(f"class-{index}", 2, float(n), 2 * n) for index in range(5)]
    calls = []
    def run(path):
        assert path == source
        calls.append(True)
        return report
    monkeypatch.setattr(module, "audit", run)
    return source, report, calls


@pytest.mark.parametrize("verdict,status", [("green", 0), ("amber", 1), ("red", 2), ("no-data", 3)])
def test_exports_preserve_native_json_status_and_single_audit(tmp_path, monkeypatch, capsys, verdict, status):
    source, report, calls = _capture(tmp_path, monkeypatch, verdict)
    before = deepcopy(report)
    base = ["--path", str(source), "--json"]
    assert module.main(base) == status
    native = json.loads(capsys.readouterr().out)
    calls.clear()
    root = tmp_path / "chosen-reports"
    assert module.main([*base, "--report-format", "json", "--report-format", "xml", "--report-output", str(root)]) == status
    shown = capsys.readouterr()
    assert json.loads(shown.out) == native and calls == [True]
    assert f"Native audit exit status: {status}" in shown.err
    context, document, _ = load_committed_report(root)
    assert context.run_id == "unknown" and document.snapshot_id == context.snapshot_id
    assert context.extensions["raptor.metrics"]["Recorded readiness verdict"] == verdict
    assert context.state == ("unknown" if verdict == "no-data" else "completed")
    assert report == before and source.read_text() == "owned source bytes"


@pytest.mark.parametrize("integrity", ["unusable", "demoted"])
def test_integrity_flags_and_partial_state_survive_offline_export(tmp_path, monkeypatch, capsys, integrity):
    source, report, calls = _capture(tmp_path, monkeypatch, integrity=integrity)
    root = tmp_path / "chosen-reports"
    expected = 3 if integrity == "demoted" else 1
    assert module.main(["--path", str(source), "--json", "--report-format", "xml", "--report-output", str(root)]) == expected
    assert json.loads(capsys.readouterr().out)["sidecar_demoted"] == report.sidecar_demoted
    context, _, _ = load_committed_report(root)
    assert context.state == "partial"
    assert context.extensions["raptor.metrics"]["Integrity key unusable"] == report.key_unusable
    xml = (root / "scorecard-audit.xml").read_bytes()
    source.unlink()
    regenerate(root, tmp_path / "offline.xml", format="xml")
    assert (tmp_path / "offline.xml").read_bytes() == xml and calls == [True]


@pytest.mark.parametrize("failure", ["destination", "source", "format", "conflict"])
def test_preflight_refusal_precedes_audit(tmp_path, monkeypatch, failure):
    source, _, calls = _capture(tmp_path, monkeypatch)
    flags = {"destination": ["--report-format", "json"],
             "source": ["--report-format", "json", "--report-output", str(source)],
             "format": ["--report-format", "unavailable-format", "--report-output", str(tmp_path / "reports")],
             "conflict": ["--no-report", "--report-format", "json"]}[failure]
    with pytest.raises(SystemExit) as error:
        module.main(["--path", str(source), *flags])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes"


def test_disabled_export_keeps_native_json_and_stale_receipts(tmp_path, monkeypatch, capsys):
    source, _, calls = _capture(tmp_path, monkeypatch)
    root = tmp_path / "portable-reports" / "scorecard-audit"
    root.mkdir(parents=True)
    manifest = root / "reporting-manifest.json"
    manifest.write_text("old unparsed receipt")
    assert module.main(["--path", str(source), "--json", "--no-report"]) == 1
    shown = capsys.readouterr()
    assert json.loads(shown.out)["verdict"] == "amber" and "not refreshed" in shown.err
    assert manifest.read_text() == "old unparsed receipt" and not (root / "summary.json").exists()
    assert calls == [True]


def test_publisher_fault_preserves_native_red_gate(tmp_path, monkeypatch, capsys):
    source, _, calls = _capture(tmp_path, monkeypatch, "red")
    from core.llm.scorecard import audit_completion
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(audit_completion, "complete_reporting", fail)
    assert module.main(["--path", str(source), "--json", "--report-format", "json", "--report-output", str(tmp_path / "reports")]) == 2
    shown = capsys.readouterr()
    assert json.loads(shown.out)["verdict"] == "red"
    assert "native audit retained" in shown.err and "private fault" not in shown.err
    assert reached == [True] and calls == [True]


def test_default_source_is_resolved_at_invocation_for_preflight(tmp_path, monkeypatch, capsys):
    source, _, calls = _capture(tmp_path, monkeypatch)
    resolutions = []
    def resolve():
        resolutions.append(True)
        return source
    monkeypatch.setattr(module, "default_scorecard_path", resolve)
    assert module.main(["--json", "--report-output", str(tmp_path / "reports")]) == 1
    assert json.loads(capsys.readouterr().out)["scorecard_path"] == str(source)
    assert resolutions == [True] and calls == [True]


def test_capture_loss_reaches_operator_and_structured_state(tmp_path, monkeypatch, capsys):
    source, report, calls = _capture(tmp_path, monkeypatch, "green")
    report.event_type_summaries.extend([EventTypeSummary(f"future-{index}", 1, 0, {10: 0, 30: 0, 100: 0}, 0) for index in range(1001)])
    root = tmp_path / "reports"
    assert module.main(["--path", str(source), "--json", "--report-format", "json", "--report-output", str(root)]) == 0
    shown = capsys.readouterr()
    context, _, _ = load_committed_report(root)
    assert context.state == "partial" and context.extensions["raptor.capture_limited"] is True
    assert context.extensions["raptor.metrics"]["Native event-type rows"] == len(report.event_type_summaries)
    assert "Portable capture is limited" in shown.err and calls == [True]
