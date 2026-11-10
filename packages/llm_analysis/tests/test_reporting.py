"""Analysis presentation consumes captured metadata without analysis dispatch."""
from copy import deepcopy
import json

import pytest

from core.reporting.document import ReportDocument
from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from core.reporting.writer import load_committed_report, regenerate
from core.testing.module_views import module_function_view, scoped_function_imports
from packages.llm_analysis import reporting


def _report(mode="full"):
    return {"mode": mode, "processed": 2, "prepped": 2, "analyzed": 0 if mode == "prep_only" else 1,
            "exploitable": 0, "exploits_generated": 0, "patches_generated": 0, "llm_stats": {"total_cost": 0.0},
            "dataflow_validation": {"n_validated": 0, "n_tier4_smt_witness": 1},
            "results": [{"finding_id": "item", "file": "<script>name</script>\x1b[2J",
                         "status": "recorded", "analysis": {"is_exploitable": False, "reasoning": "private reasoning"},
                         "exploit_code": "private exploit body", "patch_code": "private patch body", "prompt": "private prompt"}]}


def test_capture_keeps_unknown_zero_stage_populations_and_excludes_bodies():
    report = _report("prep_only")
    before = deepcopy(report)
    document = reporting.build_document(report, orchestration_skipped=True)
    assert document.summary["processed"] == 2 and document.summary["analyzed"] == 0
    assert document.summary["journal_entries_emitted"] is None
    assert document.summary["Returned result rows"] == 1
    assert document.blocks[0].rows[0][-2:] == [False, False]
    assert "Preparation only" in " ".join(document.diagnostics)
    assert "Orchestration was skipped" in " ".join(document.diagnostics)
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()
    for format in ("markdown", "json", "xml"):
        output = render_document(document, format).content.decode()
        assert "n_tier4_smt_witness" in output and "is not a completed analysis" in output
        for excluded in ("private reasoning", "private exploit body", "private patch body", "private prompt"):
            assert excluded not in output
        assert "\x1b" not in output
        if format != "json":
            assert "<script>" not in output
    assert report == before


def test_collection_limits_and_invalid_values_preserve_valid_rows():
    report = _report()
    report["results"] = [report["results"][0], None] + report["results"] * 1000
    report["llm_stats"] = {f"field-{i}": i for i in range(1100)}
    report["analyzed"] = float("nan")
    document = reporting.build_document(report)
    assert document.summary["analyzed"] is None
    assert document.summary["Returned result rows"] == 1002
    assert len(document.blocks[0].rows) == 999
    assert document.extensions["raptor.result_rows_omitted"] == 2
    assert document.extensions["raptor.retained_result_rows_rejected"] == 1
    assert document.extensions["raptor.telemetry_collection_entries_omitted"] == 100
    assert document.extensions["raptor.telemetry_values_or_subtrees_unavailable"] == 1
    assert document.extensions["raptor.capture_limited"] is True
    assert render_document(document, "json").content


def test_node_budget_bounds_nested_metadata_not_only_its_diagnostic():
    report = _report()
    report["orchestration"] = {f"model-{i}": {f"stat-{j}": j for j in range(1000)} for i in range(20)}
    document = reporting.build_document(report)
    assert document.extensions["raptor.telemetry_collection_entries_omitted"] > 0
    assert document.extensions["raptor.capture_limited"] is True
    assert len(render_document(document, "json").content) < 2_000_000


@pytest.mark.parametrize("mode", ["prep_only", "full", "orchestrated"])
def test_completed_capture_offline_export_does_not_promote_analysis_completion(tmp_path, mode):
    root = tmp_path / "run"
    root.mkdir()
    native = root / "autonomous_analysis_report.json"
    report = _report(mode)
    if mode == "orchestrated":
        report["orchestration"] = {"findings_dispatched": 4, "findings_analysed": 2, "findings_failed": 2,
                                   "consensus_all_errored": True, "cost": {"total": 0.25}}
    native.write_text(json.dumps(report))
    before = native.read_bytes()
    output = tmp_path / "portable"
    reporting.emit(report, root, [native], tmp_path / "target", ReportOptions(("json", "xml"), output))
    context, document, _ = load_committed_report(output)
    assert context.state == ("partial" if mode == "prep_only" else "unknown")
    assert context.stages[0].state == "completed" and context.stages[0].stage_id == "analysis-snapshot"
    assert context.extensions["raptor.findings_available"] is False and context.findings == []
    assert document.metadata["Native mode"] == mode
    assert native.read_bytes() == before
    rendered = (output / "analysis.xml").read_bytes()
    native.unlink()
    regenerate(output, tmp_path / "offline.xml", format="xml")
    assert (tmp_path / "offline.xml").read_bytes() == rendered


def test_disabled_exports_leave_old_receipt_unparsed_and_never_write(tmp_path, capsys):
    root = tmp_path / "run"
    receipt = root / "portable-reports" / "analysis" / "reporting-manifest.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("old receipt unparsed")
    reporting.emit(_report(), root, [], tmp_path / "target", ReportOptions(enabled=False))
    assert "not refreshed" in capsys.readouterr().err
    assert receipt.read_text() == "old receipt unparsed"
    assert not (receipt.parent / "summary.json").exists()


def test_reached_publication_fault_preserves_native_result(tmp_path, monkeypatch, capsys):
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(reporting, "complete_reporting", fail)
    report = _report()
    before = deepcopy(report)
    assert reporting.emit(report, tmp_path / "run", [], tmp_path / "target", ReportOptions(output=tmp_path / "report")) is None
    shown = capsys.readouterr()
    assert reached == [True] and "native result retained" in shown.err and "private fault" not in shown.err
    assert report == before


@pytest.mark.parametrize("filename", ["autonomous_analysis_report.json", "orchestrated_report.json", "correlation.json", "aggregation.json"])
def test_protect_native_machine_artifacts(tmp_path, filename):
    source = tmp_path / filename
    source.write_text("native evidence")
    with pytest.raises(ValueError, match="cannot replace"):
        reporting.prepare(ReportOptions(("json",), source), tmp_path, [], tmp_path / "target")
    assert source.read_text() == "native evidence"


def test_main_refusal_happens_before_constructing_analysis_provider(tmp_path):
    from packages.llm_analysis import agent
    from packages.llm_analysis.cli import build_parser
    from types import ModuleType

    parser_module = ModuleType("owned_parser")
    parser = build_parser()
    parser_module.build_parser = lambda: parser
    calls = []
    def refuse(*args, **kwargs):
        calls.append(True)
        raise AssertionError("report preflight reached analysis construction")
    # The parser owns supplied argv; main() itself sees a copied provider binding.
    parsed = parser.parse_args(["--repo", str(tmp_path), "--findings", str(tmp_path / "findings.json"), "--report-format", "unavailable"])
    parser.parse_args = lambda: parsed
    view = module_function_view(agent, bindings={"AutonomousSecurityAgentV2": refuse})
    with scoped_function_imports(view, ["main"], {"packages.llm_analysis.cli": parser_module}):
        with pytest.raises(SystemExit) as exc:
            view.main()
    assert exc.value.code == 2 and calls == []


@pytest.mark.parametrize("path", ["plain", "orchestrated", "skipped"])
def test_real_main_return_paths_export_only_the_selected_snapshot(tmp_path, path):
    from types import ModuleType
    from packages.llm_analysis import agent
    from packages.llm_analysis.cli import build_parser

    root = tmp_path / "run"
    root.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = tmp_path / "findings.json"
    source.write_text('{"findings": []}')
    destination = tmp_path / "portable"
    parser = build_parser()
    flags = ["--repo", str(target), "--findings", str(source), "--out", str(root),
             "--report-format", "json", "--report-output", str(destination)]
    if path != "plain":
        flags.extend(["--model", "owned-test-model"])
    parsed = parser.parse_args(flags)
    parser.parse_args = lambda: parsed
    parser_module = ModuleType("owned_parser")
    parser_module.build_parser = lambda: parser
    prep = _report("full" if path == "plain" else "prep_only")
    orchestrated = _report("orchestrated")
    orchestrated["processed"] = 5  # deliberate different population; never added
    calls = []
    class CapturedAgent:
        def __init__(self, *args, **kwargs):
            calls.append(("construct", kwargs))
        def process_findings(self, **kwargs):
            calls.append(("process", kwargs))
            (root / "autonomous_analysis_report.json").write_text(json.dumps(prep))
            return prep
    quiet = ModuleType("owned_quiet")
    quiet.quiet_noisy_loggers = lambda: None
    pin = ModuleType("owned_pin")
    pin.bootstrap_process_pin = lambda _: None
    trust = ModuleType("owned_trust")
    trust.resolve_dynamic_validation = lambda *a, **k: False
    orchestration = ModuleType("owned_orchestration")
    orchestration.build_llm_config_from_flags = lambda **kwargs: {"owned": True}
    def dispatch(**kwargs):
        calls.append(("orchestrate", kwargs))
        return {} if path == "skipped" else orchestrated
    orchestration.orchestrate = dispatch
    imports = {"packages.llm_analysis.cli": parser_module, "core.llm.log_quiet": quiet,
               "core.run.pin": pin, "core.project.trust": trust,
               "packages.llm_analysis.orchestrator": orchestration}
    view = module_function_view(agent, bindings={"AutonomousSecurityAgentV2": CapturedAgent})
    with scoped_function_imports(view, ["main"], imports):
        assert view.main() is None
    context, document, _ = load_committed_report(destination)
    selected = orchestrated if path == "orchestrated" else prep
    assert document.metadata["Native mode"] == selected["mode"]
    assert document.metadata["Orchestration skipped"] is (path == "skipped")
    assert document.summary["processed"] == selected["processed"]
    assert [name for name, _ in calls] == (["construct", "process"] if path == "plain" else ["construct", "process", "orchestrate"])
    assert calls[0][1]["prep_only"] is (path != "plain")
    assert context.extensions["raptor.findings_available"] is False
    assert json.loads((root / "autonomous_analysis_report.json").read_text()) == prep


def test_main_protects_checklist_input_before_analysis_construction(tmp_path):
    from types import ModuleType
    from packages.llm_analysis import agent
    from packages.llm_analysis.cli import build_parser

    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "run"
    output.mkdir()
    checklist = tmp_path / "checklist.json"  # outside target; source guard is required
    checklist.write_text('{"functions": []}')
    findings = tmp_path / "findings.json"
    findings.write_text('{"findings": []}')
    parser = build_parser()
    parsed = parser.parse_args(["--repo", str(target), "--findings", str(findings), "--checklist", str(checklist),
                                "--out", str(output), "--report-format", "json", "--report-output", str(checklist)])
    parser.parse_args = lambda: parsed
    parsers = ModuleType("owned_parser")
    parsers.build_parser = lambda: parser
    quiet = ModuleType("owned_quiet")
    quiet.quiet_noisy_loggers = lambda: None
    pin = ModuleType("owned_pin")
    pin.bootstrap_process_pin = lambda _: None
    calls = []
    def refuse(*args, **kwargs):
        calls.append(True)
        raise AssertionError("source collision reached analysis construction")
    view = module_function_view(agent, bindings={"AutonomousSecurityAgentV2": refuse})
    with scoped_function_imports(view, ["main"], {"packages.llm_analysis.cli": parsers,
                                                "core.llm.log_quiet": quiet, "core.run.pin": pin}):
        with pytest.raises(SystemExit) as exc:
            view.main()
    assert exc.value.code == 2 and calls == []
    assert checklist.read_text() == '{"functions": []}'
