"""SBOM report adapters preserve domain evidence, offline capture and machine streams."""
import json
import xml.etree.ElementTree as ET

import pytest

from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document
from core.reporting.writer import load_context, regenerate
from core.testing.logging_state import isolated_cli_logging
from packages.sca.sbom_inventory.cli import main
from packages.sca.sbom_inventory.compare import compare
from packages.sca.sbom_inventory.inventory import read_inventory
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.reporting import build_sbom_report, inventory_capture
from packages.sca.sbom_inventory.source import Source
from packages.sca.sbom_inventory.tests.test_plan import plan
from packages.sca.sbom_inventory.tests.test_verification import verify


@pytest.mark.parametrize("command", ["inspect", "stats", "diff", "why", "plan", "verify-plan", "collect", "notices"])
def test_every_sbom_boundary_advertises_only_implemented_formats(command):
    from core.reporting.capabilities import command_capabilities
    capability = next(row for row in command_capabilities() if row["command"] == "sca sbom " + command)
    assert set(capability["formats"]) == {"markdown", "json", "xml"}


@isolated_cli_logging()
def test_inspect_adds_typed_outputs_without_changing_native_json(cdx, write_json, tmp_path, capsys):
    source = write_json(cdx)
    before = source.read_bytes()
    out = tmp_path / "inventory"
    assert main(["inspect", str(source), "--format", "json", "--out", str(out),
                 "--report-format", "json", "--report-format", "xml"]) == 0
    captured = capsys.readouterr()
    native = json.loads(captured.out)
    assert native["format"] == "raptor-sbom-inventory"
    assert native["records"] == json.loads((out / "inventory.json").read_text())["records"]
    assert "selected records: 1" in captured.err
    assert "No findings" not in captured.err
    assert source.read_bytes() == before
    report = out / "report"
    assert json.loads((report / "sbom-inspect.json").read_text())["kind"] == "sbom-inspect"
    ET.parse(report / "sbom-inspect.xml")
    assert not (report / "sbom-inspect.html").exists()
    context = load_context(report)
    assert context.extensions["raptor.result"]["source_sha256"] == context.extensions["raptor.sbom"]["source_sha256"]
    assert context.findings == [] and context.extensions["raptor.findings_available"] is False
    assert all(block.kind != "legacy_markdown" for block in ReportDocument.from_dict(json.loads((report / "report-document.json").read_text())).blocks)


@isolated_cli_logging()
def test_stdout_only_preserves_no_write_contract(cdx, write_json, tmp_path, monkeypatch, capsys):
    source = write_json(cdx)
    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.iterdir())
    assert main(["stats", str(source)]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out)["format"] == "raptor-sbom-statistics"
    assert "selected records: 1" in streams.err
    assert set(tmp_path.iterdir()) == before


@isolated_cli_logging()
def test_statistics_filters_retain_total_and_selected_scope(cdx, write_json, tmp_path, capsys):
    source = write_json(cdx)
    dest = tmp_path / "stats"
    assert main(["stats", str(source), "--license", "GPL-3.0-only", "--report-output", str(dest)]) == 0
    streams = capsys.readouterr()
    result = json.loads(streams.out)
    assert result["summary"]["packages"] == 1
    assert result["selection_scopes"] == {}
    context = load_context(dest)
    assert context.extensions["raptor.metrics"]["selected records"] == 0
    assert context.extensions["raptor.scope"]["filters"]["license_id"] == "GPL-3.0-only"


@isolated_cli_logging()
def test_diff_exports_domain_comparison_without_resolution_inference(cdx, write_json, tmp_path, capsys):
    first = write_json(cdx, "old.json")
    cdx["components"][0]["version"] = "2"
    cdx["components"][0]["purl"] = "pkg:npm/example@2"
    second = write_json(cdx, "new.json")
    dest = tmp_path / "comparison"
    assert main(["diff", str(first), str(second), "--report-output", str(dest), "--report-format", "xml"]) == 0
    native = json.loads(capsys.readouterr().out)
    with Source(first) as source:
        before, _ = read_inventory(source)
    with Source(second) as source:
        after, _ = read_inventory(source)
    assert native == compare(before, after)
    context = load_context(dest)
    assert context.extensions["raptor.result"] == native
    assert "Removal is not proof of remediation" in (dest / "summary.md").read_text() or "not proof of remediation" in (dest / "sbom-diff.xml").read_text()


@isolated_cli_logging()
def test_offline_rerender_never_reopens_original_inputs(cdx, write_json, tmp_path, capsys):
    source = write_json(cdx)
    report = tmp_path / "report"
    assert main(["inspect", str(source), "--report-output", str(report), "--format", "json"]) == 0
    capsys.readouterr()
    source.unlink()
    regenerated = tmp_path / "offline.xml"
    assert regenerate(report, regenerated, format="xml") == []
    ET.parse(regenerated)
    assert "example" in regenerated.read_text()


@isolated_cli_logging()
def test_no_report_retains_native_exports_and_mechanical_summary(cdx, write_json, tmp_path, capsys):
    out = tmp_path / "inventory"
    assert main(["inspect", str(write_json(cdx)), "--out", str(out), "--format", "json", "--no-report"]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out)["format"] == "raptor-sbom-inventory"
    assert (out / "inventory.csv").exists() and (out / "summary.md").exists()
    assert (out / "report/summary.md").exists()
    assert not (out / "report/sbom-inspect.md").exists()
    assert "RAPTOR Sbom-Inspect Summary" in streams.err


@pytest.mark.parametrize("format", ["html", "pdf"])
@isolated_cli_logging()
def test_excluded_formats_rejected_before_domain_output(cdx, write_json, tmp_path, format):
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as error:
        main(["inspect", str(write_json(cdx)), "--out", str(out), "--report-format", format])
    assert error.value.code == 2 and not out.exists()


def test_inventory_capture_bound_includes_complete_selection_identity():
    rows = [Record(str(i), "package", "1", "library") for i in range(1002)]
    inventory = Inventory("fixture", "a" * 64, records=rows)
    first = inventory_capture(inventory, rows)
    assert first["selected_records"] == 1002 and first["captured_records"] == 1000
    rows[-1].id = "different occurrence beyond the captured prefix"
    second = inventory_capture(inventory, rows)
    assert first["records"] == second["records"]
    assert first["selection_sha256"] != second["selection_sha256"]
    context, document = build_sbom_report("inspect", inventory=inventory)
    assert context.state == "partial"
    assert any("1000 of 1002" in note for note in document.diagnostics)


@pytest.mark.parametrize("format", ["markdown", "json", "xml"])
def test_foreign_text_stays_data_across_portable_formats(format):
    name = '<script>alert(1)</script> ![image](https://example.invalid/a)\x1b[2J'
    inventory = Inventory("fixture", "a" * 64, records=[Record("1", name, "1", "library")])
    _, document = build_sbom_report("inspect", inventory=inventory)
    data = render_document(document, format).content.decode()
    assert "\x1b" not in data
    if format == "xml":
        assert "<script>" not in data
        ET.fromstring(data)
    elif format == "markdown":
        assert "![image](" not in data and "<script>" not in data
    else:
        assert json.loads(data)["kind"] == "sbom-inspect"


@pytest.mark.parametrize("command", ["plan", "verify-plan"])
def test_plan_and_verification_capture_original_domain_result(tmp_path, command):
    payload = plan(tmp_path) if command == "plan" else verify()
    context, document = build_sbom_report(command, payload=payload, limit=None)
    assert context.extensions["raptor.result"] == payload
    assert context.findings == []
    text = render_document(document).content.decode()
    assert "not assessed" in text if command == "plan" else "SBOM upgrade verification" in text
    assert all(block.kind != "legacy_markdown" for block in document.blocks)


@isolated_cli_logging()
def test_optional_capture_failure_preserves_domain_exit_and_stdout(cdx, write_json, tmp_path, capsys, monkeypatch):
    from packages.sca.sbom_inventory import reporting
    source = write_json(cdx)
    def fail(*args, **kwargs):
        raise OSError("untrusted text must not reach the terminal")
    monkeypatch.setattr(reporting, "complete_reporting", fail)
    assert main(["stats", str(source), "--report-output", str(tmp_path / "out")]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out)["format"] == "raptor-sbom-statistics"
    assert "Optional report unavailable (OSError)" in streams.err
    assert "untrusted text" not in streams.err


@isolated_cli_logging()
def test_report_mirror_cannot_replace_source_or_native_inventory(cdx, write_json, tmp_path, capsys):
    source = write_json(cdx)
    before = source.read_bytes()
    assert main(["inspect", str(source), "--report-output", str(source), "--report-format", "json", "--format", "json"]) == 0
    assert source.read_bytes() == before
    assert "Report persistence failed" in capsys.readouterr().err
    out = tmp_path / "inventory"
    assert main(["inspect", str(source), "--out", str(out), "--report-output", str(out / "inventory.json"),
                 "--report-format", "json", "--format", "json"]) == 0
    assert json.loads((out / "inventory.json").read_text())["format"] == "raptor-sbom-inventory"
    assert "Report persistence failed" in capsys.readouterr().err


def test_sca_inventory_enrichment_changes_snapshot_and_retains_raw_sbom(cdx, write_json, tmp_path):
    from packages.sca.reporting import build_sca_document
    from packages.sca.sbom_inventory.reporting import attach_sca_inventory
    from core.reporting.writer import publish_report
    source = write_json(cdx)
    original = source.read_bytes()
    context, document = build_sca_document(rows=[], target=tmp_path, output_dir=tmp_path, deps_analysed=1)
    old = context.snapshot_id
    attach_sca_inventory(context, document, source)
    assert context.snapshot_id != old and document.snapshot_id == context.snapshot_id
    assert context.extensions["raptor.sbom"]["summary"]["packages"] == 1
    assert context.extensions["raptor.sbom"]["notice_verification"] == "not_verified"
    assert source.read_bytes() == original
    publish_report(context, document, tmp_path / "report")
    assert load_context(tmp_path / "report").snapshot_id == context.snapshot_id


@isolated_cli_logging()
def test_directory_input_members_are_protected_from_report_mirrors(cdx, write_json, tmp_path, capsys):
    source = write_json(cdx)
    bundle = tmp_path / "inventory"
    assert main(["inspect", str(source), "--out", str(bundle), "--format", "json"]) == 0
    capsys.readouterr()
    protected = bundle / "inventory.json"
    before = protected.read_bytes()
    assert main(["inspect", str(bundle), "--format", "json", "--report-output", str(protected), "--report-format", "json"]) == 0
    assert protected.read_bytes() == before
    assert "Report persistence failed" in capsys.readouterr().err


def test_sca_cli_summary_uses_captured_inventory_metadata(tmp_path, capsys):
    from packages.sca.cli import _print_summary
    from packages.sca.pipeline import RunResult
    result = RunResult(target=tmp_path, output_dir=tmp_path, findings_path=tmp_path / "findings.json",
                       report_path=tmp_path / "report.md", sbom_path=tmp_path / "sbom.cdx.json", sarif_path=tmp_path / "findings.sarif",
                       deps_analysed=2, vuln_findings=0, hygiene_findings=0, supply_chain_findings=0, suppressed_findings=0,
                       in_kev=0, cache_hits=0, cache_misses=0,
                       sbom_summary={"packages": 2, "unresolved_declarations": 1, "notice_verification": "not_verified"})
    _print_summary(result)
    text = capsys.readouterr().out
    assert "SBOM packages     2" in text
    assert "SBOM declarations 1 unresolved" in text
    assert "notice evidence   not_verified" in text


def test_implicit_advisory_receipt_is_protected_from_report_output(tmp_path, capsys):
    from packages.sca.sbom_inventory.cli import parser
    from packages.sca.sbom_inventory.reporting import complete_sbom_report, report_options
    coverage = tmp_path / "advisory-coverage.json"
    coverage.write_text('receipt bytes retained')
    args = parser().parse_args(["verify-plan", str(tmp_path / "plan.json"), str(tmp_path / "sbom.json"),
                                "--findings", str(tmp_path / "findings.json"), "--report-output", str(coverage), "--report-format", "json"])
    result = complete_sbom_report(args, options=report_options(args), payload=verify())
    assert result.errors and coverage.read_text() == "receipt bytes retained"
    assert "Report persistence failed" in capsys.readouterr().err


def test_sca_report_cannot_replace_the_secondary_sbom(tmp_path):
    from core.json import JsonCache
    from core.reporting.options import ReportOptions
    from packages.sca.pipeline import RunOptions, run_sca
    from packages.sca.tests.test_pipeline import StubHttp
    target, out = tmp_path / "source", tmp_path / "scan"
    target.mkdir()
    options = RunOptions(enable_llm_review=False, enable_triage=False, emit_spdx_sbom=True,
                         report_options=ReportOptions(formats=("json",), output=out / "sbom.spdx.json"))
    result = run_sca(target, out, options, http=StubHttp(), cache=JsonCache(root=tmp_path / "cache"))
    assert json.loads((out / "sbom.spdx.json").read_text())["spdxVersion"] == "SPDX-2.3"
    assert json.loads((out / "sbom.cdx.json").read_text())["bomFormat"] == "CycloneDX"
    assert result.report_outputs == {} and result.sbom_summary["packages"] == 0
