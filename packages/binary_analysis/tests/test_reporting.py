"""Final binary reports preserve native phases, populations and lifecycle IDs."""
import json

import pytest

from core.evidence import EvidenceTier, make_evidence
from core.reporting.writer import load_committed_report
from core.run.metadata import load_run_metadata
from core.testing.logging_state import isolated_cli_logging
from packages.binary_analysis import cli
from packages.binary_analysis.manifest import BinaryManifest
from packages.binary_analysis.pipeline import BinaryAnalysisResult


@pytest.fixture(autouse=True)
def isolated_run_owner(monkeypatch):
    monkeypatch.setattr("core.run.metadata._get_session_pid", lambda: None)
    monkeypatch.setattr("core.run.provenance.build_start_manifest", lambda **kwargs: {"target": {"source": "owned fixture"}})


def _model(tmp_path, *, count=2):
    binary = tmp_path / "sample.json"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    out = tmp_path / "out"
    manifest = BinaryManifest(schema_version=1, binary_path=str(binary), binary_sha256="a" * 64,
                              size_bytes=binary.stat().st_size, executable=True, target_kind="elf",
                              arch="x86", bits=64, binary_format="elf")
    context = {"entry_points": [{"id": f"BEP-{i}", "name": "owned"} for i in range(count)],
               "sink_details": [], "surface_details": [], "candidate_flows": [],
               "framework_callback_candidates": [], "analysis_scope": {"string_anchor_pass": "skipped"},
               "decompilations": {"coverage": {"recovered_functions": 2, "decompiled_functions": 1}}}
    evidence = make_evidence("a" * 64, kind="owned", source="owned", summary="observation",
                             tier=EvidenceTier.OBSERVED_RUNTIME, confidence="high", reproducible=True,
                             tool="owned", data={"argument": "owned-runtime-payload-secret"})
    return binary, out, BinaryAnalysisResult(manifest, context, [evidence], [], out / "graph.sqlite",
                                             decompilations=context["decompilations"])


def _investigation(*args, **kwargs):
    return {"status": "owned", "summary": {"surface_candidates": 0, "candidate_flows": 0,
            "ranked_ingress": 0, "runtime_input_flows": 0, "fuzz_witnesses": 0, "discovered_artifacts": 0},
            "ranked_surfaces": [], "ranked_ingress": [], "priority_queue": []}


@isolated_cli_logging()
def test_map_receipt_preserves_native_summary_excludes_stale_data_and_binds_real_lifecycle(tmp_path, monkeypatch, capsys):
    from packages.binary_analysis import reporting
    binary, out, model = _model(tmp_path)
    out.mkdir()
    (out / "binary-investigation.json").write_text(json.dumps({"ranked_surfaces": [{"name": "owned-stale-investigation"}]}))
    calls = []
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: calls.append(kwargs) or model)
    monkeypatch.setattr(reporting, "DETAIL_LIMIT", 1)
    assert cli.main(["map", str(binary), "--out", str(out), "--report-format", "json"]) == 0
    assert len(calls) == 1 and "Items: 2" in capsys.readouterr().out
    native = json.loads((out / "map-result.json").read_text())
    assert native["investigation"]["ranked_surfaces"][0]["name"] == "owned-stale-investigation"
    context, document, _ = load_committed_report(out)
    payload = context.extensions["raptor.result"]
    assert payload["recorded category counts"]["entry_points"] == 2
    assert len(payload["static evidence excerpts"]["entry_points"]) == 1
    assert payload["analysis scope"]["string_anchor_pass"] == "skipped"
    assert payload["decompilation coverage"]["decompiled_functions"] == 1
    assert payload["evidence tier counts"] == {"observed_runtime": 1}
    identity = load_run_metadata(out)["reporting_identity"]
    assert context.pass_id == identity["pass_id"] and context.snapshot_id == document.snapshot_id
    text = (out / "binary-map-report.json").read_text()
    assert "owned-stale-investigation" not in text and "owned-runtime-payload-secret" not in text


@isolated_cli_logging()
def test_investigation_receipt_uses_final_population_without_replaying_active_phase(tmp_path, monkeypatch):
    binary, out, initial = _model(tmp_path, count=2)
    _, _, final = _model(tmp_path, count=1)
    models = iter([initial, final])
    calls = []
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: calls.append(kwargs) or next(models))
    phases = []
    monkeypatch.setattr(cli, "_run_active_phase", lambda **kwargs: phases.append(kwargs) or {
        "kind": "runtime", "status": "completed", "returncode": 0, "output_dir": str(out / "runtime"),
        "command": ["owned-phase-secret"], "stdout": "owned-phase-secret", "stderr": "owned-phase-secret"})
    monkeypatch.setattr(cli, "write_investigation", _investigation)
    assert cli.main(["investigate", str(binary), "--runtime", "--out", str(out), "--report-format", "json"]) == 0
    assert len(calls) == 2 and len(phases) == 1
    context, _, _ = load_committed_report(out)
    assert context.extensions["raptor.result"]["recorded category counts"]["entry_points"] == 1
    assert context.extensions["raptor.result"]["active phases"][0]["status"] == "completed"
    assert "owned-phase-secret" not in (out / "binary-map-report.json").read_text()


@isolated_cli_logging()
def test_failed_active_phase_is_partial_with_completed_baseline_map(tmp_path, monkeypatch):
    binary, out, model = _model(tmp_path)
    calls = []
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: calls.append(kwargs) or model)
    monkeypatch.setattr(cli, "_run_active_phase", lambda **kwargs: {
        "kind": "runtime", "status": "failed", "returncode": 1, "output_dir": str(out / "runtime")})
    monkeypatch.setattr(cli, "write_investigation", _investigation)
    assert cli.main(["investigate", str(binary), "--runtime", "--out", str(out), "--report-format", "json"]) == 0
    assert len(calls) == 1
    context, _, _ = load_committed_report(out)
    assert context.state == "partial"
    assert {stage.stage_id: stage.state for stage in context.stages} == {"runtime": "failed", "final binary map": "completed"}


@isolated_cli_logging()
def test_failed_map_receipt_keeps_unavailable_population_and_native_status(tmp_path, monkeypatch):
    binary, out, _ = _model(tmp_path)

    def failed(*args, **kwargs):
        raise RuntimeError("owned-raw-error-not-for-report")

    monkeypatch.setattr(cli, "analyse_blackbox_binary", failed)
    assert cli.main(["map", str(binary), "--out", str(out), "--report-format", "json"]) == 1
    context, _, _ = load_committed_report(out)
    assert context.state == "failed" and context.extensions["raptor.result"]["final map"] is None
    assert "owned-raw-error-not-for-report" not in (out / "binary-map-report.json").read_text()


@isolated_cli_logging()
def test_map_report_cannot_replace_binary_input(tmp_path, monkeypatch, capsys):
    binary, out, model = _model(tmp_path)
    before = binary.read_bytes()
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: model)
    assert cli.main(["map", str(binary), "--out", str(out), "--report-format", "json", "--report-output", str(binary)]) == 0
    assert binary.read_bytes() == before and "Report persistence failed" in capsys.readouterr().err


@isolated_cli_logging()
def test_map_report_cannot_replace_imported_evidence_metadata(tmp_path, monkeypatch, capsys):
    binary, out, model = _model(tmp_path)
    imported = tmp_path / "imported-runtime"
    imported.mkdir()
    metadata = imported / "metadata.json"
    metadata.write_text("owned imported metadata")
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: model)
    assert cli.main(["map", str(binary), "--out", str(out), "--runtime-dir", str(imported),
                     "--report-format", "json", "--report-output", str(metadata)]) == 0
    assert metadata.read_text() == "owned imported metadata" and "Optional binary map report unavailable" in capsys.readouterr().err


def test_binary_map_report_preflight_precedes_target_and_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "start_run", lambda *args, **kwargs: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        cli.main(["map", str(tmp_path / "missing"), "--report-format", "json", "--report-output", str(tmp_path / "bad.xml")])
    assert error.value.code == 2


@isolated_cli_logging()
def test_early_refusal_does_not_borrow_existing_run_identity(tmp_path):
    from core.json import save_json
    from core.run.report_identity import fresh_identity
    out = tmp_path / "old-run"
    out.mkdir()
    old = fresh_identity()
    save_json(out / ".raptor-run.json", {"command": "understand", "reporting_identity": old, "status": "completed"})
    assert cli.main(["map", str(tmp_path / "missing"), "--out", str(out), "--report-format", "json"]) == 2
    context, _, _ = load_committed_report(out)
    assert context.run_id == "unknown" and context.pass_id == context.attempt_id == ""
    assert context.run_id != old["run_id"] and any("No current native execution" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_map_receipt_uses_start_identity_if_output_metadata_changes(tmp_path, monkeypatch):
    from core.json import save_json
    from core.run.report_identity import fresh_identity
    binary, out, model = _model(tmp_path)
    original = []
    replacement = fresh_identity()

    def completed(*args, **kwargs):
        metadata = load_run_metadata(out)
        original.append(metadata["reporting_identity"])
        metadata["reporting_identity"] = replacement
        save_json(out / ".raptor-run.json", metadata)
        return model

    monkeypatch.setattr(cli, "analyse_blackbox_binary", completed)
    assert cli.main(["map", str(binary), "--out", str(out), "--report-format", "json"]) == 0
    context, _, _ = load_committed_report(out)
    assert context.run_id == original[0]["run_id"] and context.run_id != replacement["run_id"]
