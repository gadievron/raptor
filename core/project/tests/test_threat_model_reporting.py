"""Project assessment exports preserve native modes, inputs and caller paths."""
from __future__ import annotations

import json
import sys

import pytest

from core.json import save_json
from core.project import cli
from core.project.project import ProjectManager
from core.testing.state_isolation import pin_user_state_dirs
from core.threat_model import ThreatModel, project_threat_model_paths


@pytest.fixture
def project_setup(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)
    target = tmp_path / "source"
    target.mkdir()
    mgr = ProjectManager(tmp_path / "registry")
    project = mgr.create("fixture", str(target), output_dir=str(tmp_path / "project-output"))
    json_path, markdown_path = project_threat_model_paths(project)
    save_json(json_path, ThreatModel("fixture", str(target), threats=[{"id": "t-1", "title": "review", "risk_score": 1}]).to_dict())
    markdown_path.write_text("# Operator editable model\n")
    monkeypatch.setattr(cli, "ProjectManager", lambda: mgr)
    return project, json_path, markdown_path


def _run(monkeypatch, *flags):
    monkeypatch.setattr(sys, "argv", ["raptor-project", "threat-model", "report", "fixture", *flags])
    cli.main()


@pytest.mark.parametrize("flags,exported,native_written,machine", [
    ([], False, True, False), (["--no-report"], False, False, False),
    (["--report-format", "json"], True, True, False),
    (["--json", "--report-format", "json"], True, False, True),
])
def test_native_modes_and_portable_receipts(project_setup, monkeypatch, capsys, flags, exported, native_written, machine):
    project, json_path, markdown_path = project_setup
    before = [json_path.read_bytes(), markdown_path.read_bytes()]
    _run(monkeypatch, *flags)
    native_report = json_path.with_name("threat-model-report.md")
    assert native_report.exists() is native_written
    destination = json_path.parent / "threat-model-reports"
    assert (destination / "threat-model-report.json").exists() is exported
    output = capsys.readouterr().out
    if machine:
        assert set(json.loads(output)) == {"report", "lint", "drift"}
    else:
        assert "threats: 1" in output
    assert [json_path.read_bytes(), markdown_path.read_bytes()] == before
    if exported:
        context = json.loads((destination / "report-context.json").read_text())
        assert context["run_id"] == "unknown"
        assert context["extensions"]["raptor.metrics"]["Recorded threats"] == 1
        assert context["extensions"]["raptor.findings_available"] is False
        document = json.loads((destination / "report-document.json").read_text())
        assert any("historical run metadata" in note for note in document["diagnostics"])


def test_caller_relative_export_destination(project_setup, tmp_path, monkeypatch):
    caller = tmp_path / "caller"
    caller.mkdir()
    monkeypatch.setenv("RAPTOR_CALLER_DIR", str(caller))
    _run(monkeypatch, "--report-format", "json", "--report-output", "view.json")
    assert json.loads((caller / "view.json").read_text())["kind"] == "threat-model"


def test_no_report_keeps_old_assessment_but_marks_it_unrefreshed(project_setup, monkeypatch, capsys):
    _, json_path, _ = project_setup
    old = json_path.with_name("threat-model-report.md")
    old.write_text("previous assessment")
    _run(monkeypatch, "--no-report")
    assert old.read_text() == "previous assessment"
    output = capsys.readouterr()
    assert "threats: 1" in output.out
    assert "not refreshed" in output.err


def test_report_controls_rejected_for_mutation_before_registry_access(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "ProjectManager", lambda: pytest.fail("report flags must not start mutation"))
    monkeypatch.setattr(sys, "argv", ["raptor-project", "threat-model", "init", "fixture", "--report-format", "json"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2


def test_explicit_export_cannot_replace_canonical_model(project_setup, monkeypatch, capsys):
    _, json_path, _ = project_setup
    before = json_path.read_bytes()
    _run(monkeypatch, "--report-format", "json", "--report-output", str(json_path))
    assert "overwrite an input artifact" in capsys.readouterr().out
    assert json_path.read_bytes() == before
    assert not json_path.with_name("threat-model-report.md").exists()


def test_legacy_report_cannot_overwrite_context_map_input(project_setup, monkeypatch, capsys):
    _, json_path, _ = project_setup
    context_map = json_path.with_name("threat-model-report.md")
    save_json(context_map, {"entry_points": [], "trust_boundaries": [], "unchecked_flows": []})
    before = context_map.read_bytes()
    _run(monkeypatch, "--context-map", str(context_map))
    assert "overwrite an input artifact" in capsys.readouterr().out
    assert context_map.read_bytes() == before


def test_custom_canonical_path_cannot_be_replaced_by_legacy_report(project_setup, monkeypatch, capsys):
    project, json_path, _ = project_setup
    canonical = json_path.with_name("threat-model-report.md")
    canonical.write_bytes(json_path.read_bytes())
    cli.ProjectManager().update_threat_model_stamp(project.name, updated_at="fixture", path=str(canonical))
    before = canonical.read_bytes()
    _run(monkeypatch)
    assert "overwrite an input artifact" in capsys.readouterr().out
    assert canonical.read_bytes() == before
