from core.json import load_json
from core.threat_model import ThreatModel, load_model, project_threat_model_paths, save_model
from raptor_agentic import (
    _materialise_threat_model_phase,
    _write_threat_model_candidate_sarif,
)


class _FakeProject:
    def __init__(self, name, target, output_dir):
        self.name = name
        self.target = target
        self.output_dir = output_dir
        self.threat_model_path = ""
        self.threat_model_updated = ""

    def to_dict(self):
        return {
            "name": self.name,
            "target": self.target,
            "output_dir": self.output_dir,
            "threat_model_path": self.threat_model_path,
            "threat_model_updated": self.threat_model_updated,
        }


class _FakePrepass:
    def __init__(self, context_map_path):
        self.ran = context_map_path is not None
        self.context_map_path = context_map_path
        self.skipped_reason = "prepass skipped"


class _FakeProjectManager:
    def __init__(self, project, projects_dir):
        self._project = project
        self.projects_dir = projects_dir

    def find_project_for_target(self, _target):
        return self._project


def test_unchecked_flows_become_candidate_sarif(tmp_path):
    sarif_path = tmp_path / "threat-model-candidates.sarif"
    context_map = {
        "entry_points": [{
            "id": "EP-001",
            "method": "GET",
            "path": "/hello",
            "file": "bad/mod_hello.py",
            "line": 14,
            "notes": "header-controlled entry",
        }],
        "sink_details": [{
            "id": "SINK-001",
            "type": "shell_exec",
            "file": "bad/mod_hello.py",
            "line": 23,
            "notes": "shell=True sink",
        }],
        "unchecked_flows": [{
            "id": "UF-001",
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No auth before command execution",
            "severity": "critical",
        }],
    }

    count = _write_threat_model_candidate_sarif(context_map, sarif_path)

    assert count == 1
    sarif = load_json(sarif_path)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "raptor.threat_model.unchecked_flow"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad/mod_hello.py"
    assert result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["message"]["text"] == "header-controlled entry"


def test_candidate_sarif_tolerates_bad_line_metadata(tmp_path):
    sarif_path = tmp_path / "threat-model-candidates.sarif"
    context_map = {
        "entry_points": [{"id": "EP-001", "file": "entry.py", "line": "nope"}],
        "sink_details": [{"id": "SINK-001", "file": "sink.py", "line": "bad"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No boundary",
        }],
    }

    count = _write_threat_model_candidate_sarif(context_map, sarif_path)

    assert count == 1
    sarif = load_json(sarif_path)
    result = sarif["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    first_flow = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
    assert first_flow["location"]["physicalLocation"]["region"]["startLine"] == 1


def test_threat_model_phase_preserves_existing_project_model_without_refresh(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    project = _FakeProject("demo", str(target), str(tmp_path / "project-out"))
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    json_path, markdown_path = project_threat_model_paths(project)
    existing = ThreatModel(
        project_name="demo",
        target=str(target),
        summary="operator edited model",
        focus_areas=["keep this operator context"],
    )
    save_model(existing, json_path, markdown_path)
    project.threat_model_path = str(json_path)
    context_map_path = tmp_path / "context-map.json"
    context_map_path.write_text(
        '{"entry_points": [{"id": "EP-001"}], "unchecked_flows": []}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "core.project.project.ProjectManager",
        lambda: _FakeProjectManager(project, projects_dir),
    )

    summary = _materialise_threat_model_phase(
        target=target,
        out_dir=tmp_path / "run-out",
        prepass_result=_FakePrepass(context_map_path),
        refresh=False,
    )

    assert summary["completed"] is True
    assert summary["model_preserved"] is True
    assert summary["model_refreshed"] is False
    loaded = load_model(json_path)
    assert loaded.summary == "operator edited model"
    assert loaded.focus_areas == ["keep this operator context"]


def test_threat_model_phase_migrates_preserved_model_to_v2_ledger(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    project = _FakeProject("demo", str(target), str(tmp_path / "project-out"))
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    json_path, markdown_path = project_threat_model_paths(project)
    existing = ThreatModel(
        version=1,
        project_name="demo",
        target=str(target),
        summary="operator edited model",
        focus_areas=["keep this operator context"],
    )
    save_model(existing, json_path, markdown_path)
    project.threat_model_path = str(json_path)
    context_map_path = tmp_path / "context-map.json"
    context_map_path.write_text(
        """
        {
          "entry_points": [{"id": "EP-001", "name": "GET /hello"}],
          "sink_details": [{"id": "SINK-001", "type": "subprocess", "file": "hello.py"}],
          "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "severity": "critical"
          }]
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "core.project.project.ProjectManager",
        lambda: _FakeProjectManager(project, projects_dir),
    )

    summary = _materialise_threat_model_phase(
        target=target,
        out_dir=tmp_path / "run-out",
        prepass_result=_FakePrepass(context_map_path),
        refresh=False,
    )

    assert summary["completed"] is True
    assert summary["model_preserved"] is True
    assert summary["model_migrated"] is True
    assert summary["threats_count"] == 1
    loaded = load_model(json_path)
    assert loaded.summary == "operator edited model"
    assert loaded.focus_areas == ["keep this operator context"]
    assert loaded.threats[0]["category"] == "command_execution"


def test_threat_model_phase_refresh_overwrites_existing_project_model(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    project = _FakeProject("demo", str(target), str(tmp_path / "project-out"))
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    json_path, markdown_path = project_threat_model_paths(project)
    existing = ThreatModel(
        project_name="demo",
        target=str(target),
        summary="operator edited model",
        focus_areas=["old context"],
    )
    save_model(existing, json_path, markdown_path)
    project.threat_model_path = str(json_path)
    context_map_path = tmp_path / "context-map.json"
    context_map_path.write_text(
        '{"entry_points": [{"id": "EP-001", "name": "POST /login"}], "unchecked_flows": []}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "core.project.project.ProjectManager",
        lambda: _FakeProjectManager(project, projects_dir),
    )

    summary = _materialise_threat_model_phase(
        target=target,
        out_dir=tmp_path / "run-out",
        prepass_result=_FakePrepass(context_map_path),
        refresh=True,
    )

    assert summary["completed"] is True
    assert summary["model_preserved"] is False
    assert summary["model_refreshed"] is True
    assert summary["threat_model_report"].endswith("threat-model-report.md")
    assert summary["threat_model_lint"].endswith("threat-model-lint.json")
    assert summary["threat_model_drift"].endswith("threat-model-drift.json")
    assert summary["threats"].endswith("threats.json")
    loaded = load_model(json_path)
    assert loaded.summary != "operator edited model"
    assert "Entry point: POST /login" in loaded.focus_areas


def test_threat_model_phase_refuses_stale_fallback_by_default(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    understand_dir = tmp_path / "understand-old"
    understand_dir.mkdir()
    (understand_dir / "context-map.json").write_text(
        '{"entry_points": [{"id": "EP-001"}], "unchecked_flows": []}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "core.orchestration.understand_bridge.find_understand_output",
        lambda _out, target_path=None: (understand_dir, {"bad/app.py"}),
    )

    summary = _materialise_threat_model_phase(
        target=target,
        out_dir=tmp_path / "run-out",
        prepass_result=_FakePrepass(None),
        allow_stale=False,
    )

    assert summary["completed"] is False
    assert "stale" in summary["skipped_reason"]
    assert summary["stale_files"] == ["bad/app.py"]


def test_threat_model_phase_can_reuse_stale_fallback_when_allowed(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    understand_dir = tmp_path / "understand-old"
    understand_dir.mkdir()
    (understand_dir / "context-map.json").write_text(
        '{"entry_points": [{"id": "EP-001"}], "unchecked_flows": []}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "core.orchestration.understand_bridge.find_understand_output",
        lambda _out, target_path=None: (understand_dir, {"bad/app.py"}),
    )

    summary = _materialise_threat_model_phase(
        target=target,
        out_dir=tmp_path / "run-out",
        prepass_result=_FakePrepass(None),
        allow_stale=True,
    )

    assert summary["completed"] is True
    assert summary["reused_context_map"] is True
    assert summary["stale_files"] == ["bad/app.py"]
