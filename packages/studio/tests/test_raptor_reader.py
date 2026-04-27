"""Smoke tests for the raptor project reader.

Uses the bundled fixture in fixtures/ to verify the reader parses
raptor's project.json + .raptor-run.json schema correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.studio.services.raptor_reader import (
    RaptorProject,
    RaptorRun,
    list_projects,
    get_project,
)


@pytest.fixture
def fixture_projects_dir(tmp_path: Path) -> Path:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    output_root = tmp_path / "output"
    project_output = output_root / "sample"
    project_output.mkdir(parents=True)

    (projects_dir / "sample.json").write_text(json.dumps({
        "version": 1,
        "name": "sample",
        "target": "/tmp/sample-repo",
        "output_dir": str(project_output),
        "description": "fixture project",
    }))

    run_dir = project_output / "scan_sample_20260423-120000"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(json.dumps({
        "version": 1,
        "command": "raptor agentic /tmp/sample-repo",
        "timestamp": "2026-04-23T12:00:00Z",
        "status": "completed",
        "extra": {},
    }))
    (run_dir / "findings.json").write_text(json.dumps([
        {
            "id": "finding-1",
            "file": "src/app.py",
            "line": 42,
            "vuln_type": "command_injection",
            "cwe_id": "CWE-78",
            "severity_assessment": "high",
            "confidence": "high",
            "attack_scenario": "User-controlled input flows into os.system",
            "proof": {
                "vulnerable_code": "os.system(f'ls {user_input}')",
                "flow": ["input arrives at request", "input flows to os.system"],
            },
            "poc": {"payload": "; rm -rf /"},
        }
    ]))
    return projects_dir


def test_list_projects_empty(tmp_path: Path):
    assert list_projects(tmp_path) == []


def test_list_projects_reads_fixture(fixture_projects_dir: Path):
    projects = list_projects(fixture_projects_dir)
    assert len(projects) == 1
    assert projects[0].name == "sample"
    assert projects[0].target == "/tmp/sample-repo"
    assert projects[0].exists_on_disk


def test_get_project_by_name(fixture_projects_dir: Path):
    proj = get_project("sample", fixture_projects_dir)
    assert proj is not None
    assert proj.name == "sample"


def test_project_runs(fixture_projects_dir: Path):
    proj = get_project("sample", fixture_projects_dir)
    assert proj is not None
    runs = proj.runs()
    assert len(runs) == 1
    assert runs[0].status == "completed"
    assert runs[0].kind == "agentic"


def test_run_findings(fixture_projects_dir: Path):
    proj = get_project("sample", fixture_projects_dir)
    assert proj is not None
    findings = proj.runs()[0].findings()
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "command_injection"
    assert findings[0]["cwe_id"] == "CWE-78"


def test_missing_project_returns_none(fixture_projects_dir: Path):
    assert get_project("nonexistent", fixture_projects_dir) is None


def test_malformed_project_json_skipped(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (projects_dir / "broken.json").write_text("{not valid json")
    (projects_dir / "good.json").write_text(json.dumps({
        "version": 1, "name": "good", "target": "/tmp/x",
        "output_dir": str(tmp_path / "out"),
    }))
    projects = list_projects(projects_dir)
    assert len(projects) == 1
    assert projects[0].name == "good"
