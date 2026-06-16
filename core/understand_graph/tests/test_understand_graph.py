import hashlib
import json
import sqlite3
from pathlib import Path

from core.json import save_json
from core.orchestration.understand_bridge import load_understand_graph_context
from core.understand_graph import (
    build_context_map,
    graph_path_for_run,
    graph_summary,
    ingest_run,
    prompt_context_for_location,
    reachable_sinks,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fixture_run(run_dir: Path, target: Path) -> None:
    src = target / "app.py"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("def handle():\n    return request.args['q']\n", encoding="utf-8")
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 1,
        "files": [{
            "path": "app.py",
            "language": "python",
            "sha256": _sha(src),
            "items": [{
                "kind": "function",
                "name": "handle",
                "line_start": 1,
                "line_end": 2,
            }],
        }],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target), "app_type": "web_app"},
        "sources": [{"type": "http_route", "entry": "GET /search @ app.py:1"}],
        "sinks": [{"type": "template", "location": "app.py:2"}],
        "trust_boundaries": [{"boundary": "HTTP request", "check": "none"}],
        "entry_points": [{
            "id": "EP-001",
            "type": "http_route",
            "name": "GET /search",
            "file": "app.py",
            "line": 1,
        }],
        "sink_details": [{
            "id": "SINK-001",
            "type": "template",
            "name": "render",
            "file": "app.py",
            "line": 2,
        }],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No output encoding before template sink",
            "confidence": "high",
        }],
    })


def test_ingest_summary_and_context_map(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_fixture_run(run_dir, target)

    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    assert graph_path.exists()

    summary = graph_summary(graph_path)
    assert summary["exists"] is True
    assert summary["nodes"]["entry_point"] == 1
    assert summary["nodes"]["sink"] >= 1
    assert summary["edges"]["REACHES"] == 1

    context_map, stale = build_context_map(graph_path, str(target))
    assert stale == set()
    assert context_map["entry_points"][0]["id"] == "EP-001"
    assert context_map["unchecked_flows"][0]["sink"] == "SINK-001"
    assert reachable_sinks(graph_path, str(target))[0]["sink"] == "render"


def test_context_map_backfills_name_from_graph_row(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_fixture_run(run_dir, target)

    graph_path = ingest_run(run_dir, str(target))
    with sqlite3.connect(graph_path) as conn:
        row = conn.execute(
            "SELECT id, props_json FROM nodes WHERE kind='entry_point' LIMIT 1"
        ).fetchone()
        props = json.loads(row[1])
        props.pop("name", None)
        props.pop("entry", None)
        props.pop("path", None)
        conn.execute(
            "UPDATE nodes SET props_json=? WHERE id=?",
            (json.dumps(props, sort_keys=True), row[0]),
        )

    context_map, stale = build_context_map(graph_path, str(target))
    assert stale == set()
    assert context_map["entry_points"][0]["name"] == "GET /search"
    assert context_map["entry_points"][0]["entry"] == "GET /search"


def test_prompt_context_for_location(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_fixture_run(run_dir, target)
    graph_path = ingest_run(run_dir, str(target))

    block = prompt_context_for_location(graph_path, "app.py", 2)
    assert "Graph memory from prior /understand runs" in block
    assert "sink" in block


def test_validation_bridge_can_load_project_graph(tmp_path, monkeypatch):
    target = tmp_path / "target"
    project_dir = tmp_path / "project"
    understand_dir = project_dir / "understand-1"
    validate_dir = project_dir / "validate-1"
    _write_fixture_run(understand_dir, target)
    validate_dir.mkdir(parents=True)
    save_json(validate_dir / "checklist.json", json.loads((understand_dir / "checklist.json").read_text()))

    class _Project:
        output_dir = str(project_dir)

    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target_arg, content_id=None: _Project(),
    )

    ingest_run(understand_dir, str(target))
    bridge = load_understand_graph_context(validate_dir, str(target))

    assert bridge["graph_loaded"] is True
    assert bridge["context_map_loaded"] is True
    assert (validate_dir / "attack-surface.json").exists()
    assert (validate_dir / "context-map.graph.json").exists()


def test_graph_path_prefers_project_containing_run_dir(tmp_path, monkeypatch):
    target = tmp_path / "target"
    project_a = tmp_path / "projects" / "a"
    project_b = tmp_path / "projects" / "b"
    run_dir = project_b / "understand-1"
    run_dir.mkdir(parents=True)

    class _Project:
        def __init__(self, name, output_dir):
            self.name = name
            self.output_dir = str(output_dir)
            self.target = str(target)

    monkeypatch.setattr(
        "core.project.project.ProjectManager.list_projects",
        lambda self: [_Project("a", project_a), _Project("b", project_b)],
    )
    monkeypatch.setattr(
        "core.project.project.ProjectManager.get_active",
        lambda self: "a",
    )
    monkeypatch.setattr(
        "core.project.project.ProjectManager.load",
        lambda self, name: _Project(name, project_a),
    )

    assert graph_path_for_run(run_dir, str(target)) == project_b / "graph" / "raptor.graph.sqlite"
