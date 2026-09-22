"""The graph-memory fallback only answers for THIS directory's target.

The persistent graph serves the latest snapshot for a target — and the
latest any-target snapshot when the requested target has none. The
renderer must therefore derive the directory's target honestly (sealed
run metadata first, existence-gated checklist hint second) and refuse
to serve the fallback section rather than render another codebase's
context map.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.json import save_json

from ..renderer import render_directory


def _isolate_projects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep graph_path_for_run away from the host's real projects."""
    monkeypatch.setattr(
        "core.project.project.ProjectManager.list_projects",
        lambda self: [],
    )
    monkeypatch.setattr(
        "core.project.project.ProjectManager.get_active",
        lambda self: None,
    )
    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target, content_id=None: None,
    )


def _write_understand_artifacts(run_dir: Path, target: Path) -> None:
    src = target / "app.py"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        "def handle():\n    return request.args['q']\n", encoding="utf-8",
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "files": [{"path": "app.py", "language": "python", "items": []}],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target), "app_type": "web_app"},
        "entry_points": [{
            "id": "EP-001", "type": "http_route", "name": "GET /search",
            "file": "app.py", "line": 1,
        }],
        "sink_details": [{
            "id": "SINK-001", "type": "template", "name": "render",
            "file": "app.py", "line": 2,
        }],
        "unchecked_flows": [{
            "entry_point": "EP-001", "sink": "SINK-001",
            "missing_boundary": "No output encoding", "confidence": "high",
        }],
    })


def _ingest_and_strip(run_dir: Path, target: Path,
                      monkeypatch: pytest.MonkeyPatch) -> None:
    """Ingest the run into run_dir/graph, then remove the file-lane
    artifacts so only the graph fallback can serve."""
    from core.understand_graph import ingest_run

    _isolate_projects(monkeypatch)
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path == run_dir / "graph" / "raptor.graph.sqlite"
    assert graph_path.exists()
    (run_dir / "context-map.json").unlink()
    (run_dir / "checklist.json").unlink()


def _seal_target(run_dir: Path, target: Path) -> None:
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"command": "understand", "status": "completed",
                    "target_path": str(target)}),
        encoding="utf-8",
    )


def test_fallback_renders_for_matching_sealed_target(tmp_path, monkeypatch):
    target = tmp_path / "codebase"
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target)
    _ingest_and_strip(run_dir, target, monkeypatch)
    _seal_target(run_dir, target)

    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" in out
    assert "GET /search" in out


def test_fallback_renders_for_existence_gated_checklist_hint(
        tmp_path, monkeypatch):
    # Legacy run: no sealed metadata; the checklist hint names an
    # existing directory and nothing contradicts it.
    target = tmp_path / "codebase"
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target)
    _ingest_and_strip(run_dir, target, monkeypatch)
    save_json(run_dir / "checklist.json", {"target_path": str(target)})

    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" in out


def test_fallback_absent_without_derivable_target(tmp_path, monkeypatch):
    # Graph exists, but neither sealed metadata nor a checklist hint —
    # serving it would be an any-target answer.
    target = tmp_path / "codebase"
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target)
    _ingest_and_strip(run_dir, target, monkeypatch)

    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" not in out
    assert "GET /search" not in out


def test_fallback_absent_when_hint_is_not_an_existing_directory(
        tmp_path, monkeypatch):
    target = tmp_path / "codebase"
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target)
    _ingest_and_strip(run_dir, target, monkeypatch)
    save_json(run_dir / "checklist.json",
              {"target_path": str(tmp_path / "gone")})

    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" not in out


def test_fallback_absent_when_graph_serves_another_codebase(
        tmp_path, monkeypatch):
    # The graph's only snapshot belongs to codebase B; the directory's
    # sealed target is codebase A. build_context_map(…, A) falls back
    # to B's latest snapshot in this tree — the renderer must detect
    # the served-target mismatch and drop the section.
    target_a = tmp_path / "codebase-a"
    target_a.mkdir()
    target_b = tmp_path / "codebase-b"
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target_b)
    _ingest_and_strip(run_dir, target_b, monkeypatch)
    _seal_target(run_dir, target_a)

    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" not in out
    assert "GET /search" not in out


def test_checklist_hint_contradicting_sealed_record_is_refused(
        tmp_path, monkeypatch):
    target = tmp_path / "codebase"
    other = tmp_path / "other"
    other.mkdir()
    run_dir = tmp_path / "run"
    _write_understand_artifacts(run_dir, target)
    _ingest_and_strip(run_dir, target, monkeypatch)
    # Sealed record names the real target; the checklist hint points
    # at a different (existing) directory — corroboration must refuse.
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"command": "understand", "status": "completed",
                    "target_path": str(target)}),
        encoding="utf-8",
    )
    save_json(run_dir / "checklist.json", {"target_path": str(other)})

    # Sealed target wins outright (it is read first), so the section
    # renders for the SEALED target, not the drifted hint.
    out = render_directory(run_dir)
    assert "Context Map from Graph Memory" in out
