"""ingest_run hardening + rebuild_graph durability.

ingest_run was the one producer without the sibling envelope
(shape guard, BEGIN IMMEDIATE, except-skip): a list-shaped
checklist.json crashed it with AttributeError. rebuild_graph deleted
the durable graph FIRST and ingested unguarded, so one malformed run
directory converted the project's whole cross-run memory into
nothing; called on a non-project directory it resolved to the ACTIVE
project's graph and deleted that. These tests pin the sibling
envelope, per-run best-effort, the temp-store swap, and the
containment refusal.
"""

import json

import pytest

from core.json import save_json
from core.understand_graph import ingest_run, rebuild_graph
from core.understand_graph.store import open_graph


def _write_run_artifacts(run_dir, target, ts="2026-01-01T00:00:00Z"):
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / ".raptor-run.json", {
        "version": 2, "command": "understand", "timestamp": ts,
        "status": "completed", "target_path": str(target),
    })
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 1,
        "files": [{"path": "main.c", "sha256": "abc",
                   "items": [{"name": "main", "line_start": 1}]}],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "E1", "name": "main", "file": "main.c", "line": 1}],
        "sinks": [{"id": "S1", "name": "system", "file": "main.c", "line": 5}],
        "unchecked_flows": [{"id": "F1", "entry_point": "E1", "sink": "S1",
                             "confidence": "high"}],
    })


def _write_malformed_run(run_dir, target, ts):
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / ".raptor-run.json", {
        "version": 2, "command": "understand", "timestamp": ts,
        "status": "completed", "target_path": str(target),
    })
    (run_dir / "checklist.json").write_text(
        json.dumps(["not", "a", "dict"]), encoding="utf-8")
    save_json(run_dir / "context-map.json", {"meta": {"target": str(target)}})


def _node_count(graph_path):
    with open_graph(graph_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM nodes WHERE stale=0"
        ).fetchone()["c"]


def test_ingest_run_skips_junk_checklist_shape(tmp_path, capsys):
    """A list-shaped checklist.json beside a context-map degrades to a
    skipped ingest — never an AttributeError into the caller."""
    target = tmp_path / "target"
    target.mkdir()
    run_dir = tmp_path / "run"
    _write_malformed_run(run_dir, target, "2026-01-01T00")

    result = ingest_run(run_dir, str(target))
    # No crash. Whether anything ingests is shape-dependent; junk must
    # never propagate.
    assert result is None or result.exists()


def test_ingest_run_atomic_on_mid_ingest_crash(tmp_path, monkeypatch):
    """The primary understand ingest gets the sibling transaction: a
    crash mid-ingest leaves no partial snapshot behind."""
    import sqlite3

    from core.understand_graph import ingest as ingest_mod

    target = tmp_path / "target"
    target.mkdir()
    run_dir = tmp_path / "run"
    _write_run_artifacts(run_dir, target)

    original = ingest_mod._ingest_context_map

    def bomb(conn, snap_id, context_map):
        original(conn, snap_id, context_map)
        raise sqlite3.OperationalError("simulated crash")

    monkeypatch.setattr(ingest_mod, "_ingest_context_map", bomb)
    result = ingest_run(run_dir, str(target))
    assert result is None

    graph_path = run_dir / "graph" / "raptor.graph.sqlite"
    if graph_path.exists():
        with open_graph(graph_path) as conn:
            snaps = conn.execute(
                "SELECT COUNT(*) AS c FROM snapshots").fetchone()["c"]
        assert snaps == 0, "partial understand snapshot survived the crash"


def test_rebuild_survives_malformed_run_dir(tmp_path):
    """One malformed run dir sorting FIRST costs that run only — the
    good runs after it still rebuild (pre-fix: delete-first + abort ->
    nodes 7 -> 0 and a traceback out of /project graph rebuild)."""
    target = tmp_path / "target"
    target.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".raptor-project-root").touch()

    _write_run_artifacts(project_dir / "run_b", target, ts="2026-01-02T00")
    graph_path = rebuild_graph(project_dir)
    assert graph_path is not None
    baseline = _node_count(graph_path)
    assert baseline > 0

    _write_malformed_run(project_dir / "run_a", target, ts="2026-01-01T00")
    result = rebuild_graph(project_dir)
    assert result is not None
    assert _node_count(result) >= baseline


def test_rebuild_interrupt_keeps_previous_graph(tmp_path, monkeypatch):
    """An interrupt mid-rebuild (BaseException past the per-run
    best-effort net) must leave the previous durable graph in place —
    the rebuild works in a temp store swapped only on success."""
    target = tmp_path / "target"
    target.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".raptor-project-root").touch()

    _write_run_artifacts(project_dir / "run_b", target, ts="2026-01-02T00")
    graph_path = rebuild_graph(project_dir)
    baseline = _node_count(graph_path)
    assert baseline > 0

    from core.understand_graph import ingest as ingest_mod

    def interrupt(*_args, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(ingest_mod, "ingest_run", interrupt)
    with pytest.raises(KeyboardInterrupt):
        rebuild_graph(project_dir)

    assert graph_path.exists(), "previous graph destroyed by interrupted rebuild"
    assert _node_count(graph_path) == baseline


def test_rebuild_refuses_foreign_directory(tmp_path, capsys):
    """rebuild_graph(<dir that is not a project/run dir>) with an
    ACTIVE project used to resolve to the active project's graph,
    DELETE it, and return None. The resolved store must live under
    the passed directory or the rebuild refuses."""
    from core.project.project import ProjectManager

    target = tmp_path / "target"
    target.mkdir()
    proj_out = tmp_path / "projout"

    mgr = ProjectManager()
    mgr.create("rebuild-foreign-dir", str(target),
               output_dir=str(proj_out), resolve_target=False)
    mgr.set_active("rebuild-foreign-dir")
    try:
        _write_run_artifacts(proj_out / "run_a", target)
        graph_path = rebuild_graph(proj_out)
        assert graph_path is not None
        baseline = _node_count(graph_path)
        assert baseline > 0

        foreign = tmp_path / "some-random-dir"
        foreign.mkdir()
        result = rebuild_graph(foreign)
        assert result is None
        assert graph_path.exists(), (
            "active project's graph deleted by a foreign-dir rebuild"
        )
        assert _node_count(graph_path) == baseline
        assert "refus" in capsys.readouterr().err.lower()
    finally:
        mgr.delete("rebuild-foreign-dir")
