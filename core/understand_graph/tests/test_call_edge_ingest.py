"""Lean batched call-edge ingest (``ingest_call_edges``).

Pins the substrate contract the context-map routing relies on: lean
rows (no per-edge evidence/props payload), dedupe, executemany
chunking, mechanical provenance + run-bound tokens, snapshot
supersede-in-place, and the unstamped degradation when no usable key
exists (rows persist, verdict-feeding view refuses the lane).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from core.understand_graph import ingest as ingest_mod
from core.understand_graph.ingest import ingest_call_edges
from core.understand_graph.queries import verified_mechanical_call_edges
from core.understand_graph.store import open_graph

_EDGES = [
    {"caller_file": "a.c", "caller": "main", "callee": "parse",
     "callee_file": "a.c"},
    {"caller_file": "a.c", "caller": "parse", "callee": "strcpy",
     "callee_file": ""},
    {"caller_file": "b.c", "caller": "handler", "callee": "parse",
     "callee_file": "a.c"},
]


def _ingest(tmp_path: Path, edges=None, **kwargs):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    graph = tmp_path / "graph" / "raptor.graph.sqlite"
    kwargs.setdefault("graph_path", graph)
    return ingest_call_edges(
        run_dir, "/target", list(_EDGES) if edges is None else edges,
        **kwargs)


def test_round_trip_complete_verified(tmp_path):
    result = _ingest(tmp_path)
    assert result is not None
    assert result["edges"] == 3
    assert result["stamped"] is True
    lane = verified_mechanical_call_edges(
        result["graph_path"], result["snapshot"], "/target")
    assert lane is not None
    assert lane["complete"] is True
    assert sorted(
        (e["caller"], e["callee"]) for e in lane["edges"]
    ) == [("handler", "parse"), ("main", "parse"), ("parse", "strcpy")]


def test_rows_are_lean(tmp_path):
    """CALLS rows carry no per-edge evidence/props payload — the blob
    is what made the per-row upsert lane unaffordable at 10^6 rows."""
    result = _ingest(tmp_path)
    conn = open_graph(result["graph_path"])
    try:
        rows = conn.execute(
            "SELECT evidence_json, props_json, provenance FROM edges "
            "WHERE kind='CALLS'").fetchall()
        assert rows
        for row in rows:
            assert row["evidence_json"] == "{}"
            assert row["props_json"] == "{}"
            assert row["provenance"] == "mechanical"
    finally:
        conn.close()


def test_duplicates_and_junk_collapse(tmp_path):
    edges = list(_EDGES) * 3 + [
        {"caller": "", "callee": "x"},
        {"caller": "y", "callee": ""},
        "not-a-dict",
    ]
    result = _ingest(tmp_path, edges=edges)
    assert result is not None
    assert result["edges"] == 3


def test_empty_input_is_none(tmp_path):
    assert _ingest(tmp_path, edges=[]) is None
    assert not (tmp_path / "graph" / "raptor.graph.sqlite").exists()


def test_unresolvable_target_is_none(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert ingest_call_edges(run_dir, None, list(_EDGES)) is None
    assert "ingest skipped" in capsys.readouterr().err


def test_chunked_executemany_batches(tmp_path, monkeypatch):
    """Multi-chunk writes land every row exactly once."""
    monkeypatch.setattr(ingest_mod, "_EDGE_EXECUTEMANY_CHUNK", 2)
    result = _ingest(tmp_path)
    lane = verified_mechanical_call_edges(
        result["graph_path"], result["snapshot"])
    assert lane["complete"] is True
    assert len(lane["edges"]) == 3


def test_reingest_supersedes_same_snapshot(tmp_path):
    r1 = _ingest(tmp_path)
    r2 = _ingest(tmp_path)
    assert r1["snapshot"] == r2["snapshot"]
    conn = open_graph(r1["graph_path"])
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM snapshots WHERE producer='callgraph'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind='CALLS'"
        ).fetchone()[0] == 3
    finally:
        conn.close()


def test_checklist_hash_keys_snapshot_identity(tmp_path):
    r1 = _ingest(tmp_path, checklist_hash="aaa")
    r2 = _ingest(tmp_path, checklist_hash="bbb")
    assert r1["snapshot"] != r2["snapshot"]


def test_unstamped_when_no_key(tmp_path, monkeypatch):
    """No usable key: rows persist (hint tier) but the verdict-feeding
    view refuses the lane."""
    from core.understand_graph import integrity

    monkeypatch.setattr(integrity, "_load_or_create_key", lambda: None)
    result = _ingest(tmp_path)
    assert result is not None
    assert result["stamped"] is False
    conn = open_graph(result["graph_path"])
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind='CALLS'"
        ).fetchone()[0] == 3
    finally:
        conn.close()
    monkeypatch.undo()
    assert verified_mechanical_call_edges(
        result["graph_path"], result["snapshot"]) is None


def test_junk_store_costs_the_ingest_not_the_caller(tmp_path):
    graph = tmp_path / "graph" / "raptor.graph.sqlite"
    graph.parent.mkdir(parents=True)
    conn = sqlite3.connect(graph)
    conn.execute("CREATE TABLE snapshots (id TEXT)")  # wrong shape
    conn.execute("PRAGMA user_version=4")
    conn.commit()
    conn.close()
    assert _ingest(tmp_path) is None
