"""Keep-N retention for callgraph snapshots.

Each callgraph snapshot carries the full mechanical edge set, so
unbounded per-run snapshots grow the store without bound. Retention
deletes superseded ``producer='callgraph'`` snapshots (cascading their
node/edge rows) on ingest — and touches nothing else: other producers'
snapshots and other targets' callgraph snapshots survive.
"""

from __future__ import annotations

from pathlib import Path

from core.understand_graph import ingest as ingest_mod
from core.understand_graph.ingest import ingest_call_edges
from core.understand_graph.store import open_graph

_EDGES = [
    {"caller_file": "a.c", "caller": "main", "callee": "parse",
     "callee_file": "a.c"},
    {"caller_file": "a.c", "caller": "parse", "callee": "strcpy",
     "callee_file": ""},
]


def _ingest(tmp_path: Path, checklist_hash: str, target: str = "/target"):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return ingest_call_edges(
        run_dir, target, list(_EDGES),
        checklist_hash=checklist_hash,
        graph_path=tmp_path / "graph" / "raptor.graph.sqlite",
    )


def _counts(graph_path: Path) -> tuple[int, int, int]:
    conn = open_graph(graph_path)
    try:
        snaps = conn.execute(
            "SELECT COUNT(*) FROM snapshots WHERE producer='callgraph'"
        ).fetchone()[0]
        edges = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind='CALLS'").fetchone()[0]
        nodes = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE kind='function'"
        ).fetchone()[0]
        return snaps, edges, nodes
    finally:
        conn.close()


def test_keep_n_bounds_snapshots_and_cascades_rows(tmp_path):
    results = [_ingest(tmp_path, h) for h in ("h1", "h2", "h3")]
    graph = results[0]["graph_path"]
    snaps, edges, nodes = _counts(graph)
    assert snaps == ingest_mod.CALLGRAPH_SNAPSHOT_KEEP == 2
    # Cascade: only the retained snapshots' rows remain.
    assert edges == 2 * len(_EDGES)
    assert nodes == 2 * 3  # three unique functions per snapshot
    conn = open_graph(graph)
    try:
        kept = {
            row["id"] for row in
            conn.execute("SELECT id FROM snapshots WHERE producer='callgraph'")
        }
    finally:
        conn.close()
    # Newest two survive; the first ingest's snapshot is gone.
    assert results[2]["snapshot"] in kept
    assert results[1]["snapshot"] in kept
    assert results[0]["snapshot"] not in kept


def test_keep_1_supersedes_on_ingest(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_mod, "CALLGRAPH_SNAPSHOT_KEEP", 1)
    _ingest(tmp_path, "h1")
    r2 = _ingest(tmp_path, "h2")
    snaps, edges, _nodes = _counts(r2["graph_path"])
    assert snaps == 1
    assert edges == len(_EDGES)


def test_other_producers_and_targets_untouched(tmp_path):
    graph = tmp_path / "graph" / "raptor.graph.sqlite"
    conn = open_graph(graph)
    try:
        conn.execute(
            "INSERT INTO snapshots (id, target_path, producer) "
            "VALUES ('snap-und', '/target', 'understand')")
        conn.commit()
    finally:
        conn.close()
    other = _ingest(tmp_path, "hx", target="/other-target")
    for h in ("h1", "h2", "h3", "h4"):
        _ingest(tmp_path, h)
    conn = open_graph(graph)
    try:
        rows = conn.execute(
            "SELECT id, target_path, producer FROM snapshots").fetchall()
    finally:
        conn.close()
    ids = {row["id"] for row in rows}
    assert "snap-und" in ids  # other producer survives
    assert other["snapshot"] in ids  # other target survives
    assert sum(
        1 for row in rows
        if row["producer"] == "callgraph" and row["target_path"] == "/target"
    ) == 2
