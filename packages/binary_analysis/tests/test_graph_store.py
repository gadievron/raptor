"""Direct unit tests for graph_store: schema migration, CRUD, query helpers."""

from __future__ import annotations

from pathlib import Path

from packages.binary_analysis.evidence import EvidenceTier, make_evidence
from packages.binary_analysis.graph_store import (
    BinaryGraphStore,
    SCHEMA_VERSION,
    graph_connection,
    graph_path_for_run,
    graph_summary,
    open_graph,
    query_edges,
    query_evidence,
    stable_edge_id,
    stable_node_id,
)


def test_stable_ids_are_deterministic():
    a = stable_node_id("abc123", "function", "main")
    b = stable_node_id("abc123", "function", "main")
    assert a == b
    assert a.startswith("node:function:")

    c = stable_node_id("abc123", "function", "other")
    assert a != c

    e1 = stable_edge_id("abc123", "CALLS", "n1", "n2")
    e2 = stable_edge_id("abc123", "CALLS", "n1", "n2")
    assert e1 == e2
    assert e1.startswith("edge:CALLS:")


def test_graph_path_for_run(tmp_path: Path):
    p = graph_path_for_run(tmp_path / "some-run")
    assert p == tmp_path / "some-run" / "graph" / "binary-graph.sqlite"


def test_open_graph_creates_schema(tmp_path: Path):
    db_path = tmp_path / "graph.sqlite"
    conn = open_graph(db_path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "snapshots" in tables
        assert "nodes" in tables
        assert "edges" in tables
        assert "evidence" in tables
    finally:
        conn.close()


def test_graph_connection_context_manager_closes(tmp_path: Path):
    db_path = tmp_path / "graph.sqlite"
    with graph_connection(db_path) as conn:
        conn.execute("SELECT 1")
    # After exiting the context manager, the connection should be closed.
    # Attempting to use it should raise.
    try:
        conn.execute("SELECT 1")
        closed = False
    except Exception:
        closed = True
    assert closed, "graph_connection should close the connection on exit"


def test_store_snapshot_and_node_lifecycle(tmp_path: Path):
    db_path = tmp_path / "graph" / "binary-graph.sqlite"
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(
            "deadbeef" * 8, "/path/to/binary", tmp_path
        )
        assert snap_id.startswith("snap:")

        node_id = store.add_node(
            snap_id, "deadbeef" * 8, "function", "main",
            name="main", address="0x1000",
        )
        assert node_id.startswith("node:function:")

        latest = store.latest_snapshot_id()
        assert latest == snap_id
    finally:
        store.close()


def test_store_edge_and_evidence(tmp_path: Path):
    db_path = tmp_path / "graph" / "binary-graph.sqlite"
    sha = "abcd1234" * 8
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(sha, "/path/to/bin", tmp_path)

        ev = make_evidence(
            sha, kind="import_analysis", source="r2",
            summary="Found strcpy import", tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate", reproducible=True, tool="radare2",
        )
        store.add_evidence(snap_id, ev)

        n1 = store.add_node(snap_id, sha, "function", "caller", name="caller")
        n2 = store.add_node(snap_id, sha, "function", "callee", name="callee")
        edge_id = store.add_edge(
            snap_id, sha, "CALLS", n1, n2,
            confidence="xref_backed", evidence_ids=[ev.id],
        )
        assert edge_id.startswith("edge:CALLS:")
    finally:
        store.close()


def test_graph_summary_returns_counts(tmp_path: Path):
    db_path = tmp_path / "graph" / "binary-graph.sqlite"
    sha = "cafe0000" * 8
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(sha, "/bin/test", tmp_path)
        store.add_node(snap_id, sha, "function", "f1", name="f1")
        store.add_node(snap_id, sha, "function", "f2", name="f2")
        store.add_node(snap_id, sha, "import", "strcpy", name="strcpy")
        ev = make_evidence(
            sha, kind="test", source="test", summary="test",
            tier=EvidenceTier.XREF_BACKED, confidence="candidate",
            reproducible=True, tool="test",
        )
        store.add_evidence(snap_id, ev)
    finally:
        store.close()

    summary = graph_summary(db_path)
    assert summary["exists"] is True
    assert summary["nodes"]["function"] == 2
    assert summary["nodes"]["import"] == 1
    assert summary["evidence"]["xref_backed"] == 1


def test_query_edges_with_kind_filter(tmp_path: Path):
    db_path = tmp_path / "graph" / "binary-graph.sqlite"
    sha = "11112222" * 8
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(sha, "/bin/test", tmp_path)
        n1 = store.add_node(snap_id, sha, "function", "a", name="func_a")
        n2 = store.add_node(snap_id, sha, "function", "b", name="func_b")
        n3 = store.add_node(snap_id, sha, "import", "strcpy", name="strcpy")
        store.add_edge(snap_id, sha, "CALLS", n1, n2)
        store.add_edge(snap_id, sha, "IMPORTS", n2, n3)
    finally:
        store.close()

    all_edges = query_edges(db_path)
    assert len(all_edges) == 2

    call_edges = query_edges(db_path, kind="CALLS")
    assert len(call_edges) == 1
    assert call_edges[0]["kind"] == "CALLS"
    assert call_edges[0]["source"]["name"] == "func_a"
    assert call_edges[0]["target"]["name"] == "func_b"


def test_query_evidence_with_tier_filter(tmp_path: Path):
    db_path = tmp_path / "graph" / "binary-graph.sqlite"
    sha = "33334444" * 8
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(sha, "/bin/test", tmp_path)
        ev1 = make_evidence(
            sha, kind="import", source="r2", summary="s1",
            tier=EvidenceTier.HEADER_BACKED, confidence="candidate",
            reproducible=True, tool="r2",
        )
        ev2 = make_evidence(
            sha, kind="runtime", source="frida", summary="s2",
            tier=EvidenceTier.OBSERVED_RUNTIME, confidence="confirmed",
            reproducible=False, tool="frida",
        )
        store.add_evidence(snap_id, ev1)
        store.add_evidence(snap_id, ev2)
    finally:
        store.close()

    all_ev = query_evidence(db_path)
    assert len(all_ev) == 2

    runtime_ev = query_evidence(db_path, tier="observed_runtime")
    assert len(runtime_ev) == 1
    assert runtime_ev[0]["tier"] == "observed_runtime"
    assert runtime_ev[0]["reproducible"] is False


def test_graph_summary_nonexistent_path(tmp_path: Path):
    result = graph_summary(tmp_path / "nope.sqlite")
    assert result["exists"] is False


def test_query_edges_nonexistent_path(tmp_path: Path):
    assert query_edges(tmp_path / "nope.sqlite") == []


def test_query_evidence_nonexistent_path(tmp_path: Path):
    assert query_evidence(tmp_path / "nope.sqlite") == []
