"""Every read lane rides the query_graph corruption/lock guard.

The store-guard series built the degrade contract (corruption-only
quarantine, lock retry, None -> consumer empty); these tests pin that
the WHOLE public read surface adopted it — a corrupt project graph
must cost "no graph memory", never a hard failure of /validate
stage 0, /understand --trace seeding, /project graph status, or
raptor-graph-query. The schema-newer refusal degrades the same way,
but keeps the file (it is from the future, not corrupt).
"""

import ast
import sqlite3
import textwrap
from pathlib import Path

import pytest

from core.understand_graph import queries as queries_mod
from core.understand_graph.store import open_graph

_QUERIES_SRC = Path(queries_mod.__file__)

# Write lanes in queries.py that legitimately open the graph directly.
_DIRECT_OPEN_ALLOWED = {"propagate_binary_verdicts"}


def _corrupt_db(tmp_path: Path) -> Path:
    db = tmp_path / "g" / "raptor.graph.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"THIS IS NOT A SQLITE DATABASE " * 20)
    return db


def _read_lanes(db, target):
    """(callable, expected-empty) for every public read lane."""
    q = queries_mod
    return [
        (lambda: q.graph_summary(db), {"exists": False}),
        (lambda: q.build_context_map(db, target), ({}, set())),
        (lambda: q.reachable_sinks(db, target), []),
        (lambda: q.attack_paths(db, target), []),
        # reason is "graph unavailable" (degrade) or "graph not found"
        # (an earlier lane already quarantined the corrupt file) —
        # both are the non-diffable empty.
        (lambda: {"exists": q.graph_diff(db, target).get("exists")},
         {"exists": False}),
        (lambda: q.threat_model_graph_context(db, target), ""),
        (lambda: q.prompt_context_for_location(db, "server.c"), ""),
        (lambda: q.coverage_residual(db, target), []),
        (lambda: q.hypothesis_seeds(db, target), []),
        (lambda: q.fuzz_targets(db, target), []),
        (lambda: q.scan_dedup_chains(db, target), []),
        (lambda: q.alternative_paths(db, "sink-node-id", "blocked-node-id"), []),
        (lambda: q.sca_reachability(db, "somedep", target), []),
        (lambda: q.dashboard_summary(db),
         {"snapshots": [], "totals": {}, "validation_coverage": 0.0,
          "snapshot_count": 0}),
    ]


def test_corrupt_graph_degrades_every_read_lane(tmp_path):
    """Garbage bytes at the store path: every read lane returns its
    empty; the first guard hit quarantines the file (renamed aside,
    never silently unlinked) so subsequent runs self-heal."""
    target = str(tmp_path / "target")
    db = _corrupt_db(tmp_path)
    for fn, expected in _read_lanes(db, target):
        got = fn()
        assert got == expected, f"lane returned {got!r}, wanted {expected!r}"
    assert not db.exists(), "corrupt store must not persist and re-crash every run"
    assert list(db.parent.glob(db.name + ".corrupt-*")), (
        "corruption must quarantine (rename aside), never silently unlink"
    )


def test_schema_newer_degrades_and_keeps_the_store(tmp_path):
    """A store written by a newer RAPTOR: every lane (guarded and
    formerly-direct) degrades to its empty; the file is KEPT — it is
    not corrupt, and a newer RAPTOR can still read it."""
    target = str(tmp_path / "target")
    db = tmp_path / "g" / "raptor.graph.sqlite"
    conn = open_graph(db)
    conn.close()
    raw = sqlite3.connect(db)
    raw.execute("PRAGMA user_version=99")
    raw.commit()
    raw.close()

    for fn, expected in _read_lanes(db, target):
        got = fn()
        assert got == expected, f"lane returned {got!r}, wanted {expected!r}"
    assert db.exists(), "schema-newer store must never be removed"
    assert not list(db.parent.glob(db.name + ".corrupt-*"))


def _referenced_names(node: ast.AST) -> set[str]:
    """Every Name/Attribute identifier a function actually references
    — comments and string literals are invisible by construction."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.add(sub.attr)
    return names


def _census_offenders(tree: ast.Module) -> list[str]:
    """Functions (public AND private) that reference open_graph without
    routing through query_graph, minus the explicit write-lane
    allowlist. Direct opens are open_graph AND graph_connection (the
    unguarded transaction helper). AST-name-derived: a comment or
    string mentioning query_graph can never launder a direct open,
    and a private direct-open helper is an offender like any public
    lane."""
    offenders = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in _DIRECT_OPEN_ALLOWED:
            continue
        names = _referenced_names(node)
        direct_open = names & {"open_graph", "graph_connection"}
        if direct_open and "query_graph" not in names:
            offenders.append(node.name)
    return offenders


def test_no_read_lane_opens_the_graph_directly():
    """Mechanical census: every function in queries.py that touches
    open_graph routes through query_graph; direct open_graph is
    reserved for the allowlisted write lanes. This is the adoption
    oracle — a new query (public or private helper) added with a
    direct open re-opens the crash class."""
    tree = ast.parse(_QUERIES_SRC.read_text(encoding="utf-8"))
    assert _census_offenders(tree) == []


def test_census_catches_laundered_and_private_direct_opens():
    """The derivation itself is pinned: a comment or string mentioning
    query_graph must not launder a direct open, and a private
    direct-open helper is caught like any public lane."""
    planted = ast.parse(textwrap.dedent(
        """
        def sneaky_lane(db):
            # query_graph is mentioned here only in a comment
            with open_graph(db) as conn:
                return conn.execute("SELECT 1")

        def _private_helper(db):
            "query_graph named only in this string"
            return open_graph(db)

        def honest_lane(db):
            return query_graph(db, lambda conn: 1)

        def propagate_binary_verdicts(db):
            return open_graph(db)  # allowlisted write lane

        def txn_helper_lane(db):
            with graph_connection(db) as conn:
                return conn.execute("SELECT 1")
        """
    ))
    assert _census_offenders(planted) == [
        "sneaky_lane", "_private_helper", "txn_helper_lane",
    ]


def test_lock_contention_never_quarantines(tmp_path):
    """A held write lock degrades to None after retries with the file
    untouched (the guard's own contract, pinned here against the
    newly-adopted lanes)."""
    from core.understand_graph import store as store_mod

    db = tmp_path / "g" / "raptor.graph.sqlite"
    conn = open_graph(db)
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        orig_timeout = store_mod._BUSY_TIMEOUT_MS
        orig_delay = store_mod._LOCK_RETRY_DELAY_S
        store_mod._BUSY_TIMEOUT_MS = 1
        store_mod._LOCK_RETRY_DELAY_S = 0.0
        try:
            summary = queries_mod.dashboard_summary(db)
        finally:
            store_mod._BUSY_TIMEOUT_MS = orig_timeout
            store_mod._LOCK_RETRY_DELAY_S = orig_delay
    finally:
        conn.execute("ROLLBACK")
        conn.close()
    assert summary["snapshot_count"] == 0
    assert db.exists()


@pytest.mark.parametrize("lane", ["build_context_map", "graph_summary"])
def test_missing_db_still_returns_empty(tmp_path, lane):
    db = tmp_path / "nonexistent.db"
    fn = getattr(queries_mod, lane)
    result = fn(db)
    if lane == "graph_summary":
        assert result == {"exists": False}
    else:
        assert result == ({}, set())
