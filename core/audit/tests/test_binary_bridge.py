"""Tests for core.audit.binary_bridge and its wiring into priority/evidence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.audit.binary_bridge import (
    BinaryBridgeResult,
    BinaryParserBoundary,
    BinaryRankedSurface,
    BinarySinkEdge,
    _load_binary_context_map,
    _load_graph_sink_edges,
    _load_investigation,
    find_binary_run_dirs,
    load_binary_bridge,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _write_investigation(run_dir: Path, data: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "binary-investigation.json").write_text(json.dumps(data))


def _write_context_map(run_dir: Path, data: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "binary-context-map.json").write_text(json.dumps(data))


def _create_graph_store(run_dir: Path, edges: list,
                        stamp: bool = True) -> None:
    """Create a minimal graph store SQLite database with edges.

    ``stamp=True`` (default) mints the writer-close provenance stamp
    the consumer requires; ``stamp=False`` models a legacy or planted
    store."""
    graph_dir = run_dir / "graph"
    graph_dir.mkdir(parents=True, exist_ok=True)
    db_path = graph_dir / "binary-graph.sqlite"

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO metadata(key,value) VALUES ('schema_version','1')")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY, binary_sha256 TEXT,
                binary_path TEXT, created_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                snapshot_id TEXT, id TEXT, kind TEXT,
                stable_key TEXT, name TEXT DEFAULT '',
                address TEXT DEFAULT '', props_json TEXT DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                snapshot_id TEXT, id TEXT, kind TEXT,
                src_id TEXT, dst_id TEXT,
                confidence TEXT DEFAULT '', props_json TEXT DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                snapshot_id TEXT, id TEXT, kind TEXT, tier TEXT,
                confidence TEXT, reproducible INTEGER, source TEXT,
                tool TEXT, summary TEXT, props_json TEXT DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id)
            )
        """)
        conn.execute("CREATE TABLE IF NOT EXISTS node_evidence (snapshot_id TEXT, node_id TEXT, evidence_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS edge_evidence (snapshot_id TEXT, edge_id TEXT, evidence_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS artifacts (snapshot_id TEXT, kind TEXT, path TEXT, sha256 TEXT DEFAULT '')")

        snap_id = "snap1"
        conn.execute(
            "INSERT INTO snapshots VALUES (?,?,?,?)",
            (snap_id, "abc123", "/path/to/binary", "2026-01-01T00:00:00"),
        )

        for i, edge in enumerate(edges):
            src_id = f"node:fn:{i}"
            dst_id = f"node:import:{i}"
            conn.execute(
                "INSERT INTO nodes VALUES (?,?,?,?,?,?,?)",
                (snap_id, src_id, "function", f"key_{i}",
                 edge["caller"], "0x1000", "{}"),
            )
            conn.execute(
                "INSERT INTO nodes VALUES (?,?,?,?,?,?,?)",
                (snap_id, dst_id, edge.get("dst_kind", "import"), f"key_dst_{i}",
                 edge["sink"], "0x2000", "{}"),
            )
            conn.execute(
                "INSERT INTO edges VALUES (?,?,?,?,?,?,?)",
                (snap_id, f"edge:{i}", edge["kind"],
                 src_id, dst_id, edge.get("confidence", "candidate"),
                 json.dumps(edge.get("props", {}))),
            )

        conn.commit()
    finally:
        conn.close()
    if stamp:
        from packages.binary_analysis.graph_store import stamp_graph_store
        stamp_graph_store(db_path)


def _set_snapshot_identity(run_dir: Path, *, sha: str | None = None,
                           path: str | None = None) -> None:
    """Rewrite the store's snapshot identity fields and re-stamp.

    The provenance stamp covers db content, not binary identity, so a
    re-stamped rewrite models a store this install LEGITIMATELY
    produced for some binary — the exact artifact a sidecar replay
    carries into another run dir."""
    db_path = run_dir / "graph" / "binary-graph.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        if sha is not None:
            conn.execute("UPDATE snapshots SET binary_sha256=?", (sha,))
        if path is not None:
            conn.execute("UPDATE snapshots SET binary_path=?", (path,))
        conn.commit()
    finally:
        conn.close()
    from packages.binary_analysis.graph_store import stamp_graph_store
    stamp_graph_store(db_path)


# ── find_binary_run_dirs ─────────────────────────────────────────────


class TestFindBinaryRunDirs:
    def test_finds_dirs_with_graph_store(self, tmp_path):
        _create_graph_store(tmp_path / "run1", [])
        current = tmp_path / "current"
        current.mkdir()
        dirs = find_binary_run_dirs(current)
        assert len(dirs) == 1
        assert dirs[0] == tmp_path / "run1"

    def test_finds_dirs_with_investigation(self, tmp_path):
        _write_investigation(tmp_path / "run1", {"facts": []})
        current = tmp_path / "current"
        current.mkdir()
        dirs = find_binary_run_dirs(current)
        assert len(dirs) == 1

    def test_finds_dirs_with_context_map(self, tmp_path):
        _write_context_map(tmp_path / "run1", {"sinks": []})
        current = tmp_path / "current"
        current.mkdir()
        dirs = find_binary_run_dirs(current)
        assert len(dirs) == 1

    def test_excludes_current_dir(self, tmp_path):
        _write_investigation(tmp_path / "current", {"facts": []})
        dirs = find_binary_run_dirs(tmp_path / "current")
        assert dirs == []

    def test_respects_max_dirs(self, tmp_path):
        for i in range(5):
            _write_investigation(tmp_path / f"run{i}", {"facts": []})
        current = tmp_path / "current"
        current.mkdir()
        dirs = find_binary_run_dirs(current, max_dirs=2)
        assert len(dirs) == 2

    def test_empty_parent(self, tmp_path):
        dirs = find_binary_run_dirs(tmp_path / "nonexistent" / "current")
        assert dirs == []


# ── _load_graph_sink_edges ───────────────────────────────────────────


class TestLoadGraphSinkEdges:
    def test_loads_calls_surface_edges(self, tmp_path):
        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        edges = _load_graph_sink_edges(tmp_path)
        assert len(edges) == 1
        assert edges[0].caller == "process_input"
        assert edges[0].sink == "system"

    def test_excludes_plain_calls_without_is_sink(self, tmp_path):
        _create_graph_store(tmp_path, [
            {"caller": "main", "sink": "strlen",
             "kind": "CALLS", "dst_kind": "import"},
        ])
        edges = _load_graph_sink_edges(tmp_path)
        assert len(edges) == 0

    def test_includes_calls_with_is_sink_prop(self, tmp_path):
        _create_graph_store(tmp_path, [
            {"caller": "handler", "sink": "execve",
             "kind": "CALLS", "props": {"is_sink": True}},
        ])
        edges = _load_graph_sink_edges(tmp_path)
        assert len(edges) == 1
        assert edges[0].sink == "execve"

    def test_no_graph_store(self, tmp_path):
        edges = _load_graph_sink_edges(tmp_path)
        assert edges == []

    def test_excludes_may_reach(self, tmp_path):
        _create_graph_store(tmp_path, [
            {"caller": "foo", "sink": "bar",
             "kind": "MAY_REACH"},
        ])
        edges = _load_graph_sink_edges(tmp_path)
        assert len(edges) == 0

    def test_unstamped_store_is_skipped_loudly(self, tmp_path, caplog):
        """A store without a valid provenance stamp (legacy run, or a
        file planted into a sibling run dir) must not seed audit
        hypotheses: skipped with a warning naming the regeneration
        path, never parsed, never an error."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ], stamp=False)
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            assert _load_graph_sink_edges(tmp_path) == []
        assert any("provenance" in r.getMessage() and "re-run" in
                   r.getMessage() for r in caplog.records)

    def test_tampered_store_is_skipped(self, tmp_path, caplog):
        """Stamped, then rewritten: the recorded content hash no
        longer matches the db bytes — skipped, not parsed."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        db_path = tmp_path / "graph" / "binary-graph.sqlite"
        with db_path.open("r+b") as fh:
            fh.seek(-1, 2)
            last = fh.read(1)
            fh.seek(-1, 2)
            fh.write(bytes([last[0] ^ 0xFF]))
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            assert _load_graph_sink_edges(tmp_path) == []
        assert any("provenance" in r.getMessage()
                   for r in caplog.records)

    def test_swapped_store_edges_are_never_served(self, tmp_path, caplog):
        """Stamped, then the whole db swapped for a VALID sqlite store
        carrying planted sink edges (the legitimate sidecar left in
        place): the consumer queries only a verified private copy, so
        the attacker edges are never served."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        attacker = tmp_path / "attacker"
        _create_graph_store(attacker, [
            {"caller": "main", "sink": "ATTACKER_sink",
             "kind": "CALLS_SURFACE"},
        ], stamp=False)
        db_path = tmp_path / "graph" / "binary-graph.sqlite"
        db_path.write_bytes(
            (attacker / "graph" / "binary-graph.sqlite").read_bytes())
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            assert _load_graph_sink_edges(tmp_path) == []
        assert any("provenance" in r.getMessage()
                   for r in caplog.records)

    def test_planted_wal_does_not_block_or_poison(self, tmp_path):
        """A -wal planted next to a hash-matching stamped db is foreign
        by construction (stamping refuses pending journals). The
        snapshot consumer ignores it: stamped edges served, planted
        frames never folded in."""
        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        db_path = tmp_path / "graph" / "binary-graph.sqlite"
        wal = db_path.with_name(db_path.name + "-wal")
        wal.write_bytes(b"planted frames")
        edges = _load_graph_sink_edges(tmp_path)
        assert [(e.caller, e.sink) for e in edges] == [
            ("process_input", "system")]
        assert wal.read_bytes() == b"planted frames"

    # The provenance stamp binds a store to this INSTALL, not to a
    # binary — any stamped store+sidecar pair replays wherever copied.
    # The consumer binds snapshot identity itself.

    def test_replayed_store_for_foreign_binary_is_skipped(
            self, tmp_path, caplog):
        """Validly stamped store whose latest snapshot is about a
        binary outside this run's target set (sidecar replay): skipped
        with a warning, never served."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            edges = _load_graph_sink_edges(
                tmp_path,
                allowed_binary_sha256s=frozenset({"ff" * 32}),
            )
        assert edges == []
        assert any("replay" in r.getMessage() and "target set" in
                   r.getMessage() for r in caplog.records)

    def test_store_for_current_binary_is_served(self, tmp_path):
        """A snapshot whose binary_sha256 is in the run's allowlist
        passes the bind."""
        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        edges = _load_graph_sink_edges(
            tmp_path, allowed_binary_sha256s=frozenset({"abc123"}))
        assert [(e.caller, e.sink) for e in edges] == [
            ("process_input", "system")]

    def test_sha_allowlist_outranks_path_bind(self, tmp_path, caplog):
        """When the run knows its binary hashes, a sha mismatch skips
        the store even if the snapshot's recorded path sits under the
        target (strongest available bind wins)."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        _set_snapshot_identity(
            tmp_path, path=str(tmp_path / "target" / "binary"))
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            edges = _load_graph_sink_edges(
                tmp_path,
                allowed_binary_sha256s=frozenset({"ff" * 32}),
                target_root=tmp_path / "target",
            )
        assert edges == []
        assert any("replay" in r.getMessage() for r in caplog.records)

    def test_path_bind_blocks_cross_target_replay(self, tmp_path, caplog):
        """No binary hashes known: the weaker bind still refuses a
        snapshot recorded against a binary outside the audited
        target."""
        import logging

        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.binary_bridge"):
            edges = _load_graph_sink_edges(
                tmp_path,
                target_root=tmp_path / "some-target",
            )
        assert edges == []
        assert any("outside" in r.getMessage() and "replay" in
                   r.getMessage() for r in caplog.records)

    def test_path_bind_accepts_in_target_snapshot(self, tmp_path):
        """A snapshot recorded against a binary under the audited
        target passes the path bind."""
        target = tmp_path / "some-target"
        target.mkdir()
        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        _set_snapshot_identity(tmp_path, path=str(target / "app"))
        edges = _load_graph_sink_edges(tmp_path, target_root=target)
        assert [(e.caller, e.sink) for e in edges] == [
            ("process_input", "system")]

    def test_unbound_call_preserves_behavior(self, tmp_path):
        """Neither identity signal available (e.g. the engagement
        router path): the pre-existing stamped-store behavior."""
        _create_graph_store(tmp_path, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        edges = _load_graph_sink_edges(tmp_path)
        assert [(e.caller, e.sink) for e in edges] == [
            ("process_input", "system")]

    def test_bridge_wires_current_build_ids_into_bind(self, tmp_path):
        """load_binary_bridge hashes current_build_ids binaries into
        the allowlist: a sibling store about a different binary drops;
        rewriting its snapshot to the current binary's hash serves."""
        from core.audit.build_id_cache import _binary_sha256

        run1 = tmp_path / "run1"
        _create_graph_store(run1, [
            {"caller": "process_input", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        current = tmp_path / "current"
        current.mkdir()
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELFcurrent-binary")

        result = load_binary_bridge(
            current, current_build_ids={"bid1": str(binary)})
        assert result is None or result.sink_edges == []

        sha = _binary_sha256(str(binary))
        assert sha is not None
        _set_snapshot_identity(run1, sha=sha)
        result = load_binary_bridge(
            current, current_build_ids={"bid1": str(binary)})
        assert result is not None
        assert [(e.caller, e.sink) for e in result.sink_edges] == [
            ("process_input", "system")]


# ── _load_investigation ──────────────────────────────────────────────


class TestLoadInvestigation:
    def test_loads_surfaces_from_facts(self, tmp_path):
        _write_investigation(tmp_path, {
            "facts": [
                {"type": "surface_classification",
                 "subject": "process_input",
                 "detail": {"function": "process_input",
                            "category": "process_execution",
                            "score": 95.0, "is_sink": True}},
            ],
            "priority_queue": [],
        })
        surfaces, boundaries = _load_investigation(tmp_path)
        assert len(surfaces) == 1
        assert surfaces[0].function == "process_input"
        assert surfaces[0].category == "process_execution"
        assert surfaces[0].is_sink is True

    def test_loads_from_priority_queue(self, tmp_path):
        _write_investigation(tmp_path, {
            "facts": [],
            "priority_queue": [
                {"name": "parse_header", "category": "parser",
                 "score": 80, "is_sink": False},
            ],
        })
        surfaces, _ = _load_investigation(tmp_path)
        assert len(surfaces) == 1
        assert surfaces[0].function == "parse_header"

    def test_loads_parser_boundaries(self, tmp_path):
        _write_investigation(tmp_path, {
            "facts": [],
            "parser_boundaries": [
                {"function": "inflate_block", "ingress_function": "url_handler",
                 "depth": 3, "score": 72.0, "evidence_tier": "xref_backed"},
            ],
        })
        _, boundaries = _load_investigation(tmp_path)
        assert len(boundaries) == 1
        assert boundaries[0].function == "inflate_block"
        assert boundaries[0].ingress_function == "url_handler"

    def test_no_investigation_file(self, tmp_path):
        surfaces, boundaries = _load_investigation(tmp_path)
        assert surfaces == []
        assert boundaries == []

    def test_malformed_score_skipped(self, tmp_path):
        _write_investigation(tmp_path, {
            "facts": [],
            "priority_queue": [
                {"name": "bad_score", "score": "not_a_number"},
                {"name": "good_score", "score": 50},
            ],
        })
        surfaces, _ = _load_investigation(tmp_path)
        assert len(surfaces) == 1
        assert surfaces[0].function == "good_score"


# ── _load_binary_context_map ────────────────────────────────────────


class TestLoadBinaryContextMap:
    def test_loads_sinks(self, tmp_path):
        _write_context_map(tmp_path, {
            "sinks": [
                {"name": "memcpy", "category": "memory_write", "score": 90},
            ],
        })
        surfaces, boundaries = _load_binary_context_map(tmp_path)
        assert len(surfaces) == 1
        assert surfaces[0].function == "memcpy"
        assert surfaces[0].is_sink is True

    def test_loads_external_ingress(self, tmp_path):
        _write_context_map(tmp_path, {
            "sinks": [],
            "external_ingress": [
                {"function": "url_handler", "ingress": "XPC",
                 "score": 100, "evidence_tier": "observed_runtime"},
            ],
        })
        _, boundaries = _load_binary_context_map(tmp_path)
        assert len(boundaries) == 1
        assert boundaries[0].function == "url_handler"

    def test_no_file(self, tmp_path):
        surfaces, boundaries = _load_binary_context_map(tmp_path)
        assert surfaces == []
        assert boundaries == []


# ── load_binary_bridge (end-to-end) ──────────────────────────────────


class TestLoadBinaryBridge:
    def test_returns_none_without_data(self, tmp_path):
        result = load_binary_bridge(tmp_path / "empty")
        assert result is None

    def test_aggregates_all_sources(self, tmp_path):
        _create_graph_store(tmp_path / "run1", [
            {"caller": "fn_a", "sink": "system",
             "kind": "CALLS_SURFACE"},
        ])
        _write_investigation(tmp_path / "run2", {
            "facts": [],
            "priority_queue": [
                {"name": "fn_b", "category": "parser", "score": 70},
            ],
            "parser_boundaries": [
                {"function": "fn_c", "depth": 2, "score": 60},
            ],
        })
        current = tmp_path / "current"
        current.mkdir()

        result = load_binary_bridge(current)
        assert result is not None
        assert result.has_data
        assert len(result.sink_edges) == 1
        assert len(result.ranked_surfaces) == 1
        assert len(result.parser_boundaries) == 1

    def test_convenience_methods(self, tmp_path):
        result = BinaryBridgeResult(
            sink_edges=[
                BinarySinkEdge("fn_a", "system", "xref", "high", "/bin"),
                BinarySinkEdge("fn_b", "execve", "xref", "high", "/bin"),
            ],
            ranked_surfaces=[
                BinaryRankedSurface("fn_c", "parser", 80.0, False),
                BinaryRankedSurface("fn_c", "parser", 90.0, False),
            ],
            parser_boundaries=[
                BinaryParserBoundary("fn_d", "ingress", 2, 60.0, "xref"),
            ],
        )
        assert result.sink_callers() == {"fn_a", "fn_b"}
        assert result.surface_functions() == {"fn_c": 90.0}
        assert result.boundary_functions() == {"fn_d"}


# ── Priority scoring with binary bridge ──────────────────────────────


class TestBinaryBridgePriority:
    def test_binary_sink_boosts_score(self):
        from core.audit.priority import SCORE_BINARY_SINK, score_functions

        bridge = BinaryBridgeResult(
            sink_edges=[BinarySinkEdge("fn1", "system", "xref", "high", "")],
        )
        gaps = [
            {"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50},
            {"file": "a.c", "name": "fn2", "priority": 0, "sloc": 50},
        ]
        scored = score_functions(gaps, binary_bridge=bridge)
        by_name = {g["name"]: g for g in scored}
        assert by_name["fn1"]["priority_score"] >= SCORE_BINARY_SINK
        assert by_name["fn2"]["priority_score"] < SCORE_BINARY_SINK

    def test_binary_surface_boosts_score(self):
        from core.audit.priority import SCORE_BINARY_SURFACE, score_functions

        bridge = BinaryBridgeResult(
            ranked_surfaces=[
                BinaryRankedSurface("fn1", "parser", 80, False),
            ],
        )
        gaps = [
            {"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50},
            {"file": "a.c", "name": "fn2", "priority": 0, "sloc": 50},
        ]
        scored = score_functions(gaps, binary_bridge=bridge)
        by_name = {g["name"]: g for g in scored}
        assert by_name["fn1"]["priority_score"] >= SCORE_BINARY_SURFACE
        assert by_name["fn2"]["priority_score"] < SCORE_BINARY_SURFACE

    def test_parser_boundary_boosts_score(self):
        from core.audit.priority import SCORE_PARSER_BOUNDARY, score_functions

        bridge = BinaryBridgeResult(
            parser_boundaries=[
                BinaryParserBoundary("fn1", "ingress", 2, 60, "xref"),
            ],
        )
        gaps = [
            {"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50},
        ]
        scored = score_functions(gaps, binary_bridge=bridge)
        assert scored[0]["priority_score"] >= SCORE_PARSER_BOUNDARY

    def test_no_bridge_no_effect(self):
        from core.audit.priority import score_functions

        gaps = [{"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50}]
        scored = score_functions(gaps, binary_bridge=None)
        scored2 = score_functions(gaps)
        assert scored[0]["priority_score"] == scored2[0]["priority_score"]


# ── Evidence index with binary bridge ────────────────────────────────


class TestBinaryBridgeEvidence:
    def test_attaches_sink_edges(self):
        from core.evidence import build_evidence_index

        bridge = BinaryBridgeResult(
            sink_edges=[
                BinarySinkEdge("check_pw", "system", "xref", "high", ""),
            ],
        )
        checklist = {
            "files": [
                {"path": "auth.c", "items": [{"name": "check_pw"}]},
            ],
        }
        index = build_evidence_index(
            checklist=checklist, binary_bridge=bridge,
        )
        rec = index["auth.c:check_pw"]
        assert len(rec.binary_sink_edges) == 1
        assert rec.binary_sink_edges[0]["sink"] == "system"

    def test_attaches_surface_category(self):
        from core.evidence import build_evidence_index

        bridge = BinaryBridgeResult(
            ranked_surfaces=[
                BinaryRankedSurface("parse_header", "parser", 80, False),
            ],
        )
        checklist = {
            "files": [
                {"path": "http.c", "items": [{"name": "parse_header"}]},
            ],
        }
        index = build_evidence_index(
            checklist=checklist, binary_bridge=bridge,
        )
        rec = index["http.c:parse_header"]
        assert rec.binary_surface_category == "parser"

    def test_attaches_parser_boundary(self):
        from core.evidence import build_evidence_index

        bridge = BinaryBridgeResult(
            parser_boundaries=[
                BinaryParserBoundary("inflate", "url_handler", 3, 72, "xref"),
            ],
        )
        checklist = {
            "files": [
                {"path": "zip.c", "items": [{"name": "inflate"}]},
            ],
        }
        index = build_evidence_index(
            checklist=checklist, binary_bridge=bridge,
        )
        assert index["zip.c:inflate"].binary_parser_boundary is True

    def test_no_bridge_no_fields(self):
        from core.evidence import build_evidence_index

        checklist = {
            "files": [
                {"path": "a.c", "items": [{"name": "fn"}]},
            ],
        }
        index = build_evidence_index(checklist=checklist)
        rec = index["a.c:fn"]
        assert rec.binary_sink_edges == []
        assert rec.binary_surface_category is None
        assert rec.binary_parser_boundary is False


# ── Evidence prose formatting ────────────────────────────────────────


class TestBinaryEvidenceProse:
    def test_formats_sink_edges(self):
        from core.evidence import EvidenceRecord, format_evidence_prose

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.binary_sink_edges = [
            {"sink": "system", "tier": "xref_backed", "confidence": "high"},
        ]
        prose = format_evidence_prose(rec)
        assert "BINARY" in prose
        assert "system" in prose
        assert "xref_backed" in prose

    def test_formats_surface_category(self):
        from core.evidence import EvidenceRecord, format_evidence_prose

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.binary_surface_category = "process_execution"
        prose = format_evidence_prose(rec)
        assert "BINARY surface" in prose
        assert "process_execution" in prose

    def test_formats_parser_boundary(self):
        from core.evidence import EvidenceRecord, format_evidence_prose

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.binary_parser_boundary = True
        prose = format_evidence_prose(rec)
        assert "BINARY parser boundary" in prose

    def test_tier_sanitized(self):
        from core.evidence import EvidenceRecord, format_evidence_prose

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.binary_sink_edges = [
            {"sink": "system", "tier": "inject<script>", "confidence": "high"},
        ]
        prose = format_evidence_prose(rec)
        assert "<script>" not in prose


# ── Joern/taint/binary evidence overrides sink_unreachable ───────────


class TestMechanicalFlowOverridesSinkUnreachable:
    """When mechanical evidence confirms a flow exists, the function
    should NOT be marked sink_unreachable even if the call graph says
    it's unreachable. Tests the orchestrator's _build_context logic."""

    def test_joern_flows_prevent_unreachable(self):
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.sink_unreachable = True
        rec.joern_flows = [{"source_method": "fn", "sink_call": "system"}]

        has_mechanical_flow = (
            rec.all_joern_flows()
            or (rec.taint_approx and rec.taint_approx.dangerous_flows)
            or rec.binary_sink_edges
        )
        assert has_mechanical_flow

    def test_binary_edges_prevent_unreachable(self):
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.sink_unreachable = True
        rec.binary_sink_edges = [
            {"sink": "system", "tier": "xref", "confidence": "high"},
        ]

        has_mechanical_flow = (
            rec.all_joern_flows()
            or (rec.taint_approx and rec.taint_approx.dangerous_flows)
            or rec.binary_sink_edges
        )
        assert has_mechanical_flow

    def test_no_evidence_allows_unreachable(self):
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(file="a.c", function="fn")
        rec.sink_unreachable = True

        has_mechanical_flow = (
            rec.all_joern_flows()
            or (rec.taint_approx and rec.taint_approx.dangerous_flows)
            or rec.binary_sink_edges
        )
        assert not has_mechanical_flow
