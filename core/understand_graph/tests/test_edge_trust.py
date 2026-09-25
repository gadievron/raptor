"""Trust posture for verdict-feeding edge rows.

The store's call edges can feed negative reachability (a
suppression/demotion input), so edges carry a provenance tier and a
run-bound integrity token. These tests pin the schema migration
(legacy rows land in the hint tier), the token discipline (store
binding, tamper demotion, unusable-key degradation), and the
suppression-capable read (``verified_mechanical_call_edges``:
mechanical-and-verified rows only; deletion and tampering read as an
incomplete set; a broken snapshot token or foreign target yields no
lane at all).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from core.understand_graph import integrity
from core.understand_graph.queries import verified_mechanical_call_edges
from core.understand_graph.store import open_graph

_V3_SCHEMA = """
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE snapshots (id TEXT PRIMARY KEY, target_path TEXT NOT NULL,
        target_hash TEXT NOT NULL DEFAULT '', git_sha TEXT NOT NULL DEFAULT '',
        checklist_hash TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
        producer_run TEXT NOT NULL DEFAULT '', props_json TEXT NOT NULL DEFAULT '{}',
        producer TEXT NOT NULL DEFAULT 'understand');
    CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
        stable_key TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
        file TEXT NOT NULL DEFAULT '', line_start INTEGER, line_end INTEGER,
        snapshot_id TEXT NOT NULL, stale INTEGER NOT NULL DEFAULT 0,
        props_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE);
    CREATE TABLE edges (id TEXT PRIMARY KEY, src_id TEXT NOT NULL, dst_id TEXT NOT NULL,
        kind TEXT NOT NULL, confidence TEXT NOT NULL DEFAULT '',
        snapshot_id TEXT NOT NULL, stale INTEGER NOT NULL DEFAULT 0,
        evidence_json TEXT NOT NULL DEFAULT '{}', props_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE);
    CREATE TABLE artifacts (id TEXT PRIMARY KEY, kind TEXT NOT NULL, path TEXT NOT NULL,
        run_dir TEXT NOT NULL DEFAULT '', snapshot_id TEXT NOT NULL,
        sha256 TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
        props_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE);
    INSERT INTO snapshots (id, target_path) VALUES ('snap1', '/legacy/target');
    INSERT INTO nodes (id, kind, stable_key, name, snapshot_id) VALUES
        ('n1','entry_point','entry_point://EP-1','handle_request','snap1'),
        ('n2','sink','sink://SINK-1','system','snap1');
    INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id) VALUES
        ('e1','n1','n2','REACHES','snap1');
    PRAGMA user_version=3;
"""


def _make_v3_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_V3_SCHEMA)
    conn.commit()
    conn.close()


class TestMigrationV4:
    def test_legacy_edges_migrate_to_imported_tier(self, tmp_path):
        db = tmp_path / "raptor.graph.sqlite"
        _make_v3_db(db)
        conn = open_graph(db)
        try:
            row = conn.execute(
                "SELECT provenance, integrity FROM edges WHERE id='e1'"
            ).fetchone()
            assert row["provenance"] == "imported"
            assert row["integrity"] == ""
            snap = conn.execute(
                "SELECT integrity FROM snapshots WHERE id='snap1'"
            ).fetchone()
            assert snap["integrity"] == ""
            assert conn.execute("PRAGMA user_version").fetchone()[0] >= 4
        finally:
            conn.close()

    def test_fresh_store_has_trust_columns(self, tmp_path):
        db = tmp_path / "raptor.graph.sqlite"
        conn = open_graph(db)
        try:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(edges)")}
            assert {"provenance", "integrity"} <= cols
            snap_cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(snapshots)")
            }
            assert "integrity" in snap_cols
        finally:
            conn.close()

    def test_upsert_edge_defaults_to_llm_tier(self, tmp_path):
        from core.understand_graph.ingest import _upsert_edge

        db = tmp_path / "raptor.graph.sqlite"
        conn = open_graph(db)
        try:
            conn.execute(
                "INSERT INTO snapshots (id, target_path) VALUES ('s', '/t')")
            _upsert_edge(conn, "s", "REACHES", "a", "b")
            _upsert_edge(conn, "s", "CALLS", "a", "c",
                         provenance="mechanical")
            conn.commit()
            rows = {
                (r["src_id"], r["dst_id"]): r["provenance"]
                for r in conn.execute("SELECT * FROM edges")
            }
            assert rows[("a", "b")] == "llm"
            assert rows[("a", "c")] == "mechanical"
        finally:
            conn.close()


class TestRowStamper:
    def test_mint_verify_round_trip(self, tmp_path):
        store = tmp_path / "graph" / "raptor.graph.sqlite"
        store.parent.mkdir(parents=True)
        stamper = integrity.edge_stamper(store)
        assert stamper.usable
        payload = integrity.edge_payload("snap", "a.c", "f", "a.c", "g")
        token = stamper.mint(payload)
        assert token
        assert stamper.verify(payload, token)

    def test_binding_is_store_directory(self, tmp_path):
        """A token minted for one store never verifies for a store in
        another directory (copied-store demotion), but DOES verify for
        a sibling temp file in the same directory (the rebuild swap)."""
        store_a = tmp_path / "proj-a" / "graph" / "raptor.graph.sqlite"
        store_b = tmp_path / "proj-b" / "graph" / "raptor.graph.sqlite"
        store_a.parent.mkdir(parents=True)
        store_b.parent.mkdir(parents=True)
        payload = integrity.edge_payload("snap", "a.c", "f", "a.c", "g")
        token = integrity.edge_stamper(store_a).mint(payload)
        assert not integrity.edge_stamper(store_b).verify(payload, token)
        sibling = store_a.with_name(".rebuild-1-raptor.graph.sqlite")
        assert integrity.edge_stamper(sibling).verify(payload, token)

    def test_tampered_payload_fails(self, tmp_path):
        stamper = integrity.edge_stamper(tmp_path / "g.sqlite")
        token = stamper.mint(
            integrity.edge_payload("snap", "a.c", "f", "a.c", "g"))
        assert not stamper.verify(
            integrity.edge_payload("snap", "a.c", "f", "a.c", "EVIL"), token)
        assert not stamper.verify(
            integrity.edge_payload("other-snap", "a.c", "f", "a.c", "g"),
            token)

    def test_qualified_name_resplit_fails(self, tmp_path):
        """The payload carries endpoint file and name separately: a
        re-split of the same joined ``file::name`` spelling (possible
        for C++ qualified names) is a DIFFERENT payload and must not
        verify."""
        stamper = integrity.edge_stamper(tmp_path / "g.sqlite")
        token = stamper.mint(integrity.edge_payload(
            "snap", "a.c", "f", "vec.cpp", "std::vector::push_back"))
        assert not stamper.verify(
            integrity.edge_payload(
                "snap", "a.c", "f", "vec.cpp::std", "vector::push_back"),
            token)

    def test_domain_separation(self, tmp_path):
        """An edge token never authenticates a snapshot payload even
        under the shared key."""
        store = tmp_path / "g.sqlite"
        payload = {"same": "payload"}
        token = integrity.edge_stamper(store).mint(payload)
        assert not integrity.snapshot_stamper(store).verify(payload, token)

    def test_unusable_key_degrades(self, tmp_path, monkeypatch):
        monkeypatch.setattr(integrity, "_load_or_create_key", lambda: None)
        stamper = integrity.edge_stamper(tmp_path / "g.sqlite")
        assert not stamper.usable
        payload = integrity.edge_payload("snap", "a.c", "f", "a.c", "g")
        assert stamper.mint(payload) is None
        assert stamper.verify(payload, "deadbeef") is False


def _seed_callgraph_snapshot(
    db: Path,
    *,
    edges: list[tuple[str, str, str, str]],
    target: str = "/target",
    snap_id: str = "snap-cg",
    edge_count: int | None = None,
    snapshot_token: str | None = None,
    created_at: str = "2026-01-01T00:00:00+00:00",
) -> None:
    """Hand-roll a callgraph snapshot with stamped mechanical edges
    (the writer lands with the batched ingest; this pins the read
    contract independently)."""
    edge_stamper = integrity.edge_stamper(db)
    snap_stamper = integrity.snapshot_stamper(db)
    count = len(edges) if edge_count is None else edge_count
    token = snapshot_token
    if token is None:
        token = snap_stamper.mint(integrity.snapshot_payload(
            snap_id, target, "clh", "callgraph", count, created_at)) or ""
    conn = open_graph(db)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO snapshots (id, target_path, "
            "checklist_hash, producer, props_json, integrity, created_at) "
            "VALUES (?, ?, 'clh', 'callgraph', ?, ?, ?)",
            (snap_id, target, f'{{"edge_count": {count}}}', token,
             created_at),
        )
        for i, (cf, c, ef, e) in enumerate(edges):
            src = f"n-src-{i}-{snap_id}"
            dst = f"n-dst-{i}-{snap_id}"
            conn.execute(
                "INSERT OR REPLACE INTO nodes (id, kind, stable_key, name, "
                "file, snapshot_id) VALUES (?, 'function', ?, ?, ?, ?)",
                (src, f"function://{cf}::{c}", c, cf, snap_id),
            )
            conn.execute(
                "INSERT OR REPLACE INTO nodes (id, kind, stable_key, name, "
                "file, snapshot_id) VALUES (?, 'function', ?, ?, ?, ?)",
                (dst, f"function://{ef}::{e}", e, ef, snap_id),
            )
            edge_token = edge_stamper.mint(integrity.edge_payload(
                snap_id, cf, c, ef, e)) or ""
            conn.execute(
                "INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id, "
                "provenance, integrity) "
                "VALUES (?, ?, ?, 'CALLS', ?, 'mechanical', ?)",
                (f"e-{i}-{snap_id}", src, dst, snap_id, edge_token),
            )
        conn.commit()
    finally:
        conn.close()


class TestVerifiedMechanicalCallEdges:
    def test_complete_verified_lane(self, tmp_path):
        db = tmp_path / "graph" / "raptor.graph.sqlite"
        _seed_callgraph_snapshot(db, edges=[
            ("a.c", "main", "a.c", "parse"),
            ("a.c", "parse", "", "strcpy"),
        ])
        lane = verified_mechanical_call_edges(db, "snap-cg", "/target")
        assert lane is not None
        assert lane["complete"] is True
        assert lane["total"] == 2
        assert lane["unverified"] == 0
        assert {"caller": "parse", "caller_file": "a.c",
                "callee": "strcpy", "callee_file": ""} in lane["edges"]

    def test_store_absent_is_no_lane(self, tmp_path):
        assert verified_mechanical_call_edges(
            tmp_path / "missing.sqlite", "snap-cg") is None

    def test_unknown_snapshot_is_no_lane(self, tmp_path):
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        assert verified_mechanical_call_edges(db, "other-snap") is None
        assert verified_mechanical_call_edges(db, "") is None

    def test_foreign_target_is_no_lane(self, tmp_path):
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        assert verified_mechanical_call_edges(
            db, "snap-cg", "/other/target") is None

    def test_broken_snapshot_token_is_no_lane(self, tmp_path):
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(
            db, edges=[("a.c", "f", "a.c", "g")],
            snapshot_token="0" * 64)
        assert verified_mechanical_call_edges(db, "snap-cg") is None

    def test_doctored_edge_count_is_no_lane(self, tmp_path):
        """The snapshot token covers edge_count; rewriting the count
        (to hide deletions) breaks the token — no lane."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        raw = sqlite3.connect(db)
        raw.execute(
            "UPDATE snapshots SET props_json='{\"edge_count\": 0}' "
            "WHERE id='snap-cg'")
        raw.commit()
        raw.close()
        assert verified_mechanical_call_edges(db, "snap-cg") is None

    def test_llm_tier_row_is_excluded(self, tmp_path):
        """A CALLS row at llm tier — even validly stamped — never
        enters the verdict-feeding view."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        conn = open_graph(db)
        try:
            conn.execute(
                "INSERT INTO nodes (id, kind, stable_key, name, file, "
                "snapshot_id) VALUES ('n-x', 'function', "
                "'function://a.c::h', 'h', 'a.c', 'snap-cg')")
            token = integrity.edge_stamper(db).mint(integrity.edge_payload(
                "snap-cg", "a.c", "f", "a.c", "h")) or ""
            conn.execute(
                "INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id, "
                "provenance, integrity) VALUES ('e-llm', "
                "'n-src-0-snap-cg', 'n-x', 'CALLS', 'snap-cg', 'llm', ?)",
                (token,),
            )
            conn.commit()
        finally:
            conn.close()
        lane = verified_mechanical_call_edges(db, "snap-cg")
        assert lane is not None
        assert lane["complete"] is True  # mechanical set still accounts
        assert all(e["callee"] != "h" for e in lane["edges"])

    def test_tampered_node_name_demotes_row_and_completeness(self, tmp_path):
        """Rewriting a joined node's name breaks every edge token that
        covered it: the row leaves the view and the set reads
        incomplete (negative conclusions must degrade)."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[
            ("a.c", "main", "a.c", "parse"),
            ("a.c", "parse", "", "strcpy"),
        ])
        raw = sqlite3.connect(db)
        raw.execute("UPDATE nodes SET name='evil' WHERE name='strcpy'")
        raw.commit()
        raw.close()
        lane = verified_mechanical_call_edges(db, "snap-cg")
        assert lane is not None
        assert lane["complete"] is False
        assert lane["unverified"] == 1
        assert all(e["callee"] != "evil" for e in lane["edges"])

    def test_deleted_row_reads_incomplete(self, tmp_path):
        """Row MACs cannot witness deletion; the snapshot's pinned
        count does."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[
            ("a.c", "main", "a.c", "parse"),
            ("a.c", "parse", "", "strcpy"),
        ])
        raw = sqlite3.connect(db)
        raw.execute("DELETE FROM edges WHERE id='e-1-snap-cg'")
        raw.commit()
        raw.close()
        lane = verified_mechanical_call_edges(db, "snap-cg")
        assert lane is not None
        assert lane["complete"] is False
        assert len(lane["edges"]) == 1

    def test_duplicate_row_cannot_mask_a_deletion(self, tmp_path):
        """Delete-one + duplicate-another keeps the ROW count at the
        pinned value with every row verifying (a token verifies for
        any byte-identical payload) — completeness must count DISTINCT
        verified payloads, so the masked deletion still reads
        incomplete."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[
            ("a.c", "main", "a.c", "parse"),
            ("a.c", "parse", "", "strcpy"),
        ])
        raw = sqlite3.connect(db)
        raw.row_factory = sqlite3.Row
        survivor = raw.execute(
            "SELECT * FROM edges WHERE id='e-0-snap-cg'").fetchone()
        raw.execute("DELETE FROM edges WHERE id='e-1-snap-cg'")
        raw.execute(
            "INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id, "
            "provenance, integrity) VALUES ('e-dup', ?, ?, 'CALLS', "
            "'snap-cg', 'mechanical', ?)",
            (survivor["src_id"], survivor["dst_id"],
             survivor["integrity"]),
        )
        raw.commit()
        raw.close()
        lane = verified_mechanical_call_edges(db, "snap-cg")
        assert lane is not None
        assert lane["complete"] is False
        assert len(lane["edges"]) == 1  # deduped distinct set

    def test_superseded_generation_is_no_lane(self, tmp_path):
        """Only the latest callgraph generation for a target is
        verdict-grade; a retained older generation (or a marker
        steered at it) falls to the floor."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(
            db, edges=[("a.c", "f", "a.c", "g")], snap_id="snap-old",
            created_at="2026-01-01T00:00:00+00:00")
        _seed_callgraph_snapshot(
            db, edges=[("a.c", "f", "a.c", "h")], snap_id="snap-new",
            created_at="2026-01-02T00:00:00+00:00")
        assert verified_mechanical_call_edges(db, "snap-old") is None
        lane = verified_mechanical_call_edges(db, "snap-new")
        assert lane is not None and lane["complete"] is True

    def test_forged_newer_sibling_only_drops_the_lane(self, tmp_path):
        """A planted callgraph snapshot row with a newer timestamp
        (unverifiable — no key) displaces the genuine latest: the
        genuine lane drops to the floor, and the forged one has no
        verified lane of its own. Denial, never a verdict."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        raw = sqlite3.connect(db)
        raw.execute(
            "INSERT INTO snapshots (id, target_path, producer, "
            "created_at, props_json, integrity) VALUES ('snap-forged', "
            "'/target', 'callgraph', '2099-01-01T00:00:00+00:00', "
            "'{\"edge_count\": 0}', 'deadbeef')")
        raw.commit()
        raw.close()
        assert verified_mechanical_call_edges(db, "snap-cg") is None
        assert verified_mechanical_call_edges(db, "snap-forged") is None

    def test_foreign_key_demotes_every_row(self, tmp_path, monkeypatch):
        """A store stamped under another install's key (or after a key
        reset) yields no verified lane — never a verdict input."""
        db = tmp_path / "g.sqlite"
        _seed_callgraph_snapshot(db, edges=[("a.c", "f", "a.c", "g")])
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "other-xdg"))
        assert verified_mechanical_call_edges(db, "snap-cg") is None
