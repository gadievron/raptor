"""Graph-store provenance stamps: minted at every writer close over
the db content hash, verified by trusted consumers before edge reuse.
Unstamped / tampered / journal-pending stores never verify — the
degrade is a skip, never an error."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.binary_analysis.graph_store import (
    BinaryGraphStore,
    VerifiedGraphSnapshot,
    graph_connection,
    open_verified_graph_store,
    provenance_path_for,
    stamp_graph_store,
    verify_graph_store,
)


@pytest.fixture(autouse=True)
def _key_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Innermost XDG pin: every test mints against a private key."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _closed_store(db_path: Path, sha: str = "feed5678" * 8) -> None:
    store = BinaryGraphStore(db_path)
    try:
        snap_id = store.begin_snapshot(sha, "/bin/test", db_path.parent)
        n1 = store.add_node(snap_id, sha, "function", "a", name="func_a")
        n2 = store.add_node(snap_id, sha, "function", "b", name="func_b")
        store.add_edge(snap_id, sha, "CALLS", n1, n2)
    finally:
        store.close()


def test_writer_close_stamps_and_verifies(tmp_path: Path):
    db = tmp_path / "graph" / "binary-graph.sqlite"
    _closed_store(db)
    assert provenance_path_for(db).is_file()
    assert verify_graph_store(db)


def test_graph_connection_exit_restamps(tmp_path: Path):
    # The mutate-then-close cycle: a later legitimate write through
    # graph_connection re-stamps over the NEW content.
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    with graph_connection(db) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) "
            "VALUES ('note', 'updated')",
        )
    assert verify_graph_store(db)


def test_tampered_db_bytes_fail(tmp_path: Path):
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    assert verify_graph_store(db)
    with db.open("r+b") as fh:
        fh.seek(-1, 2)
        last = fh.read(1)
        fh.seek(-1, 2)
        fh.write(bytes([last[0] ^ 0xFF]))
    assert not verify_graph_store(db)


def test_legacy_store_without_sidecar_fails(tmp_path: Path):
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    provenance_path_for(db).unlink()
    assert not verify_graph_store(db)


def test_tampered_sidecar_token_fails(tmp_path: Path):
    import json
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    sidecar = provenance_path_for(db)
    payload = json.loads(sidecar.read_text())
    payload["token"] = "0" * 64
    sidecar.write_text(json.dumps(payload))
    assert not verify_graph_store(db)


def test_replayed_sidecar_from_another_store_fails(tmp_path: Path):
    # A valid sidecar copied next to a DIFFERENT (planted) db binds
    # the wrong content hash.
    db_a = tmp_path / "a.sqlite"
    db_b = tmp_path / "b.sqlite"
    _closed_store(db_a, sha="aaaa5678" * 8)
    _closed_store(db_b, sha="bbbb5678" * 8)
    provenance_path_for(db_b).write_bytes(
        provenance_path_for(db_a).read_bytes())
    assert not verify_graph_store(db_b)


def test_pending_journal_blocks_verify_and_stamp(tmp_path: Path):
    # A non-empty -wal sibling changes the store's EFFECTIVE content
    # without changing the db hash: neither verify nor a fresh stamp
    # accepts the store in that state.
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    wal = db.with_name(db.name + "-wal")
    wal.write_bytes(b"planted frames")
    assert not verify_graph_store(db)
    provenance_path_for(db).unlink()
    stamp_graph_store(db)
    assert not provenance_path_for(db).is_file()
    # Checkpointed (empty/removed) journal: stamping works again.
    wal.unlink()
    stamp_graph_store(db)
    assert verify_graph_store(db)


def test_missing_db_never_verifies(tmp_path: Path):
    assert not verify_graph_store(tmp_path / "absent.sqlite")
    stamp_graph_store(tmp_path / "absent.sqlite")
    assert not (tmp_path / "absent.sqlite.provenance.json").exists()


# ── open_verified_graph_store: the TOCTOU-free consumer path ─────────


def _snapshot_edge_names(
    snapshot: VerifiedGraphSnapshot,
) -> list[tuple[str, str]]:
    return [
        (e["source"]["name"], e["target"]["name"])
        for e in snapshot.edges(kind=None)
    ]


def test_verified_snapshot_serves_stamped_edges(tmp_path: Path):
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is not None
        assert _snapshot_edge_names(snapshot) == [("func_a", "func_b")]
        assert snapshot.summary()["latest_snapshot"]["binary_path"] == "/bin/test"


def test_swap_after_verify_is_not_served(tmp_path: Path):
    """The finding's repro: verify passes on the legitimate store, the
    run-dir writer then swaps in an attacker db (the legit sidecar
    stays). The snapshot open hashes the bytes it actually copies, so
    the attacker's edges are never served."""
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    attacker_db = tmp_path / "attacker" / "graph.sqlite"
    store = BinaryGraphStore(attacker_db)
    try:
        sha = "feed5678" * 8
        snap_id = store.begin_snapshot(sha, "/bin/test", attacker_db.parent)
        n1 = store.add_node(snap_id, sha, "function", "a", name="main")
        n2 = store.add_node(
            snap_id, sha, "function", "x", name="ATTACKER_callee")
        store.add_edge(snap_id, sha, "CALLS", n1, n2)
    finally:
        store.close()

    # Point-in-time verify passes — then the swap lands.
    assert verify_graph_store(db)
    db.write_bytes(attacker_db.read_bytes())
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is None


def test_snapshot_reads_survive_source_swap(tmp_path: Path):
    """Once the snapshot is open, every query reads the private copy:
    rewriting or deleting the source mid-consumption changes nothing —
    no residual open-by-path pair."""
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is not None
        db.write_bytes(b"not sqlite at all")
        assert _snapshot_edge_names(snapshot) == [("func_a", "func_b")]
        db.unlink()
        assert _snapshot_edge_names(snapshot) == [("func_a", "func_b")]


def test_planted_wal_is_ignored_not_folded(tmp_path: Path):
    """A -wal planted next to a hash-matching db can only be foreign
    (stamping refuses pending journals, so the stamped bytes were
    journal-free). The immutable snapshot open never consults it: the
    stamped content is served, the planted frames are never folded in,
    and the plant does not even deny service."""
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    wal = db.with_name(db.name + "-wal")
    wal.write_bytes(b"planted frames")
    shm = db.with_name(db.name + "-shm")
    shm.write_bytes(b"planted shm")
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is not None
        assert _snapshot_edge_names(snapshot) == [("func_a", "func_b")]
    # The source siblings were never consumed or removed.
    assert wal.read_bytes() == b"planted frames"


def test_unstamped_and_tampered_stores_yield_none(tmp_path: Path):
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    provenance_path_for(db).unlink()
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is None
    stamp_graph_store(db)
    with db.open("r+b") as fh:
        fh.seek(-1, 2)
        last = fh.read(1)
        fh.seek(-1, 2)
        fh.write(bytes([last[0] ^ 0xFF]))
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is None


def test_oversize_store_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    import packages.binary_analysis.graph_store as gs

    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    monkeypatch.setattr(gs, "_SNAPSHOT_MAX_DB_BYTES", 16)
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is None


def test_symlinked_db_is_refused(tmp_path: Path):
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    link = tmp_path / "link.sqlite"
    link.symlink_to(db)
    # Sidecar rides along so the refusal exercises the O_NOFOLLOW open.
    provenance_path_for(link).write_bytes(
        provenance_path_for(db).read_bytes())
    with open_verified_graph_store(link) as snapshot:
        assert snapshot is None


def test_snapshot_scratch_dir_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    import tempfile

    import packages.binary_analysis.graph_store as gs

    created: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def _recording_mkdtemp(*args: object, **kwargs: object) -> str:
        path = real_mkdtemp(*args, **kwargs)  # type: ignore[arg-type]
        created.append(path)
        return path

    monkeypatch.setattr(gs.tempfile, "mkdtemp", _recording_mkdtemp)
    db = tmp_path / "graph.sqlite"
    _closed_store(db)
    with open_verified_graph_store(db) as snapshot:
        assert snapshot is not None
    assert len(created) == 1
    assert created[0].rpartition("/")[2].startswith("raptor-graph-verify-")
    assert not Path(created[0]).exists()
