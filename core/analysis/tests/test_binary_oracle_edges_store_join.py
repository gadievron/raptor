"""Graph-store name cleaning and active-project search-leg tests for
:mod:`core.analysis.binary_oracle_edges`."""
from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("packages.binary_analysis.graph_store")

from core.analysis.binary_oracle_edges import _try_graph_store  # noqa: E402
from packages.binary_analysis.graph_store import (  # noqa: E402
    BinaryGraphStore,
    graph_path_for_run,
)


def _write_store(run_dir, sha, binary_path, caller_name, callee_name):
    store = BinaryGraphStore(graph_path_for_run(run_dir))
    snap = store.begin_snapshot(sha, str(binary_path), run_dir)
    src = store.add_node(snap, sha, "function", "src", name=caller_name)
    dst = store.add_node(snap, sha, "function", "dst", name=callee_name)
    store.add_edge(snap, sha, "CALLS_FUNCTION", src, dst)
    store.close()


def test_graph_store_names_are_r2_cleaned(tmp_path, monkeypatch):
    """Graph-store node names carry r2 prefixes (``sym.`` /
    ``fcn.`` / stacked ``sym.imp.``); the reused index must clean
    them, or the bare-name inventory join downstream silently misses
    while this result SHADOWS fresh (cleaning) r2 extraction."""
    root = tmp_path / "raptor"
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF target bytes")
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setenv("RAPTOR_DIR", str(root))

    run_dir = root / "out" / "mapped-run"
    _write_store(run_dir, sha, binary, "sym.main", "sym.imp.leaf")

    reused = _try_graph_store(binary)
    assert reused is not None
    assert [(e.caller, e.callee) for e in reused.edges] == [("main", "leaf")]
    assert reused.callees == {"leaf"}


def test_graph_store_found_under_active_project_dir(tmp_path, monkeypatch):
    """The last-activated project bookmark lives at
    ``PROJECTS_DIR/.active`` — the search leg must consult it (the
    old RAPTOR_DIR-relative ``.active`` path never exists)."""
    import core.project.project as project_mod

    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF target bytes")
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()

    # RAPTOR_DIR exists but has no out/ dir and no .active — the only
    # place the store can be found is the active project directory.
    raptor_dir = tmp_path / "raptor"
    raptor_dir.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(raptor_dir))

    projects_root = tmp_path / "projects"
    project_dir = projects_root / "myproj"
    run_dir = project_dir / "run_1"
    run_dir.mkdir(parents=True)
    _write_store(run_dir, sha, binary, "main", "leaf")
    (projects_root / ".active").symlink_to(project_dir)
    monkeypatch.setattr(project_mod, "PROJECTS_DIR", projects_root)

    reused = _try_graph_store(binary)
    assert reused is not None
    assert [(e.caller, e.callee) for e in reused.edges] == [("main", "leaf")]


def test_store_in_binary_tree_is_not_consumed(tmp_path, monkeypatch):
    """A graph store planted in the BINARY'S OWN directory tree — the
    scanned target's build dir, attacker-writable by definition — must
    never be discovered: its sqlite bytes would be parsed by this
    trusted, unsandboxed process, and its planted edges would steer
    reachability. Mapping runs only ever write stores under
    RAPTOR-owned out/ and project dirs."""
    import core.project.project as project_mod

    raptor_dir = tmp_path / "raptor"
    (raptor_dir / "out").mkdir(parents=True)
    monkeypatch.setenv("RAPTOR_DIR", str(raptor_dir))
    monkeypatch.setattr(project_mod, "PROJECTS_DIR",
                        tmp_path / "projects")

    build = tmp_path / "target-build"
    build.mkdir()
    binary = build / "target"
    binary.write_bytes(b"\x7fELF target bytes")
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    _write_store(build / "planted-run", sha, binary, "main", "evil_leaf")

    assert _try_graph_store(binary) is None


def _searchable_store(tmp_path, monkeypatch):
    """A stamped store in the RAPTOR out/ search leg, plus its paths."""
    root = tmp_path / "raptor"
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF target bytes")
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setenv("RAPTOR_DIR", str(root))
    run_dir = root / "out" / "mapped-run"
    _write_store(run_dir, sha, binary, "main", "leaf")
    return binary, graph_path_for_run(run_dir)


def test_unstamped_store_is_skipped_loudly(tmp_path, monkeypatch, caplog):
    """An edge store without a valid provenance stamp (legacy run, or
    a file planted into the writable run dir) must not steer verdicts:
    the reuse leg skips it with a warning naming the regeneration
    path, never errors."""
    import logging

    from packages.binary_analysis.graph_store import provenance_path_for

    binary, store_path = _searchable_store(tmp_path, monkeypatch)
    provenance_path_for(store_path).unlink()
    with caplog.at_level(logging.WARNING,
                         logger="core.analysis.binary_oracle_edges"):
        assert _try_graph_store(binary) is None
    assert any("provenance" in r.getMessage() and "re-run" in
               r.getMessage() for r in caplog.records)


def test_tampered_store_is_skipped(tmp_path, monkeypatch, caplog):
    """A stamped store whose db bytes were rewritten afterwards no
    longer matches its recorded content hash — skipped, not parsed."""
    import logging

    binary, store_path = _searchable_store(tmp_path, monkeypatch)
    with store_path.open("r+b") as fh:
        fh.seek(-1, 2)
        last = fh.read(1)
        fh.seek(-1, 2)
        fh.write(bytes([last[0] ^ 0xFF]))
    with caplog.at_level(logging.WARNING,
                         logger="core.analysis.binary_oracle_edges"):
        assert _try_graph_store(binary) is None
    assert any("provenance" in r.getMessage() for r in caplog.records)


def test_swapped_store_edges_are_never_served(tmp_path, monkeypatch, caplog):
    """A whole-file swap after stamping (the run-dir writer replacing
    the db with its own VALID sqlite store carrying planted edges, the
    legitimate sidecar left in place): the consumer reads only a
    verified private copy, so the attacker edges are never served."""
    import logging

    binary, store_path = _searchable_store(tmp_path, monkeypatch)
    attacker_run = tmp_path / "attacker-run"
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    _write_store(attacker_run, sha, binary, "main", "ATTACKER_callee")
    store_path.write_bytes(graph_path_for_run(attacker_run).read_bytes())
    with caplog.at_level(logging.WARNING,
                         logger="core.analysis.binary_oracle_edges"):
        assert _try_graph_store(binary) is None
    assert any("provenance" in r.getMessage() for r in caplog.records)


def test_planted_wal_does_not_block_or_poison_reuse(tmp_path, monkeypatch):
    """A -wal planted next to a hash-matching stamped db is foreign by
    construction (stamping refuses pending journals). The snapshot
    consumer ignores it: the stamped edges are served and the planted
    frames are never folded into anything the consumer reads."""
    binary, store_path = _searchable_store(tmp_path, monkeypatch)
    wal = store_path.with_name(store_path.name + "-wal")
    wal.write_bytes(b"planted frames")
    reused = _try_graph_store(binary)
    assert reused is not None
    assert [(e.caller, e.callee) for e in reused.edges] == [("main", "leaf")]
    assert wal.read_bytes() == b"planted frames"
