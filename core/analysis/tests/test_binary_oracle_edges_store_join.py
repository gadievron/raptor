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
