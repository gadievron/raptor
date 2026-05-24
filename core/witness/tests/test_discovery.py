"""Tests for ``core.witness.discovery``."""

from __future__ import annotations

import sys
from pathlib import Path


# core/witness/tests/test_discovery.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    WitnessStore,
    compute_bytes_hash,
    discover_witness_stores,
    iter_visible_witnesses,
)


def _put_one(root: Path, data: bytes, *, source=WitnessSource.FUZZ):
    """Create a store at ``root`` with one witness in it."""
    store = WitnessStore(root)
    store.put(
        Witness(
            bytes_hash=compute_bytes_hash(data),
            bytes_len=len(data),
            source=source,
            observed_outcome=WitnessOutcome.EXIT_SIGNAL,
            outcome_detail={"finding_id": data.decode("utf-8", "replace")[:16]},
        ),
        data,
    )


# ----------------------------------------------------------------------
# discover_witness_stores
# ----------------------------------------------------------------------


def test_no_output_dir_no_project_returns_empty():
    assert discover_witness_stores(None) == []


def test_nonexistent_output_dir_returns_empty(tmp_path):
    assert discover_witness_stores(tmp_path / "does_not_exist") == []


def test_run_local_finds_witnesses_subdir(tmp_path):
    """The conventional ``<out>/witnesses/`` store."""
    _put_one(tmp_path / "witnesses", b"x")
    stores = discover_witness_stores(tmp_path)
    assert len(stores) == 1
    assert (stores[0].resolve()) == (tmp_path / "witnesses").resolve()


def test_run_local_finds_analysis_witnesses(tmp_path):
    """The crash-agent location ``<out>/analysis/witnesses/``."""
    _put_one(tmp_path / "analysis" / "witnesses", b"x")
    stores = discover_witness_stores(tmp_path)
    assert len(stores) == 1
    assert "analysis" in str(stores[0])


def test_run_local_finds_autonomous_witnesses(tmp_path):
    """The /agentic location ``<out>/autonomous/witnesses/``."""
    _put_one(tmp_path / "autonomous" / "witnesses", b"x")
    stores = discover_witness_stores(tmp_path)
    assert len(stores) == 1
    assert "autonomous" in str(stores[0])


def test_run_local_finds_all_three(tmp_path):
    _put_one(tmp_path / "witnesses", b"x1")
    _put_one(tmp_path / "analysis" / "witnesses", b"x2")
    _put_one(tmp_path / "autonomous" / "witnesses", b"x3")
    stores = discover_witness_stores(tmp_path)
    assert len(stores) == 3


def test_dir_without_manifests_subdir_not_a_store(tmp_path):
    """Defensive: a dir named witnesses/ that lacks manifests/
    is not a WitnessStore — never had a put() call."""
    (tmp_path / "witnesses").mkdir()
    # No manifests/ subdir
    assert discover_witness_stores(tmp_path) == []


# ----------------------------------------------------------------------
# Project-wide discovery
# ----------------------------------------------------------------------


def test_project_root_globs_sibling_runs(tmp_path):
    """When a project root is provided, every sibling run's
    witness store is discovered."""
    project = tmp_path / "project"
    project.mkdir()
    # Three sibling runs
    _put_one(project / "fuzz_001" / "witnesses", b"fuzz1")
    _put_one(project / "agentic_002" / "autonomous" / "witnesses", b"a1")
    _put_one(
        project / "fuzz_003" / "analysis" / "witnesses", b"crash_agent_1",
    )

    out_dir = project / "validate_004"
    out_dir.mkdir()

    stores = discover_witness_stores(out_dir, project_root=project)
    # 3 sibling stores; current run has no store of its own
    assert len(stores) == 3


def test_run_local_listed_before_project_siblings(tmp_path):
    """Run-local stores come first — operators expect "what I
    just produced" at the top of the list, sibling-run history
    after."""
    project = tmp_path / "project"
    project.mkdir()
    _put_one(project / "fuzz_001" / "witnesses", b"sibling")

    out_dir = project / "validate_002"
    out_dir.mkdir()
    _put_one(out_dir / "witnesses", b"current")

    stores = discover_witness_stores(out_dir, project_root=project)
    # First entry is the current run's store
    assert "validate_002" in str(stores[0])
    assert any("fuzz_001" in str(s) for s in stores)


def test_dedup_by_resolved_path(tmp_path):
    """Same store reachable via two paths (e.g. current run is
    under project_root) is deduplicated."""
    project = tmp_path / "project"
    project.mkdir()
    _put_one(project / "fuzz_001" / "witnesses", b"x")

    out_dir = project / "fuzz_001"  # current run IS the sibling
    stores = discover_witness_stores(out_dir, project_root=project)
    assert len(stores) == 1


def test_project_root_unreadable_returns_empty_silently(tmp_path):
    """Cannot list project root → empty list, no exception.
    The end-of-run summary should never crash because of a
    permissions glitch on a stale project dir."""
    import os
    project = tmp_path / "project"
    project.mkdir()
    _put_one(project / "fuzz_001" / "witnesses", b"x")

    os.chmod(project, 0o000)
    try:
        # Should not raise even though project_root is unreadable
        stores = discover_witness_stores(None, project_root=project)
        # Either 0 (unreadable, log+return) or 1 (root-equivalent
        # bypasses chmod). Contract: doesn't raise.
        assert isinstance(stores, list)
    finally:
        os.chmod(project, 0o755)


# ----------------------------------------------------------------------
# iter_visible_witnesses
# ----------------------------------------------------------------------


def test_iter_yields_pairs(tmp_path):
    """Each yielded pair is (store_path, Witness)."""
    _put_one(tmp_path / "witnesses", b"x")
    stores = discover_witness_stores(tmp_path)
    pairs = list(iter_visible_witnesses(stores))
    assert len(pairs) == 1
    store_path, w = pairs[0]
    assert store_path == stores[0]
    assert w.bytes_hash == compute_bytes_hash(b"x")


def test_iter_dedups_by_bytes_hash(tmp_path):
    """Same bytes_hash in two stores → only first yielded."""
    project = tmp_path / "project"
    project.mkdir()
    # Same bytes in two sibling runs
    _put_one(project / "fuzz_001" / "witnesses", b"shared")
    _put_one(project / "fuzz_002" / "witnesses", b"shared")
    _put_one(project / "fuzz_002" / "witnesses", b"unique")

    stores = discover_witness_stores(None, project_root=project)
    pairs = list(iter_visible_witnesses(stores))
    hashes = [w.bytes_hash for _, w in pairs]
    # 2 unique hashes; the duplicate "shared" yielded only once
    assert len(hashes) == 2
    assert hashes.count(compute_bytes_hash(b"shared")) == 1
    assert hashes.count(compute_bytes_hash(b"unique")) == 1
