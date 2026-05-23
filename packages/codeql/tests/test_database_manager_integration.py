"""Integration tests for CodeQL database_manager concurrent-write safety.

These tests use real multiprocessing (one mp.Process per worker, spawn
context) to exercise the build-in-staging + atomic-promote flow with
real PIDs and real concurrent file operations — exactly the conditions
where the bug this fix addresses (two concurrent /codeql runs corrupting
each other's canonical DB) actually manifests.

Mocks-only unit tests in test_database_manager.py validate the logic
shape; these tests validate behaviour under real concurrency.

Tests are timing-sensitive (rely on sleep widening the race window).
Marked slow; default 30s timeout per test.
"""

import multiprocessing as mp
import os
import random
import time
from pathlib import Path
from unittest.mock import patch, MagicMock



# Module-level worker — spawn pickles by name, so it must not be nested
# inside a test class or closure. State arrives via args; nothing from
# the parent process is captured.
def _concurrent_create_worker(args):
    """Worker run inside a subprocess.

    Each process:
      - constructs its own DatabaseManager pointing at the shared cache_dir
      - patches `core.sandbox.run` locally (patches don't cross process
        boundaries, so each worker sets up its own)
      - calls create_database; returns the outcome
    """
    cache_dir_str, repo_path_str, sleep_min, sleep_max = args

    cache_dir = Path(cache_dir_str)
    repo_path = Path(repo_path_str)

    from packages.codeql.database_manager import DatabaseManager

    mgr = DatabaseManager.__new__(DatabaseManager)
    mgr.codeql_cli = "/usr/bin/codeql"
    mgr.db_root = cache_dir

    def fake_sandbox_run(cmd, **kwargs):
        # cmd[3] is the staging path the production code told codeql to
        # write to. Simulate codeql writing real content to that path,
        # with a randomised delay to widen the race window between
        # workers.
        staging = Path(cmd[3])
        staging.mkdir(parents=True, exist_ok=True)
        time.sleep(random.uniform(sleep_min, sleep_max))
        # codeql-database.yml is the legacy marker validate_database
        # checked for. Batch 399 added a stricter check: at least one
        # `db-<lang>/` subdirectory must exist and hold > 100KB of
        # content (real codeql databases write per-language tries
        # under db-cpp/, db-java/, db-python/, etc.). The fixture
        # mimics that shape so validate_database accepts it.
        (staging / "codeql-database.yml").write_text(
            "sourceLocationPrefix: /repo\nlanguage: python\n"
        )
        (staging / "db-info.json").write_text(f'{{"pid": {os.getpid()}}}')
        db_subdir = staging / "db-python"
        db_subdir.mkdir(exist_ok=True)
        # > 100KB of "trie" content under db-python/ to pass the
        # validate_database minimum-substance check.
        for i in range(3):
            (db_subdir / f"chunk-{i}.bin").write_bytes(b"x" * 50_000)
        r = MagicMock()
        r.returncode = 0
        r.stdout = "2.16.0"
        r.stderr = ""
        return r

    with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
         patch.object(mgr, '_count_database_files', return_value=4):
        result = mgr.create_database(repo_path, "python")

    return {
        'success': result.success,
        'database_path': str(result.database_path) if result.database_path else None,
        'pid': os.getpid(),
        'cached': result.cached,
    }


def _process_worker_target(args, queue):
    """Module-level Process target so spawn can pickle it. Forwards the
    worker's return value through the queue."""
    queue.put(_concurrent_create_worker(args))


def _run_concurrent_workers(args_list):
    """Spawn one fresh process per task and collect their results.

    Why mp.Process per task instead of mp.Pool.map: Pool uses a shared
    task queue (chunksize=1 by default), so a worker that finishes its
    first task fast can pull the next one before slower siblings finish
    their first — concentrating multiple tasks onto fewer PIDs. That
    breaks the "N independent /codeql invocations" model these tests
    are simulating, and it would also exercise the same staging-path
    twice within one process (PID-derived path) which is not what the
    concurrent-write story is about.
    """
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    procs = [ctx.Process(target=_process_worker_target, args=(args, queue))
             for args in args_list]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    # Result order is by completion time, not args order; tests treat
    # results as a set of independent outcomes so this is fine.
    return [queue.get() for _ in args_list]


class TestConcurrentCreateDatabase:
    """End-to-end concurrent-write safety: multiple real processes
    racing to populate the same cache slot must all succeed without
    corruption, exactly one canonical survives, no orphan staging."""

    def _make_target_repo(self, tmp_path: Path) -> Path:
        """Build a small fake repo for compute_repo_hash to digest."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.py").write_text("def f():\n    return 42\n")
        (repo / "lib.py").write_text("def g(x):\n    return x * 2\n")
        return repo

    def test_four_concurrent_writers_all_succeed_no_corruption(self, tmp_path):
        """Four parallel processes call create_database against the same
        target. All must succeed; exactly one wins the canonical slot;
        losers either get a database_path pointing at canonical (race
        absorbed via re-check) or at their own staging (rare fallback);
        no orphan .staging-* dirs left behind.
        """
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        repo_path = self._make_target_repo(tmp_path)

        n_workers = 4
        # Wide-ish sleep window forces real overlap between workers
        args = [(str(cache_dir), str(repo_path), 0.1, 0.3)
                for _ in range(n_workers)]

        results = _run_concurrent_workers(args)

        # All workers succeeded
        for i, r in enumerate(results):
            assert r['success'], f"worker {i} failed: {r}"

        # One process per task — each worker has its own PID.
        assert len(set(r['pid'] for r in results)) == n_workers

        # Cache slot is populated. Compute hash from the same code path
        # workers used so we look in the right place.
        from packages.codeql.database_manager import DatabaseManager
        helper = DatabaseManager.__new__(DatabaseManager)
        helper.db_root = cache_dir
        repo_hash = helper.compute_repo_hash(repo_path)
        canonical = cache_dir / repo_hash / "python-db"

        assert canonical.exists(), \
            f"canonical {canonical} should exist after the race"
        assert (canonical / "db-info.json").exists(), \
            "canonical should have content from whichever worker won"

        # No orphan staging dirs — every worker either renamed theirs
        # to canonical or cleaned up after losing the promotion race.
        repo_dir = canonical.parent
        orphan_staging = list(repo_dir.glob(".staging-*"))
        assert orphan_staging == [], \
            f"orphan staging dirs remain: {orphan_staging}"

        # No stale markers (none should be created on a fresh-cache run)
        orphan_stale = list(repo_dir.glob("*.stale.*"))
        assert orphan_stale == [], \
            f"unexpected stale markers: {orphan_stale}"

    def test_eight_concurrent_writers_with_tighter_race(self, tmp_path):
        """Higher concurrency with shorter sleep windows — increases the
        chance of multiple workers ALL hitting cache miss simultaneously,
        which is the worst case for redundant work but should still
        produce zero corruption."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        repo_path = self._make_target_repo(tmp_path)

        n_workers = 8
        args = [(str(cache_dir), str(repo_path), 0.02, 0.1)
                for _ in range(n_workers)]

        results = _run_concurrent_workers(args)

        # Same invariants as the 4-worker case
        for i, r in enumerate(results):
            assert r['success'], f"worker {i} failed: {r}"

        from packages.codeql.database_manager import DatabaseManager
        helper = DatabaseManager.__new__(DatabaseManager)
        helper.db_root = cache_dir
        repo_hash = helper.compute_repo_hash(repo_path)
        canonical = cache_dir / repo_hash / "python-db"

        assert canonical.exists()
        repo_dir = canonical.parent
        assert list(repo_dir.glob(".staging-*")) == []

    def test_sequential_after_concurrent_uses_cache(self, tmp_path):
        """After the race resolves and canonical is populated, a
        subsequent (sequential) invocation should hit the cache rather
        than rebuild — confirms the redundant-work cost is bounded to
        the initial race, not amortised across every later run."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        repo_path = self._make_target_repo(tmp_path)

        # Phase 1: initial concurrent burst populates cache
        results = _run_concurrent_workers(
            [(str(cache_dir), str(repo_path), 0.05, 0.15)
             for _ in range(3)]
        )
        assert all(r['success'] for r in results)

        # Phase 2: a fresh single process — should hit cache
        # NOTE: get_cached_database checks for metadata + valid DB; the
        # workers' save_metadata DOES run when their staging promotes to
        # canonical, so the cache hit path should fire.
        result = _concurrent_create_worker(
            (str(cache_dir), str(repo_path), 0.05, 0.15)
        )
        assert result['success']
        assert result['cached'], \
            "second-phase invocation should have hit the cache " \
            "populated by the first-phase race"
