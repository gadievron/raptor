"""Tests for CodeQL database manager build command handling."""

import os
import stat
import subprocess as sp
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from packages.codeql.build_detector import BuildSystem
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def db_manager(tmp_path):
    """Create a DatabaseManager with a fake codeql binary."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.cache_dir = tmp_path / "cache"
        mgr.cache_dir.mkdir()
        # db_root mirrors what real __init__ sets (RaptorConfig.CODEQL_DB_DIR);
        # needed by load_metadata / get_metadata_path which don't go through
        # the get_database_dir seam that other tests patch.
        mgr.db_root = mgr.cache_dir
        return mgr


def _run_create(db_manager, tmp_path, command, language="javascript"):
    """Run create_database and capture the subprocess command and script state."""
    bs = BuildSystem(type="npm", command=command, working_dir=tmp_path,
                     env_vars={}, confidence=1.0, detected_files=[])
    captured = {"cmd": [], "script_content": None, "script_mode": None}

    def fake_run(cmd, **kwargs):
        # Only capture the database create call, not codeql version etc.
        if "database" in cmd or "create" in cmd:
            captured["cmd"] = list(cmd)
            for arg in cmd:
                p = Path(str(arg))
                if p.name.startswith(".raptor_codeql_build_") and p.exists():
                    captured["script_content"] = p.read_text()
                    captured["script_mode"] = p.stat().st_mode
        r = MagicMock()
        r.returncode = 0
        r.stdout = "2.16.0"
        return r

    db_path = tmp_path / "db"
    with patch('subprocess.run', side_effect=fake_run), \
         patch.object(db_manager, '_count_database_files', return_value=0), \
         patch.object(db_manager, 'save_metadata'), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir', return_value=db_path):
        db_manager.create_database(tmp_path, language, bs)

    return captured


class TestBuildScript:
    """CodeQL --command is always wrapped in a build script."""

    def test_simple_command_passed_directly(self, db_manager, tmp_path):
        """Single-word commands like 'make' pass through without a script."""
        c = _run_create(db_manager, tmp_path, "make")
        assert c["script_content"] is None
        idx = c["cmd"].index("--command")
        assert c["cmd"][idx + 1] == "make"

    def test_shell_operators_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert "npm install && npm run build" in c["script_content"]

    def test_or_operator_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "pip install -e . || pip install -r requirements.txt")
        assert "||" in c["script_content"]

    def test_script_has_shebang(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert c["script_content"].startswith("#!/bin/bash\n")

    def test_script_is_executable(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert c["script_mode"] & stat.S_IEXEC

    def test_script_passed_as_command_arg(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert "--command" in c["cmd"]
        idx = c["cmd"].index("--command")
        assert ".raptor_codeql_build_" in c["cmd"][idx + 1]

    def test_no_command_equals_format(self, db_manager, tmp_path):
        """Never uses --command=value (the old broken format)."""
        c = _run_create(db_manager, tmp_path, "make")
        assert not any(arg.startswith("--command=") for arg in c["cmd"])

    def test_script_cleaned_up_after_success(self, db_manager, tmp_path):
        _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_failure(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 1
            r.stderr = "fail"
            return r

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_timeout(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=sp.TimeoutExpired("cmd", 60)), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_empty_command_no_script(self, db_manager, tmp_path):
        bs = BuildSystem(type="no-build", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            nonlocal captured_cmd
            captured_cmd = list(cmd)
            r = MagicMock()
            r.returncode = 0
            return r

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "python", bs)

        assert "--command" not in captured_cmd
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))


# ---------------------------------------------------------------------------
# Concurrent-write safety: build-in-staging + atomic-promote
# ---------------------------------------------------------------------------


class TestStagingPromote:
    """create_database builds in staging, atomic-promotes to canonical;
    concurrent writers don't corrupt; readers never see partial state."""

    def test_staging_path_is_same_parent_as_canonical(self, db_manager, tmp_path):
        # Same-fs requirement for atomic rename — staging and canonical
        # must share a parent directory.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            staging = db_manager._staging_path("abc", "python")
        assert staging.parent == canonical.parent

    def test_staging_path_includes_pid(self, db_manager, tmp_path):
        # Per-process staging means concurrent writers don't collide on
        # the staging dir itself.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            staging = db_manager._staging_path("abc", "python")
        assert f"-{os.getpid()}" in staging.name
        assert staging.name.startswith(".staging-")

    def test_successful_build_renames_staging_to_canonical(self, db_manager, tmp_path):
        # On success, staging dir disappears (was renamed) and canonical
        # exists with the build's content.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            # Simulate codeql writing the DB to the staging path it was
            # given on the command line. cmd[3] is the staging path
            # (codeql, database, create, <staging>, ...).
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "db-info.json").write_text("{}")
            r = MagicMock(); r.returncode = 0; r.stdout = "2.16.0"; r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=1), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is True
        assert canonical.exists(), "canonical should exist after promote"
        assert (canonical / "db-info.json").exists(), "canonical content present"
        # No staging dirs left behind (the rename ate ours; no orphans).
        assert not list(canonical.parent.glob(".staging-*"))

    def test_lost_promotion_race_uses_winner_canonical(self, db_manager, tmp_path):
        # Simulate: another writer populated canonical between our cache-miss
        # check and our promote attempt. We should cleanup our staging and
        # return the winner's canonical path.
        # Canonical must pass validate_database for the lost-race branch
        # to accept it: batch 399 requires not just `codeql-database.yml`
        # but also a `db-<lang>/` subdir holding > 100KB of trie content
        # (real CodeQL DB shape). The fixture mimics that shape so the
        # test exercises the "winner is valid → use their canonical"
        # path rather than the "winner looks broken → evict + retry"
        # path which has its own dedicated tests.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        # Pre-populate canonical (simulating sibling who finished first)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        (canonical / "winner-marker").write_text("winner")
        winner_db = canonical / "db-python"
        winner_db.mkdir()
        # > 100KB to clear validate_database's minimum-substance check.
        (winner_db / "trie.bin").write_bytes(b"w" * 150_000)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "loser-marker").write_text("loser")
            r = MagicMock(); r.returncode = 0; r.stdout = "2.16.0"; r.stderr = ""
            return r

        # Patch _evict_stale_canonical to no-op so the test stays focused on
        # the lost-race-with-valid-canonical scenario rather than the
        # pre-build eviction logic (which has its own dedicated tests).
        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=1), \
             patch.object(db_manager, 'save_metadata') as save_meta_mock, \
             patch.object(db_manager, '_evict_stale_canonical'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is True
        assert result.database_path == canonical
        # Winner's content survived (loser's didn't overwrite)
        assert (canonical / "winner-marker").exists()
        assert not (canonical / "loser-marker").exists()
        # Loser's staging dir is gone (cleanup)
        assert not list(canonical.parent.glob(".staging-*"))
        # used_cached=True correctly reflects that we're using sibling's cache
        assert result.cached is True
        # Loser must NOT overwrite winner's metadata (winner already saved
        # consistent metadata; saving again would just be churn)
        save_meta_mock.assert_not_called()

    def test_lost_promotion_race_with_invalid_canonical_evicts_and_promotes_ours(
            self, db_manager, tmp_path):
        """Sibling promoted broken content (e.g., missing codeql-database.yml)
        between our cache check and our promote attempt. We must:
        (a) validate canonical before trusting it — without this check,
            a sibling who promoted broken content would propagate to us
            as success=True pointing at garbage,
        (b) evict the broken canonical and retry-promote our valid
            staging into the now-empty slot — without retry, the next
            run would redundantly rebuild because the cache slot stays
            empty.

        We patch _evict_stale_canonical to no-op so this test focuses on
        the post-build lost-race branch. The pre-build eviction logic
        has its own dedicated tests in TestEvictStaleCanonicalGracePeriod.
        """
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        # Pre-populate canonical with INVALID content (no codeql-database.yml).
        canonical.mkdir()
        (canonical / "marker").write_text("broken sibling promote")

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "codeql-database.yml").write_text("language: python\n")
            (staging_arg / "valid-content").write_text("our build")
            r = MagicMock(); r.returncode = 0; r.stdout = "2.16.0"; r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=2), \
             patch.object(db_manager, 'save_metadata') as save_meta_mock, \
             patch.object(db_manager, '_evict_stale_canonical'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        # We succeeded (didn't propagate sibling's broken canonical as success)
        assert result.success is True
        assert result.cached is False  # we used our own build, not cache
        # Result points at canonical because we retry-promoted our valid
        # staging into the empty slot (after evicting broken sibling copy).
        # Pre-R2 behaviour was final_path=staging; R2 now retries the
        # promote so future runs hit cache instead of redundantly rebuilding.
        assert result.database_path == canonical, \
            f"expected canonical (promoted via retry), got: {result.database_path}"
        assert (canonical / "codeql-database.yml").exists()
        assert (canonical / "valid-content").exists()
        # Broken canonical was evicted (renamed to .stale.*) — exactly one
        # marker since this is a single eviction.
        stale_markers = list(canonical.parent.glob("*.stale.*"))
        assert len(stale_markers) == 1, \
            f"expected 1 stale marker from eviction, got: {len(stale_markers)}"
        # We DID save metadata because we retry-promoted (did_promote=True)
        save_meta_mock.assert_called_once()
        # Our staging dir is gone — got renamed to canonical
        assert not list(canonical.parent.glob(".staging-*"))

    def test_build_failure_cleans_up_staging(self, db_manager, tmp_path):
        # Failed builds must not leave staging dirs lying around (would
        # confuse cache lookups and pollute the cache dir).
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "partial").write_text("garbage")
            r = MagicMock(); r.returncode = 1; r.stdout = ""; r.stderr = "build failed"
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is False
        assert not canonical.exists(), "failed build must not promote"
        assert not list(canonical.parent.glob(".staging-*")), "staging cleanup"


class TestStaleMarkerGC:
    """_gc_stale_markers reaps abandoned .staging-*/.stale.* dirs after TTL."""

    def test_gc_removes_old_staging_dirs(self, db_manager, tmp_path):
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        old = repo_dir / ".staging-python-99999"
        old.mkdir()
        # Make it look 2 hours old (well past 1-hour TTL)
        old_mtime = time.time() - 7200
        os.utime(old, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert not old.exists()

    def test_gc_preserves_recent_staging(self, db_manager, tmp_path):
        # Active concurrent writer's staging dir is fresh; must not be GC'd
        # while the writer might still need it.
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        recent = repo_dir / ".staging-python-12345"
        recent.mkdir()  # mtime = now

        db_manager._gc_stale_markers(repo_dir)

        assert recent.exists()

    def test_gc_removes_old_stale_markers(self, db_manager, tmp_path):
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        # Evicted-stale marker name pattern from _evict_stale_canonical
        old_stale = repo_dir / "python-db.stale.1234567890.99999"
        old_stale.mkdir()
        old_mtime = time.time() - 7200
        os.utime(old_stale, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert not old_stale.exists()

    def test_gc_leaves_unrelated_files(self, db_manager, tmp_path):
        # Real DBs and metadata files in the cache dir must not be touched.
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        real_db = repo_dir / "python-db"
        real_db.mkdir()
        real_meta = repo_dir / "python-metadata.json"
        real_meta.write_text("{}")

        db_manager._gc_stale_markers(repo_dir)

        assert real_db.exists()
        assert real_meta.exists()


class TestStaleMarkerName:
    """`_stale_marker_name` must produce nanosecond-unique names so two
    same-second evictions from the same process don't collide on the
    rename target (which would silently leave the canonical in place)."""

    def test_marker_includes_nanosecond_timestamp(self, db_manager, tmp_path):
        canonical = tmp_path / "python-db"
        marker = db_manager._stale_marker_name(canonical)
        # Format: <name>.stale.<time_ns>.<pid>
        # Nanosecond timestamps are 19 digits as of 2026 (approx).
        parts = marker.split(".stale.")
        assert parts[0] == "python-db"
        ts_pid = parts[1].split(".")
        assert len(ts_pid) == 2
        ts, pid = ts_pid
        assert ts.isdigit() and len(ts) >= 18, \
            f"expected ns-precision timestamp, got {ts!r}"
        assert pid.startswith("") and pid.isdigit()

    def test_two_calls_in_same_second_produce_distinct_names(
            self, db_manager, tmp_path):
        # The whole point of using time_ns: two calls in quick succession
        # (likely same second) get distinct names so consecutive evictions
        # don't collide on the rename target.
        canonical = tmp_path / "python-db"
        a = db_manager._stale_marker_name(canonical)
        b = db_manager._stale_marker_name(canonical)
        assert a != b, f"same-second marker collision: {a} == {b}"


class TestEvictStaleCanonicalGracePeriod:
    """Regression for the R1 race: in-flight writers (just promoted
    canonical, haven't called save_metadata yet) must NOT have their
    canonical evicted by a sibling. Before the grace period was added,
    _evict_stale_canonical aggressively evicted any canonical with no
    metadata — racing the writer's hundreds-of-ms post-promote/pre-save
    window."""

    def test_fresh_canonical_with_no_metadata_is_not_evicted(
            self, db_manager, tmp_path):
        # Simulate: writer just renamed staging→canonical but hasn't
        # called save_metadata yet. canonical's mtime is fresh.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        # NOTE: deliberately no <lang>-metadata.json file — simulating
        # the gap between os.rename and save_metadata.

        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            db_manager._evict_stale_canonical("abc", "python", max_age_days=7)

        # Fresh canonical without metadata must NOT be evicted (grace
        # period protects in-flight writers).
        assert canonical.exists(), \
            "in-flight writer's fresh canonical was wrongly evicted"
        assert not list(canonical.parent.glob("*.stale.*")), \
            "no stale markers should be created"

    def test_old_canonical_with_no_metadata_IS_evicted(
            self, db_manager, tmp_path):
        # Simulate: previous writer crashed between rename and
        # save_metadata, leaving canonical orphaned. It's been there
        # for longer than the grace period — must be evicted so the
        # next run can rebuild and save consistent metadata.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        # Backdate canonical's mtime well past the grace period.
        from core.config import RaptorConfig
        old_mtime = time.time() - (RaptorConfig.CODEQL_DB_MISSING_METADATA_GRACE + 60)
        os.utime(canonical, (old_mtime, old_mtime))

        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            db_manager._evict_stale_canonical("abc", "python", max_age_days=7)

        # Orphan must be evicted to break the rebuild loop.
        assert not canonical.exists(), \
            "orphaned canonical past grace period should be evicted"
        assert len(list(canonical.parent.glob("*.stale.*"))) == 1, \
            "exactly one stale marker should be created from eviction"
