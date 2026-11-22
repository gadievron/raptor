"""Cached CodeQL database bytes must match the stamped sidecar digest.

The metadata MAC (``packages.codeql.cache_integrity``) binds the
sidecar's CLAIMS, but the database tree beside it was plain trusted
bytes: anyone who can write the cache tree (a same-user process, a
restored or shared cache) could swap relation files or ``src.zip``
under a validly-stamped sidecar and steer every later analysis.
``database_content_digest`` closes the gap with an immutable-subset
digest — minted at promote on the out-of-grant canonical tree,
stamped into the MAC'd sidecar, recomputed and compared at serve. The
subset excludes everything ``database analyze`` legitimately writes
(results, logs, evaluator cache dirs) so the cache never false-misses
after an analyze, and the digest walk doubles as the hostile-shape
sweep: an internal symlink or special file anywhere refuses the tree
(it would ride into analyze's writable sandbox bind).

All tests are fully mocked — no codeql CLI, no sandbox, no network.
The conftest pins ``XDG_DATA_HOME`` per test, so each test owns its
MAC key.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.build.build_detector import BuildSystem
from packages.codeql.database_manager import (
    DatabaseManager,
    DatabaseMetadata,
    database_content_digest,
)

REPO_HASH = "a" * 64


@pytest.fixture
def manager(tmp_path):
    mgr = object.__new__(DatabaseManager)
    mgr.db_root = tmp_path / "cache"
    mgr.db_root.mkdir()
    return mgr


def _plant_db(manager, language: str = "python") -> Path:
    """A structurally valid DB with content in every region class:
    digest-covered (yml, src.zip, relations), analyze-writable
    (evaluator cache), and outside-the-subset (results)."""
    db = manager.get_database_dir(REPO_HASH, language)
    default = db / f"db-{language}" / "default"
    default.mkdir(parents=True)
    (db / "codeql-database.yml").write_text(f"primaryLanguage: {language}\n")
    (db / "src.zip").write_bytes(b"PK-src-archive-bytes")
    (default / "data.rel").write_bytes(b"\x01" * 20480)
    (default / "cache").mkdir()
    (default / "cache" / "page.bin").write_bytes(b"\x02" * 64)
    (db / "results").mkdir()
    (db / "results" / "old.sarif").write_text("{}")
    return db


def _metadata(manager, repo: Path, db: Path,
              language: str = "python") -> DatabaseMetadata:
    return DatabaseMetadata(
        repo_hash=REPO_HASH, repo_path=str(repo), language=language,
        created_at=datetime.now(timezone.utc).isoformat(),
        codeql_version="2.26.3", build_command="",
        build_system="source-only", file_count=1, success=True,
        duration_seconds=0.1, errors=[], database_path=str(db),
        content_digest=database_content_digest(db),
    )


def _serve(manager, repo: Path, language: str = "python") -> Path | None:
    return manager.get_cached_database(
        repo, language, repo_hash=REPO_HASH, max_age_days=7)


def _served_entry(manager, tmp_path) -> tuple:
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _plant_db(manager)
    manager.save_metadata(_metadata(manager, repo, db))
    return repo, db


class TestDigestSubset:
    def test_stable_across_analyze_writes(self, manager):
        db = _plant_db(manager)
        before = database_content_digest(db)
        assert isinstance(before, str) and before
        # Everything `database analyze` writes inside the DB: results,
        # logs, diagnostics, and the evaluator cache under db-*.
        (db / "results" / "new.sarif").write_text('{"runs": []}')
        (db / "log").mkdir()
        (db / "log" / "execute-queries.log").write_text("ran\n")
        (db / "diagnostic").mkdir()
        (db / "diagnostic" / "d.jsonl").write_text("{}\n")
        cache = db / "db-python" / "default" / "cache"
        (cache / "lock").write_text("pid")
        (cache / "page.bin").write_bytes(b"\x03" * 128)
        assert database_content_digest(db) == before

    @pytest.mark.parametrize("rel_path", [
        "codeql-database.yml",
        "src.zip",
        "db-python/default/data.rel",
    ])
    def test_rewriting_subset_file_changes_digest(self, manager, rel_path):
        db = _plant_db(manager)
        before = database_content_digest(db)
        target = db / rel_path
        # Same length — a size-only fingerprint would not notice.
        target.write_bytes(bytes(len(target.read_bytes())))
        assert database_content_digest(db) != before

    def test_added_and_renamed_relations_change_digest(self, manager):
        db = _plant_db(manager)
        before = database_content_digest(db)
        extra = db / "db-python" / "default" / "extra.rel"
        extra.write_bytes(b"\x04" * 32)
        added = database_content_digest(db)
        assert added != before
        # Renames change the manifest even with identical bytes: the
        # digest covers paths, not just a bag of content hashes.
        extra.rename(db / "db-python" / "default" / "other.rel")
        assert database_content_digest(db) not in (before, added)

    def test_symlink_anywhere_refuses(self, manager, tmp_path):
        # Even in regions OUTSIDE the digest subset: the whole tree
        # becomes a writable analyze bind, so a link is hostile shape
        # wherever it sits.
        outside = tmp_path / "outside.txt"
        outside.write_text("host file\n")
        for rel in ("results/link", "db-python/default/cache/link",
                    "db-python/default/link.rel"):
            db = _plant_db(manager)
            (db / rel).symlink_to(outside)
            assert database_content_digest(db) is None, rel
            import shutil
            shutil.rmtree(db.parent)

    def test_special_file_refuses(self, manager):
        db = _plant_db(manager)
        os.mkfifo(db / "db-python" / "default" / "pipe")
        assert database_content_digest(db) is None

    def test_hardlinked_file_refuses(self, manager, tmp_path):
        # A hard link is a second dirent to the same inode: the bytes
        # can be rewritten from OUTSIDE the tree after the verdict,
        # and analyze's writable bind writes the shared inode wherever
        # else it is linked — hostile shape in any region.
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"\x06" * 32)
        for rel in ("db-python/default/linked.rel", "results/linked"):
            db = _plant_db(manager)
            os.link(outside, db / rel)
            assert database_content_digest(db) is None, rel
            import shutil
            shutil.rmtree(db.parent)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
    def test_unreadable_subset_file_refuses(self, manager):
        db = _plant_db(manager)
        rel = db / "db-python" / "default" / "data.rel"
        rel.chmod(0)
        try:
            assert database_content_digest(db) is None
        finally:
            rel.chmod(0o600)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
    def test_unreadable_directory_refuses(self, manager):
        """An unreadable directory must refuse the whole tree, not be
        skipped: ``os.walk``'s default onerror swallows the failure
        silently, and whatever the directory holds — a symlink the
        shape sweep never sees, relations the digest never covers —
        would be invisible to the trust decision."""
        db = _plant_db(manager)
        hidden = db / "db-python" / "default" / "hidden"
        hidden.mkdir()
        (hidden / "x.rel").write_bytes(b"\x05" * 16)
        hidden.chmod(0)
        try:
            assert database_content_digest(db) is None
        finally:
            hidden.chmod(0o700)


class TestServeComparesDigest:
    def test_matching_tree_serves(self, manager, tmp_path):
        repo, db = _served_entry(manager, tmp_path)
        assert _serve(manager, repo) == db

    def test_swapped_relation_file_reads_as_miss(self, manager, tmp_path):
        repo, db = _served_entry(manager, tmp_path)
        rel = db / "db-python" / "default" / "data.rel"
        rel.write_bytes(bytes(len(rel.read_bytes())))
        assert _serve(manager, repo) is None

    def test_swapped_src_zip_reads_as_miss(self, manager, tmp_path):
        # src.zip is the source every snippet/coverage reader trusts.
        repo, db = _served_entry(manager, tmp_path)
        (db / "src.zip").write_bytes(b"PK-other-source-bytes")
        assert _serve(manager, repo) is None

    def test_analyze_writes_do_not_miss(self, manager, tmp_path):
        repo, db = _served_entry(manager, tmp_path)
        (db / "results" / "run.sarif").write_text("{}")
        (db / "db-python" / "default" / "cache" / "lock").write_text("pid")
        assert _serve(manager, repo) == db

    def test_internal_symlink_reads_as_miss(self, manager, tmp_path):
        repo, db = _served_entry(manager, tmp_path)
        (db / "results" / "link").symlink_to(tmp_path / "anywhere")
        assert _serve(manager, repo) is None

    def test_hardlinked_file_reads_as_miss(self, manager, tmp_path):
        repo, db = _served_entry(manager, tmp_path)
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"\x06" * 32)
        os.link(outside, db / "results" / "linked")
        assert _serve(manager, repo) is None

    def test_legacy_entry_without_digest_reads_as_miss(
            self, manager, tmp_path):
        # Stamped before the digest existed: the MAC verifies but the
        # content was never bound — one-time rebuild, same posture as
        # the unstamped-sidecar upgrade path. (Stripping the field
        # from a digest-bearing sidecar breaks the MAC instead.)
        repo = tmp_path / "repo"
        repo.mkdir()
        db = _plant_db(manager)
        meta = _metadata(manager, repo, db)
        meta.content_digest = None
        manager.save_metadata(meta)
        assert manager.load_metadata(REPO_HASH, "python") is not None
        assert _serve(manager, repo) is None


# ---------------------------------------------------------------------------
# Promote-side: the digest is minted on the out-of-grant canonical
# tree and hostile shapes never become the cache slot.
# ---------------------------------------------------------------------------


@pytest.fixture
def db_manager(tmp_path):
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.db_root = tmp_path / "cache"
        mgr.db_root.mkdir()
        mgr.cache_dir = mgr.db_root
        return mgr


def _create(db_manager, tmp_path, *, returncode: int = 0,
            build_hook=None):
    """create_database with a fake sandbox; ``build_hook(staging_db)``
    shapes the build output (default: a valid minimal DB)."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    canonical = db_manager.db_root / "abc" / "python-db"

    def fake_run(cmd, **kwargs):
        if "database" in cmd and "create" in cmd:
            staging_db = Path(cmd[3])
            default = staging_db / "db-python" / "default"
            default.mkdir(parents=True, exist_ok=True)
            (staging_db / "codeql-database.yml").write_text(
                "primaryLanguage: python\n")
            (staging_db / "src.zip").write_bytes(b"PK-src")
            (default / "data.rel").write_bytes(b"\x01" * 20480)
            if build_hook:
                build_hook(staging_db)
        r = MagicMock()
        r.returncode = returncode
        r.stdout = ""
        r.stderr = "build failed" if returncode else ""
        return r

    build = BuildSystem(type="pip", command="", working_dir=tmp_path,
                        env_vars={}, confidence=1.0, detected_files=[])
    with patch('core.sandbox.run', side_effect=fake_run), \
         patch.object(db_manager, 'get_codeql_version',
                      return_value="2.26.3"), \
         patch.object(db_manager, '_count_database_files',
                      return_value=1), \
         patch.object(db_manager, 'get_cached_database',
                      return_value=None), \
         patch.object(db_manager, 'compute_repo_hash',
                      return_value='abc'), \
         patch.object(db_manager, 'get_database_dir',
                      return_value=canonical):
        result = db_manager.create_database(repo, "python", build)
    return result, canonical


class TestPromoteMintsDigest:
    def test_promote_stamps_the_canonical_trees_digest(
            self, db_manager, tmp_path):
        result, canonical = _create(db_manager, tmp_path)
        assert result.success
        assert result.metadata.content_digest == \
            database_content_digest(canonical)
        # And the persisted sidecar carries it under the MAC.
        loaded = db_manager.load_metadata("abc", "python")
        assert loaded is not None
        assert loaded.content_digest == result.metadata.content_digest

    def test_internal_symlink_in_build_output_refused(
            self, db_manager, tmp_path):
        # The top-level dirent gate cannot see a link NESTED in the
        # build output; the promote sweep must.
        outside = tmp_path / "host-file"
        outside.write_text("host\n")
        result, canonical = _create(
            db_manager, tmp_path,
            build_hook=lambda db: (
                db / "db-python" / "planted").symlink_to(outside))
        assert result.success is False
        assert any("refused" in e for e in result.errors)
        assert not canonical.exists()
        assert db_manager.load_metadata("abc", "python") is None

    def test_detach_refuses_internal_symlink(self, db_manager, tmp_path):
        # The promote-failure fallback hands the caller a DB for
        # direct analysis — same sweep, same refusal.
        staging = tmp_path / ".staging-x" / "python-db"
        (staging / "db-python").mkdir(parents=True)
        (staging / "db-python" / "planted").symlink_to(tmp_path)
        slot = tmp_path / "slot"
        slot.mkdir()
        assert db_manager._detach_staging_from_gc(
            staging, "python", slot_dir=slot) is None
        assert not any(slot.iterdir())


class TestFailurePreserveSalvage:
    def test_salvage_reads_from_the_preserved_tree(
            self, db_manager, tmp_path):
        # The failed staging is lifted OUT of the build grant first
        # (rename to slot level), and the log tail is read from the
        # preserved tree — the pre-fix order read it from the staging
        # path while an orphaned build child could still swap it.
        def plant_log(staging_db: Path) -> None:
            log = staging_db / "log"
            log.mkdir()
            (log / "database-create-20260101.log").write_text(
                "extractor exploded: marker-text-xyz\n")

        result, canonical = _create(
            db_manager, tmp_path, returncode=1, build_hook=plant_log)
        assert result.success is False
        assert any("marker-text-xyz" in e for e in result.errors)
        preserved = canonical.parent / ".staging-failed-python"
        assert (preserved / "log").is_dir()
        assert not canonical.exists()
