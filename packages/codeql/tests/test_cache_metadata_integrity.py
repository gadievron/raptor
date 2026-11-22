"""Metadata sidecars must authenticate before they steer the cache.

``<language>-metadata.json`` feeds the serve decision, the
extraction-mode contract and both eviction legs, yet it is plain JSON
in a tree whose name any same-user writer can predict. The MAC
(``packages.codeql.cache_integrity``) makes forged, tampered, or
cross-slot-replayed sidecars read as cache misses; the fixtures here
exercise the real save/load chokepoints, not the MAC primitives alone.

The conftest pins ``XDG_DATA_HOME`` per test, so each test owns its
key file.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from packages.codeql import cache_integrity
from packages.codeql.database_manager import DatabaseManager, DatabaseMetadata

REPO_HASH = "a" * 64


@pytest.fixture
def manager(tmp_path):
    mgr = object.__new__(DatabaseManager)
    mgr.db_root = tmp_path / "cache"
    mgr.db_root.mkdir()
    return mgr


def _metadata(manager, repo: Path, language: str = "python") -> DatabaseMetadata:
    from packages.codeql.database_manager import database_content_digest
    db = manager.get_database_dir(REPO_HASH, language)
    return DatabaseMetadata(
        repo_hash=REPO_HASH, repo_path=str(repo), language=language,
        created_at=datetime.now(timezone.utc).isoformat(),
        codeql_version="2.26.3", build_command="",
        build_system="source-only", file_count=1, success=True,
        duration_seconds=0.1,
        errors=[],
        database_path=str(db),
        # Serve requires the promote-minted content digest to match
        # the planted DB's bytes.
        content_digest=database_content_digest(db),
    )


def _plant_valid_db(manager, language: str = "python") -> Path:
    db = manager.get_database_dir(REPO_HASH, language)
    sub = db / f"db-{language}"
    sub.mkdir(parents=True)
    (db / "codeql-database.yml").write_text(f"primaryLanguage: {language}\n")
    (sub / "blob.bin").write_bytes(b"\0" * 20480)
    return db


class TestSaveLoadRoundtrip:
    def test_saved_metadata_is_stamped_and_loads_back(
            self, manager, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _plant_valid_db(manager)
        manager.save_metadata(_metadata(manager, repo))

        raw = json.loads(
            manager.get_metadata_path(REPO_HASH, "python").read_text())
        assert cache_integrity.extract_token(raw), \
            "save_metadata must persist a stamped sidecar"

        loaded = manager.load_metadata(REPO_HASH, "python")
        assert loaded is not None
        assert loaded.success is True
        assert loaded.build_system == "source-only"

    def test_authentic_entry_serves_the_cached_db(self, manager, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        db = _plant_valid_db(manager)
        manager.save_metadata(_metadata(manager, repo))
        assert manager.get_cached_database(
            repo, "python", repo_hash=REPO_HASH, max_age_days=7) == db


class TestVerificationDemotes:
    def _plant_served_entry(self, manager, tmp_path) -> tuple[Path, Path]:
        repo = tmp_path / "repo"
        repo.mkdir()
        db = _plant_valid_db(manager)
        manager.save_metadata(_metadata(manager, repo))
        return repo, db

    def test_unstamped_legacy_sidecar_reads_as_miss(self, manager, tmp_path):
        repo, _db = self._plant_served_entry(manager, tmp_path)
        sidecar = manager.get_metadata_path(REPO_HASH, "python")
        raw = json.loads(sidecar.read_text())
        raw.pop(cache_integrity.TOKEN_KEY)
        sidecar.write_text(json.dumps(raw))

        assert manager.load_metadata(REPO_HASH, "python") is None
        assert manager.get_cached_database(
            repo, "python", repo_hash=REPO_HASH, max_age_days=7) is None

    def test_tampered_field_under_valid_token_reads_as_miss(
            self, manager, tmp_path):
        # The serve-steering fields are exactly what a forger would
        # rewrite: vouch a failed build as a success.
        repo, _db = self._plant_served_entry(manager, tmp_path)
        sidecar = manager.get_metadata_path(REPO_HASH, "python")
        raw = json.loads(sidecar.read_text())
        raw["build_system"] = "custom"
        raw["build_command"] = "make"
        sidecar.write_text(json.dumps(raw))

        assert manager.load_metadata(REPO_HASH, "python") is None

    def test_cross_slot_replay_reads_as_miss(self, manager, tmp_path):
        # A validly-stamped sidecar copied over ANOTHER slot's filename
        # must fail: the reader derives the binding name from its own
        # lookup arguments, never from the file content.
        repo, _db = self._plant_served_entry(manager, tmp_path)
        src = manager.get_metadata_path(REPO_HASH, "python")
        other_hash = "b" * 64
        dst = manager.get_metadata_path(other_hash, "python")
        dst.parent.mkdir(parents=True)
        dst.write_bytes(src.read_bytes())

        assert manager.load_metadata(other_hash, "python") is None
        # The original slot still authenticates.
        assert manager.load_metadata(REPO_HASH, "python") is not None

    def test_cross_language_replay_reads_as_miss(self, manager, tmp_path):
        repo, _db = self._plant_served_entry(manager, tmp_path)
        src = manager.get_metadata_path(REPO_HASH, "python")
        dst = manager.get_metadata_path(REPO_HASH, "cpp")
        dst.write_bytes(src.read_bytes())

        assert manager.load_metadata(REPO_HASH, "cpp") is None


class TestUnusableKeyDegradation:
    def test_unusable_key_persists_unstamped_and_misses(
            self, manager, tmp_path):
        # A group-readable key file is refused, never replaced: writes
        # persist unstamped and every read is a miss — caching is
        # honestly disabled rather than silently re-keyed.
        key_path = (Path(os.environ["XDG_DATA_HOME"]) / "raptor"
                    / "codeql-cache-mac.key")
        key_path.parent.mkdir(parents=True, mode=0o700)
        key_path.write_bytes(b"k" * 32)
        key_path.chmod(0o640)

        assert cache_integrity.key_usable() is False

        repo = tmp_path / "repo"
        repo.mkdir()
        _plant_valid_db(manager)
        manager.save_metadata(_metadata(manager, repo))

        raw = json.loads(
            manager.get_metadata_path(REPO_HASH, "python").read_text())
        assert cache_integrity.extract_token(raw) is None
        assert manager.load_metadata(REPO_HASH, "python") is None


class TestTokenShape:
    def test_malformed_token_boxes_read_as_unstamped(self):
        for box in (None, "bare-string", 7, {"token": 7}, []):
            assert cache_integrity.extract_token(
                {cache_integrity.TOKEN_KEY: box}) is None

    def test_verify_entry_refuses_non_dict(self):
        assert cache_integrity.verify_entry("x/python", ["not", "a", "dict"]) is False
