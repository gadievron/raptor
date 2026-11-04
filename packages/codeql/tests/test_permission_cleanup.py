"""Database retention reclaims protected files without losing failure receipts."""

import json
from datetime import datetime, timedelta, timezone
import pytest
from packages.codeql.database_manager import DatabaseManager
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("dry_run", [False, True])
def test_database_retention_respects_dry_run_and_reclaims_permissions(
    tmp_path, mode, dry_run
):
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.db_root = tmp_path
    repo = tmp_path / "repo"
    with restricted_tree(repo / "python", mode) as tree:
        metadata = repo / "python-metadata.json"
        metadata.write_text(
            json.dumps(
                {
                    "database_path": str(tree),
                    "created_at": (
                        datetime.now(timezone.utc) - timedelta(days=60)
                    ).isoformat(),
                }
            )
        )
        assert manager.cleanup_old_databases(days=30, dry_run=dry_run) == [str(tree)]
        assert tree.exists() is dry_run
        assert metadata.exists() is dry_run


def test_failed_database_cleanup_keeps_metadata_for_retry(tmp_path, monkeypatch):
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.db_root = tmp_path
    repo = tmp_path / "repo"
    with restricted_tree(repo / "python", 0o555) as tree:
        metadata = repo / "python-metadata.json"
        metadata.write_text(
            json.dumps(
                {
                    "database_path": str(tree),
                    "created_at": (
                        datetime.now(timezone.utc) - timedelta(days=60)
                    ).isoformat(),
                }
            )
        )
        with monkeypatch.context() as fault:
            fault.setattr("shutil.rmtree", lambda *args, **kwargs: None)
            assert manager.cleanup_old_databases(days=30) == []
        assert tree.exists()
        assert metadata.exists()
