"""Cache sidecar success must be Boolean before it can admit reuse."""
from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from packages.codeql.database_manager import DatabaseManager


@pytest.mark.parametrize('success,accepted', [
    pytest.param('false', False, id='text-false'),
    pytest.param('true', False, id='text-true'),
    pytest.param(1, False, id='number'),
    pytest.param([False], False, id='array'),
    pytest.param({'failed': True}, False, id='object'),
    pytest.param(True, True, id='boolean-success'),
    pytest.param(False, False, id='boolean-failure'),
])
def test_cache_reuse_requires_boolean_success_sidecar(tmp_path, success, accepted):
    manager = object.__new__(DatabaseManager)
    manager.db_root = tmp_path / 'cache'
    repo = tmp_path / 'repo'
    repo.mkdir()
    repo_hash = 'a' * 64
    database = manager.get_database_dir(repo_hash, 'python')
    content = database / 'db-python' / 'default'
    content.mkdir(parents=True)
    (database / 'codeql-database.yml').write_text('name: owned-cache-layout\n')
    # Exercise the real structural validator, not an actual CodeQL database.
    (content / 'owned.bin').write_bytes(b'\0' * (10 * 1024 + 1))
    sidecar = manager.get_metadata_path(repo_hash, 'python')
    data = {
        'repo_hash': repo_hash, 'repo_path': str(repo), 'language': 'python',
        'created_at': datetime.now(timezone.utc).isoformat(), 'codeql_version': 'owned',
        'build_command': '', 'build_system': 'source-only', 'file_count': 1,
        'success': success, 'duration_seconds': 0.1, 'errors': [],
        'database_path': str(database),
    }
    sidecar.write_text(json.dumps(data))
    original = sidecar.read_bytes()
    assert manager.validate_database(database)

    cached = manager.get_cached_database(repo, 'python', repo_hash=repo_hash, max_age_days=7)

    assert cached == (database if accepted else None)
    loaded = manager.load_metadata(repo_hash, 'python')
    if type(success) is bool:
        assert loaded is not None and loaded.success is success
    else:
        assert loaded is None
    assert sidecar.read_bytes() == original
    assert (content / 'owned.bin').stat().st_size == 10 * 1024 + 1
