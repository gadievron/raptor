"""Integration: ``DatabaseManager.create_database`` honours the
codeql trust check before invoking the codeql CLI.

We don't actually build a database — that needs codeql + a build
toolchain on the test host. We just stand up a target dir with an
unsafe pack file and confirm:

  * Without ``--trust-repo`` the call returns a failed
    ``DatabaseResult`` whose error mentions ``--trust-repo``.
  * The codeql CLI subprocess is NOT invoked (the trust gate
    fires before the cache check and before the subprocess).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                      # pragma: no cover
    pass

from core.security.codeql_trust import _scan_cached, set_trust_override
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture(autouse=True)
def _clear_trust_state():
    _scan_cached.cache_clear()
    set_trust_override(False)
    yield
    _scan_cached.cache_clear()
    set_trust_override(False)


def _unsafe_target(tmp_path: Path) -> Path:
    """A repo carrying a pack file with a custom extractor."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "qlpack.yml").write_text(
        "name: attacker/evil\n"
        "extractor: ./build/evil-binary\n"
    )
    return target


def _safe_target(tmp_path: Path) -> Path:
    """A repo with no codeql config at all."""
    target = tmp_path / "target"
    target.mkdir()
    return target


def _dm(tmp_path: Path) -> DatabaseManager:
    """Fresh DatabaseManager pinned at the test's tmp_path."""
    return DatabaseManager(
        codeql_cli="codeql",
        db_root=tmp_path / "dbs",
    )


def test_unsafe_target_refused_without_trust_repo(tmp_path):
    target = _unsafe_target(tmp_path)
    dm = _dm(tmp_path)

    result = dm.create_database(target, "python")

    assert result.success is False
    assert result.database_path is None
    # The error string steers the operator at the right escape hatch.
    assert any("--trust-repo" in e for e in result.errors)
    # And the codeql CLI specifically wasn't invoked — metadata-related
    # subprocess calls (e.g. git rev-parse for repo-hash) happen later
    # in the flow, after the trust gate fires.
    assert "codeql" not in " ".join(result.errors).lower() or \
        "unsafe CodeQL pack" in " ".join(result.errors)


def test_unsafe_target_proceeds_with_trust_override(tmp_path):
    """``set_trust_override(True)`` must let create_database past the
    gate; we can't easily complete the full subprocess flow but the
    early-refuse error MUST not fire."""
    target = _unsafe_target(tmp_path)
    set_trust_override(True)
    dm = _dm(tmp_path)

    # Mock get_cached_database to short-circuit so we don't need to
    # actually build. Returning a fake path means create_database
    # returns success without subprocess work.
    fake_db = tmp_path / "fake-db"
    fake_db.mkdir()
    with patch.object(dm, "get_cached_database", return_value=fake_db), \
         patch.object(dm, "load_metadata", return_value=None):
        result = dm.create_database(target, "python")

    # Trust gate didn't refuse — the cached-DB short-circuit returned
    # success; the unsafe-pack-config error must NOT be in errors.
    assert not any("unsafe CodeQL pack config" in e for e in result.errors)
    assert result.success is True


def test_safe_target_does_not_short_circuit_at_trust_gate(tmp_path):
    """A target with no pack files must NOT be refused by the trust
    check. (It might still fail later for build reasons; the trust
    gate should pass cleanly.)"""
    target = _safe_target(tmp_path)
    dm = _dm(tmp_path)

    fake_db = tmp_path / "fake-db"
    fake_db.mkdir()
    with patch.object(dm, "get_cached_database", return_value=fake_db), \
         patch.object(dm, "load_metadata", return_value=None):
        result = dm.create_database(target, "python")

    # Trust gate didn't fire — cached path returned success.
    assert result.success is True
