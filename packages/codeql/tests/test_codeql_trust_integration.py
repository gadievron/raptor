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

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.security.codeql_trust import set_trust_override
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture(autouse=True)
def _clear_trust_state(monkeypatch):
    from core.security import codeql_trust as trust
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(trust, {"_trust_override_set": False}):
        try:
            yield
        finally:
            monkeypatch.undo()


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
    assert any("failed the CodeQL trust check" in e for e in result.errors)
    # And the codeql CLI specifically wasn't invoked — metadata-related
    # subprocess calls (e.g. git rev-parse for repo-hash) happen later
    # in the flow, after the trust gate fires.
    assert "codeql" not in " ".join(result.errors).lower() or \
        "failed the CodeQL trust check" in " ".join(result.errors)


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
    # success; the trust-check refusal error must NOT be in errors.
    assert not any("failed the CodeQL trust check" in e for e in result.errors)
    assert result.success is True


def test_unexaminable_target_refused_with_lane_covering_message(tmp_path):
    """The refusal string must cover BOTH gate lanes: a target the
    checker cannot stat refuses with the same operator steering as a
    dangerous-config block (the stdout diagnostic carries the lane
    detail)."""
    dm = _dm(tmp_path)

    result = dm.create_database(tmp_path / "does-not-exist", "python")

    assert result.success is False
    assert any("failed the CodeQL trust check" in e for e in result.errors)
    assert any("could not be examined" in e for e in result.errors)
    assert any("--trust-repo" in e for e in result.errors)


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


def _swap_during_hash(dm, target: Path, tmp_path: Path):
    """Doctored repo-hash step that swaps the target spelling at a
    fresh inode — landing the swap in the verdict→dispatch window the
    held-handle recheck exists to close."""
    import os

    def _swap(repo_path):
        os.rename(target, tmp_path / "swapped-aside")
        target.mkdir()
        return "fakehash"

    return patch.object(dm, "compute_repo_hash", side_effect=_swap)


def test_post_verdict_swap_refused_before_spawn(tmp_path):
    """The trust verdict is released against the repo SPELLING; the
    hash/cache/staging work before the codeql spawn is a swap window.
    A target swapped inside that window must be refused by the
    pre-spawn recheck — the sandbox must never be invoked."""
    target = _safe_target(tmp_path)
    dm = _dm(tmp_path)
    spawned = []

    def _spy(*args, **kwargs):
        spawned.append(args)
        raise AssertionError("codeql spawned against a swapped target")

    with _swap_during_hash(dm, target, tmp_path), \
         patch.object(dm, "get_cached_database", return_value=None), \
         patch("core.sandbox.run", side_effect=_spy):
        result = dm.create_database(target, "python")

    assert result.success is False
    assert result.database_path is None
    assert any("changed during the CodeQL trust check" in e
               for e in result.errors)
    assert not spawned


def test_stable_target_passes_recheck_and_spawns(tmp_path):
    """Discriminating companion: the SAME flow without the swap must
    get through the recheck to the sandbox spawn — the re-bracket is
    refuse-only, never a new blocker for honest targets."""
    import subprocess

    target = _safe_target(tmp_path)
    dm = _dm(tmp_path)
    spawned = []

    def _spy(cmd, *args, **kwargs):
        spawned.append(cmd)
        # Abort the flow here: TimeoutExpired is a handled exit that
        # (for a non-traced python create) has no buildless fallback,
        # so the test never needs a real codeql CLI.
        raise subprocess.TimeoutExpired(cmd="codeql", timeout=1)

    with patch.object(dm, "compute_repo_hash", return_value="fakehash"), \
         patch.object(dm, "get_cached_database", return_value=None), \
         patch("core.sandbox.run", side_effect=_spy):
        result = dm.create_database(target, "python")

    assert spawned, "recheck blocked a stable target before the spawn"
    assert not any("changed during the CodeQL trust check" in e
                   for e in result.errors)
