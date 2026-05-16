"""Tests for core.run.safe_io.safe_run_mkdir."""

from __future__ import annotations

import os

import pytest

from core.run.safe_io import safe_run_mkdir, UnsafeRunDirError


# ── Fresh-create behaviour ───────────────────────────────────────────────


def test_fresh_create_sets_mode_0700(tmp_path):
    p = tmp_path / "fresh"
    safe_run_mkdir(p)
    assert p.is_dir()
    assert (p.stat().st_mode & 0o777) == 0o700


def test_fresh_create_default_mode_unaffected_by_loose_umask(tmp_path):
    """Default mode 0o700 has no group/world bits, so no umask value can
    relax it to something more permissive. Verifies the security invariant
    that fresh-created dirs are always owner-only."""
    old = os.umask(0o000)
    try:
        p = tmp_path / "fresh"
        safe_run_mkdir(p)
        assert (p.stat().st_mode & 0o777) == 0o700
    finally:
        os.umask(old)


def test_str_path_accepted(tmp_path):
    p = tmp_path / "fresh"
    safe_run_mkdir(str(p))
    assert p.is_dir()


def test_symlinked_parent_allowed(tmp_path):
    """Symlinks higher in the path are not refused — by design.

    Defending against parent-chain manipulation is out of scope: an
    attacker who can manipulate parent directories has capabilities
    well beyond what this helper is intended to defend against, and
    parent-chain refusal would break legitimate FHS / mount-symlink
    layouts (e.g. ``/home`` → ``/data/home``)."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    p = link / "child"
    safe_run_mkdir(p)
    assert p.is_dir()


# ── Pre-existing safe dirs accepted ──────────────────────────────────────


def test_existing_owner_only_dir_accepted(tmp_path):
    p = tmp_path / "a"
    p.mkdir(mode=0o700)
    safe_run_mkdir(p)


def test_idempotent(tmp_path):
    p = tmp_path / "a"
    safe_run_mkdir(p)
    safe_run_mkdir(p)


def test_world_readable_dir_allowed(tmp_path):
    """0o755 (default umask 0o022) is read-only by other users, so not
    an injection vector — accept without warning. Chmod after mkdir to
    pin the mode regardless of the test runner's umask."""
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o755)
    safe_run_mkdir(p)


def test_group_writable_warns_but_allowed(tmp_path, monkeypatch):
    """0o775 (default umask 0o002 + private user group) is the most common
    real-world existing run-dir mode. Warn but accept.

    The warning's content is asserted by patching the module logger:
    :class:`RaptorLogger` is a singleton with ``propagate=False`` and a
    StreamHandler bound to a pre-pytest stderr, so caplog/capfd cannot
    observe its output."""
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o775)

    captured: list[str] = []
    from core.run import safe_io as mod
    monkeypatch.setattr(mod.logger, "warning", lambda msg, **_: captured.append(msg))

    safe_run_mkdir(p)

    assert captured, "expected a warning to be logged"
    assert "group-writable" in captured[0].lower()


# ── Refusals ─────────────────────────────────────────────────────────────


def test_world_writable_refused(tmp_path):
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o777)
    with pytest.raises(UnsafeRunDirError, match="world-writable"):
        safe_run_mkdir(p)


def test_symlink_to_dir_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_symlink_to_file_refused(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_dangling_symlink_refused(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "nonexistent")
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_regular_file_refused(tmp_path):
    p = tmp_path / "file"
    p.write_text("x")
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(p)


def test_foreign_uid_refused(tmp_path, monkeypatch):
    """Existing dir owned by a different UID must be refused.

    Simulated via geteuid monkeypatch — actually chowning would require
    CAP_CHOWN which test environments don't have."""
    p = tmp_path / "a"
    p.mkdir(mode=0o700)
    real_uid = os.lstat(p).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: real_uid + 1)
    with pytest.raises(UnsafeRunDirError, match="not owned by current user"):
        safe_run_mkdir(p)
