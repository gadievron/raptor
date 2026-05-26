"""Tests for ``packages.sca._atomic``.

The atomic-write helper is used for manifest rewrites in
``optimise._apply_in_place`` and other places that touch user-owned
files. A torn write here corrupts the user's project, so the
contract is load-bearing.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.sca._atomic import atomic_write_bytes, atomic_write_text


# ---------------------------------------------------------------------------
# Happy-path semantics
# ---------------------------------------------------------------------------

def test_writes_new_file(tmp_path: Path) -> None:
    p = tmp_path / "manifest.txt"
    atomic_write_text(p, "hello\n")
    assert p.read_text(encoding="utf-8") == "hello\n"


def test_overwrites_existing(tmp_path: Path) -> None:
    p = tmp_path / "manifest.txt"
    p.write_text("old\n")
    atomic_write_text(p, "new\n")
    assert p.read_text(encoding="utf-8") == "new\n"


def test_creates_parent_directory(tmp_path: Path) -> None:
    p = tmp_path / "deeper" / "manifest.txt"
    atomic_write_text(p, "x\n")
    assert p.read_text(encoding="utf-8") == "x\n"


def test_bytes_variant_round_trips(tmp_path: Path) -> None:
    p = tmp_path / "data.bin"
    payload = b"\x00\xff\x10\x20"
    atomic_write_bytes(p, payload)
    assert p.read_bytes() == payload


def test_unicode_round_trips(tmp_path: Path) -> None:
    """UTF-8 default encoding handles non-ASCII manifest content."""
    p = tmp_path / "pyproject.toml"
    atomic_write_text(p, "name = \"日本語\"\n")
    assert p.read_text(encoding="utf-8") == "name = \"日本語\"\n"


# ---------------------------------------------------------------------------
# Atomicity / cleanup
# ---------------------------------------------------------------------------

def test_no_temp_file_left_after_success(tmp_path: Path) -> None:
    """A successful write leaves no .tmp.<pid> debris in the dir."""
    p = tmp_path / "manifest.txt"
    atomic_write_text(p, "x\n")
    leftover = list(tmp_path.glob("*.tmp.*"))
    assert leftover == [], f"unexpected temp files: {leftover}"


def test_temp_file_cleaned_up_on_failure(tmp_path: Path) -> None:
    """If ``os.replace`` raises, the temp file is removed."""
    p = tmp_path / "manifest.txt"

    def _boom(src, dst, *a, **kw):
        # Simulate a rename failure. Real causes: cross-device rename,
        # destination locked on Windows.
        raise OSError("simulated rename failure")

    with patch("packages.sca._atomic.os.replace", _boom):
        with pytest.raises(OSError, match="simulated rename failure"):
            atomic_write_text(p, "x\n")

    # Original (none) preserved; no temp file left behind.
    assert not p.exists()
    assert list(tmp_path.glob("*.tmp.*")) == []


def test_keyboard_interrupt_during_write_cleans_up(tmp_path: Path) -> None:
    """KeyboardInterrupt mid-write must not leave a temp file behind.

    BaseException catch in atomic_write covers Ctrl-C — the very
    scenario we're hardening against.
    """
    p = tmp_path / "manifest.txt"

    def _interrupt(*a, **kw):
        raise KeyboardInterrupt()

    with patch("packages.sca._atomic.os.fsync", _interrupt):
        with pytest.raises(KeyboardInterrupt):
            atomic_write_text(p, "x\n")

    # Original (none) preserved; no temp file left behind.
    assert not p.exists()
    assert list(tmp_path.glob("*.tmp.*")) == []


def test_failure_does_not_corrupt_existing(tmp_path: Path) -> None:
    """If the rename fails, the existing file is unchanged."""
    p = tmp_path / "manifest.txt"
    p.write_text("ORIGINAL CONTENT\n")

    def _boom(src, dst, *a, **kw):
        raise OSError("simulated")

    with patch("packages.sca._atomic.os.replace", _boom):
        with pytest.raises(OSError):
            atomic_write_text(p, "NEW CONTENT\n")

    # Original content is intact.
    assert p.read_text() == "ORIGINAL CONTENT\n"


def test_pid_suffix_isolates_concurrent_runs(tmp_path: Path) -> None:
    """The PID suffix means parallel writers don't collide on the
    temp filename."""
    p = tmp_path / "manifest.txt"
    expected_tmp = tmp_path / f"manifest.txt.tmp.{os.getpid()}"

    # Pre-create a temp file with a DIFFERENT PID — should not collide
    # with our write.
    other_pid_tmp = tmp_path / "manifest.txt.tmp.999999"
    other_pid_tmp.write_text("another writer's draft\n")

    atomic_write_text(p, "ours\n")
    assert p.read_text() == "ours\n"
    # Other writer's temp is untouched.
    assert other_pid_tmp.exists()
    assert other_pid_tmp.read_text() == "another writer's draft\n"
    # Our temp was consumed by os.replace.
    assert not expected_tmp.exists()


def test_preserves_existing_mode_bits(tmp_path: Path) -> None:
    """When the destination already exists with a non-default mode
    (e.g. 0o600 — operator chmod'd a manifest carrying credentials),
    a subsequent atomic_write_text MUST NOT widen the permissions
    back to 0o644. The post-rewrite mode reflects the pre-rewrite
    mode."""
    import stat as _stat
    p = tmp_path / "manifest.txt"
    p.write_text("v1\n")
    p.chmod(0o600)
    pre_mode = _stat.S_IMODE(p.stat().st_mode)
    assert pre_mode == 0o600

    atomic_write_text(p, "v2\n")
    post_mode = _stat.S_IMODE(p.stat().st_mode)
    assert post_mode == pre_mode, (
        f"mode widened on rewrite: {pre_mode:o} → {post_mode:o}"
    )
    assert p.read_text() == "v2\n"


def test_new_file_uses_default_mode(tmp_path: Path) -> None:
    """When writing a NEW file (no existing destination to preserve),
    the historical 0o644 default applies — minus the process umask.
    Pin the umask before checking so the test is deterministic."""
    import stat as _stat
    p = tmp_path / "new-manifest.txt"
    old_umask = os.umask(0o022)
    try:
        atomic_write_text(p, "fresh\n")
    finally:
        os.umask(old_umask)
    mode = _stat.S_IMODE(p.stat().st_mode)
    # 0o644 & ~0o022 == 0o644. fchmod inside the writer applies the
    # captured ``preserve_mode`` (0o644 default for new files)
    # verbatim — the umask is honoured by the open() but fchmod
    # then overrides. Either result (0o644 with fchmod / 0o644 with
    # umask-022) is the same here.
    assert mode == 0o644
