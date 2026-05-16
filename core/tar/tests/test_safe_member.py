"""Tests for ``core.tar.safe_member``.

The predicate is a security gate — gaps mean malicious tarballs
get extracted. Tests cover each rejection class explicitly so a
future Python tarfile.data_filter shift (or PEP 706 amendment)
doesn't silently relax the check.
"""

from __future__ import annotations

import sys
import tarfile

import pytest

from core.tar import (
    DEFAULT_MAX_MEMBER_BYTES,
    UnsafeMemberReason,
    is_safe_member,
    safe_member_reason,
)


def _file_member(name: str, *, size: int = 100, mode: int = 0o644) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.REGTYPE
    info.size = size
    info.mode = mode
    return info


def _symlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.size = 0
    return info


def _hardlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    info.size = 0
    return info


def _devnode(name: str, *, kind: str = "char") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = (
        tarfile.CHRTYPE if kind == "char"
        else tarfile.BLKTYPE if kind == "block"
        else tarfile.FIFOTYPE if kind == "fifo"
        else tarfile.REGTYPE
    )
    info.size = 0
    return info


# ---------------------------------------------------------------------------
# Safe paths
# ---------------------------------------------------------------------------


def test_normal_relative_file_safe():
    """Plain ``foo/bar.txt`` — the load-bearing common case. If
    this returned False, every tarball would be unextractable."""
    assert is_safe_member(_file_member("foo/bar.txt"))
    assert safe_member_reason(_file_member("foo/bar.txt")) \
        == UnsafeMemberReason.SAFE


def test_deep_subpath_safe():
    """``a/b/c/d/e/file.txt`` — depth alone isn't a concern."""
    assert is_safe_member(_file_member("a/b/c/d/e/file.txt"))


def test_directory_member_safe():
    """Directory members are extracted as ``mkdir`` calls; safe
    when the path itself is safe (no traversal)."""
    info = tarfile.TarInfo(name="foo/")
    info.type = tarfile.DIRTYPE
    info.size = 0
    assert is_safe_member(info)


# ---------------------------------------------------------------------------
# Path traversal (the classic CVE class)
# ---------------------------------------------------------------------------


def test_parent_traversal_rejected():
    """``../etc/passwd`` — extracting walks up out of dest. The
    canonical zip-slip / tar-slip vulnerability."""
    assert not is_safe_member(_file_member("../etc/passwd"))
    assert safe_member_reason(_file_member("../etc/passwd")) \
        == UnsafeMemberReason.PATH_TRAVERSAL


def test_deep_traversal_rejected():
    """``../../../etc/passwd`` — same shape, deeper."""
    assert safe_member_reason(_file_member("../../../etc/passwd")) \
        == UnsafeMemberReason.PATH_TRAVERSAL


def test_traversal_buried_in_path_rejected():
    """``foo/../../etc/passwd`` — the traversal is inside the path.
    A naive "starts with ..." check would miss this; data_filter
    catches it."""
    assert not is_safe_member(_file_member("foo/../../etc/passwd"))


def test_absolute_path_rejected():
    """``/etc/passwd`` — leading slash means "this tar wants to
    write to the absolute path", not relative to dest."""
    assert safe_member_reason(_file_member("/etc/passwd")) \
        == UnsafeMemberReason.ABSOLUTE_PATH


# ---------------------------------------------------------------------------
# Symlinks (the post-extract escape vector)
# ---------------------------------------------------------------------------


def test_symlink_to_outside_rejected():
    """``ln -s /etc/shadow shadow.lnk`` — after extraction, opening
    ``shadow.lnk`` follows the symlink out of dest."""
    assert safe_member_reason(_symlink("shadow.lnk", "/etc/shadow")) \
        == UnsafeMemberReason.SYMLINK_UNSAFE


def test_symlink_with_traversal_target_rejected():
    """``ln -s ../../etc/shadow shadow.lnk`` — traversal in the
    link TARGET (not the link name)."""
    assert not is_safe_member(_symlink("shadow.lnk", "../../etc/shadow"))


def test_internal_symlink_safe():
    """``ln -s actual/file alias`` — link target stays inside dest.
    This is a legitimate use of symlinks in tar (some Python wheels
    use it); shouldn't be rejected."""
    assert is_safe_member(_symlink("alias", "actual/file"))


# ---------------------------------------------------------------------------
# Hard links (refused unconditionally)
# ---------------------------------------------------------------------------


def test_hard_link_always_rejected():
    """Hard links can point inside or outside dest — but no consumer
    we have today needs them. Refused unconditionally; if a future
    consumer needs them, relax the predicate explicitly."""
    assert safe_member_reason(_hardlink("alias", "real/file")) \
        == UnsafeMemberReason.HARD_LINK


# ---------------------------------------------------------------------------
# Special files
# ---------------------------------------------------------------------------


def test_block_device_rejected():
    """Block / char devices in a "data" tarball are nonsense at
    best, escape attempts at worst."""
    assert safe_member_reason(_devnode("/dev/sda", kind="block")) \
        == UnsafeMemberReason.SPECIAL_FILE


def test_char_device_rejected():
    assert safe_member_reason(_devnode("/dev/null", kind="char")) \
        == UnsafeMemberReason.SPECIAL_FILE


def test_fifo_rejected():
    assert safe_member_reason(_devnode("named.pipe", kind="fifo")) \
        == UnsafeMemberReason.SPECIAL_FILE


# ---------------------------------------------------------------------------
# Size budget
# ---------------------------------------------------------------------------


def test_oversized_member_rejected():
    """A 1 GB member in a SBOM-extraction context is either
    wasteful or malicious — refuse before extracting."""
    big = _file_member("var/lib/dpkg/status", size=10 * 1024 * 1024)
    assert safe_member_reason(big, max_size=1024) \
        == UnsafeMemberReason.OVERSIZED


def test_default_max_size_is_generous():
    """Sanity: ordinary package-state files (KB to a few MB) pass
    the default budget."""
    one_mb = _file_member("data", size=1024 * 1024)
    assert is_safe_member(one_mb)
    assert DEFAULT_MAX_MEMBER_BYTES >= 16 * 1024 * 1024


def test_size_check_runs_first():
    """Size is the cheapest check; should fire before path
    validation runs. Reduces work on bombs that ALSO have unsafe
    paths (the size check is the early-out)."""
    bomb = _file_member("../etc/passwd", size=10 * 1024 * 1024)
    assert safe_member_reason(bomb, max_size=1024) \
        == UnsafeMemberReason.OVERSIZED


# ---------------------------------------------------------------------------
# Python-version fallback
# ---------------------------------------------------------------------------


def test_predicate_works_on_current_python():
    """Smoke test: the module loads and the predicate runs without
    raising on Python 3.13 (the version we ship with) — covers
    that the data_filter integration imports cleanly. If this fails
    after a Python upgrade, the import names in safe_member.py need
    refresh."""
    member = _file_member("test/file")
    # Just verify it returns a Reason; specific value covered by
    # other tests.
    assert isinstance(
        safe_member_reason(member), UnsafeMemberReason,
    )
