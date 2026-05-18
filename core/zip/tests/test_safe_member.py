"""Tests for core.zip.safe_member.

Covers every rejection class plus the SAFE happy paths. Each test
builds a minimal in-memory ZipInfo so the substrate sees exactly
the shape it would in a real attacker-influenced archive.
"""

from __future__ import annotations

import io
import stat
import zipfile

from core.zip.safe_member import (
    DEFAULT_MAX_MEMBER_BYTES,
    UnsafeMemberReason,
    is_safe_member,
    safe_member_reason,
)


def _zip_with(*entries: tuple[str, bytes, int | None]) -> bytes:
    """Build a zip in memory containing the supplied entries.

    Each entry is ``(filename, data, mode_or_none)``. ``mode``
    populates ``external_attr`` so we can simulate symlinks /
    special files. ``None`` leaves it at zip's default.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            zi = zipfile.ZipInfo(name)
            if mode is not None:
                zi.external_attr = mode << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def _first_info(data: bytes) -> zipfile.ZipInfo:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.infolist()[0]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_safe_member_returns_safe_for_plain_file():
    data = _zip_with(("plain.txt", b"hello", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.SAFE
    assert is_safe_member(info)


def test_safe_member_returns_safe_for_subdir_file():
    data = _zip_with(("a/b/c.txt", b"hello", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.SAFE


def test_allow_absolute_paths_when_consumer_is_in_memory():
    data = _zip_with(("/etc/passwd", b"shadow", None))
    info = _first_info(data)
    assert safe_member_reason(info, allow_absolute_paths=True) \
        == UnsafeMemberReason.SAFE


# ---------------------------------------------------------------------------
# Path-shape rejections
# ---------------------------------------------------------------------------

def test_rejects_absolute_path():
    data = _zip_with(("/etc/passwd", b"shadow", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.ABSOLUTE_PATH


def test_rejects_path_traversal():
    data = _zip_with(("../escape.txt", b"oops", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.PATH_TRAVERSAL


def test_rejects_path_traversal_deeper_segment():
    data = _zip_with(("safe/../../../etc/passwd", b"oops", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.PATH_TRAVERSAL


def test_rejects_nfkc_fullwidth_dot_traversal():
    """``safe/．．/x`` (FULLWIDTH FULL STOP U+FF0E) extracts as
    ``safe/../x`` on HFS+ / case-insensitive filesystems that
    NFKC-normalise on write. Must reject."""
    data = _zip_with(("safe/．．/escape", b"oops", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.PATH_TRAVERSAL


def test_rejects_nfkc_normalised_absolute_path():
    """A fullwidth-slash leading path NFKC-normalises to ``/...``
    on filesystems that fold the slash. Defense in depth."""
    # FULLWIDTH SOLIDUS (U+FF0F) is folded to '/' by NFKC.
    data = _zip_with(("／etc/passwd", b"oops", None))
    info = _first_info(data)
    # The original name doesn't start with '/' so the first
    # absolute-path check passes; NFKC normalises U+FF0F to '/'
    # and the second pass catches it.
    assert safe_member_reason(info) == UnsafeMemberReason.ABSOLUTE_PATH


def test_rejects_backslash_path():
    data = _zip_with(("win\\path.txt", b"oops", None))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.BACKSLASH_PATH


def test_rejects_empty_name():
    info = zipfile.ZipInfo("")
    info.file_size = 0
    info.compress_size = 0
    assert safe_member_reason(info) == UnsafeMemberReason.UNRECOGNISED_TYPE


# ---------------------------------------------------------------------------
# Special-file rejections (Unix mode in external_attr)
# ---------------------------------------------------------------------------

def test_rejects_symlink():
    data = _zip_with(("link", b"target", stat.S_IFLNK | 0o777))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.SYMLINK_UNSAFE


def test_rejects_fifo():
    data = _zip_with(("pipe", b"", stat.S_IFIFO | 0o666))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.SPECIAL_FILE


def test_rejects_block_device():
    data = _zip_with(("blk", b"", stat.S_IFBLK | 0o666))
    info = _first_info(data)
    assert safe_member_reason(info) == UnsafeMemberReason.SPECIAL_FILE


# ---------------------------------------------------------------------------
# Size-shape rejections
# ---------------------------------------------------------------------------

def test_rejects_oversized():
    # Build a member with declared size above the cap. We don't
    # actually need 64 MB of bytes in the archive — set file_size
    # directly after writing a small entry.
    data = _zip_with(("big.bin", b"a", None))
    info = _first_info(data)
    info.file_size = DEFAULT_MAX_MEMBER_BYTES + 1
    assert safe_member_reason(info) == UnsafeMemberReason.OVERSIZED


def test_accepts_at_size_cap():
    data = _zip_with(("at-cap.bin", b"a", None))
    info = _first_info(data)
    info.file_size = DEFAULT_MAX_MEMBER_BYTES
    # Compression ratio of ``file_size / compress_size`` will fire
    # the bomb defense at this size unless we relax it. Pump max_ratio.
    assert safe_member_reason(info, max_ratio=10**9) \
        == UnsafeMemberReason.SAFE


def test_rejects_compression_bomb():
    # 10 MB of zeros compresses to a few KB → ratio well above
    # the default 200 cap.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("bomb.bin", b"\x00" * (10 * 1024 * 1024))
    info = _first_info(buf.getvalue())
    assert safe_member_reason(info) == UnsafeMemberReason.COMPRESSION_BOMB


def test_compression_bomb_relaxed_by_max_ratio():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("bomb.bin", b"\x00" * (10 * 1024 * 1024))
    info = _first_info(buf.getvalue())
    # Operator who trusts the producer can disable the ratio check.
    assert safe_member_reason(info, max_ratio=10**9) \
        == UnsafeMemberReason.SAFE


def test_empty_file_does_not_divide_by_zero():
    data = _zip_with(("empty.txt", b"", None))
    info = _first_info(data)
    assert info.file_size == 0
    assert info.compress_size == 0
    assert safe_member_reason(info) == UnsafeMemberReason.SAFE
