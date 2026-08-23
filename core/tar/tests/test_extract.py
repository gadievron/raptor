"""Tests for :func:`core.tar.extract_files_from_tar`.

Covers the substrate that consumers (core.oci.blob, SCA's
version_diff_review) sit on top of — selection, safety filter,
streaming-vs-buffered source, early-exit, mode handling.
"""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest
from typing import List, Optional

from core.tar.extract import (
    TarOpenError,
    TarTotalBytesExceeded,
    extract_files_from_tar,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar(
    members: List[tuple],
    *,
    gzipped: bool = False,
) -> bytes:
    """Build an in-memory tar from ``[(name, content_bytes), ...]``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, content in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    raw = buf.getvalue()
    if gzipped:
        raw = gzip.compress(raw)
    return raw


def _chunks(data: bytes, size: int = 4096):
    """Yield ``data`` in chunks — simulates an HTTP body iterator."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _select_all(_member) -> str:
    """Selector that keeps every safe member, keyed by member.name."""
    return _member.name


def _select_by_extensions(*exts: str):
    """Selector factory that keeps members whose name ends with one
    of ``exts`` (matches SCA's selection shape)."""
    def _s(member: tarfile.TarInfo) -> Optional[str]:
        for e in exts:
            if member.name.endswith(e):
                return member.name
        return None
    return _s


def _select_named(*names: str):
    """Selector factory that keeps only exactly-named members."""
    wanted = set(names)

    def _s(member: tarfile.TarInfo) -> Optional[str]:
        return member.name if member.name in wanted else None
    return _s


# ---------------------------------------------------------------------------
# Source shapes — bytes and chunk iterators
# ---------------------------------------------------------------------------


def test_bytes_source_extracts_selected_member():
    raw = _make_tar([("a.txt", b"alpha"), ("b.txt", b"beta")])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {"a.txt": b"alpha", "b.txt": b"beta"}


def test_chunk_source_extracts_selected_member():
    """Streaming iterator must work with stream-mode tar reader."""
    raw = _make_tar([("a.txt", b"alpha")], gzipped=True)
    out = extract_files_from_tar(
        _chunks(raw, size=64), selector=_select_all, mode="r|gz",
    )
    assert out == {"a.txt": b"alpha"}


def test_chunk_source_small_chunks_still_works():
    """Stream reader must reassemble across many tiny chunks."""
    raw = _make_tar(
        [("file.txt", b"hello world this is a longer payload")],
        gzipped=True,
    )
    out = extract_files_from_tar(
        _chunks(raw, size=3), selector=_select_all, mode="r|gz",
    )
    assert out == {"file.txt": b"hello world this is a longer payload"}


# ---------------------------------------------------------------------------
# Selector behaviour
# ---------------------------------------------------------------------------


def test_selector_returning_none_skips_member():
    raw = _make_tar([
        ("keep.txt", b"yes"),
        ("skip.bin", b"no"),
        ("also-keep.txt", b"sure"),
    ])
    out = extract_files_from_tar(
        raw,
        selector=_select_by_extensions(".txt"),
        mode="r:*",
    )
    assert out == {"keep.txt": b"yes", "also-keep.txt": b"sure"}


def test_selector_can_remap_keys():
    """Selector return value becomes the dict key — consumer can
    normalise paths or strip top-level dirs in one go."""
    raw = _make_tar([
        ("pkg-1.0/setup.py", b"setup-content"),
        ("pkg-1.0/README.md", b"readme-content"),
    ])

    def _strip_top(member):
        parts = member.name.split("/", 1)
        return parts[1] if len(parts) > 1 else member.name

    out = extract_files_from_tar(
        raw, selector=_strip_top, mode="r:*",
    )
    assert out == {"setup.py": b"setup-content",
                   "README.md": b"readme-content"}


# ---------------------------------------------------------------------------
# Safety filter
# ---------------------------------------------------------------------------


def test_path_traversal_member_skipped():
    """A `../escape` entry must be rejected by the safety filter
    BEFORE the selector sees it. Selector sees only safe members."""
    raw = _make_tar([
        ("safe.txt", b"safe"),
        ("../escape.txt", b"bad"),
    ])
    seen_by_selector = []

    def _s(member):
        seen_by_selector.append(member.name)
        return member.name

    out = extract_files_from_tar(raw, selector=_s, mode="r:*")
    assert "safe.txt" in out
    assert "../escape.txt" not in out
    assert "../escape.txt" not in seen_by_selector


def test_oversized_member_skipped():
    """A member larger than max_member_bytes is dropped."""
    raw = _make_tar([("big.bin", b"x" * 5000)])
    out = extract_files_from_tar(
        raw,
        selector=_select_all,
        mode="r:*",
        max_member_bytes=1000,
    )
    assert out == {}


def test_absolute_path_strict_default_rejects():
    """Default ``allow_absolute_paths=False`` rejects absolute paths
    — appropriate for consumers that extract to disk."""
    raw = _make_tar([("/etc/passwd", b"not on my watch")])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {}


def test_absolute_path_allowed_when_opted_in():
    """``allow_absolute_paths=True`` lets layer-style absolute names
    through — appropriate for read-into-memory consumers (OCI
    layers carry ``/var/lib/...`` member names)."""
    raw = _make_tar([("/var/lib/dpkg/status", b"package data")])
    out = extract_files_from_tar(
        raw,
        selector=_select_all,
        mode="r:*",
        allow_absolute_paths=True,
    )
    assert out == {"/var/lib/dpkg/status": b"package data"}


# ---------------------------------------------------------------------------
# Early exit
# ---------------------------------------------------------------------------


def test_expected_count_short_circuits():
    """Once expected_count members are found, the walk stops — the
    selector must not be called on any subsequent members."""
    raw = _make_tar([
        ("a.txt", b"first"),
        ("b.txt", b"second"),
        ("c.txt", b"third"),
        ("d.txt", b"fourth"),
    ])

    seen = []

    def _s(member):
        seen.append(member.name)
        return member.name

    out = extract_files_from_tar(
        raw, selector=_s, mode="r:*", expected_count=2,
    )
    assert len(out) == 2
    assert "a.txt" in out and "b.txt" in out
    # The walk MUST have stopped once 2 were collected — c.txt
    # may or may not have been seen by the selector depending on
    # iteration order, but d.txt definitely shouldn't have been.
    # In practice (a, b, c, d order) the walk stops after b.
    assert "d.txt" not in seen


def test_expected_count_none_walks_full_archive():
    """No expected_count → walk every member."""
    raw = _make_tar([
        ("a", b"1"), ("b", b"2"), ("c", b"3"), ("d", b"4"),
    ])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert len(out) == 4


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_directory_member_skipped():
    """Directory entries don't have content — must be skipped
    silently, not crash."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        d = tarfile.TarInfo(name="adir/")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        f = tarfile.TarInfo(name="adir/inside.txt")
        f.size = 4
        tf.addfile(f, io.BytesIO(b"data"))
    out = extract_files_from_tar(
        buf.getvalue(), selector=_select_all, mode="r:*",
    )
    assert out == {"adir/inside.txt": b"data"}


def test_invalid_archive_refuses():
    """Garbage bytes → TarOpenError (fail closed). Returning an empty
    dict converted corrupt attacker-influenced input into a
    "successfully empty" result downstream consumers treated as a
    complete extraction."""
    with pytest.raises(TarOpenError):
        extract_files_from_tar(
            b"this is not a tar archive",
            selector=_select_all,
            mode="r:*",
        )


def test_invalid_gzip_stream_refuses():
    """Truncated / corrupt gzip stream → TarOpenError (fail closed)."""
    with pytest.raises(TarOpenError):
        extract_files_from_tar(
            _chunks(b"\x1f\x8b\x00\x00garbage", size=2),
            selector=_select_all,
            mode="r|gz",
        )


def test_empty_archive_returns_empty():
    raw = _make_tar([])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {}


def test_selector_is_only_called_on_files():
    """Directory / symlink / hardlink members must not reach the
    selector — they're filtered out before."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        d = tarfile.TarInfo(name="adir/")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        f = tarfile.TarInfo(name="afile.txt")
        f.size = 5
        tf.addfile(f, io.BytesIO(b"hello"))

    seen = []

    def _s(member):
        seen.append((member.name, member.isfile()))
        return member.name

    extract_files_from_tar(
        buf.getvalue(), selector=_s, mode="r:*",
    )
    assert seen == [("afile.txt", True)]


def test_max_total_and_entry_caps_with_default_unchanged():
    from core.tar.extract import TarEntryCountExceeded, TarTotalBytesExceeded
    raw = _make_tar([(f"f{i}", b"A" * 100) for i in range(5)])
    # Default (no caps): all extracted — existing callers unaffected.
    assert len(extract_files_from_tar(raw, selector=lambda m: m.name, mode="r:")) == 5
    # Aggregate-bytes cap raises (never silently truncates).
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            raw, selector=lambda m: m.name, mode="r:", max_total_bytes=250)
    # Entry-count cap raises.
    with pytest.raises(TarEntryCountExceeded):
        extract_files_from_tar(
            raw, selector=lambda m: m.name, mode="r:", max_entry_count=2)


# ---------------------------------------------------------------------------
# Decompression budget — max_total_bytes counts skipped members too
#
# In stream mode (``r|gz``) tarfile must decompress a member's data
# even to skip past it, so a gzip-bomb layer whose huge member is
# skipped (selector miss, safety-filter reject) would burn unbounded
# CPU if only kept members' bytes counted. Every member's
# header-declared size is charged against the budget — before the
# member's data is consumed — so the walk aborts ahead of
# decompressing a bomb member.
# ---------------------------------------------------------------------------


def test_selector_missed_member_counts_toward_total_bytes():
    """A big member the selector skips must still trip the budget —
    the OCI gzip-bomb shape (huge non-wanted member first)."""
    raw = _make_tar([
        ("bomb.bin", b"\x00" * 10_000),
        ("var/lib/dpkg/status", b"wanted"),
    ], gzipped=True)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            _chunks(raw),
            selector=_select_named("var/lib/dpkg/status"),
            mode="r|gz",
            max_total_bytes=1_000,
        )


def test_safety_filter_rejected_member_counts_toward_total_bytes():
    """A member the safety filter rejects (oversized per-member) is
    skipped-and-decompressed in stream mode — it must count too."""
    raw = _make_tar([
        ("oversized.bin", b"\x00" * 10_000),
        ("small.txt", b"ok"),
    ], gzipped=True)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            _chunks(raw),
            selector=lambda m: m.name,
            mode="r|gz",
            max_member_bytes=100,
            max_total_bytes=1_000,
        )


def test_budget_check_happens_before_member_data_is_consumed():
    """The budget must trip at header-read time, BEFORE tarfile pulls
    the bomb member's data from the stream — that early abort is the
    entire CPU-DoS defense."""
    bomb = b"\x00" * 1_000_000
    raw = _make_tar([("bomb.bin", bomb)])  # uncompressed → byte-countable

    consumed = 0

    def _counting_chunks():
        nonlocal consumed
        for i in range(0, len(raw), 512):
            chunk = raw[i:i + 512]
            consumed += len(chunk)
            yield chunk

    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            _counting_chunks(),
            selector=lambda m: None,  # everything is skipped
            mode="r|",
            max_total_bytes=10_000,
        )
    # Header blocks plus tarfile read-ahead only — nowhere near the
    # 1 MB member body.
    assert consumed < len(bomb) // 2


def test_kept_members_still_enforce_budget_in_stream_mode():
    """Kept bytes trip the cap in stream mode too."""
    raw = _make_tar([(f"f{i}", b"A" * 100) for i in range(5)], gzipped=True)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            _chunks(raw),
            selector=lambda m: m.name,
            mode="r|gz",
            max_total_bytes=250,
        )


def test_under_budget_mixed_kept_and_skipped_succeeds():
    raw = _make_tar([
        ("skip.bin", b"\x00" * 300),
        ("keep.txt", b"payload"),
    ], gzipped=True)
    out = extract_files_from_tar(
        _chunks(raw),
        selector=_select_named("keep.txt"),
        mode="r|gz",
        max_total_bytes=1_000,
    )
    assert out == {"keep.txt": b"payload"}


def test_no_cap_leaves_skipped_members_unbudgeted():
    """max_total_bytes=None (the opt-out) is unchanged: no counting,
    no exception, big skipped members tolerated."""
    raw = _make_tar([
        ("big-skip.bin", b"\x00" * 50_000),
        ("keep.txt", b"data"),
    ], gzipped=True)
    out = extract_files_from_tar(
        _chunks(raw),
        selector=_select_named("keep.txt"),
        mode="r|gz",
        max_total_bytes=None,
    )
    assert out == {"keep.txt": b"data"}


def test_expected_count_short_circuits_before_later_bomb():
    """Once the wanted members are found, the walk stops — a bomb
    member AFTER the last wanted one must not trip the budget."""
    raw = _make_tar([
        ("keep.txt", b"data"),
        ("bomb.bin", b"\x00" * 50_000),
    ], gzipped=True)
    out = extract_files_from_tar(
        _chunks(raw),
        selector=_select_named("keep.txt"),
        mode="r|gz",
        max_total_bytes=10_000,
        expected_count=1,
    )
    assert out == {"keep.txt": b"data"}


# ---------------------------------------------------------------------------
# Header-time metadata budget — GNU longname / pax record data is
# materialised in memory inside tf.next() (and, for buffered modes,
# inside tarfile.open's firstmember parse); max_total_bytes must bound
# it BEFORE the allocation.
# ---------------------------------------------------------------------------


def _metadata_bomb(name_len: int, fmt: int) -> bytes:
    """A gzipped tar whose FIRST member carries a huge name: GNU
    format stores it as a longname record, pax format as an extended
    header record — both are header-time in-memory allocations."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        info = tarfile.TarInfo(name="d/" + "a" * name_len)
        info.size = 0
        tf.addfile(info)
    return gzip.compress(buf.getvalue())


def test_gnu_longname_bomb_aborts_within_budget_stream_mode():
    bomb = _metadata_bomb(8 * 1024 * 1024, tarfile.GNU_FORMAT)
    assert len(bomb) < 64 * 1024  # tiny wire size, huge declared name
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            bomb, selector=lambda m: m.name, mode="r|gz",
            max_total_bytes=1024 * 1024,
        )


def test_gnu_longname_bomb_aborts_within_budget_buffered_mode():
    """Buffered modes parse the first member inside tarfile.open
    itself — the budget must already be armed there."""
    bomb = _metadata_bomb(8 * 1024 * 1024, tarfile.GNU_FORMAT)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            bomb, selector=lambda m: m.name, mode="r:*",
            max_total_bytes=1024 * 1024,
        )


def test_pax_header_bomb_aborts_within_budget():
    bomb = _metadata_bomb(8 * 1024 * 1024, tarfile.PAX_FORMAT)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            bomb, selector=lambda m: m.name, mode="r|gz",
            max_total_bytes=1024 * 1024,
        )


def test_longname_chain_of_empty_records_is_bounded():
    """Each metadata record charges at least its header block, so an
    archive that is nothing but longname records cannot spin the
    parser unbudgeted."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.GNU_FORMAT) as tf:
        for i in range(200):
            info = tarfile.TarInfo(name=f"d{i}/" + "b" * 200)
            info.size = 0
            tf.addfile(info)
    raw = gzip.compress(buf.getvalue())
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(
            raw, selector=lambda m: m.name, mode="r|gz",
            max_total_bytes=10_000,
        )


def test_legitimate_long_name_under_budget_extracts():
    """The metadata budget must not refuse ordinary deep-path
    archives: a 300-char name is a normal GNU longname record."""
    long_name = "pkg/" + "sub/" * 60 + "leaf.txt"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.GNU_FORMAT) as tf:
        info = tarfile.TarInfo(name=long_name)
        content = b"payload"
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    raw = gzip.compress(buf.getvalue())
    found = extract_files_from_tar(
        raw, selector=lambda m: m.name, mode="r|gz",
        max_total_bytes=1024 * 1024,
    )
    assert found == {long_name: b"payload"}


# ---------------------------------------------------------------------------
# sink mode — members stream out instead of accumulating in the dict
# ---------------------------------------------------------------------------


def test_sink_receives_members_and_dict_holds_placeholders():
    raw = _make_tar([("a.txt", b"alpha"), ("b.txt", b"beta")])
    streamed = {}
    found = extract_files_from_tar(
        raw, selector=lambda m: m.name, mode="r:",
        sink=streamed.__setitem__,
    )
    assert streamed == {"a.txt": b"alpha", "b.txt": b"beta"}
    # Placeholders keep expected_count / unique_keys semantics without
    # retaining the bytes.
    assert found == {"a.txt": b"", "b.txt": b""}


def test_sink_exception_aborts_walk():
    raw = _make_tar([("a.txt", b"alpha"), ("b.txt", b"beta")])
    seen = []

    def sink(key, data):
        seen.append(key)
        raise RuntimeError("budget blown")

    with pytest.raises(RuntimeError, match="budget blown"):
        extract_files_from_tar(
            raw, selector=lambda m: m.name, mode="r:", sink=sink,
        )
    assert seen == ["a.txt"]
