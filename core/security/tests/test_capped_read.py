"""Contract tests for ``core.security.capped_read.read_capped``."""

from __future__ import annotations

import os

from core.security.capped_read import read_capped


def test_reads_file_within_cap(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"hello")
    assert read_capped(f, 10) == b"hello"


def test_exactly_cap_is_allowed(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"x" * 10)
    assert read_capped(f, 10) == b"x" * 10


def test_over_cap_returns_none(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"x" * 11)
    assert read_capped(f, 10) is None


def test_missing_file_returns_none(tmp_path):
    assert read_capped(tmp_path / "absent", 10) is None


def test_symlink_not_followed(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert read_capped(link, 100) is None


def test_fifo_returns_none_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert read_capped(fifo, 100) is None


def test_directory_returns_none(tmp_path):
    assert read_capped(tmp_path, 100) is None


def test_fd_closed_exactly_once_by_owner(tmp_path, monkeypatch):
    """The raw fd is owned by read_capped's finally block: the fdopen
    wrapper must NOT close it too. A double-close is a real bug class
    in threaded callers — between the two closes another thread can be
    handed the same fd number, and the second close silently destroys
    the stranger's descriptor."""
    p = tmp_path / "f.txt"
    p.write_bytes(b"content")

    closed: list[int] = []
    failed: list[int] = []
    real_close = os.close

    def spying_close(fd: int) -> None:
        try:
            real_close(fd)
        except OSError:
            failed.append(fd)
            raise
        closed.append(fd)

    monkeypatch.setattr(os, "close", spying_close)
    assert read_capped(p, 100) == b"content"
    assert failed == [], "explicit close hit an already-closed fd"
    assert len(closed) == 1


# ---------------------------------------------------------------------------
# Extended contract: raise_on_refusal / follow_symlinks / text wrapper.
# These pin the parametrized surface the former private copies
# (core/sandbox/triage, core/build/macro_config, sca parsers) map onto.
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from core.security.capped_read import (  # noqa: E402
    CappedReadRefused,
    read_capped_text,
)


def test_default_contract_unchanged_none_never_raises(tmp_path):
    """Both directions: without raise_on_refusal every refusal is
    still None (missing, symlink, oversized) — no exception escapes."""
    assert read_capped(tmp_path / "absent", 10) is None
    target = tmp_path / "t"
    target.write_bytes(b"secret")
    link = tmp_path / "l"
    link.symlink_to(target)
    assert read_capped(link, 100) is None
    big = tmp_path / "big"
    big.write_bytes(b"x" * 11)
    assert read_capped(big, 10) is None


def test_raise_mode_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        read_capped(tmp_path / "absent", 10, raise_on_refusal=True)


def test_raise_mode_symlink_raises_oserror(tmp_path):
    target = tmp_path / "t"
    target.write_bytes(b"secret")
    link = tmp_path / "l"
    link.symlink_to(target)
    with pytest.raises(OSError):
        read_capped(link, 100, raise_on_refusal=True)


def test_raise_mode_fifo_raises_refusal(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(CappedReadRefused) as ei:
        read_capped(fifo, 100, raise_on_refusal=True)
    assert ei.value.reason == "not_regular"
    assert isinstance(ei.value, ValueError)


def test_raise_mode_over_cap_raises_refusal(tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"x" * 11)
    with pytest.raises(CappedReadRefused) as ei:
        read_capped(f, 10, raise_on_refusal=True)
    assert ei.value.reason == "over_cap"
    assert ei.value.st_size == 11
    # Message shape the pre-migration macro_config copy raised —
    # its callers' degradation logs must not change.
    assert "exceeds 10 byte cap" in str(ei.value)


def test_raise_mode_grew_past_cap(tmp_path, monkeypatch):
    """Simulate the fstat-vs-read race: fstat reports an in-cap size
    while the file actually holds more. The +1 read must refuse
    (grew_past_cap), never return a silently-truncated prefix."""
    f = tmp_path / "grow"
    f.write_bytes(b"x" * 20)
    real_fstat = os.fstat

    def lying_fstat(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        return os.stat_result(
            (st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
             st.st_gid, 5, st.st_atime, st.st_mtime, st.st_ctime))

    monkeypatch.setattr(os, "fstat", lying_fstat)
    with pytest.raises(CappedReadRefused) as ei:
        read_capped(f, 10, raise_on_refusal=True)
    assert ei.value.reason == "grew_past_cap"


def test_over_cap_refused_before_any_read(tmp_path, monkeypatch):
    """The fstat size gate refuses BEFORE reading: a planted
    multi-GiB blob must not cost a cap-sized read to refuse."""
    f = tmp_path / "big"
    f.write_bytes(b"x" * 11)
    opened: list[int] = []
    real_fdopen = os.fdopen

    def spying_fdopen(fd, *a, **kw):
        opened.append(fd)
        return real_fdopen(fd, *a, **kw)

    monkeypatch.setattr(os, "fdopen", spying_fdopen)
    assert read_capped(f, 10) is None
    assert opened == [], "over-cap file was read before refusal"


def test_open_flags_carry_cloexec_nofollow_nonblock(tmp_path, monkeypatch):
    """Pin the hardened flag set: O_CLOEXEC keeps the fd from leaking
    across a concurrent exec (the private triage/macro_config copies
    carried it; the chokepoint must not be weaker), O_NOFOLLOW and
    O_NONBLOCK close the symlink / FIFO holes."""
    f = tmp_path / "f"
    f.write_bytes(b"data")
    seen: list[int] = []
    real_open = os.open

    def spying_open(path, flags, *a, **kw):
        seen.append(flags)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", spying_open)
    assert read_capped(f, 100) == b"data"
    assert len(seen) == 1
    assert seen[0] & os.O_CLOEXEC
    assert seen[0] & os.O_NOFOLLOW
    assert seen[0] & os.O_NONBLOCK


def test_follow_symlinks_reads_through_link(tmp_path):
    """Opt-in for operator-named paths: the link is followed but the
    regular-file check still applies to the final target."""
    target = tmp_path / "t"
    target.write_bytes(b"content")
    link = tmp_path / "l"
    link.symlink_to(target)
    assert read_capped(link, 100, follow_symlinks=True) == b"content"


def test_follow_symlinks_still_refuses_nonregular_target(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    link = tmp_path / "l"
    link.symlink_to(fifo)
    assert read_capped(link, 100, follow_symlinks=True) is None


def test_text_decodes_with_replacement(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"ok\xff\xfe")
    text = read_capped_text(f, 100)
    assert text is not None
    assert text.startswith("ok")
    assert "�" in text


def test_text_refusal_is_none(tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"x" * 11)
    assert read_capped_text(f, 10) is None


def test_text_raise_mode_returns_str_or_raises(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"hello")
    assert read_capped_text(f, 10, raise_on_refusal=True) == "hello"
    big = tmp_path / "big"
    big.write_bytes(b"x" * 11)
    with pytest.raises(CappedReadRefused):
        read_capped_text(big, 10, raise_on_refusal=True)


def test_text_strict_decode_failure_no_raise_returns_none(tmp_path):
    """The None-on-refusal contract holds for every ``errors=``
    policy: in no-raise mode a caller-passed ``errors="strict"`` on
    undecodable bytes yields None — a ``UnicodeDecodeError`` must not
    escape the no-exception mode."""
    f = tmp_path / "f"
    f.write_bytes(b"ok\xff\xfe")
    assert read_capped_text(f, 100, errors="strict") is None


def test_text_strict_decode_failure_raise_mode_propagates(tmp_path):
    """In raise mode the decode error stays the caller's problem,
    exactly like the open/read ``OSError``."""
    f = tmp_path / "f"
    f.write_bytes(b"ok\xff\xfe")
    with pytest.raises(UnicodeDecodeError):
        read_capped_text(
            f, 100, errors="strict", raise_on_refusal=True,
        )


def test_text_default_replace_no_raise_unchanged(tmp_path):
    """No behavior change for existing callers: default
    ``errors="replace"`` in no-raise mode still returns the
    replaced text, never None."""
    f = tmp_path / "f"
    f.write_bytes(b"ok\xff\xfe")
    text = read_capped_text(f, 100)
    assert text == "ok��"
