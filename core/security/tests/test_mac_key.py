"""core.security.mac_key — shared per-purpose MAC key discipline.

The load-or-create contract: O_EXCL atomic creation with complete
writes, fd-fstat read discipline (symlink / foreign-owner / permissive
mode refusal), immediate fail-closed on stable wrong-length content,
and race-loser tolerance of the winner's create-to-write window with
no suspect-key warning on the benign race.
"""

from __future__ import annotations

import itertools
import multiprocessing
import os
import stat
import time
from pathlib import Path

import pytest

from core.security import mac_key

_KEY_LEN = 32


@pytest.fixture()
def key_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "test-mac.key"


@pytest.fixture()
def warn_calls() -> list[tuple]:
    return []


def _warn_into(calls: list[tuple]):
    def _warn(path: Path, reason: str, remedy: str) -> None:
        calls.append((path, reason, remedy))
    return _warn


class TestCreate:
    def test_creates_key_with_private_modes(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        key = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert isinstance(key, bytes)
        assert len(key) == _KEY_LEN
        assert key_path.read_bytes() == key
        assert os.stat(key_path).st_mode & 0o777 == 0o600
        assert os.stat(key_path.parent).st_mode & 0o777 == 0o700
        assert warn_calls == []

    def test_existing_key_reused_not_rotated(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        warn = _warn_into(warn_calls)
        first = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=warn)
        second = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=warn)
        assert first == second
        assert warn_calls == []

    def test_short_os_write_still_lands_full_key(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """os.write may write fewer bytes than asked; an unchecked
        short write would leave a torn key every later load refuses."""
        real_write = os.write

        def one_byte_write(fd: int, data) -> int:
            return real_write(fd, bytes(data)[:1])

        monkeypatch.setattr(os, "write", one_byte_write)
        key = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        monkeypatch.undo()
        assert isinstance(key, bytes)
        assert key_path.read_bytes() == key
        assert len(key) == _KEY_LEN
        assert warn_calls == []


def _backdate(path: Path, seconds: float = 60.0) -> None:
    """Age *path* past the freshness window (explicit utime — never a
    real sleep)."""
    old = time.time() - seconds
    os.utime(path, (old, old))


class TestStaleCorruptKey:
    def test_stale_empty_key_refused_immediately_without_retry_stall(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """A STALE 0-byte key (torn write from a past crash, needing
        operator rm) must refuse with a wrong-length warning and MUST
        NOT spin the creation-race retry budget — that stall (plus a
        race-window message) would repeat on every mint/verify."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.touch(mode=0o600)
        _backdate(key_path)
        sleeps: list[float] = []
        monkeypatch.setattr(time, "sleep", sleeps.append)

        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))

        assert got is None
        assert sleeps == []
        assert len(warn_calls) == 1
        assert "wrong length (0 bytes" in warn_calls[0][1]
        # Never replaced: the torn key is left for investigation.
        assert key_path.read_bytes() == b""

    def test_stale_short_key_refused(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(b"short")
        key_path.chmod(0o600)
        _backdate(key_path)
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got is None
        assert len(warn_calls) == 1
        assert "wrong length (5 bytes" in warn_calls[0][1]
        assert key_path.read_bytes() == b"short"

    def test_far_future_mtime_reads_stale_and_refuses(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """A torn key whose mtime landed in the FAR future (corrupt
        timestamp / gross clock skew) cannot be a peer writing "just
        now" — pre-fix the negative age read as fresh forever, so
        every call re-entered the race poll instead of refusing with
        the operator-visible wrong-length warning."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(b"short")
        key_path.chmod(0o600)
        future = time.time() + 3600
        os.utime(key_path, (future, future))
        sleeps: list[float] = []
        monkeypatch.setattr(time, "sleep", sleeps.append)

        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))

        assert got is None
        assert sleeps == []
        assert len(warn_calls) == 1
        assert "wrong length (5 bytes" in warn_calls[0][1]
        assert key_path.read_bytes() == b"short"

    def test_slightly_future_mtime_still_reads_fresh(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        """Skew INSIDE the window keeps the fresh classification — a
        racing peer on an NFS mount with sub-window clock skew must
        not be misdiagnosed as a stale torn key."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(b"")
        key_path.chmod(0o600)
        near_future = time.time() + 1.0
        os.utime(key_path, (near_future, near_future))
        assert mac_key._recently_modified(key_path) is True

    def test_recreate_hint_lands_in_remedy(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(b"short")
        key_path.chmod(0o600)
        _backdate(key_path)
        mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            recreate_hint="a fresh key is created on the next store")
        assert "next store" in warn_calls[0][2]


class TestFreshWrongLengthKey:
    """Fresh wrong-length content (possible concurrent cold-start
    winner mid-write) routes through the race-tolerant create path —
    the other direction of the freshness gate."""

    def test_fresh_empty_key_converges_on_winner(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """The initial read sees a concurrent winner's freshly-created
        0-byte file; the loser must land in the O_EXCL poll and read
        the winner's completed key — no suspect-key warning."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.touch(mode=0o600)  # winner created, not yet written
        monkeypatch.setattr(time, "sleep", lambda s: None)
        full_key = b"k" * _KEY_LEN
        reads = iter([b"", b"", full_key])
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            read_existing=lambda path: next(reads))
        assert got == full_key
        assert warn_calls == []

    def test_fresh_stable_short_key_warns_after_poll(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """A genuinely torn FRESH key exhausts the poll and refuses
        with the wrong-length diagnosis (never a race-window one)."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(b"short")
        key_path.chmod(0o600)
        monkeypatch.setattr(time, "sleep", lambda s: None)
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            read_existing=lambda path: b"short")
        assert got is None
        assert len(warn_calls) == 1
        assert "wrong length (5 bytes" in warn_calls[0][1]


class TestReadDiscipline:
    def test_symlinked_key_refused_and_not_replaced(
            self, key_path: Path, warn_calls: list[tuple],
            tmp_path: Path) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        target = tmp_path / "attacker-controlled"
        target.write_bytes(b"k" * _KEY_LEN)
        target.chmod(0o600)
        key_path.symlink_to(target)

        warn = _warn_into(warn_calls)
        assert mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=warn) is mac_key.REFUSED
        assert mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=warn) is None
        assert key_path.is_symlink()
        assert any("symlink" in remedy for _, _, remedy in warn_calls)

    def test_group_other_readable_key_refused(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(os.urandom(_KEY_LEN))
        key_path.chmod(0o644)
        got = mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got is mac_key.REFUSED
        assert "chmod 600" in warn_calls[0][2]

    def test_foreign_owner_refused(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.write_bytes(os.urandom(_KEY_LEN))
        key_path.chmod(0o600)
        real_fstat = os.fstat

        def foreign(fd: int) -> os.stat_result:
            st = real_fstat(fd)
            values = list(st)
            values[4] = st.st_uid + 1  # st_uid slot
            return os.stat_result(values)

        monkeypatch.setattr(os, "fstat", foreign)
        got = mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got is mac_key.REFUSED
        assert "owned by uid=" in warn_calls[0][1]

    def test_non_regular_file_refused(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        key_path.parent.mkdir(mode=0o700, parents=True)
        key_path.mkdir(mode=0o700)  # a directory at the key path
        got = mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got is mac_key.REFUSED
        assert "not a regular file" in warn_calls[0][1]

    def test_chunked_read_delivers_full_key(
            self, key_path: Path, warn_calls: list[tuple],
            monkeypatch: pytest.MonkeyPatch) -> None:
        """os.read may legally return fewer bytes than requested; the
        read loop must not land a healthy key in the wrong-length
        refusal."""
        key_path.parent.mkdir(mode=0o700, parents=True)
        data = os.urandom(_KEY_LEN)
        key_path.write_bytes(data)
        key_path.chmod(0o600)
        real_read = os.read
        monkeypatch.setattr(
            os, "read", lambda fd, n: real_read(fd, min(n, 5)))
        got = mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got == data
        assert warn_calls == []

    def test_absent_key_reads_none(
            self, key_path: Path, warn_calls: list[tuple]) -> None:
        got = mac_key.read_existing_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls))
        assert got is None
        assert warn_calls == []


class TestCreationRace:
    @pytest.fixture()
    def lose_creation_race(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the key-create os.open lose the O_EXCL race."""
        real_open = os.open

        def fake_open(path, flags, mode=0o777):
            if flags & os.O_EXCL:
                raise FileExistsError(path)
            return real_open(path, flags, mode)

        monkeypatch.setattr(os, "open", fake_open)
        monkeypatch.setattr(time, "sleep", lambda s: None)

    def test_race_loser_retries_through_empty_read(
            self, key_path: Path, warn_calls: list[tuple],
            lose_creation_race: None) -> None:
        """First re-read sees the winner's 0-byte file, second sees
        the full key — hit, no suspect-key warning on the benign
        race."""
        full_key = b"k" * _KEY_LEN
        reads = iter([None, b"", full_key])
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            read_existing=lambda path: next(reads))
        assert got == full_key
        assert warn_calls == []

    def test_persistent_wrong_length_warns_after_retries(
            self, key_path: Path, warn_calls: list[tuple],
            lose_creation_race: None) -> None:
        """Bounded budget, other direction: a key file that STAYS
        short is genuinely suspect — the loop runs out of retries,
        warns once, and refuses (None)."""
        reads = itertools.chain([None], itertools.repeat(b"short"))
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            read_existing=lambda path: next(reads))
        assert got is None
        assert len(warn_calls) == 1
        assert "wrong length" in warn_calls[0][1]

    def test_refused_read_mid_race_refuses(
            self, key_path: Path, warn_calls: list[tuple],
            lose_creation_race: None) -> None:
        reads = iter([None, mac_key.REFUSED])
        got = mac_key.load_or_create_key(
            key_path, key_len=_KEY_LEN, warn=_warn_into(warn_calls),
            read_existing=lambda path: next(reads))
        assert got is None


def _parallel_creator(path_str: str, barrier, queue) -> None:
    """Cross-process worker: create/load the shared key, report
    (key hex or None, suspect-key warn reasons)."""
    warns: list[str] = []
    barrier.wait()  # line all creators up on the O_EXCL race
    key = mac_key.load_or_create_key(
        Path(path_str), key_len=_KEY_LEN,
        warn=lambda path, reason, remedy: warns.append(reason))
    queue.put((None if key is None else key.hex(), warns))


class TestParallelCreators:
    def test_parallel_creators_converge_on_one_key_without_warnings(
            self, key_path: Path) -> None:
        """Concurrency regression: N processes cold-start the same key
        file. Every loser of the O_EXCL creation race must end up with
        the winner's full key — one consistent key everywhere, no
        suspect-key warnings for the benign race."""
        n = 8
        methods = multiprocessing.get_all_start_methods()
        ctx = multiprocessing.get_context(
            "fork" if "fork" in methods else "spawn")
        barrier = ctx.Barrier(n)
        queue = ctx.Queue()
        procs = [
            ctx.Process(
                target=_parallel_creator,
                args=(str(key_path), barrier, queue))
            for _ in range(n)
        ]
        for p in procs:
            p.start()
        results = [queue.get(timeout=30) for _ in range(n)]
        for p in procs:
            p.join(timeout=30)

        keys = {key_hex for key_hex, _ in results}
        assert None not in keys, results
        assert len(keys) == 1, results
        all_warns = [w for _, warns in results for w in warns]
        assert all_warns == []
        on_disk = key_path.read_bytes()
        assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
        assert on_disk.hex() in keys
