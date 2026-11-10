"""Own plain PID lockfile descriptors without invoking lifecycle actions."""
import errno
import os
from types import SimpleNamespace

import pytest

from cve_env.utils import lifecycle as lf


@pytest.fixture
def lock_io(tmp_path, monkeypatch):
    directory = tmp_path / 'owned-locks'
    directory.mkdir(mode=0o700)
    path = directory / f'{lf.LOCK_PREFIX}{os.getpid()}{lf.LOCK_SUFFIX}'
    state = SimpleNamespace(path=path, opened=[], live=set(), opens=[], closes=[],
                            primary=None, cleanup=None, writes=0)

    def open_fd(name, flags, mode):
        assert name == str(path)
        assert flags == os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        assert mode == 0o644
        state.opens.append((name, flags, mode))
        fd = os.open(name, flags, mode)
        state.opened.append(fd)
        state.live.add(fd)
        return fd

    def write_fd(fd, data):
        assert fd in state.live
        assert data == str(os.getpid()).encode()
        count = os.write(fd, data)
        state.writes += 1
        if state.primary is not None:
            raise state.primary
        return count

    def close_fd(fd):
        assert fd in state.live
        state.live.remove(fd)
        os.close(fd)
        state.closes.append(fd)
        if state.cleanup is not None:
            raise state.cleanup

    def forbidden(*args, **kwargs):
        pytest.fail('lock control invoked lifecycle process actions')

    monkeypatch.setattr(lf, 'LOCK_DIR', directory)
    monkeypatch.setattr(lf, 'os', SimpleNamespace(**{**vars(os), 'open': open_fd,
                                                  'write': write_fd, 'close': close_fd,
                                                  'kill': forbidden}))
    monkeypatch.setattr(lf, 'run_with_timeout', forbidden)
    try:
        yield state
    finally:
        for fd in list(state.live):
            state.live.remove(fd)
            os.close(fd)


def assert_retired(state, stale):
    assert len(state.opens) == (2 if stale else 1)
    assert len(state.opened) == state.writes == len(state.closes) == 1
    assert state.closes == state.opened and not state.live
    with pytest.raises(OSError) as caught:
        os.fstat(state.opened[0])
    assert caught.value.errno == errno.EBADF
    assert state.path.read_text() == str(os.getpid())


@pytest.mark.parametrize('stale', [False, True], ids=['new', 'stale'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_write_failure_survives_consumed_close(lock_io, stale, primary, cleanup):
    if stale:
        lock_io.path.write_text('stale pid')
    lock_io.primary = primary('after native PID write')
    lock_io.cleanup = cleanup('after native descriptor close')
    with pytest.raises(primary) as caught:
        lf.acquire_lock()
    assert caught.value is lock_io.primary
    assert_retired(lock_io, stale)


@pytest.mark.parametrize('stale', [False, True], ids=['new', 'stale'])
@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_still_prevents_return(lock_io, stale, cleanup):
    if stale:
        lock_io.path.write_text('stale pid')
    lock_io.cleanup = cleanup('fresh close failure')
    with pytest.raises(cleanup) as caught:
        lf.acquire_lock()
    assert caught.value is lock_io.cleanup
    assert_retired(lock_io, stale)


@pytest.mark.parametrize('stale', [False, True], ids=['new', 'stale'])
def test_success_preserves_pid_write_and_release_contract(lock_io, stale):
    if stale:
        lock_io.path.write_text('stale pid')
    assert lf.acquire_lock() == lock_io.path
    assert_retired(lock_io, stale)
    lf.release_lock(lock_io.path)
    assert not lock_io.path.exists()
