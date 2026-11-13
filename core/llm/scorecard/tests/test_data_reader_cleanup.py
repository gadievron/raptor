"""Read-only scorecard data streams preserve errors during consumed close."""
import builtins
import errno
import fcntl
import io
import os
from types import SimpleNamespace

import pytest

from core.llm.scorecard import scorecard
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def saved(tmp_path, monkeypatch):
    path = tmp_path / 'owned.json'
    payload = b' \n'
    path.write_bytes(payload)
    lock_path = path.with_suffix('.json.lock')
    state = SimpleNamespace(path=path, payload=payload, primary=None, cleanup=None,
                            reads=[], streams=[], locks=[], closes=0, fd=None, lock_fd=None, lock_checks=0)

    class Reader(io.TextIOWrapper):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            with builtins.open(lock_path, 'rb') as probe:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            state.lock_checks += 1
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def owned_open(candidate, mode='r', *, encoding):
        assert encoding == 'utf-8'
        if candidate == lock_path:
            assert mode == 'a+'
            lock = builtins.open(candidate, mode, encoding=encoding)
            state.lock_fd = lock.fileno()
            state.locks.append(lock)
            return lock
        assert candidate == path and mode == 'r'
        native = io.FileIO(candidate, 'r')
        state.fd = native.fileno()
        info, expected = os.fstat(state.fd), path.stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        reader = Reader(native, encoding=encoding)
        state.streams.extend([native, reader])
        return reader

    def forbidden(*args, **kwargs):
        pytest.fail('read-only whitespace scorecard must not use integrity keys or writes')

    monkeypatch.setattr(scorecard, 'open', owned_open, raising=False)
    monkeypatch.setattr(scorecard, 'save_json', forbidden)
    for name in ('extract_token', 'verify', 'key_usable', 'stamp'):
        patch_module_attribute(monkeypatch, scorecard, 'integrity', name, forbidden)
    state.card = scorecard.ModelScorecard(path)
    state.run = state.card.get_stats
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.TextIOWrapper.close(stream)
        for lock in state.locks:
            lock.close()
        if path.exists():
            assert path.read_bytes() == payload
        assert not list(tmp_path.glob('*.unverified'))
        assert not list(tmp_path.glob('*.corrupt'))


def retired(saved):
    assert saved.reads == [(-1, saved.payload.decode())]
    assert saved.closes == saved.lock_checks == 1 and all(stream.closed for stream in saved.streams)
    assert len(saved.locks) == 1 and saved.locks[0].closed
    for fd in (saved.fd, saved.lock_fd):
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, OSError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_stats_data_read_error_survives_consumed_close(saved, primary, cleanup):
    saved.primary = primary('after actual owned scorecard read')
    saved.cleanup = cleanup('after consumed scorecard data close')
    with pytest.raises(primary) as caught:
        saved.run()
    assert caught.value is saved.primary
    retired(saved)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_public_stats_fresh_data_close_error_remains_visible(saved, cleanup):
    saved.cleanup = cleanup('fresh scorecard data close failure')
    with pytest.raises(cleanup) as caught:
        saved.run()
    assert caught.value is saved.cleanup
    retired(saved)


def test_public_stats_whitespace_remains_empty_without_integrity_or_write(saved):
    assert saved.run() == []
    retired(saved)


def test_public_stats_missing_data_still_reads_empty(saved):
    saved.path.unlink()
    assert saved.run() == []
    assert not saved.reads and not saved.streams and saved.closes == 0
    assert len(saved.locks) == 1 and saved.locks[0].closed


def test_public_stats_handled_missing_read_does_not_become_cleanup_cancellation(saved):
    saved.primary = FileNotFoundError('after actual data read')
    saved.cleanup = KeyboardInterrupt('after consumed data close')
    assert saved.run() == []
    retired(saved)
