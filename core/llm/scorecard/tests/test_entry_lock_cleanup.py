"""Failed scorecard entry retires its lock without replacing the read error."""
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
                            reads=[], streams=[], locks=[], contexts=[], lock_checks=0,
                            closes=0, fd=None, lock_fd=None)

    class Data(io.TextIOWrapper):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            with lock_path.open('rb') as probe:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            state.lock_checks += 1
            if state.primary is not None:
                raise state.primary
            return data

    class Lock(io.TextIOWrapper):
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
            native = io.FileIO(candidate, 'a+')
            lock = Lock(native, encoding=encoding)
            state.lock_fd = native.fileno()
            state.locks.extend([native, lock])
            return lock
        assert candidate == path and mode == 'r'
        native = io.FileIO(candidate, 'r')
        state.fd = native.fileno()
        info, expected = os.fstat(state.fd), path.stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        data = Data(native, encoding=encoding)
        state.streams.extend([native, data])
        return data

    def forbidden(*args, **kwargs):
        pytest.fail('read-only whitespace scorecard must not access keys or write')

    monkeypatch.setattr(scorecard, 'open', owned_open, raising=False)
    monkeypatch.setattr(scorecard, 'save_json', forbidden)
    for name in ('extract_token', 'verify', 'key_usable', 'stamp'):
        patch_module_attribute(monkeypatch, scorecard, 'integrity', name, forbidden)
    state.card = scorecard.ModelScorecard(path)
    original_context = state.card._with_lock

    def observed_context(*, write=True):
        assert write is False
        context = original_context(write=write)
        state.contexts.append(context)
        return context

    monkeypatch.setattr(state.card, '_with_lock', observed_context)
    state.run = state.card.get_stats
    try:
        yield state
    finally:
        state.cleanup = None
        for stream in reversed(state.streams + state.locks):
            if not stream.closed:
                io.TextIOWrapper.close(stream)
        assert path.read_bytes() == payload


def retired(saved):
    assert saved.reads == [(-1, saved.payload.decode())] and saved.lock_checks == 1
    assert saved.closes == 1 and all(stream.closed for stream in saved.streams + saved.locks)
    assert len(saved.contexts) == 1
    for fd in (saved.fd, saved.lock_fd):
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, OSError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_read_error_survives_consumed_entry_lock_close(saved, primary, cleanup):
    saved.primary = primary('after actual owned data read')
    saved.cleanup = cleanup('after consumed native lock close')
    with pytest.raises(primary) as caught:
        saved.run()
    assert caught.value is saved.primary
    retired(saved)
    assert saved.contexts[0].lock_fh is None


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_successful_entry_fresh_lock_close_failure_remains_visible(saved, cleanup):
    saved.cleanup = cleanup('fresh lock close failure')
    with pytest.raises(cleanup) as caught:
        saved.run()
    assert caught.value is saved.cleanup
    retired(saved)


def test_healthy_public_read_keeps_empty_scorecard(saved):
    assert saved.run() == []
    retired(saved)


def test_handled_missing_read_keeps_fresh_lock_close_failure_visible(saved):
    saved.primary = FileNotFoundError('handled missing data read')
    saved.cleanup = MemoryError('fresh lock close after handled read')
    with pytest.raises(MemoryError) as caught:
        saved.run()
    assert caught.value is saved.cleanup
    retired(saved)
