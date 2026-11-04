"""A damaged status channel cannot establish successful target execution."""
import errno
import os

import pytest

from core.sandbox import _spawn


@pytest.mark.parametrize('prefix', [b'G:', b'G', b'', b'G:X:exec failed', b'M:mount failed'])
def test_read_error_never_returns_exec_success(monkeypatch, prefix):
    chunks = [prefix] if prefix else []
    closed = []

    def read(fd, count):
        if chunks:
            return chunks.pop(0)
        raise OSError(errno.EIO, 'status read failed')

    monkeypatch.setattr(_spawn.os, 'read', read)
    monkeypatch.setattr(_spawn.os, 'close', closed.append)
    owned = {12345}
    result = _spawn._drain_status_pipe(12345, owned)
    assert result is not None
    if prefix == b'G:':
        assert result[0] == '!'
        assert 'unknown' in result[1]
    elif b'X:' in prefix:
        assert result == ('X', 'exec failed')
    elif prefix.startswith(b'M:'):
        assert result == ('M', 'mount failed')
    assert closed == [12345]
    assert owned == set()


@pytest.mark.parametrize('tail', [b'', BlockingIOError(errno.EAGAIN, 'not ready')])
def test_successful_or_nonblocking_drain_preserves_confirmation(monkeypatch, tail):
    chunks = iter([b'G:', tail])

    def read(fd, count):
        item = next(chunks)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(_spawn.os, 'read', read)
    monkeypatch.setattr(_spawn.os, 'close', lambda fd: None)
    owned = {12345}
    assert _spawn._drain_status_pipe(12345, owned) is None
    assert not owned


def test_real_pipe_confirmation_followed_by_exec_failure():
    read_fd, write_fd = os.pipe()
    owned = {read_fd}
    try:
        os.write(write_fd, b'G:X:exec failed')
    finally:
        os.close(write_fd)
    assert _spawn._drain_status_pipe(read_fd, owned) == ('X', 'exec failed')
    assert not owned
