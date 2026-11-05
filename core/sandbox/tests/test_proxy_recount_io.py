"""Recount byte limits include only one lookahead byte."""
import os

import pytest

from core.sandbox import context


@pytest.mark.parametrize('limit', [0, 1, 31, 1 << 20])
@pytest.mark.parametrize('short_reads', [False, True])
def test_recount_reads_at_most_limit_plus_one(tmp_path, monkeypatch, limit, short_reads):
    path = tmp_path / 'events'
    path.write_bytes(b'\n' * (limit + 100))
    original = os.read
    consumed = []

    def read(fd, size):
        chunk = original(fd, min(size, 7) if short_reads else size)
        consumed.append(len(chunk))
        return chunk

    monkeypatch.setattr(os, 'read', read)
    assert context._count_lines_bounded(path, max_bytes=limit) == (limit + 1, True)
    assert sum(consumed) == limit + 1


@pytest.mark.parametrize('payload', [b'', b'a\n', b'a\nb\n'])
def test_exact_limit_is_not_overflow(tmp_path, payload):
    path = tmp_path / 'events'
    path.write_bytes(payload)
    assert context._count_lines_bounded(path, max_bytes=len(payload)) == (payload.count(b'\n'), False)


@pytest.mark.parametrize('read_fails', [False, True])
def test_close_error_preserves_result(tmp_path, monkeypatch, read_fails):
    path = tmp_path / 'events'
    path.write_bytes(b'a\nb\n')
    original = os.close
    closed = []

    def close(fd):
        original(fd)
        closed.append(fd)
        raise OSError('close error after release')

    if read_fails:
        def failed_read(*args):
            raise OSError('read failed')
        monkeypatch.setattr(os, 'read', failed_read)
    monkeypatch.setattr(os, 'close', close)
    assert context._count_lines_bounded(path) == ((0, False) if read_fails else (2, False))
    assert len(closed) == 1
