"""Live-only review preserves read errors without loading authorization state."""
import errno
import io
import os
from types import SimpleNamespace

import pytest

from core.sage import boot_payload_review as review


@pytest.fixture
def capture(tmp_path, monkeypatch):
    path = tmp_path / 'owned-capture.txt'
    payload = b'### initialize.instructions\nowned\rinert capture\n'
    path.write_bytes(payload)
    state = SimpleNamespace(path=path, payload=payload, primary=None, cleanup=None,
                            reads=[], streams=[], closes=0, fd=None)

    class Reader(io.TextIOWrapper):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
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

    def owned_open(candidate, mode='r', *, encoding, newline):
        assert candidate == str(path) and mode == 'r'
        assert encoding == 'utf-8' and newline == ''
        native = io.FileIO(candidate, 'r')
        state.fd = native.fileno()
        info, expected = os.fstat(state.fd), path.stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        reader = Reader(native, encoding=encoding, newline=newline)
        state.streams.extend([native, reader])
        return reader

    def forbidden(*args, **kwargs):
        pytest.fail('live-only reader must not load guards or decide authorization')

    monkeypatch.setattr(review, 'open', owned_open, raising=False)
    for name in ('_load_guard', '_load_preflight', 'merge', 'deny'):
        monkeypatch.setattr(review, name, forbidden)
    state.run = lambda: review.main(['strip-tools', '--live', str(path)])
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.TextIOWrapper.close(stream)
        if path.exists():
            assert path.read_bytes() == state.payload


def retired(capture):
    assert capture.reads == [(review._MAX_CAPTURE_CHARS + 1, capture.payload.decode())]
    assert capture.closes == 1 and all(stream.closed for stream in capture.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(capture.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_live_only_read_error_survives_consumed_close(capture, primary, cleanup):
    capture.primary = primary('after actual inert capture read')
    capture.cleanup = cleanup('after consumed capture close')
    with pytest.raises(primary) as caught:
        capture.run()
    assert caught.value is capture.primary
    retired(capture)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_live_only_fresh_close_keeps_policy(capture, cleanup, capsys):
    capture.cleanup = cleanup('fresh capture close failure')
    if cleanup is OSError:
        assert capture.run() == 3
        assert 'cannot read live capture' in capsys.readouterr().err
    else:
        with pytest.raises(cleanup) as caught:
            capture.run()
        assert caught.value is capture.cleanup
    retired(capture)


def test_live_only_healthy_output_preserves_carriage_return(capture, capsys):
    assert capture.run() == 0
    assert capsys.readouterr().out == capture.payload.decode()
    retired(capture)


def test_live_only_read_oserror_remains_diagnostic_refusal(capture, capsys):
    capture.primary = OSError('ordinary capture read failure')
    capture.cleanup = KeyboardInterrupt('secondary capture close failure')
    assert capture.run() == 3
    assert 'cannot read live capture' in capsys.readouterr().err
    retired(capture)


def test_live_only_duplicate_header_refusal_survives_close_failure(capture, capsys):
    capture.payload = b'### initialize.instructions\none\n### initialize.instructions\ntwo\n'
    capture.path.write_bytes(capture.payload)
    capture.cleanup = MemoryError('after close during parse refusal')
    assert capture.run() == 3
    output = capsys.readouterr()
    assert not output.out and 'duplicate section header' in output.err
    retired(capture)


def test_live_only_missing_capture_remains_refusal(capture, capsys):
    capture.path.unlink()
    assert capture.run() == 3
    assert 'cannot read live capture' in capsys.readouterr().err
    assert not capture.reads and not capture.streams and capture.closes == 0
