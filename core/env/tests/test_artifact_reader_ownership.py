"""Ordinary artifact readers retain their raising and optional policies."""
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.engagement.ledger import _read_head
from core.env.build import _sha256


@pytest.fixture(params=['hash', 'head'])
def reader(request, tmp_path):
    path = tmp_path / 'owned.bin'
    payload = bytes(range(256)) * 300
    path.write_bytes(payload)
    state = SimpleNamespace(kind=request.param, path=path, payload=payload, opened=[], wrappers=[],
                            reads=[], closes=0, primary=None, cleanup=None)

    class Reader(io.BufferedReader):
        def read(self, *args, **kwargs):
            value = super().read(*args, **kwargs)
            state.reads.append(args[0] if args else -1)
            if state.primary is not None:
                raise state.primary
            return value

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class InputPath(type(Path())):
        def open(self, mode='r', *args, **kwargs):
            assert mode == 'rb' and not args and not kwargs
            native = super().open(mode)
            state.opened.append(native)
            wrapper = Reader(native)
            state.wrappers.append(wrapper)
            return wrapper

    function = _sha256 if request.param == 'hash' else _read_head
    state.run = lambda: function(InputPath(path))
    try:
        yield state
    finally:
        for stream in state.wrappers:
            if not stream.closed:
                io.BufferedReader.close(stream)


def assert_retired(state):
    assert state.closes == len(state.opened) == 1
    assert all(stream.closed for stream in state.opened + state.wrappers)
    assert state.path.read_bytes() == state.payload


@pytest.mark.parametrize('primary', [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_unhandled_read_error_survives_consumed_close(reader, primary, cleanup):
    reader.primary = primary('after native artifact read')
    reader.cleanup = cleanup('after native reader close')
    with pytest.raises(primary) as caught:
        reader.run()
    assert caught.value is reader.primary
    assert_retired(reader)


@pytest.mark.parametrize('cleanup', [None, KeyboardInterrupt])
def test_read_oserror_retains_required_or_optional_policy(reader, cleanup):
    reader.primary = OSError('after native artifact read')
    reader.cleanup = cleanup('fresh cleanup cancellation') if cleanup else None
    if reader.kind == 'hash':
        with pytest.raises(OSError) as caught:
            reader.run()
        assert caught.value is reader.primary
    elif cleanup:
        with pytest.raises(cleanup) as caught:
            reader.run()
        assert caught.value is reader.cleanup
    else:
        assert reader.run() is None
    assert_retired(reader)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_fresh_close_failure_retains_existing_policy(reader, cleanup):
    reader.cleanup = cleanup('fresh close failure')
    if reader.kind == 'head' and cleanup is OSError:
        assert reader.run() is None
    else:
        with pytest.raises(cleanup) as caught:
            reader.run()
        assert caught.value is reader.cleanup
    assert_retired(reader)


def test_healthy_reader_keeps_chunking_and_result(reader):
    result = reader.run()
    if reader.kind == 'hash':
        assert result == hashlib.sha256(reader.payload).hexdigest()
        assert reader.reads == [65536, 65536, 65536]
    else:
        assert result == reader.payload[:64]
        assert reader.reads == [64]
    assert_retired(reader)


def test_missing_input_preserves_open_error_policy(reader):
    reader.path.unlink()
    if reader.kind == 'hash':
        with pytest.raises(FileNotFoundError):
            reader.run()
    else:
        assert reader.run() is None
    assert not reader.opened and not reader.wrappers
    assert reader.closes == 0
