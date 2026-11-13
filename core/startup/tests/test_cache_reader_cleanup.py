"""Existing inert cache comparison keeps read errors primary during close."""
import errno
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.startup import install_guard
from core.testing.module_views import module_function_view


@pytest.fixture
def cache(tmp_path):
    path = tmp_path / 'owned-inert-cache'
    payload = b'inert comparison bytes; never compiled or unmarshalled\n'
    path.write_bytes(payload)
    state = SimpleNamespace(primary=None, cleanup=None, reads=[], streams=[], closes=0,
                            fd=None, expected=payload, path=path, payload=payload)

    class Reader(io.BufferedReader):
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

    class CachePath(type(Path())):
        def open(self, mode='r', *args, **kwargs):
            assert self == path and mode == 'rb' and not args and not kwargs
            native = path.open(mode)
            state.fd = native.fileno()
            info, expected = os.fstat(state.fd), path.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            reader = Reader(native)
            state.streams.extend([native, reader])
            return reader

    def forbidden(*args, **kwargs):
        pytest.fail('cache comparison must not compile, precompile, write or execute')

    view = module_function_view(install_guard, bindings={
        '_bytecode_stream': forbidden, '_compile_bytecode': forbidden,
        '_bytecode_sources': forbidden, 'precompile': forbidden,
    })
    state.run = lambda: view._save_bytecode(CachePath(path), state.expected)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.BufferedReader.close(stream)
        assert path.read_bytes() == payload
        assert sorted(tmp_path.iterdir()) == [path]


def retired(cache):
    assert cache.reads == [(len(cache.payload) + 1, cache.payload)]
    assert cache.closes == 1 and all(stream.closed for stream in cache.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(cache.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, OSError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_existing_cache_read_error_survives_consumed_close(cache, primary, cleanup):
    cache.primary = primary('after actual inert cache read')
    cache.cleanup = cleanup('after consumed inert cache close')
    with pytest.raises(primary) as caught:
        cache.run()
    assert caught.value is cache.primary
    retired(cache)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_existing_cache_fresh_close_error_remains_visible(cache, cleanup):
    cache.cleanup = cleanup('fresh inert cache close error')
    with pytest.raises(cleanup) as caught:
        cache.run()
    assert caught.value is cache.cleanup
    retired(cache)


def test_matching_inert_cache_returns_without_writing(cache):
    assert cache.run() is None
    retired(cache)


def test_no_expected_cache_bytes_does_not_open_or_write(cache):
    cache.expected = None
    assert cache.run() is None
    assert not cache.reads and not cache.streams and cache.closes == 0
