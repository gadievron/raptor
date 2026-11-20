"""Header harvesting preserves read errors while retiring its owned stream."""
import errno
import io
import os
import threading
from types import SimpleNamespace

import pytest

from core.concepts import library_detect as library


@pytest.fixture
def includes(tmp_path, monkeypatch):
    path = tmp_path / 'owned.c'
    payload = b'#include <stdio.h>\n#include "private.h"\n#include <sys/socket.h>\n'
    path.write_bytes(payload)
    (tmp_path / 'ignored.txt').write_text('#include <ignored.h>\n')
    state = SimpleNamespace(path=path, root=tmp_path, payload=payload, primary=None,
                            cleanup=None, reads=[], streams=[], closes=0, fd=None)

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

    def owned_open(candidate):
        assert candidate == path
        raw = io.FileIO(candidate, 'r')
        state.fd = raw.fileno()
        info, expected = os.fstat(state.fd), path.stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        reader = Reader(raw)
        state.streams.extend([raw, reader])
        return reader

    monkeypatch.setattr(library, 'open_regular_gated', owned_open)

    def forbidden(*args, **kwargs):
        pytest.fail('header harvest must not dispatch package, archive or program work')

    monkeypatch.setattr(library, '_run_quiet', forbidden)
    monkeypatch.setattr(library, '_extract_tarball', forbidden)
    monkeypatch.setattr(library, '_detect_resolver', forbidden)
    state.run = lambda: library.harvest_system_includes(tmp_path)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.BufferedReader.close(stream)
        if path.exists():
            assert path.read_bytes() == payload


def retired(includes):
    assert includes.reads == [(library._MAX_SOURCE_READ_BYTES, includes.payload)]
    assert includes.closes == 1 and all(stream.closed for stream in includes.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(includes.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_harvest_read_error_survives_consumed_close(includes, primary, cleanup):
    includes.primary = primary('after actual owned source read')
    includes.cleanup = cleanup('after consumed source close')
    with pytest.raises(primary) as caught:
        includes.run()
    assert caught.value is includes.primary
    retired(includes)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_harvest_fresh_close_keeps_policy(includes, cleanup):
    includes.cleanup = cleanup('fresh source close failure')
    if cleanup is OSError:
        assert includes.run() == set()
    else:
        with pytest.raises(cleanup) as caught:
            includes.run()
        assert caught.value is includes.cleanup
    retired(includes)


def test_harvest_read_oserror_still_skips_file(includes):
    includes.primary = OSError('after actual source read')
    includes.cleanup = KeyboardInterrupt('after consumed source close')
    assert includes.run() == set()
    retired(includes)


def test_harvest_healthy_headers_and_extension_filter(includes):
    assert includes.run() == {'stdio.h', 'sys/socket.h'}
    retired(includes)


def test_harvest_missing_source_remains_empty(includes):
    includes.path.unlink()
    assert includes.run() == set()
    assert not includes.reads and not includes.streams and includes.closes == 0


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='requires POSIX FIFOs')
def test_harvest_refuses_fifo_without_hanging(tmp_path):
    """A planted FIFO named like a source file is skipped, never read.

    The real (un-monkeypatched) gated open must return instead of
    blocking on the reader-less FIFO; the harvest runs in a worker
    thread so a regression fails the join timeout instead of hanging
    the suite.
    """
    (tmp_path / 'good.c').write_text('#include <stdio.h>\n')
    os.mkfifo(tmp_path / 'trap.c')
    results: list[set[str]] = []
    worker = threading.Thread(
        target=lambda: results.append(library.harvest_system_includes(tmp_path)),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), 'FIFO source file hung the harvest'
    assert results == [{'stdio.h'}]
