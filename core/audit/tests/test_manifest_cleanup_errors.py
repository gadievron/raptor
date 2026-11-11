"""Owned manifest stream cleanup must not consume cancellation."""
import errno
import os
from pathlib import Path

import pytest

from core.audit import summary_cache
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('failure', [None, OSError, TypeError, KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize('close_error', [False, True])
def test_manifest_native_cleanup(tmp_path, failure, close_error):
    original = b'django==4.2.1\n'
    (tmp_path / 'requirements.txt').write_bytes(original)
    primary = failure('after native manifest read') if failure else None
    streams = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def read(self, size):
            assert self.stream.read(size) == original
            self.reads += 1
            if primary is not None:
                raise primary
            return original

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_error:
                raise OSError('after native manifest close')

    class OwnedPath(type(Path())):
        def open(self, *args, **kwargs):
            stream = Stream(Path.open(self, *args, **kwargs))
            streams.append(stream)
            return stream

    view = module_function_view(summary_cache)
    caught = None
    result = None
    try:
        try:
            result = view.detect_library_version(OwnedPath(tmp_path), 'django')
        except BaseException as exc:
            caught = exc
        assert len(streams) == 1
        stream = streams[0]
        assert stream.reads == stream.closes == 1
        assert stream.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(stream.fd)
        assert retired.value.errno == errno.EBADF
        assert (tmp_path / 'requirements.txt').read_bytes() == original
        if failure in (KeyboardInterrupt, SystemExit, GeneratorExit):
            assert caught is primary
        else:
            assert caught is None
            assert result == ('4.2.1' if failure is None and not close_error else None)
    finally:
        for stream in streams:
            if not stream.stream.closed:
                stream.stream.close()
