"""Owned inert header read preserves interruption across native close."""
import errno
import os

import pytest

from core.audit import integer_abi
from core.source import gated
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize('failure', [None, OSError, ValueError, TypeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_error', [False, True])
def test_abi_native_read_cleanup(tmp_path, failure, close_error):
    path = tmp_path / 'owned-inert-header'
    original = b'inert ordinary file\n'
    path.write_bytes(original)
    primary = failure('after native header read') if failure else None
    resources = []

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
                raise OSError('after native header close')

    def open_owned(path):
        resource = Stream(gated.open_regular_gated(path))
        resources.append(resource)
        return resource

    caught = None
    result = object()
    try:
        with scoped_function_imports(integer_abi, ['binary_integer_abi'], {'core.source.gated': gated}) as imports:
            getattr(imports, 'core.source.gated').open_regular_gated = open_owned
            try:
                result = integer_abi.binary_integer_abi(path)
            except BaseException as exc:
                caught = exc
        assert len(resources) == 1
        resource = resources[0]
        assert resource.reads == resource.closes == 1
        assert resource.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(resource.fd)
        assert retired.value.errno == errno.EBADF
        assert path.read_bytes() == original
        if failure in (TypeError, KeyboardInterrupt, SystemExit):
            assert caught is primary
        else:
            assert caught is None
            assert result is None
    finally:
        for resource in resources:
            if not resource.stream.closed:
                resource.stream.close()
