"""A rotation source-read failure survives consuming source-stream close."""
import errno
import os

import pytest

from core.audit import audit_log_rotate as rotation
from core.audit import record
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('failure', [None, OSError, TypeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_error', [False, True])
def test_rotation_native_source_cleanup(tmp_path, failure, close_error):
    source = tmp_path / record.AUDIT_LOG_FILENAME
    original = b'owned log row\n' * 400
    source.write_bytes(original)
    primary = failure('after native rotation readline') if failure else None
    secondary = OSError('after native source close')
    readers = []
    writers = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def readline(self, size):
            line = self.stream.readline(size)
            self.reads += 1
            if primary is not None:
                assert line == b'owned log row\n'
                raise primary
            return line

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_error:
                raise secondary

    def adopt(fd, mode, *args, **kwargs):
        stream = rotation.adopt_fd(fd, mode, *args, **kwargs)
        if mode == 'rb':
            wrapped = Reader(stream)
            readers.append(wrapped)
            return wrapped
        writers.append(stream)
        return stream

    # Same tiny rewrite bounds as retained native cleanup controls, private
    # to this module view; production constants and reader budgets stay intact.
    view = module_function_view(rotation, bindings={
        'adopt_fd': adopt, '_AUDIT_LOG_MAX_BYTES': 2048,
        '_AUDIT_LOG_SHARD_ROLL_BYTES': 1536,
    })
    caught = None
    result = None
    try:
        try:
            result = view._rotate_audit_log(tmp_path)
        except BaseException as exc:
            caught = exc
        assert len(readers) == 1 and writers
        reader = readers[0]
        assert reader.reads >= 1 and reader.closes == 1
        assert reader.stream.closed
        assert all(stream.closed for stream in writers)
        with pytest.raises(OSError) as retired:
            os.fstat(reader.fd)
        assert retired.value.errno == errno.EBADF
        assert not list(tmp_path.glob(rotation._TMP_PREFIX + '*'))
        if primary is not None or close_error:
            assert source.read_bytes() == original
            assert not list(tmp_path.glob('*.pre-rotate*'))
            assert caught is (primary if primary is not None else secondary)
        else:
            assert caught is None
            assert result.rotated
            assert b''.join(p.read_bytes() for p in record.audit_log_paths(tmp_path)) == original
    finally:
        for stream in [r.stream for r in readers] + writers:
            if not stream.closed:
                stream.close()
