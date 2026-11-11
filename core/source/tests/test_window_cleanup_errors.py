"""Source windows preserve read failures across native stream retirement."""
import errno
import os

import pytest

from core.source import windows
from core.testing.module_views import module_function_view


@pytest.mark.parametrize(('kind', 'anchored'), [
    ('prefix', False), ('prefix', True), ('bytes', False), ('bytes', True), ('text', False),
])
@pytest.mark.parametrize('failure', [None, OSError, TypeError, KeyboardInterrupt])
@pytest.mark.parametrize('close_error', [False, True])
def test_window_native_cleanup(tmp_path, kind, anchored, failure, close_error):
    path = tmp_path / 'owned-source.c'
    original = b'int f(void) { return 1; }\n'
    path.write_bytes(original)
    primary = failure('controlled after native read') if failure else None
    opened = []

    class AfterEffectStream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = 0
            self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def read(self, size):
            data = self.stream.read(size)
            self.reads += 1
            if primary is not None:
                assert data == (original.decode() if kind == 'text' else original)
                raise primary
            return data

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_error:
                raise OSError('controlled after native close')

    def wrap(stream):
        assert stream is not None
        wrapped = AfterEffectStream(stream)
        opened.append(wrapped)
        return wrapped

    def open_owned(path, mode, **kwargs):
        return wrap(windows.open_regular(path, mode, **kwargs))

    def open_contained(root, path, mode, **kwargs):
        return wrap(windows._open_contained(root, path, mode, **kwargs))

    reader = module_function_view(windows, bindings={
        'open_regular': open_owned, '_open_contained': open_contained,
    })
    caught = None
    result = None
    kwargs = {'target_root': tmp_path} if anchored else {}
    try:
        try:
            if kind == 'prefix':
                result = reader.read_bytes_prefix_capped(path, 3, max_bytes=100, **kwargs)
            elif kind == 'bytes':
                result = reader.read_line_window_capped(path, 0, 1, max_bytes=100, **kwargs)
            else:
                result = reader.read_text_line_window_capped(path, 0, 1, max_chars=100, **kwargs)
        except BaseException as exc:
            caught = exc
        assert len(opened) == 1
        resource = opened[0]
        assert resource.reads >= 1
        assert resource.closes == 1
        assert resource.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(resource.fd)
        assert retired.value.errno == errno.EBADF
        assert path.read_bytes() == original
        if failure in (TypeError, KeyboardInterrupt):
            assert caught is primary
        elif failure is OSError or close_error:
            assert caught is None
            assert result is None
        else:
            assert caught is None
            expected = (b'int', False) if kind == 'prefix' else ([original.decode().rstrip('\n')], False)
            assert result == expected
    finally:
        for resource in opened:
            if not resource.stream.closed:
                resource.stream.close()
