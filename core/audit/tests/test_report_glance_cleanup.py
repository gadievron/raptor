"""An interrupted native report count read is not an ordinary zero."""
import errno
import os
from pathlib import Path

import pytest

from core.audit import report
from core.testing.module_views import module_function_view


def test_glance_count_native_cancellation_survives_close(tmp_path):
    original = b'{"rule_id":"audit:glance-escalation-cap","dropped":false}\n'
    path = tmp_path / 'suppressions.jsonl'
    path.write_bytes(original)
    primary = KeyboardInterrupt('after native report trail iteration')
    resources = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            assert next(self.stream).encode() == original
            self.reads += 1
            raise primary

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            raise OSError('after native report trail close')

    class OwnedPath(type(Path())):
        def open(self, *args, **kwargs):
            resource = Stream(Path.open(self, *args, **kwargs))
            resources.append(resource)
            return resource

    view = module_function_view(report, bindings={'Path': OwnedPath})
    caught = None
    result = None
    try:
        try:
            result = view._load_glance_cap(tmp_path)
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
        assert caught is primary, f'reader returned {result!r}'
    finally:
        for resource in resources:
            if not resource.stream.closed:
                resource.stream.close()


@pytest.mark.parametrize(
    ('body_kind', 'close_kind', 'expected'),
    [
        (None, None, 1),
        (None, OSError, 0),
        (OSError, OSError, 0),
        (KeyboardInterrupt, OSError, None),
        (SystemExit, OSError, None),
        (GeneratorExit, OSError, None),
        (KeyboardInterrupt, SystemExit, None),
        (ValueError, OSError, None),
    ],
)
def test_glance_count_cleanup_contract(tmp_path, body_kind, close_kind, expected):
    original = (
        b'\ninvalid json\n[]\n'
        b'{"rule_id":"unrelated"}\n'
        b'{"rule_id":"audit:glance-escalation-cap","dropped":false}\n'
    )
    path = tmp_path / 'suppressions.jsonl'
    path.write_bytes(original)
    primary = body_kind('after native iteration') if body_kind else None
    resources = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.closes = self.reads = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            line = next(self.stream)
            self.reads += 1
            if primary is not None:
                raise primary
            return line

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_kind:
                raise close_kind('after native close')

    class OwnedPath(type(Path())):
        def open(self, *args, **kwargs):
            resource = Stream(Path.open(self, *args, **kwargs))
            resources.append(resource)
            return resource

    view = module_function_view(report, bindings={'Path': OwnedPath})
    try:
        if expected is None:
            with pytest.raises(body_kind) as caught:
                view._load_glance_cap(tmp_path)
            assert caught.value is primary
        else:
            assert view._load_glance_cap(tmp_path) == expected
        assert len(resources) == 1
        resource = resources[0]
        assert resource.closes == 1
        assert resource.reads == (1 if primary else 5)
        assert resource.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(resource.fd)
        assert retired.value.errno == errno.EBADF
        assert path.read_bytes() == original
    finally:
        for resource in resources:
            if not resource.stream.closed:
                resource.stream.close()


def test_glance_count_missing_trail(tmp_path):
    assert report._load_glance_cap(tmp_path) == 0
