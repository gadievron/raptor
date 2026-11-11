"""Native strategy-log iteration keeps its primary interruption."""
import builtins
from collections import defaultdict
import errno
import os

import pytest

from core.audit import strategy_stats
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('failure', [None, OSError, TypeError, KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize('close_error', [False, True])
def test_strategy_native_cleanup(tmp_path, failure, close_error):
    path = tmp_path / 'owned-log.jsonl'
    original = b'{"action":"orchestrator_review","status":"finding","strategies":["alpha"]}\n'
    path.write_bytes(original)
    primary = failure('after native strategy log iteration') if failure else None
    streams = []

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
            line = next(self.stream)
            assert line.encode() == original
            self.reads += 1
            if primary is not None:
                raise primary
            return line

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_error:
                raise OSError('after native log close')

    def open_owned(*args, **kwargs):
        resource = Stream(builtins.open(*args, **kwargs))
        streams.append(resource)
        return resource

    view = module_function_view(strategy_stats, bindings={'open': open_owned})
    stats = defaultdict(lambda: {'wins': 0, 'misses': 0, 'total': 0})
    caught = None
    try:
        try:
            view._tally_strategy_log(path, stats)
        except BaseException as exc:
            caught = exc
        assert len(streams) == 1
        stream = streams[0]
        assert stream.reads == stream.closes == 1
        assert stream.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(stream.fd)
        assert retired.value.errno == errno.EBADF
        assert path.read_bytes() == original
        if failure not in (None, OSError):
            assert caught is primary
        else:
            assert caught is None
        assert dict(stats) == ({'alpha': {'wins': 1, 'misses': 0, 'total': 1}} if failure is None else {})
    finally:
        for stream in streams:
            if not stream.stream.closed:
                stream.stream.close()
