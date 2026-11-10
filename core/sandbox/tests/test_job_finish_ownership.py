"""Final accounting interruptions retire passive native directory owners."""
from contextlib import ExitStack
import errno
import os

import pytest

from core.sandbox import job_budget
from core.security import cgroup_scope
from core.testing.module_views import module_function_view


@pytest.fixture
def scope(tmp_path):
    directory = tmp_path / 'owned'
    directory.mkdir()
    records = []
    with ExitStack() as owners:
        for path in (directory, tmp_path):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            info = os.fstat(descriptor)
            records.append((descriptor, info.st_dev, info.st_ino))

            def close(fd=descriptor, identity=(info.st_dev, info.st_ino)):
                try:
                    live = os.fstat(fd)
                except OSError:
                    return
                if (live.st_dev, live.st_ino) == identity:
                    os.close(fd)

            owners.callback(close)
        yield cgroup_scope.Scope(directory, records[0][0], records[1][0]), records


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, MemoryError],
                         ids=['interrupt', 'exit', 'memory'])
def test_initial_snapshot_failure_retires_scope_owners(scope, error_type):
    owned, records = scope
    failure = error_type('owned initial snapshot failure')
    calls = []

    def snapshot(actual):
        assert actual is owned
        calls.append('snapshot')
        raise failure

    private = module_function_view(job_budget, bindings={'_snapshot': snapshot})
    caught = result = None
    try:
        result = private._finish_scope(owned)
    except BaseException as error:
        caught = error
    live = []
    for descriptor, device, inode in records:
        try:
            info = os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            if (info.st_dev, info.st_ino) == (device, inode):
                live.append(descriptor)
    assert not live, f'initial accounting failure left scope directory handles live: {live}'
    assert calls == ['snapshot']
    assert caught is None
    assert result['cleanup'] == 'failed'
    assert result['cleanup_error'] == error_type.__name__
    assert result['usage'] == {}
    assert 'final_usage' not in result and 'killed_remaining_processes' not in result
    assert owned.node is None and owned.parent is None
    assert not owned.admission_closed
    assert list(owned.path.iterdir()) == []
