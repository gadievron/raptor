"""Native directory cleanup controls, without cgroup admission or enforcement."""
import errno
import os

import pytest

from core.sandbox import job_budget
from core.security import cgroup_scope
from core.testing.module_views import module_function_view


@pytest.fixture
def discovery(tmp_path):
    current = tmp_path / 'current'
    alternate = (tmp_path / 'user.slice' / f'user-{os.geteuid()}.slice'
                 / f'user@{os.geteuid()}.service')
    for path in (current, alternate):
        path.mkdir(parents=True)
        (path / 'cgroup.subtree_control').write_text('memory pids\n')
    records, events = [], []

    def create(*, primary=None, close_error=None, first_content=None):
        if first_content is not None:
            (current / 'cgroup.subtree_control').write_text(first_content)

        def opened(path):
            # This seam owns ordinary directories, never claims kernel admission.
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            info = os.fstat(fd)
            records.append((fd, info.st_dev, info.st_ino))
            events.append(('open', path))
            return fd

        def read(fd, name):
            result = cgroup_scope._read(fd, name)
            events.append(('read', result))
            if primary is not None:
                raise primary
            return result

        def close(fd):
            os.close(fd)
            events.append(('close', fd))
            if close_error is not None:
                raise close_error

        private_os = module_function_view(os, bindings={'close': close})
        controls = module_function_view(cgroup_scope, bindings={
            'CGROUP_ROOT': tmp_path, 'current_group': lambda: current,
            '_open_directory': opened, '_read': read,
        })
        return module_function_view(job_budget, bindings={
            'os': private_os, 'cgroup_scope': controls,
        })

    yield create, current, alternate, records, events
    for fd, dev, ino in records:
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            if (info.st_dev, info.st_ino) == (dev, ino):
                os.close(fd)
                pytest.fail('discovery left its owned directory live')


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_discovery_cancellation_survives_directory_close_io(discovery, error_type):
    create, _, _, records, events = discovery
    primary = error_type('owned eligibility cancellation')
    private = create(primary=primary, close_error=OSError('owned after-close IO'))
    with pytest.raises(error_type) as caught:
        private.find_delegation((('pids.max', '4'),))
    assert caught.value is primary
    assert len(records) == 1
    assert [event[0] for event in events] == ['open', 'read', 'close']


def test_unexpected_eligibility_error_survives_cleanup_cancellation(discovery):
    create, _, _, records, events = discovery
    primary = ValueError('owned invalid eligibility result')
    private = create(primary=primary, close_error=KeyboardInterrupt('owned close cancellation'))
    with pytest.raises(ValueError) as caught:
        private.find_delegation((('pids.max', '4'),))
    assert caught.value is primary
    assert len(records) == 1 and events[-1][0] == 'close'


def test_selected_directory_is_closed_before_return(discovery):
    create, current, _, records, events = discovery
    assert create().find_delegation((('pids.max', '4'),)) == current
    assert len(records) == 1
    assert [event[0] for event in events] == ['open', 'read', 'close']


def test_missing_controller_keeps_alternate_selection(discovery):
    create, _, alternate, records, events = discovery
    private = create(first_content='memory\n')
    assert private.find_delegation((('pids.max', '4'),)) == alternate
    assert len(records) == 2
    assert [event[0] for event in events] == ['open', 'read', 'close'] * 2


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_fresh_close_failure_is_not_hidden(discovery, error_type):
    create, _, _, records, events = discovery
    failure = error_type('owned fresh close failure')
    with pytest.raises(error_type) as caught:
        create(close_error=failure).find_delegation((('pids.max', '4'),))
    assert caught.value is failure
    assert len(records) == 1 and events[-1][0] == 'close'


def test_no_eligible_controller_keeps_enotsup(discovery):
    create, _, alternate, records, events = discovery
    (alternate / 'cgroup.subtree_control').write_text('memory\n')
    private = create(first_content='memory\n')
    with pytest.raises(OSError) as caught:
        private.find_delegation((('pids.max', '4'),))
    assert caught.value.errno == errno.ENOTSUP
    assert len(records) == 2 and len(events) == 6
