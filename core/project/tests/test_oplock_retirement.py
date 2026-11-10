"""A retired operation-lock descriptor must not be retried after close fails."""

import os
from types import SimpleNamespace

import pytest

from core.project import oplock


@pytest.fixture
def retired_lock(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    state = {'project': project, 'foreign': None, 'closed_foreign': False,
             'retire_calls': 0, 'failure': None, 'first': True}
    real_open = oplock._open_op_lock

    def open_lock(path):
        fd = real_open(path)
        if state['first']:
            state['first'] = False
            state['retiring'] = fd
            # Replace our own temporary lock name while retaining the old
            # native locked inode, exercising the real identity retry.
            path.rename(path.with_name('old-lock'))
            path.touch(mode=0o600)
        return fd

    def close(fd):
        if fd == state['retiring'] and state['retire_calls'] == 0:
            os.close(fd)
            state['retire_calls'] += 1
            foreign = os.open(tmp_path / 'owned-independent-file',
                              os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            state['foreign'] = foreign
            assert foreign == fd
            info = os.fstat(foreign)
            state['identity'] = info.st_dev, info.st_ino
            if state['failure'] is not None:
                raise state['failure']
            return
        if fd == state['foreign']:
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) == state['identity']
            state['closed_foreign'] = True
            state['foreign'] = None
        os.close(fd)

    monkeypatch.setattr(oplock, '_open_op_lock', open_lock)
    monkeypatch.setattr(oplock, 'os', SimpleNamespace(**{**vars(os), 'close': close}))
    try:
        yield state
    finally:
        if state['foreign'] is not None:
            os.close(state['foreign'])


@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('required', [False, True])
def test_consumed_retirement_is_not_closed_again(retired_lock, failure_type, required):
    failure = failure_type('retired native lock close failed')
    retired_lock['failure'] = failure
    with pytest.raises(failure_type) as raised:
        with oplock.project_op_lock(retired_lock['project'], 'owned-test',
                                    grace=0, required=required):
            pytest.fail('close failure must prevent entering the body')
    assert raised.value is failure
    assert retired_lock['retire_calls'] == 1
    assert not retired_lock['closed_foreign']


def test_successful_retirement_reacquires_current_inode(retired_lock):
    with oplock.project_op_lock(retired_lock['project'], 'owned-test',
                                grace=0, required=True) as fd:
        held = os.fstat(fd)
        current = oplock.op_lock_path(retired_lock['project']).stat()
        assert (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)
    assert retired_lock['retire_calls'] == 1
    assert not retired_lock['closed_foreign']
