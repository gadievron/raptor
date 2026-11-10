"""Watcher pre-fork failures retire native pipes without replacing the cause."""

import builtins
from contextlib import ExitStack
import errno
import os
import sys

import pytest

import core.sandbox as package
from core.sandbox import job_budget, _spawn as spawn
from core.security.cgroup_scope import Scope
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.linux_native,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux watcher pipes')]


@pytest.fixture
def prepared_job(tmp_path):
    with ExitStack() as owners:
        node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, node)
        parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, parent)
        scope = Scope(tmp_path, node, parent)
        job = job_budget.Job(None, namespace_backend=False)
        job.budget = job_budget.Budget.parse({'pids_max': 1})
        job.scope = scope
        job.record.update(requested=dict(job.budget.controls), required=True)
        try:
            yield job
        finally:
            job.scope = None
            scope.node = scope.parent = None


@pytest.mark.parametrize('phase,stage', [
    pytest.param('fork', stage, id=f'fork-{stage or "normal"}')
    for stage in ('writer', 'lifetime', 'reply', None)
] + [pytest.param('reply-pipe', stage, id=f'pipe-{stage}')
     for stage in ('writer', 'lifetime')])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_startup_failure_retires_sibling_pipes(prepared_job, phase, stage, error_type):
    # A real Scope's directory metadata suffices for this startup primitive.
    # No cgroup admission/control operation, watcher or payload is performed.
    job = prepared_job
    primary = OSError(errno.EAGAIN, 'owned fork refusal')
    secondary = error_type('owned after-close cancellation')
    owned, closes = {}, []

    def remember(fd, role):
        info = os.fstat(fd)
        owned[fd] = (role, info.st_dev, info.st_ino)

    def death_pipe():
        lifetime, writer = spawn.open_death_pipe()
        remember(lifetime, 'lifetime')
        remember(writer, 'writer')
        return lifetime, writer

    def reply_pipe():
        if phase == 'reply-pipe':
            raise primary
        reader, reply = os.pipe()
        remember(reader, 'reader')
        remember(reply, 'reply')
        return reader, reply

    def close(fd):
        role = owned[fd][0]
        os.close(fd)
        closes.append(role)
        if role == stage:
            raise secondary

    def close_writer(fd):
        assert spawn.close_death_w(fd)
        closes.append('writer')
        if stage == 'writer':
            raise secondary

    def fork():
        raise primary

    private_spawn = module_function_view(spawn, bindings={
        'open_death_pipe': death_pipe, 'close_death_w': close_writer,
    })
    parent = module_function_view(package, bindings={'_spawn': private_spawn})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and '_spawn' in fromlist:
            return parent
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(job_budget, bindings={
        '_start_watcher': job_budget.Job._start_watcher,
        'os': module_function_view(os, bindings={'pipe': reply_pipe, 'fork': fork, 'close': close}),
    }, import_hook=imports)
    caught = None
    try:
        try:
            private._start_watcher(job)
        except BaseException as error:
            caught = error
        live = []
        for fd, (role, device, inode) in owned.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                if (info.st_dev, info.st_ino) == (device, inode):
                    live.append(role)
        assert len(owned) == (4 if phase == 'fork' else 2)
        assert not live, f'watcher startup leaked native pipe owners: {live}'
        assert caught is primary
        assert sorted(closes) == (['lifetime', 'reader', 'reply', 'writer']
                                  if phase == 'fork' else ['lifetime', 'writer'])
        assert job.writer is None and job.reader is None and job.watcher is None
    finally:
        # Independent safety net owns only the original pipe identities.
        for fd, (role, device, inode) in owned.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                if role == 'writer' and spawn.close_death_w(fd):
                    continue
                os.close(fd)
