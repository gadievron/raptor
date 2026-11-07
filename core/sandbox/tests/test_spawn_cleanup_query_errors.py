"""Metadata and grace-wait errors cannot skip safe direct-child cleanup."""
import errno
import os
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import _spawn as spawn


from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('operation', ['getpgid', 'getpgrp'])
def test_group_query_failure_still_kills_and_reaps_child(monkeypatch, operation):
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    groups = Mock()
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(spawn.os, operation, Mock(side_effect=OSError(errno.EIO, 'query failed')))
            patch_module_attribute(scoped, spawn, 'os', 'killpg', groups)
            spawn._kill_and_reap(process.pid)
        groups.assert_not_called()
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
    finally:
        process.kill()
        process.wait(timeout=5)


@pytest.mark.parametrize('stage', ['grace', 'tracer'])
@pytest.mark.parametrize('error', [InterruptedError(), OSError(errno.EIO, 'wait failed')])
def test_wait_error_does_not_skip_reaping(monkeypatch, stage, error):
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    read_fd, write_fd = spawn.open_death_pipe()
    parent_fds = {write_fd}
    operation = 'waitid' if stage == 'grace' else 'waitpid'
    original = getattr(os, operation)
    calls = []

    def wait(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise error
        return original(*args, **kwargs)

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(spawn.os, operation, wait)
            if stage == 'grace':
                spawn._teardown_target(process.pid, write_fd, parent_fds, grace_s=0.02)
            else:
                spawn._reap_tracer(process.pid, timeout_s=0.02)
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        assert len(calls) >= 2
    finally:
        os.close(read_fd)
        spawn.close_death_w(write_fd)
        process.kill()
        process.wait(timeout=5)
