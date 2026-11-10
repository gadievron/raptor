"""Status-pipe ownership starts before native descriptor flag operations."""

import errno
import os
import sys

import pytest

from core.sandbox import _spawn as spawn
from core.testing.module_bindings import patch_module_attribute


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux native setup')


@pytest.mark.parametrize('stage,failure_type', [
    ('get-inheritable', OSError), ('set-blocking', OSError),
    ('get-inheritable', KeyboardInterrupt), ('set-blocking', KeyboardInterrupt),
    ('inheritable-guard', RuntimeError),
], ids=['get-io', 'set-io', 'get-interrupt', 'set-interrupt', 'inheritable-refusal'])
def test_status_flag_failure_retires_both_unlaunched_pipe_ends(monkeypatch, stage, failure_type):
    failure = failure_type('owned status flag interruption')
    real_pipe = os.pipe
    identities = {}
    pairs = []
    status_pair = []
    operations = []

    def pipe():
        pair = real_pipe()
        pairs.append(pair)
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
        return pair

    def get_inheritable(fd):
        actual = os.get_inheritable(fd)
        status_pair[:] = next(pair for pair in pairs if pair[1] == fd)
        assert not actual
        if stage == 'inheritable-guard':
            operations.append(stage)
            return True
        if stage == 'get-inheritable':
            operations.append(stage)
            raise failure
        return actual

    def set_blocking(fd, value):
        assert fd == status_pair[0] and value is False
        os.set_blocking(fd, value)
        operations.append(stage)
        raise failure

    def forbid_fork():
        pytest.fail('a descriptor preparation failure must precede child launch')

    try:
        patch_module_attribute(monkeypatch, spawn, 'os', 'pipe', pipe)
        patch_module_attribute(monkeypatch, spawn, 'os', 'get_inheritable', get_inheritable)
        patch_module_attribute(monkeypatch, spawn, 'os', 'set_blocking', set_blocking)
        patch_module_attribute(monkeypatch, spawn, 'os', 'fork', forbid_fork)
        with pytest.raises(failure_type) as caught:
            spawn.run_sandboxed(
                ['/bin/true'], target=None, output=None, block_network=False,
                nproc_limit=0, limits={}, writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None, seccomp_profile=None, seccomp_block_udp=False,
                env={}, cwd=None, timeout=1, capture_output=False)
        if stage == 'inheritable-guard':
            assert 'write-end is inheritable' in str(caught.value)
        else:
            assert caught.value is failure
        assert operations == [stage]
        assert len(status_pair) == 2
        for fd in identities:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
    finally:
        # Only retire native descriptions created by this fixture, even on RED.
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
