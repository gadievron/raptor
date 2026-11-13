"""Parent status integrity with owned pipes and a nonexecuting launch seam."""
import errno
import os
import subprocess

import pytest

from core.sandbox import _macos_spawn as mac
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX status pipes')


@pytest.mark.parametrize('payload, fault, category', [
    pytest.param(b'K', 'io', 'B', id='ready-then-error'),
    pytest.param(b'', 'io', 'B', id='error-without-ready'),
    pytest.param(b'KP', 'io', 'P', id='known-tamper-preserved'),
    pytest.param(b'K?', 'io', 'B', id='unknown-bytes-preserved'),
    pytest.param(b'K', 'interrupt', None, id='interrupt-then-ready'),
    pytest.param(b'K', None, None, id='clean-ready'),
])
def test_parent_refuses_incomplete_status_after_read_error(tmp_path, payload, fault, category):
    endpoints, identities, status, reads, launches = [], {}, {}, [], []

    def pipe():
        pair = os.pipe()
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
            endpoints.append(fd)
        return pair

    def read(fd, size):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == status.get('identity'):
            reads.append(True)
            if fault == 'interrupt' and len(reads) == 1:
                raise InterruptedError(errno.EINTR, 'owned interrupted status read')
            if fault == 'io' and (not payload or len(reads) > 1):
                raise OSError(errno.EIO, 'owned incomplete status')
        return os.read(fd, size)

    class Process:
        pid = 12345  # Diagnostic only; every process/signal seam is inert.
        returncode = 0
        stdin = stdout = stderr = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def communicate(self, *args, **kwargs):
            return b'owned output', b''

        def poll(self):
            return self.returncode

    def launch(command, **kwargs):
        assert mac.SANDBOX_EXEC in command
        launches.append(True)
        fd = int(kwargs['env']['_RAPTOR_STATUS_FD'])
        info = os.fstat(fd)
        status['identity'] = (info.st_dev, info.st_ino)
        if payload:
            os.write(fd, payload)
        return Process()

    def forbid(*args, **kwargs):
        pytest.fail('status test must not query tools, launch or signal processes')

    private = module_function_view(mac, bindings={
        'os': module_function_view(os, bindings={'pipe': pipe, 'read': read,
                                                'kill': forbid, 'killpg': forbid}),
        'subprocess': module_function_view(subprocess, bindings={'Popen': launch}),
        '_grant_pin_mismatch': lambda *args: None,
        '_ps_snapshot': lambda: [],
        '_sweep_descendants': lambda *args, **kwargs: set(),
        '_apple_metadata_query': forbid,
    })
    output = tmp_path / 'output'
    output.mkdir()
    try:
        result = private.run_sandboxed(['/bin/true'], env={}, nproc_limit=0,
                                      output=str(output), capture_output=True, timeout=1)
        actual = result._setup_status
        if category is None:
            assert actual is None
        else:
            assert actual is not None and actual[0] == category
        assert launches == [True] and reads
        for fd in endpoints:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
