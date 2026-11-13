"""A caller's handled exception is not the backend's cleanup primary."""
import errno
import os
import subprocess

import pytest

from core.sandbox import _macos_spawn as mac
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('ambient', [False, True])
@pytest.mark.parametrize('body_fails', [False, True])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit])
def test_local_failure_context_controls_cleanup(tmp_path, ambient, body_fails, error_type):
    primary = ValueError('owned backend failure') if body_fails else None
    cleanup = error_type('owned death endpoint close cancellation')
    invoke, endpoints, identities = _backend(tmp_path, primary, cleanup)
    try:
        expected = primary if body_fails else cleanup
        with pytest.raises(type(expected)) as raised:
            if ambient:
                try:
                    raise LookupError('unrelated caller exception')
                except LookupError:
                    invoke()
            else:
                invoke()
        assert raised.value is expected
        _assert_retired(endpoints)
    finally:
        _close_remaining(identities)


@pytest.mark.parametrize('ambient', [False, True])
def test_success_remains_success_inside_handled_exception(tmp_path, ambient):
    invoke, endpoints, identities = _backend(tmp_path, None, None)
    try:
        if ambient:
            try:
                raise LookupError('unrelated caller exception')
            except LookupError:
                result = invoke()
        else:
            result = invoke()
        assert result.returncode == 0 and result._setup_status is None
        _assert_retired(endpoints)
    finally:
        _close_remaining(identities)


def _backend(tmp_path, primary, cleanup):
    endpoints, identities, pairs = [], {}, []
    fired = False

    def pipe():
        pair = os.pipe()
        endpoints.extend(pair)
        for fd in pair:
            identities.setdefault(fd, set())
        for fd in pair:
            info = os.fstat(fd)
            identities[fd].add((info.st_dev, info.st_ino))
        pairs.append(pair)
        return pair

    def close(fd):
        nonlocal fired
        os.close(fd)
        if cleanup is not None and len(pairs) > 1 and fd == pairs[1][0] and not fired:
            fired = True
            raise cleanup

    class Process:
        pid = 12345  # Diagnostic token only; no process is started.
        returncode = 0
        stdin = stdout = stderr = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def communicate(self, *args, **kwargs):
            if primary is not None:
                raise primary
            return b'owned output', b''

        def poll(self):
            return self.returncode

        def wait(self, *, timeout):
            assert timeout == 5
            return self.returncode

        def kill(self):
            pass  # Inert completed-process teardown seam.

    def launch(command, **kwargs):
        assert mac.SANDBOX_EXEC in command
        os.write(int(kwargs['env']['_RAPTOR_STATUS_FD']), b'K')
        return Process()

    def forbid(*args, **kwargs):
        pytest.fail('no process, signal or tool query belongs to this test')

    def killpg(pid, signum):
        assert pid == Process.pid and signum == mac.signal.SIGKILL

    private = module_function_view(mac, bindings={
        'os': module_function_view(os, bindings={'pipe': pipe, 'close': close,
                                                'kill': forbid, 'killpg': killpg}),
        'subprocess': module_function_view(subprocess, bindings={'Popen': launch}),
        '_grant_pin_mismatch': lambda *args: None,
        '_ps_snapshot': lambda: [],
        '_sweep_descendants': lambda *args, **kwargs: set(),
        '_apple_metadata_query': forbid,
    })
    output = tmp_path / 'output'
    output.mkdir()
    return (lambda: private.run_sandboxed(['/bin/true'], env={}, nproc_limit=0,
                                         output=str(output), capture_output=True, timeout=1),
            endpoints, identities)


def _assert_retired(endpoints):
    assert len(endpoints) == 4
    for fd in endpoints:
        with pytest.raises(OSError) as raised:
            os.fstat(fd)
        assert raised.value.errno == errno.EBADF


def _close_remaining(identities):
    for fd, identity in identities.items():
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        if not identity or (info.st_dev, info.st_ino) in identity:
            os.close(fd)
