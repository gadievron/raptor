"""Abort ownership through inert process adapters and real owned pipe endpoints."""
import errno
import os
import subprocess

import pytest

from core.sandbox import _macos_spawn as mac
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('fault', ['snapshot', 'grace', 'group', 'kill', 'sweep', 'stdout'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit])
def test_cleanup_cancellation_keeps_primary_and_attempts_remaining_owners(tmp_path, fault, error_type):
    primary = ValueError('owned communication failure')
    run, events, process, cleanup = _driver(tmp_path, primary, fault, error_type)
    try:
        with pytest.raises(ValueError) as raised:
            run()
        assert raised.value is primary
        for label in ('snapshot', 'grace', 'group', 'kill', 'sweep', 'stdout', 'stderr', 'stdin'):
            assert label in events, (label, events)
        assert 'context-exit' not in events
        assert process.stdout is process.stderr is process.stdin is None
        assert any(error_type.__name__ in note for note in primary.__notes__)
        assert primary.sandbox_cleanup_pending is (fault != 'grace')
        if fault == 'grace':
            assert events.count('final') == 1
            assert process.returncode == 0
        if fault == 'stdout':
            assert len(primary.sandbox_pipes) == 1
            assert primary.sandbox_cleanup_pending
    finally:
        cleanup()


def test_unconfirmed_reap_skips_status_read_and_preserves_process(tmp_path):
    primary = subprocess.TimeoutExpired('owned inert command', 1)
    run, events, process, cleanup = _driver(tmp_path, primary, 'unreaped')
    try:
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            run()
        assert raised.value is primary
        assert primary.sandbox_process is process
        assert primary.sandbox_cleanup_pending
        assert events.count('grace') == events.count('final') == 1
        assert 'status-read' not in events
        assert 'context-exit' not in events
        assert all(label in events for label in ('group', 'kill', 'sweep', 'stdout', 'stderr', 'stdin'))
    finally:
        cleanup()


def test_normal_completion_preserves_output_and_status(tmp_path):
    run, events, process, cleanup = _driver(tmp_path, None)
    try:
        result = run()
        assert result.stdout == b'owned output' and result.stderr == b''
        assert result.returncode == 0 and result._setup_status is None
        assert 'status-read' in events
        assert all(label in events for label in ('stdout', 'stderr', 'stdin'))
        assert not any(label in events for label in ('snapshot', 'group', 'kill', 'context-exit'))
    finally:
        cleanup()


def _driver(tmp_path, primary, fault=None, error_type=KeyboardInterrupt):
    events, identities = [], {}

    def record(label):
        events.append(label)
        if fault == label:
            raise error_type('owned ' + label + ' cancellation')

    class Stream:
        closed = False
        def __init__(self, label):
            self.label = label
        def close(self):
            record(self.label)
            self.closed = True

    streams = [Stream(label) for label in ('stdout', 'stderr', 'stdin')]

    class Process:
        pid = 12345  # Inert identity token, never passed to a real OS operation.
        returncode = None
        stdout, stderr, stdin = streams
        def __enter__(self):
            return self
        def __exit__(self, *args):
            events.append('context-exit')
            raise AssertionError('implicit Popen owner must not run')
        def communicate(self, *args, **kwargs):
            if primary is not None:
                raise primary
            self.returncode = 0
            return b'owned output', b''
        def poll(self):
            return self.returncode
        def wait(self, *, timeout):
            assert timeout in (5, 10), 'no unbounded wait belongs to abort cleanup'
            record('grace' if timeout == 5 else 'final')
            if fault == 'unreaped':
                raise subprocess.TimeoutExpired('owned inert command', timeout)
            self.returncode = 0
            return 0
        def kill(self):
            record('kill')

    process = Process()
    pairs = []
    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
        return pair
    def read(fd, count):
        events.append('status-read')
        assert fault != 'unreaped', 'unconfirmed child must not trigger blocking status harvest'
        return os.read(fd, count)
    def launch(command, **kwargs):
        assert mac.SANDBOX_EXEC in command
        os.write(int(kwargs['env']['_RAPTOR_STATUS_FD']), b'K')
        return process
    def forbid(*args, **kwargs):
        pytest.fail('real process, signal, probe or tool action is forbidden')
    def snapshot():
        record('snapshot')
        return []
    def sweep(*args, **kwargs):
        record('sweep')
        return set()
    def killpg(pid, signum):
        assert pid == process.pid and signum == mac.signal.SIGKILL
        record('group')
    private = module_function_view(mac, bindings={
        'os': module_function_view(os, bindings={'pipe': pipe, 'read': read, 'kill': forbid, 'killpg': killpg}),
        'subprocess': module_function_view(subprocess, bindings={'Popen': launch}),
        '_grant_pin_mismatch': lambda *args: None,
        '_ps_snapshot': snapshot, '_sweep_descendants': sweep,
        '_apple_metadata_query': forbid,
    })
    output = tmp_path / 'output'
    output.mkdir()
    def cleanup():
        for stream in streams:
            stream.closed = True
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                if (info.st_dev, info.st_ino) == identity:
                    os.close(fd)
    def run():
        try:
            return private.run_sandboxed(['/bin/true'], env={}, nproc_limit=0,
                                        output=str(output), capture_output=True, timeout=1)
        finally:
            for pair in pairs:
                for fd in pair:
                    with pytest.raises(OSError) as raised:
                        os.fstat(fd)
                    assert raised.value.errno == errno.EBADF
    return run, events, process, cleanup
