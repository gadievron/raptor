"""Explicit stderr sources retain their pre-redirection identity."""
from types import SimpleNamespace
import subprocess

import pytest

from core.sandbox import _stdio
from core.testing.module_views import module_function_view


class StdoutFile:
    def __init__(self):
        self.lookups = 0

    def fileno(self):
        self.lookups += 1
        return 1


@pytest.mark.parametrize('mode', ['devnull', 'capture', 'swap', 'merge', 'unchanged', 'file'])
def test_source_identity_survives_stdout_change(mode):
    descriptors = {0: 'input', 1: 'original stdout', 2: 'original stderr',
                   31: 'devnull', 32: 'stdout capture'}
    closed, duplicates = [], []
    file = StdoutFile()
    stdout = 2 if mode == 'swap' else None if mode == 'unchanged' else subprocess.DEVNULL
    stderr = subprocess.STDOUT if mode == 'merge' else file if mode == 'file' else 1
    capture = mode == 'capture'

    def duplicate(source, operation, minimum):
        assert source == 1 and operation == 99 and minimum == 3
        duplicates.append(source)
        descriptors[41] = descriptors[source]
        return 41

    def close(fd):
        closed.append(fd)
        del descriptors[fd]

    private = module_function_view(_stdio, bindings={
        'os': SimpleNamespace(close=close),
        'fcntl': SimpleNamespace(fcntl=duplicate, F_DUPFD_CLOEXEC=99),
    })
    with private.preserve_output_sources(stdout, stderr, capture_stdout=capture,
                                         capture_stderr=False) as (out_source, err_source):
        # Model the two existing native-loop dup2 operations in their order.
        if capture:
            descriptors[1] = descriptors[32]
        elif out_source == subprocess.DEVNULL:
            descriptors[1] = descriptors[31]
        elif out_source is not None:
            descriptors[1] = descriptors[out_source]
        if err_source == subprocess.STDOUT:
            descriptors[2] = descriptors[1]
        else:
            source = err_source if isinstance(err_source, int) else err_source.fileno()
            descriptors[2] = descriptors[source]
        if mode == 'merge':
            assert descriptors[2] == 'devnull'
        else:
            assert descriptors[2] == 'original stdout'
        if mode == 'swap':
            assert descriptors[1] == 'original stderr'
    needed = mode not in {'merge', 'unchanged'}
    assert duplicates == ([1] if needed else [])
    assert closed == ([41] if needed else [])
    assert 41 not in descriptors
    if mode == 'file':
        assert file.lookups == 1


@pytest.mark.parametrize('failure', ['duplicate', 'body', 'close'])
def test_temporary_source_is_owned_on_success_and_failure(failure):
    closed = []
    primary = ValueError('owned redirect failure')
    secondary = OSError('owned close failure')

    def duplicate(*args):
        if failure == 'duplicate':
            raise primary
        return 41

    def close(fd):
        assert fd == 41
        closed.append(fd)
        raise secondary

    private = module_function_view(_stdio, bindings={
        'os': SimpleNamespace(close=close),
        'fcntl': SimpleNamespace(fcntl=duplicate, F_DUPFD_CLOEXEC=99),
    })
    expected = secondary if failure == 'close' else primary
    with pytest.raises(type(expected)) as raised:
        with private.preserve_output_sources(subprocess.DEVNULL, 1,
                                             capture_stdout=False, capture_stderr=False):
            if failure == 'body':
                raise primary
    assert raised.value is expected
    assert closed == ([] if failure == 'duplicate' else [41])


def test_captured_stderr_does_not_consult_unused_file_object():
    file = StdoutFile()
    private = module_function_view(_stdio, bindings={
        'fcntl': SimpleNamespace(fcntl=lambda *a: pytest.fail('unneeded duplicate')),
    })
    with private.preserve_output_sources(subprocess.DEVNULL, file,
                                         capture_stdout=False, capture_stderr=True) as sources:
        assert sources == (subprocess.DEVNULL, file)
    assert file.lookups == 0


def test_unchanged_explicit_stdout_needs_no_temporary_descriptor():
    file = StdoutFile()
    private = module_function_view(_stdio, bindings={
        'fcntl': SimpleNamespace(fcntl=lambda *a: pytest.fail('unneeded duplicate')),
    })
    with private.preserve_output_sources(file, 1, capture_stdout=False,
                                         capture_stderr=False) as sources:
        assert sources == (1, 1)
    assert file.lookups == 1


@pytest.mark.parametrize('primary_kind', [ValueError, KeyboardInterrupt], ids=['error', 'interrupt'])
def test_cleanup_interrupt_does_not_replace_active_failure(primary_kind):
    primary = primary_kind('primary redirect failure')
    cleanup = KeyboardInterrupt('cleanup interruption')
    closed = []

    def close(fd):
        closed.append(fd)
        raise cleanup

    private = module_function_view(_stdio, bindings={
        'os': SimpleNamespace(close=close),
        'fcntl': SimpleNamespace(fcntl=lambda *args: 41, F_DUPFD_CLOEXEC=99),
    })
    caught = None
    try:
        with private.preserve_output_sources(subprocess.DEVNULL, 1,
                                             capture_stdout=False, capture_stderr=False):
            raise primary
    except BaseException as error:
        caught = error
    assert caught is primary
    assert caught.__cause__ is cleanup
    assert closed == [41]
