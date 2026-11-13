"""Explicit stdin retains its original source and standard output owners."""
from types import SimpleNamespace

import pytest

from core.sandbox import _stdio
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('filelike', [False, True], ids=['integer', 'file'])
@pytest.mark.parametrize('source', [0, 1, 2], ids=['stdin', 'stdout', 'stderr'])
@pytest.mark.parametrize('changed_output', [False, True], ids=['inherited', 'redirected'])
def test_stdin_identity_and_exec_inheritability(source, changed_output, filelike):
    original = {0: 'input', 1: 'original stdout', 2: 'original stderr'}
    descriptors = dict(original)
    inheritable = {0: False, 1: True, 2: True}
    closed, duplicated = [], []

    def duplicate(fd, operation, minimum):
        assert fd == source and fd in (1, 2) and operation == 99 and minimum == 3
        duplicated.append(fd)
        descriptors[41] = descriptors[fd]
        inheritable[41] = False
        return 41

    def close(fd):
        closed.append(fd)
        del descriptors[fd]
        del inheritable[fd]

    def inherit(fd, enabled):
        assert fd == 0 and enabled is True
        inheritable[fd] = enabled

    lookups = []

    class InputFile:
        def fileno(self):
            lookups.append(source)
            return source

    supplied = InputFile() if filelike else source
    private = module_function_view(_stdio, bindings={
        'os': SimpleNamespace(close=close, set_inheritable=inherit),
        'fcntl': SimpleNamespace(fcntl=duplicate, F_DUPFD_CLOEXEC=99),
    })
    with private.preserve_stdin_source(supplied) as (stdin_source, owned):
        if changed_output:
            descriptors[1] = 'new stdout'
            descriptors[2] = 'new stderr'
        # The native input mapping runs after output mapping. The context
        # owns its temporary; the native branch must not retire it twice.
        if stdin_source != 0:
            descriptors[0] = descriptors[stdin_source]
            inheritable[0] = True
        if stdin_source != 0 and stdin_source != owned:
            close(stdin_source)
        assert descriptors[0] == original[source]
        assert inheritable[0] is True
    assert descriptors[1] == ('new stdout' if changed_output else original[1])
    assert descriptors[2] == ('new stderr' if changed_output else original[2])
    assert duplicated == ([source] if source else [])
    assert closed == ([41] if source else [])
    assert 41 not in descriptors
    assert lookups == ([source] if filelike else [])


@pytest.mark.parametrize('stdin', [None, -1, -3], ids=['default', 'pipe', 'devnull'])
def test_sentinel_input_needs_no_descriptor_copy(stdin):
    private = module_function_view(_stdio, bindings={
        'fcntl': SimpleNamespace(fcntl=lambda *a: pytest.fail('unexpected copy')),
    })
    with private.preserve_stdin_source(stdin) as sources:
        assert sources == (stdin, None)


@pytest.mark.parametrize('kind', [AttributeError, OSError, ValueError])
def test_file_lookup_preserves_fallback_and_refusal_behavior(kind):
    problem = kind('owned fileno failure')

    class InputFile:
        def fileno(self):
            raise problem

    if kind is ValueError:
        with pytest.raises(ValueError) as caught:
            with _stdio.preserve_stdin_source(InputFile()):
                pytest.fail('must not reach setup after invalid fileno')
        assert caught.value is problem
    else:
        with _stdio.preserve_stdin_source(InputFile()) as sources:
            assert sources == (-3, None)


def test_fd_zero_inheritability_failure_refuses_setup():
    problem = OSError('owned inheritability failure')

    def refused(fd, value):
        assert fd == 0 and value is True
        raise problem

    private = module_function_view(_stdio, bindings={'os': SimpleNamespace(set_inheritable=refused)})
    with pytest.raises(OSError) as caught:
        with private.preserve_stdin_source(0):
            pytest.fail('inheritability failure must not proceed')
    assert caught.value is problem


def test_input_temporary_is_retired_when_setup_is_interrupted():
    closed = []
    private = module_function_view(_stdio, bindings={
        'os': SimpleNamespace(close=closed.append),
        'fcntl': SimpleNamespace(fcntl=lambda *a: 41, F_DUPFD_CLOEXEC=99),
    })
    problem = KeyboardInterrupt('owned setup interruption')
    with pytest.raises(KeyboardInterrupt) as caught:
        with private.preserve_stdin_source(1) as sources:
            assert sources == (41, 41)
            raise problem
    assert caught.value is problem
    assert closed == [41]
