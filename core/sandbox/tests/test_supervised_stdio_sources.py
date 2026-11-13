"""Target stdio identity and ownership through a private descriptor model."""
from types import SimpleNamespace

import pytest

from core.sandbox import _stdio
from core.sandbox import supervised as sup
from core.testing.module_views import module_function_view


class TargetExit(BaseException):
    pass


@pytest.mark.parametrize('outputs,expected,flags', [
    ((2, 1), ('stderr', 'stdout'), (True, True)),
    ((31, 1), ('file out', 'stdout'), (True, True)),
    ((1, None), ('stdout', 'stderr'), (True, False)),
    ((None, 2), ('stdout', 'stderr'), (False, True)),
    ((31, 32), ('file out', 'file err'), (True, True)),
    ((None, None), ('stdout', 'stderr'), (False, False)),
])
def test_target_preserves_output_sources(outputs, expected, flags):
    state = _drive_target(outputs)
    assert state.snapshot == (expected, flags)
    assert state.closed == ([97, 41] if outputs[1] == 1 else [97])
    assert state.writes == [(97, b'-1\n'), (98, b'execvpe returned')]


@pytest.mark.parametrize('failure', ['duplicate', 'inherit', 'dup2', 'close', 'interrupt'])
def test_target_reports_redirect_failure_without_exec(failure):
    outputs = (1, None) if failure == 'inherit' else (2, 1)
    state = _drive_target(outputs, failure)
    assert state.snapshot is None
    assert state.writes[0] == (97, b'-1\n')
    assert state.writes[-1][0] == 98
    assert b'errno 5' in state.writes[-1][1] if failure != 'interrupt' else (
        state.writes[-1][1] == b'KeyboardInterrupt before exec'
    )
    assert 1 not in state.closed and 2 not in state.closed
    if failure in {'dup2', 'close', 'interrupt'}:
        assert state.closed.count(41) == 1


def _drive_target(outputs, failure=None):
    descriptors = {0: 'input', 1: 'stdout', 2: 'stderr', 31: 'file out',
                   32: 'file err', 97: 'report', 98: 'status'}
    inheritable = dict.fromkeys(descriptors, False)
    state = SimpleNamespace(snapshot=None, closed=[], writes=[])

    def fail():
        raise OSError(5, 'owned redirect failure')

    def duplicate(source, operation, minimum):
        assert (source, operation, minimum) == (1, 99, 3)
        if failure == 'duplicate':
            fail()
        assert 41 not in descriptors
        descriptors[41] = descriptors[source]
        inheritable[41] = False
        return 41

    def close(fd):
        assert fd in {41, 97}
        state.closed.append(fd)
        del descriptors[fd]
        if fd == 41 and failure == 'close':
            fail()
        if fd == 41 and failure == 'interrupt':
            raise KeyboardInterrupt

    def set_inheritable(fd, value):
        assert fd in {1, 2} and value is True
        if failure == 'inherit':
            fail()
        inheritable[fd] = value

    def dup2(source, destination):
        assert destination in {1, 2}
        if failure == 'dup2':
            fail()
        descriptors[destination] = descriptors[source]
        if source != destination:
            inheritable[destination] = True

    def write(fd, frame):
        assert fd in descriptors
        state.writes.append((fd, frame))
        return len(frame)

    def readlink(path):
        assert path == '/proc/self'
        return '-1'

    def execvpe(command, argv, env):
        assert (command, argv, env) == ('owned-target', ['owned-target'], {})
        assert 41 not in descriptors and 97 not in descriptors
        assert descriptors[98] == 'status'
        state.snapshot = ((descriptors[1], descriptors[2]),
                          (inheritable[1], inheritable[2]))

    def exit_target(code):
        assert code == sup._TARGET_EXEC_FAILED_EXIT
        raise TargetExit

    private_os = SimpleNamespace(close=close, set_inheritable=set_inheritable,
                                 dup2=dup2, write=write, readlink=readlink,
                                 execvpe=execvpe, _exit=exit_target)
    private_stdio = module_function_view(_stdio, bindings={
        'os': private_os,
        'fcntl': SimpleNamespace(fcntl=duplicate, F_DUPFD_CLOEXEC=99),
    })
    private = module_function_view(sup, bindings={
        'os': private_os,
        '_preserve_output_sources': private_stdio.preserve_output_sources,
    })
    target = private._make_target_exec(['owned-target'], {}, None, *outputs, 97, 98)
    with pytest.raises(TargetExit):
        target()
    return state
