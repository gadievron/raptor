"""Devnull setup preserves standard descriptors across descriptor reuse."""
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn as spawn
from core.testing.module_views import module_function_view


def redirect_view(destination, *, alias, failure=None):
    sink = object()
    source = destination if alias else 31
    descriptors, inheritable, closed = {}, {}, []
    problem = OSError('owned redirect failure')
    flags = 0 if destination == 0 else 1

    def open_fd(path, mode):
        assert path == '/dev/null' and mode == flags
        if failure == 'open':
            raise problem
        descriptors[source] = sink
        inheritable[source] = False
        return source

    def duplicate(fd, target):
        assert fd == source and target == destination
        if failure in {'dup2', 'dup2-close'}:
            raise problem
        descriptors[target] = descriptors[fd]
        inheritable[target] = True

    def set_inheritable(fd, value):
        assert fd == destination and value is True
        if failure == 'inheritable':
            raise problem
        inheritable[fd] = value

    def close(fd):
        closed.append(fd)
        del descriptors[fd]
        del inheritable[fd]
        if failure in {'close', 'dup2-close'}:
            raise problem if failure == 'close' else OSError('secondary close failure')

    private = module_function_view(spawn, bindings={'os': SimpleNamespace(
        open=open_fd, dup2=duplicate, close=close, set_inheritable=set_inheritable)})
    return private, flags, sink, descriptors, inheritable, closed, problem


@pytest.mark.parametrize('destination', [0, 1, 2], ids=['stdin', 'stdout', 'stderr'])
@pytest.mark.parametrize('alias', [False, True], ids=['separate', 'reused'])
def test_installed_standard_descriptor_remains_open_and_inheritable(destination, alias):
    private, flags, sink, descriptors, inheritable, closed, _ = redirect_view(
        destination, alias=alias)
    borrowed = (spawn.os.open, spawn.os.dup2, spawn.os.close, spawn.os.set_inheritable)
    private._redirect_devnull(destination, flags)
    assert descriptors == {destination: sink}
    assert inheritable == {destination: True}
    assert closed == ([] if alias else [31])
    assert borrowed == (spawn.os.open, spawn.os.dup2, spawn.os.close, spawn.os.set_inheritable)


@pytest.mark.parametrize('failure', ['open', 'dup2', 'inheritable', 'close', 'dup2-close'])
def test_setup_failure_propagates_to_existing_child_guard(failure):
    private, flags, _, _, _, closed, problem = redirect_view(
        0, alias=failure == 'inheritable', failure=failure)
    with pytest.raises(OSError) as raised:
        private._redirect_devnull(0, flags)
    assert raised.value is problem
    assert closed == ([31] if failure in {'dup2', 'close', 'dup2-close'} else [])
