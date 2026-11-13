"""Audit stdin setup must replace inherited input or refuse execution."""
import errno
from types import SimpleNamespace

import pytest

from core.sandbox import _landlock_audit as audit
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('failure', ['open', 'dup2', None, 'fd-zero'])
def test_devnull_redirect_refuses_failures_and_preserves_installed_stdin(failure):
    inherited = object()
    devnull = object()
    descriptors = {0: inherited}
    closed = []
    calls = []
    problem = OSError(errno.EIO, 'owned stdin setup failure')
    number = 0 if failure == 'fd-zero' else 41

    def open_fd(path, flags):
        calls.append('open')
        assert path == '/dev/null' and flags == 0
        if failure == 'open':
            raise problem
        descriptors[number] = devnull
        return number

    def duplicate(fd, destination):
        calls.append('dup2')
        assert fd == number and destination == 0
        if failure == 'dup2':
            raise problem
        descriptors[destination] = descriptors[fd]

    def close(fd):
        closed.append(fd)
        del descriptors[fd]

    original_open, original_dup2, original_close = audit.os.open, audit.os.dup2, audit.os.close
    private = module_function_view(audit, bindings={'os': SimpleNamespace(
        O_RDONLY=0, open=open_fd, dup2=duplicate, close=close)})
    if failure in {'open', 'dup2'}:
        with pytest.raises(OSError) as raised:
            private._redirect_devnull_stdin()
        assert raised.value is problem
        assert descriptors[0] is inherited
        assert closed == ([number] if failure == 'dup2' else [])
    else:
        private._redirect_devnull_stdin()
        assert descriptors[0] is devnull
        assert closed == ([] if number == 0 else [number])
    assert calls[0] == 'open'
    assert (audit.os.open, audit.os.dup2, audit.os.close) == (
        original_open, original_dup2, original_close)
