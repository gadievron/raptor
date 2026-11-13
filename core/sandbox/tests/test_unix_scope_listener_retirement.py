"""Late notification calls cannot touch a retired listener's reused number."""
import os
import threading

import pytest

from core.sandbox import _unix_scope as scope
from core.testing.module_bindings import patch_module_attribute
from core.testing.pipes import pipes_for_setup


@pytest.mark.parametrize('operation', ['respond', 'valid'])
@pytest.mark.parametrize('cancel_close', [False, True])
def test_retired_listener_does_not_ioctl_replacement(request, monkeypatch, operation, cancel_close):
    with pipes_for_setup(2) as pairs:
        (notify, writer), (replacement, replacement_writer) = pairs
        owned = {notify, writer, replacement, replacement_writer}
        request.addfinalizer(lambda: _close_owned(owned))
    supervisor = _supervisor(notify)
    calls = []

    class CancelledEvent:
        def set(self):
            raise KeyboardInterrupt('owned close cancellation')

    def ioctl(fd, command, argument):
        # This is a private recorder, never a seccomp/kernel operation.
        assert os.fstat(fd).st_ino == os.fstat(replacement).st_ino
        calls.append((fd, command))
        return 0

    patch_module_attribute(monkeypatch, scope, 'fcntl', 'ioctl', ioctl)
    try:
        if cancel_close:
            supervisor._closed = CancelledEvent()
            with pytest.raises(KeyboardInterrupt):
                supervisor.close()
        else:
            supervisor.close()
        assert supervisor._owns_fd is False
        os.dup2(replacement, notify, inheritable=False)
        if operation == 'respond':
            supervisor._respond(7, 0)
        else:
            assert supervisor._id_valid(7) is False
        assert calls == []
        assert os.fstat(notify).st_ino == os.fstat(replacement).st_ino
    finally:
        _close_owned(owned)


@pytest.mark.parametrize('operation', ['respond', 'valid'])
@pytest.mark.parametrize('fails', [False, True])
def test_owned_listener_still_performs_ioctl(monkeypatch, operation, fails):
    supervisor = _supervisor(71)  # Inert token; no real descriptor involved.
    calls = []

    def ioctl(fd, command, argument):
        calls.append((fd, command))
        if fails:
            raise OSError('owned ioctl refusal')
        return 0

    patch_module_attribute(monkeypatch, scope, 'fcntl', 'ioctl', ioctl)
    if operation == 'respond':
        supervisor._respond(7, 0)
        assert calls == [(71, scope._IOCTL_NOTIF_SEND)]
    else:
        assert supervisor._id_valid(7) is (not fails)
        assert calls == [(71, scope._IOCTL_NOTIF_ID_VALID)]


def _supervisor(fd):
    # Skip constructor capability predicates; only lifecycle-owned state.
    supervisor = object.__new__(scope.UnixScopeSupervisor)
    supervisor._fd = fd
    supervisor._owns_fd = True
    supervisor._close_lock = threading.RLock()
    supervisor._closed = threading.Event()
    return supervisor


def _close_owned(owned):
    while owned:
        fd = owned.pop()
        try:
            os.close(fd)
        except OSError:
            pass
