"""Ready receive cancellation retains supervisor cleanup ownership."""
from types import SimpleNamespace
import array
import socket

import pytest

from core.sandbox import supervised as sup
from core.sandbox.errors import SandboxSetupError
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('stage', ['timeout_setup', 'receive', 'parse'])
@pytest.mark.parametrize('death_w', [None, 81])
def test_cancellation_retires_supervisor_once(stage, death_w):
    primary = KeyboardInterrupt('owned startup cancellation')
    private, transport, events = _view(stage, primary)
    with pytest.raises(KeyboardInterrupt) as raised:
        private._recv_ready(transport, 71, death_w)
    assert raised.value is primary
    assert events == [('kill', 71), *([('death', 81)] if death_w else []),
                      *([('close', 77)] if stage == 'parse' else [])]


@pytest.mark.parametrize('message,reap', [(b'', True), (b'fail U refused', True),
                                         (b'bad ready', False)])
def test_existing_refusals_retire_once(message, reap):
    private, transport, events = _view(None, None, message=message)
    with pytest.raises(SandboxSetupError):
        private._recv_ready(transport, 71, 81)
    assert events == [('wait' if reap else 'kill', 71), ('death', 81), ('close', 77)]


def test_success_transfers_received_descriptor_without_retirement():
    private, transport, events = _view(None, None)
    assert private._recv_ready(transport, 71, None) == (72, 73, 77)
    assert events == []


def test_cleanup_failure_preserves_cancellation_and_attempts_other_owners():
    primary = KeyboardInterrupt('owned cancellation')
    private, transport, events = _view('parse', primary, cleanup_error=True)
    with pytest.raises(KeyboardInterrupt) as raised:
        private._recv_ready(transport, 71, 81)
    assert raised.value is primary
    assert events == [('kill', 71), ('death', 81), ('close', 77)]


def _view(stage, primary, *, message=b'ok pidns 72 73', cleanup_error=False):
    events = []

    class CancelledMessage(bytes):
        def decode(self, *args):
            raise primary

    class Transport:
        def settimeout(self, timeout):
            assert timeout == sup._READY_DEADLINE_S
            if stage == 'timeout_setup':
                raise primary

        def recvmsg(self, size, ancillary_size):
            assert size == 512 and ancillary_size > 0
            if stage == 'receive':
                raise primary
            frame = CancelledMessage(message) if stage == 'parse' else message
            return frame, [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array('i', [77]).tobytes())], 0, None

    def kill(pid):
        events.append(('kill', pid))
        if cleanup_error:
            raise OSError('owned cleanup failure')

    private = module_function_view(sup, bindings={
        '_kill_and_reap': kill,
        'close_death_w': lambda fd: events.append(('death', fd)),
        'os': SimpleNamespace(waitpid=lambda pid, flags: events.append(('wait', pid)),
                              close=lambda fd: events.append(('close', fd))),
    })
    return private, Transport(), events
