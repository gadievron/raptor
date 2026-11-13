"""Readiness resources stay owned until the caller receives a handle."""
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from core.sandbox import supervised as sup
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('stage', ['socket_close', 'pidfd', 'handle'])
def test_cancelled_handoff_retires_supervisor_and_pidfds(stage):
    private, events, primary = _view(stage)
    with pytest.raises(KeyboardInterrupt) as raised:
        private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                  False, False, None)
    assert raised.value is primary
    assert events.count(('kill', 71)) == 1
    assert events.count(('close', 901)) == 1
    assert (('close', 902) in events) == (stage == 'handle')


def test_success_transfers_pidfds_without_retirement():
    private, events, _ = _view(None)
    result = private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                      False, False, None)
    assert result.ns_init_pidfd == 901 and result.pidfd == 902
    assert not any(event[0] in {'kill', 'close'} for event in events)


def test_receive_failure_has_no_duplicate_retirement():
    private, events, primary = _view('receive')
    with pytest.raises(KeyboardInterrupt) as raised:
        private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                  False, False, None)
    assert raised.value is primary
    assert events.count(('kill', 71)) == 1
    assert not any(event[0] == 'close' for event in events)


def _view(stage, cleanup_error=False):
    events = []
    primary = KeyboardInterrupt('owned handoff cancellation')

    class Endpoint:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(('socket', self.name))
            if self.name == 'parent' and stage == 'socket_close':
                raise primary

    parent, child = Endpoint('parent'), Endpoint('supervisor')

    def receive(*args):
        if stage == 'receive':
            events.append(('kill', 71))  # Existing receive owner retires A.
            raise primary
        return 72, 73, 901

    def pidfd_open(pid):
        assert pid == 71
        if stage == 'pidfd':
            raise primary
        return 902

    def handle(**kwargs):
        if stage == 'handle':
            raise primary
        return SimpleNamespace(**kwargs)

    def kill(pid):
        events.append(('kill', pid))
        if cleanup_error:
            raise OSError('owned retirement failure')

    private = module_function_view(sup, bindings={
        '_get_libc': lambda: None, '_DEATH_W_LOCK': nullcontext(),
        'socket': SimpleNamespace(socketpair=lambda *args: (parent, child),
                                  AF_UNIX=1, SOCK_SEQPACKET=5),
        'os': SimpleNamespace(fork=lambda: 71, pidfd_open=pidfd_open,
                              close=lambda fd: events.append(('close', fd))),
        '_recv_ready': receive, 'SupervisedHandle': handle,
        '_kill_and_reap': kill,
    })
    return private, events, primary


def test_cleanup_failure_keeps_cancellation_and_retires_both_pidfds():
    private, events, primary = _view('handle', cleanup_error=True)
    with pytest.raises(KeyboardInterrupt) as raised:
        private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                  False, False, None)
    assert raised.value is primary
    assert events[-3:] == [('kill', 71), ('close', 901), ('close', 902)]
