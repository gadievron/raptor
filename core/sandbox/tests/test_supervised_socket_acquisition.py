"""Failed supervisor acquisition releases both owned socket endpoints."""
from contextlib import nullcontext
from types import SimpleNamespace
import socket

import pytest

from core.sandbox import supervised as sup
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('stage', ['death_pipe', 'fork'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_failed_acquisition_closes_pair_with_traceback_retained(stage, error_type):
    endpoints = []
    primary = error_type('owned acquisition failure')

    def socketpair(*args):
        pair = socket.socketpair(*args)
        endpoints.extend(pair)
        return pair

    def fail():
        raise primary

    private = module_function_view(sup, bindings={
        '_get_libc': lambda: None,
        '_DEATH_W_LOCK': nullcontext(),
        'open_death_pipe': fail,
        'os': SimpleNamespace(fork=fail),
        'socket': SimpleNamespace(socketpair=socketpair, AF_UNIX=socket.AF_UNIX,
                                  SOCK_SEQPACKET=socket.SOCK_SEQPACKET),
    })
    try:
        with pytest.raises(error_type) as raised:
            private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                      False, stage == 'death_pipe', None)
        assert raised.value is primary
        assert primary.__traceback__ is not None
        assert len(endpoints) == 2
        assert [endpoint.fileno() for endpoint in endpoints] == [-1, -1]
    finally:
        # Own fixture resources even when the pre-fix regression fails.
        for endpoint in endpoints:
            endpoint.close()


def test_successful_parent_handoff_closes_pair_without_starting_process():
    endpoints = []
    sentinel = object()

    def socketpair(*args):
        pair = socket.socketpair(*args)
        endpoints.extend(pair)
        return pair

    def ready(parent, pid, death):
        assert parent is endpoints[0] and parent.fileno() >= 0
        assert endpoints[1].fileno() == -1
        assert pid == 71 and death is None
        return 72, 73, 901

    def no_pidfd(pid):
        assert pid == 71
        raise OSError('inert pidfd refusal')

    def handle(**kwargs):
        assert kwargs['pid'] == 71 and kwargs['target_pid'] == 73
        assert kwargs['ns_init_pidfd'] == 901 and kwargs['death_w'] is None
        return sentinel

    private = module_function_view(sup, bindings={
        '_get_libc': lambda: None, '_DEATH_W_LOCK': nullcontext(),
        '_recv_ready': ready, 'SupervisedHandle': handle,
        'os': SimpleNamespace(fork=lambda: 71, pidfd_open=no_pidfd),
        'socket': SimpleNamespace(socketpair=socketpair, AF_UNIX=socket.AF_UNIX,
                                  SOCK_SEQPACKET=socket.SOCK_SEQPACKET),
    })
    try:
        assert private._spawn_pidns_tier(['owned-target'], {}, None, None, None,
                                        False, False, None) is sentinel
        assert [endpoint.fileno() for endpoint in endpoints] == [-1, -1]
    finally:
        for endpoint in endpoints:
            endpoint.close()
