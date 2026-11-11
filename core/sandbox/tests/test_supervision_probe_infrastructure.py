"""Parent probe-result decoding with a nonexecuting wait-status adapter."""

from collections import deque
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import probes
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux probe protocol')


@pytest.fixture
def transport(monkeypatch):
    statuses, fork_effects, calls = deque(), deque(), []

    def forbidden(*args, **kwargs):
        raise AssertionError('child operation must not run')

    def fork():
        calls.append('fork-adapter')
        if fork_effects:
            effect = fork_effects.popleft()
            if isinstance(effect, BaseException):
                raise effect
        return 43001

    def waitpid(pid, options):
        assert (pid, options) == (43001, 0)
        calls.append('wait-adapter')
        status = statuses.popleft()
        if isinstance(status, BaseException):
            raise status
        return pid, status

    for name in ('unshare', 'pidfd_open', '_exit', 'open', 'write', 'close'):
        patch_module_attribute(monkeypatch, probes, 'os', name, forbidden, raising=False)
    patch_module_attribute(monkeypatch, probes, 'os', 'fork', fork)
    patch_module_attribute(monkeypatch, probes, 'os', 'waitpid', waitpid)
    patch_module_attribute(monkeypatch, probes, 'os', 'getuid', lambda: 1000)
    patch_module_attribute(monkeypatch, probes, 'os', 'getgid', lambda: 1000)
    patch_module_attribute(monkeypatch, probes, 'state', '_pidns_supervision_cache', None)
    return SimpleNamespace(statuses=statuses, fork_effects=fork_effects, calls=calls)


@pytest.mark.parametrize('code,expected', [
    (0, True), (190, False), (191, False), (192, None),
    (193, False), (194, None), (195, False), (196, None),
], ids=['engaged', 'permission-refusal', 'unsupported', 'unexpected-unshare',
        'self-map-refusal', 'fork-pressure', 'wrong-namespace', 'abnormal-child'])
def test_existing_probe_status_cache_policy(transport, code, expected):
    transport.statuses.extend([code << 8, 0])
    first = probes.check_pidns_supervision_available()
    assert first[0] is expected
    assert bool(first[1]) is (expected is not True)
    if expected is None:
        assert probes.state._pidns_supervision_cache is None
        assert probes.check_pidns_supervision_available() == (True, '')
        assert transport.calls.count('fork-adapter') == 2
    else:
        assert probes.state._pidns_supervision_cache == first
        assert probes.check_pidns_supervision_available() == first
        assert transport.calls.count('fork-adapter') == 1


def test_signal_death_remains_inconclusive(transport):
    transport.statuses.extend([9, 0])
    verdict, reason = probes.check_pidns_supervision_available()
    assert verdict is None and 'signal 9' in reason
    assert probes.state._pidns_supervision_cache is None
    assert probes.check_pidns_supervision_available() == (True, '')
    assert transport.calls.count('fork-adapter') == 2


def test_fork_transport_failure_remains_inconclusive(transport):
    transport.fork_effects.append(OSError('owned fork adapter failure'))
    transport.statuses.append(0)
    assert probes.check_pidns_supervision_available()[0] is None
    assert probes.state._pidns_supervision_cache is None
    assert probes.check_pidns_supervision_available() == (True, '')
    assert transport.calls.count('fork-adapter') == 2
    assert transport.calls.count('wait-adapter') == 1


def test_reaped_status_remains_inconclusive(transport):
    transport.statuses.extend([ChildProcessError('owned wait adapter failure'), 0])
    assert probes.check_pidns_supervision_available()[0] is None
    assert probes.state._pidns_supervision_cache is None
    assert probes.check_pidns_supervision_available() == (True, '')
    assert transport.calls.count('fork-adapter') == 2
