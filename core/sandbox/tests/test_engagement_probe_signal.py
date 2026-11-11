"""Engagement cache tests with a nonexecuting completed-result adapter."""

from collections import deque
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.config import RaptorConfig
from core.sandbox import probes
from core.testing.module_bindings import patch_module_attribute

FLAGS = ('--user', '--pid', '--fork')


@pytest.fixture
def transport(monkeypatch):
    results, calls = deque(), []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        value = results.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    patch_module_attribute(monkeypatch, probes, 'subprocess', 'run', run)
    patch_module_attribute(monkeypatch, probes, 'state', '_unshare_engage_cache', {})
    monkeypatch.setattr(probes, '_resolve_sandbox_binary', lambda name: '/owned/unshare')
    monkeypatch.setattr(probes, 'Path', lambda value: SimpleNamespace(exists=lambda: True))
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', lambda: {'OWNED': 'probe-control'})
    return SimpleNamespace(results=results, calls=calls, cache=probes.state._unshare_engage_cache)


def result(returncode, stderr=b''):
    return subprocess.CompletedProcess(['owned-probe'], returncode, b'', stderr)


@pytest.mark.parametrize('signal_number', [2, 9, 15])
def test_signal_termination_is_inconclusive_and_allows_a_healthy_retry(transport, signal_number):
    transport.results.extend([result(-signal_number), result(0)])
    verdict, reason = probes.check_unshare_engages(FLAGS)
    assert verdict is None
    assert str(signal_number) in reason
    assert FLAGS not in transport.cache
    assert probes.check_unshare_engages(FLAGS) == (True, '')
    assert transport.cache[FLAGS] == (True, '')
    assert len(transport.calls) == 2
    for cmd, kwargs in transport.calls:
        assert cmd == ['/owned/unshare', *FLAGS, '--', '/usr/bin/true']
        assert kwargs == {'capture_output': True, 'timeout': 5,
                          'env': {'OWNED': 'probe-control'}}


@pytest.mark.parametrize('returncode', [1, 2])
def test_ordinary_refusal_remains_cached(transport, returncode):
    transport.results.append(result(returncode, b'owned refusal'))
    assert probes.check_unshare_engages(FLAGS) == (False, 'owned refusal')
    assert probes.check_unshare_engages(FLAGS) == (False, 'owned refusal')
    assert len(transport.calls) == 1


def test_success_remains_cached(transport):
    transport.results.append(result(0))
    assert probes.check_unshare_engages(FLAGS) == (True, '')
    assert probes.check_unshare_engages(FLAGS) == (True, '')
    assert len(transport.calls) == 1


@pytest.mark.parametrize('failure', [subprocess.TimeoutExpired('owned-probe', 5),
                                    OSError('owned transport failure')])
def test_transport_failure_remains_uncached(transport, failure):
    transport.results.extend([failure, result(0)])
    assert probes.check_unshare_engages(FLAGS)[0] is None
    assert FLAGS not in transport.cache
    assert probes.check_unshare_engages(FLAGS) == (True, '')
    assert len(transport.calls) == 2


def test_missing_binary_remains_a_cached_refusal(transport, monkeypatch):
    resolve = Mock(side_effect=FileNotFoundError('owned missing probe'))
    monkeypatch.setattr(probes, '_resolve_sandbox_binary', resolve)
    assert probes.check_unshare_engages(FLAGS)[0] is False
    assert probes.check_unshare_engages(FLAGS)[0] is False
    assert resolve.call_count == 1
    assert transport.calls == []


def test_signal_result_does_not_replace_another_flagsets_verdict(transport):
    other = ('--user', '--net')
    transport.cache[other] = (False, 'owned different flagset refusal')
    transport.results.append(result(-9))
    assert probes.check_unshare_engages(FLAGS)[0] is None
    assert transport.cache == {other: (False, 'owned different flagset refusal')}
