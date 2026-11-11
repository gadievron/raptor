"""Interrupted fresh-proc probes retain the existing uncached, fail-visible result."""

from collections import deque
import subprocess
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from core.sandbox import probes
from core.testing.module_bindings import patch_module_attribute


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
    patch_module_attribute(monkeypatch, probes, 'state', '_pidns_fresh_proc_cache', None)
    monkeypatch.setattr(probes, '_find_sandbox_binary', lambda name: '/owned/unshare')
    monkeypatch.setattr(probes, 'Path', lambda value: SimpleNamespace(exists=lambda: True))
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', lambda: {'OWNED': 'fresh-proc-control'})
    return SimpleNamespace(results=results, calls=calls)


def result(returncode):
    return subprocess.CompletedProcess(['owned-probe'], returncode, b'', b'owned diagnostic')


@pytest.mark.parametrize('signal_number', [2, 9, 15])
@pytest.mark.parametrize('stage', ['mount', 'control'])
def test_interrupted_stage_stays_uncached_and_allows_a_healthy_retry(
    transport, stage, signal_number,
):
    if stage == 'control':
        transport.results.append(result(1))
    transport.results.extend([result(-signal_number), result(0)])
    assert probes.check_pidns_fresh_proc_available() is True
    assert probes.state._pidns_fresh_proc_cache is None
    interrupted_calls = 1 if stage == 'mount' else 2
    assert len(transport.calls) == interrupted_calls
    assert probes.check_pidns_fresh_proc_available() is True
    assert probes.state._pidns_fresh_proc_cache is True
    assert len(transport.calls) == interrupted_calls + 1
    for _cmd, kwargs in transport.calls:
        assert kwargs == {'capture_output': True, 'timeout': 5,
                          'env': {'OWNED': 'fresh-proc-control'}}


@pytest.mark.parametrize('codes,expected', [([0], True), ([1, 0], False), ([1, 1], True)],
                         ids=['mount-works', 'mount-refused', 'namespaces-refused'])
def test_determinate_results_keep_their_existing_cache_policy(transport, codes, expected):
    transport.results.extend(map(result, codes))
    assert probes.check_pidns_fresh_proc_available() is expected
    assert probes.state._pidns_fresh_proc_cache is expected
    assert probes.check_pidns_fresh_proc_available() is expected
    assert len(transport.calls) == len(codes)


@pytest.mark.parametrize('failure', [subprocess.TimeoutExpired('owned-probe', 5),
                                    OSError('owned transport failure')])
def test_transport_failure_keeps_the_existing_uncached_result(transport, failure):
    transport.results.extend([failure, result(0)])
    assert probes.check_pidns_fresh_proc_available() is True
    assert probes.state._pidns_fresh_proc_cache is None
    assert probes.check_pidns_fresh_proc_available() is True
    assert probes.state._pidns_fresh_proc_cache is True
    assert len(transport.calls) == 2


def test_missing_binary_keeps_the_existing_cached_result(transport, monkeypatch):
    monkeypatch.setattr(probes, '_find_sandbox_binary', lambda name: None)
    assert probes.check_pidns_fresh_proc_available() is True
    assert probes.state._pidns_fresh_proc_cache is True
    assert transport.calls == []
