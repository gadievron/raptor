"""Independent ASAN runtime prerequisites never certify sandbox outcomes."""
from types import SimpleNamespace
import subprocess

import pytest

from core.testing import asan


@pytest.fixture(autouse=True)
def clear_probe_cache():
    probe = asan._runtime_unavailable_reason
    probe.cache_clear()
    yield
    probe.cache_clear()


@pytest.mark.parametrize('mode', ['healthy', 'hang', 'compile-failure', 'startup-failure', 'no-main-marker'])
def test_clean_runtime_probe_checks_execution_and_is_cached(monkeypatch, mode):
    from core.config import RaptorConfig
    calls = []
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', lambda: {'PATH': '/usr/bin:/bin'})
    def run(command, **kwargs):
        calls.append(command)
        assert kwargs['cwd'] == '/'
        assert kwargs['env']['ASAN_OPTIONS'] == 'detect_leaks=0:symbolize=0:abort_on_error=0'
        if len(calls) == 1:
            assert command[:5] == ['/usr/bin/c++', '-fsanitize=address', '-x', 'c++', '-']
            assert kwargs['input'] == asan._CLEAN_SOURCE
            return SimpleNamespace(returncode=1 if mode == 'compile-failure' else 0)
        if mode == 'hang':
            raise subprocess.TimeoutExpired(command, 5)
        return SimpleNamespace(returncode=1 if mode == 'startup-failure' else 0,
                               stdout='' if mode == 'no-main-marker' else 'raptor-asan-main\n')
    monkeypatch.setattr(subprocess, 'run', run)
    reason = asan._runtime_unavailable_reason('/usr/bin/c++')
    assert (reason is None) == (mode == 'healthy')
    assert asan._runtime_unavailable_reason('/usr/bin/c++') == reason
    assert len(calls) == (1 if mode == 'compile-failure' else 2)


def test_unusable_runtime_is_a_prerequisite_skip(monkeypatch):
    from packages.autonomous import exploit_validator
    import sys
    monkeypatch.setattr(exploit_validator, '_detect_cxx_compiler', lambda: sys.executable)
    monkeypatch.setattr(asan, '_runtime_unavailable_reason', lambda compiler: 'clean ASAN probe timed out')
    with pytest.raises(pytest.skip.Exception, match='ASAN runtime prerequisite:.*timed out'):
        asan.require_asan_runtime()
