"""Independent ASAN runtime prerequisites never certify sandbox outcomes."""
from types import SimpleNamespace
import subprocess

import pytest

from core.testing import asan


@pytest.fixture(autouse=True)
def clear_probe_cache(monkeypatch):
    from functools import lru_cache
    borrowed = asan._runtime_unavailable_reason
    fresh = lru_cache(**borrowed.cache_parameters())(borrowed.__wrapped__)
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(asan, {"_runtime_unavailable_reason": fresh}):
        try:
            yield
        finally:
            monkeypatch.undo()


@pytest.mark.parametrize('mode', ['healthy', 'hang', 'compile-hang', 'compile-failure', 'startup-failure', 'no-main-marker'])
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
            if mode == 'compile-hang':
                raise subprocess.TimeoutExpired(command, 15)
            return SimpleNamespace(returncode=1 if mode == 'compile-failure' else 0)
        if mode == 'hang':
            raise subprocess.TimeoutExpired(command, 5)
        return SimpleNamespace(returncode=1 if mode == 'startup-failure' else 0,
                               stdout='' if mode == 'no-main-marker' else 'raptor-asan-main\n')
    monkeypatch.setattr(subprocess, 'run', run)
    reason = asan._runtime_unavailable_reason('/usr/bin/c++')
    assert (reason is None) == (mode == 'healthy')
    assert asan._runtime_unavailable_reason('/usr/bin/c++') == reason
    assert len(calls) == (1 if mode in ('compile-failure', 'compile-hang') else 2)
    if mode == 'compile-hang':
        assert 'compilation timed out' in reason


def test_unusable_runtime_is_a_prerequisite_skip(monkeypatch):
    from packages.autonomous import exploit_validator
    import sys
    monkeypatch.setattr(exploit_validator, '_detect_cxx_compiler', lambda: sys.executable)
    monkeypatch.setattr(asan, '_runtime_unavailable_reason', lambda compiler: 'clean ASAN probe timed out')
    with pytest.raises(pytest.skip.Exception, match='ASAN runtime prerequisite:.*timed out'):
        asan.require_asan_runtime()


@pytest.mark.parametrize('reason,has_hint', [
    ('clean ASAN probe timed out before successful completion', True),
    ('clean ASAN probe did not complete normally (exit -9)', True),
    ('clean ASAN probe compilation timed out', False),
    ('clean ASAN probe did not compile (exit 1)', False),
], ids=['startup-timeout', 'startup-exit', 'compile-timeout', 'compile-error'])
def test_macos_runtime_skip_explains_selected_toolchain(monkeypatch, reason, has_hint):
    import sys
    from packages.autonomous import exploit_validator
    monkeypatch.setattr(exploit_validator, '_detect_cxx_compiler', lambda: sys.executable)
    monkeypatch.setattr(asan, '_runtime_unavailable_reason', lambda compiler: reason)
    monkeypatch.setattr(sys, 'platform', 'darwin')
    with pytest.raises(pytest.skip.Exception) as skipped:
        asan.require_asan_runtime()
    message = str(skipped.value)
    assert 'compiler:' in message
    assert ('xcode-select -p' in message) == has_hint
    assert ('DEVELOPER_DIR' in message) == has_hint
