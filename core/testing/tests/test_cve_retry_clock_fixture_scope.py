"""CVE unit retry fixtures preserve borrowed clocks and the real retry loop."""

import ast
from pathlib import Path
import time
from types import ModuleType
from unittest.mock import Mock

import pytest

from cve_diff.llm import client
from core.testing.module_bindings import patch_module_attribute


_CONFTEST = (Path(__file__).resolve().parents[3]
             / 'packages/cve_diff/tests/unit/conftest.py')


def _apply_native_fixtures(monkeypatch):
    tree = ast.parse(_CONFTEST.read_text())
    fixtures = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name in ('_no_real_retry_backoff', '_no_retry_backoff_sleep')]
    assert fixtures, 'native retry fixture disappeared'
    for function in fixtures:
        function.decorator_list = []
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(_CONFTEST), 'exec'), namespace)
        namespace[function.name](monkeypatch)


@pytest.mark.parametrize('borrowed_kind', ['shared', 'private'])
@pytest.mark.parametrize('exit_kind', ['normal', 'error', 'interrupt'])
def test_native_fixture_restores_clock_identity(borrowed_kind, exit_kind):
    original_sleep = time.sleep
    original_monotonic = time.monotonic
    with pytest.MonkeyPatch.context() as owner:
        if borrowed_kind == 'private':
            borrowed = ModuleType('caller_clock')
            vars(borrowed).update(vars(time))
            borrowed.sleep = Mock(name='caller_sleep')
            owner.setattr(client, 'time', borrowed)
        borrowed = client.time
        borrowed_sleep = borrowed.sleep
        failure = {'normal': None, 'error': RuntimeError, 'interrupt': KeyboardInterrupt}[exit_kind]
        try:
            with pytest.MonkeyPatch.context() as scope:
                _apply_native_fixtures(scope)
                assert time.sleep is original_sleep
                assert borrowed.sleep is borrowed_sleep
                assert client.time is not borrowed
                assert client.time.sleep(16) is None
                assert client.time.monotonic is original_monotonic
                if failure:
                    raise failure('injected unwind')
        except (RuntimeError, KeyboardInterrupt) as error:
            assert type(error) is failure
        finally:
            assert client.time is borrowed
            assert borrowed.sleep is borrowed_sleep
            assert time.sleep is original_sleep


@pytest.mark.parametrize('max_retries', [0, 1, 3])
@pytest.mark.parametrize('hard_failure', [False, True])
def test_native_fixture_preserves_retry_schedule(max_retries, hard_failure):
    provider = Mock()
    provider.generate.side_effect = (RuntimeError('401 authentication_error')
                                     if hard_failure else TimeoutError('timed out'))
    instance = client.ResilientLLMClient(max_retries=max_retries, backoff_factor=2)
    sleeps = []
    with pytest.MonkeyPatch.context() as scope:
        _apply_native_fixtures(scope)
        skipped_sleep = client.time.sleep

        def record(delay):
            sleeps.append(delay)
            return skipped_sleep(delay)

        patch_module_attribute(scope, client, 'time', 'sleep', record)
        scope.setattr(instance, '_get_provider', lambda _model: provider)
        with pytest.raises(client.LLMCallFailed):
            instance.complete('fixture-model', 'fixture prompt')
    attempts = 1 if hard_failure else max_retries + 1
    assert provider.generate.call_count == attempts
    assert sleeps == [2 ** attempt for attempt in range(1, attempts)]
