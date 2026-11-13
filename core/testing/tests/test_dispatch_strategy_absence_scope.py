"""Trace and hunt absence fixtures own only their prompt function imports."""
import builtins
from contextlib import nullcontext
import json

import pytest

from packages.code_understanding.tests.dispatch import test_hunt_strategy_wiring as hunt
from packages.code_understanding.tests.dispatch import test_trace_strategy_wiring as trace


@pytest.mark.parametrize('native', [hunt, trace], ids=['hunt', 'trace'])
@pytest.mark.parametrize('case', ['message', 'direct'])
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_dispatch_absence_preserves_importer(native, case, failure):
    importer = builtins.__import__
    factory = native.module_function_view
    message = native.dispatch._format_user_message
    strategy_name = '_build_hunt_strategy_block' if native is hunt else '_build_strategy_block'
    strategy = getattr(native.dispatch, strategy_name)
    entered, refused, results = [], [], []

    def checked(module, *, import_hook):
        assert module is native.dispatch

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            if name == 'core.llm.cwe_strategies':
                refused.append(name)
            return import_hook(name, *args, **kwargs)

        view = factory(module, import_hook=observed)
        assert view._format_user_message.__code__ is message.__code__
        assert getattr(view, strategy_name).__code__ is strategy.__code__
        selected = '_format_user_message' if case == 'message' else strategy_name
        invoke = getattr(view, selected)

        def call(*args, **kwargs):
            result = invoke(*args, **kwargs)
            if case == 'message':
                kind = 'hunt-pattern' if native is hunt else 'flow-traces'
                assert f'kind="{kind}"' in result
                assert '</untrusted-' in result
                assert 'Bug-class lenses' not in result
            else:
                assert result == ''
            results.append(result)
            return result

        setattr(view, selected, call)
        entered.append(view)
        return view

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as body:
            body.setattr(native, 'module_function_view', checked)
            if case == 'message':
                native.TestRobustness().test_substrate_import_failure_returns_base_message()
            else:
                native.TestStrategyBlockDirect().test_returns_empty_when_substrate_missing()
            assert len(entered) == len(results) == 1
            assert refused == ['core.llm.cwe_strategies']
            assert builtins.__import__('json') is json
            if failure:
                raise failure('owned body failure')
    assert native.module_function_view is factory
    assert native.dispatch._format_user_message is message
    assert native._format_user_message is message
    assert getattr(native.dispatch, strategy_name) is strategy
    assert getattr(native, strategy_name) is strategy
    assert builtins.__import__ is importer
