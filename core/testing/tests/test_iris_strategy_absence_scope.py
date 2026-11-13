"""IRIS strategy import refusals stay local to real validator functions."""
import builtins
from contextlib import nullcontext
import json

import pytest

from core.labeled_attempts import retrieval
from core.run import output
from packages.llm_analysis.tests import test_iris_strategy_wiring as native


@pytest.mark.parametrize('case', ['hypothesis', 'direct'])
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_iris_absence_preserves_importer(tmp_path, case, failure):
    importer = builtins.__import__
    factory = native.module_function_view
    builder = native.dataflow_validation._build_hypothesis
    strategy = native.dataflow_validation._build_strategy_block
    reader = retrieval.retrieve_exemplars
    resolver = output._resolve_active_project
    entered, refused, results = [], [], []

    def checked(module, *, import_hook):
        assert module is native.dataflow_validation

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            if name == 'core.llm.cwe_strategies':
                refused.append(name)
            return import_hook(name, *args, **kwargs)

        view = factory(module, import_hook=observed)
        assert view._build_hypothesis.__code__ is builder.__code__
        assert view._build_strategy_block.__code__ is strategy.__code__
        name = '_build_hypothesis' if case == 'hypothesis' else '_build_strategy_block'
        invoke = getattr(view, name)

        def call(*args, **kwargs):
            result = invoke(*args, **kwargs)
            if case == 'hypothesis':
                assert result.target == tmp_path
                assert 'Bug-class lenses' not in result.context
            else:
                assert result == ''
            results.append(result)
            return result

        setattr(view, name, call)
        entered.append(view)
        return view

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as body:
            native._empty_l3_pool.__wrapped__(body)
            body.setattr(native, 'module_function_view', checked)
            if case == 'hypothesis':
                native.TestRobustness().test_substrate_import_failure_doesnt_break_validator(
                    tmp_path, body,
                )
            else:
                native.TestStrategyBlockDirect().test_returns_empty_when_substrate_missing()
            assert len(entered) == len(results) == 1
            assert refused == ['core.llm.cwe_strategies']
            assert builtins.__import__('json') is json
            if failure:
                raise failure('owned body failure')
    assert native.module_function_view is factory
    assert native.dataflow_validation._build_hypothesis is builder
    assert native._build_hypothesis is builder
    assert native.dataflow_validation._build_strategy_block is strategy
    assert native._build_strategy_block is strategy
    assert retrieval.retrieve_exemplars is reader
    assert output._resolve_active_project is resolver
    assert builtins.__import__ is importer
