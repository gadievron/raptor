"""Missing prompt-strategy fixtures refuse imports only in their consumer."""
import builtins
from contextlib import nullcontext
import json

import pytest

from packages.llm_analysis.tests import test_strategy_in_analysis_prompt as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_strategy_absence_preserves_importer(failure):
    importer = builtins.__import__
    builder = native.analysis.build_analysis_prompt_bundle
    strategy = native.analysis._build_strategy_block
    factory = native.module_function_view
    entered, refused, results = [], [], []

    def checked(module, *, import_hook):
        assert module is native.analysis

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            if name == 'core.llm.cwe_strategies':
                refused.append(name)
            return import_hook(name, *args, **kwargs)

        view = factory(module, import_hook=observed)
        invoke = view.build_analysis_prompt_bundle
        assert invoke.__code__ is builder.__code__
        assert view._build_strategy_block.__code__ is strategy.__code__

        def build(*args, **kwargs):
            bundle = invoke(*args, **kwargs)
            system = native._system_message(bundle)
            assert 'ASSUME-EXPLOIT' in system
            assert 'Bug-class lenses' not in system
            results.append(bundle)
            return bundle

        view.build_analysis_prompt_bundle = build
        entered.append(view)
        return view

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as body:
            body.setattr(native, 'module_function_view', checked)
            native.TestRobustness().test_substrate_missing_doesnt_break(body)
            assert len(entered) == len(results) == 1
            assert refused == ['core.llm.cwe_strategies']
            assert builtins.__import__('json') is json
            if failure:
                raise failure('owned body failure')
    assert native.module_function_view is factory
    assert native.analysis.build_analysis_prompt_bundle is builder
    assert native.build_analysis_prompt_bundle is builder
    assert native.analysis._build_strategy_block is strategy
    assert builtins.__import__ is importer
