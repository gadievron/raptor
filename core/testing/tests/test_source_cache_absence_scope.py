"""Optional cache import refusals leave the inherited importer untouched."""
import builtins
from contextlib import nullcontext
import importlib
import json

import pytest

from packages.source_intel.tests import test_cache_invalidation as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_cache_absence_restores_state(tmp_path, failure):
    importer = builtins.__import__
    clear = native.source_intel.clear_all_source_intel_caches
    factory = native.module_function_view
    analyze = importlib.import_module('packages.source_intel.analyze')
    inject = importlib.import_module('packages.llm_analysis.source_intel_inject')
    inventory = analyze._INVENTORY_BY_TARGET
    result_cache = inject._SI_RESULT_CACHE
    inventory_contents, result_contents = inventory.copy(), result_cache.copy()
    alias = native._INVENTORY_BY_TARGET
    entered, refused = [], []

    def checked(module, *, import_hook):
        assert module is native.source_intel

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            if name == 'packages.llm_analysis.source_intel_inject':
                refused.append(name)
            return import_hook(name, *args, **kwargs)

        view = factory(module, import_hook=observed)
        assert view.clear_all_source_intel_caches.__code__ is clear.__code__
        entered.append(view)
        return view

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'module_function_view', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                state = native._reset_caches.__wrapped__(body)
                next(state)
                try:
                    native.test_clear_all_safe_when_inject_module_unavailable(tmp_path)
                    assert not analyze._INVENTORY_BY_TARGET
                    assert builtins.__import__('json') is json
                    assert len(entered) == 1
                    assert refused == ['packages.llm_analysis.source_intel_inject']
                    if failure:
                        raise failure('owned body failure')
                finally:
                    body.undo()
                    state.close()
        assert analyze._INVENTORY_BY_TARGET is inventory
        assert inventory == inventory_contents
        assert inject._SI_RESULT_CACHE is result_cache
        assert result_cache == result_contents
        assert native._INVENTORY_BY_TARGET is alias
        assert native.source_intel.clear_all_source_intel_caches is clear
        assert builtins.__import__ is importer
    assert native.module_function_view is factory
