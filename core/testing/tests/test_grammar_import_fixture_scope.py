"""Grammar import fakes belong only to the actual shared inventory cache."""
from contextlib import nullcontext
import importlib
import json

import pytest

from core.inventory.tests import test_ts_cache as native


@pytest.mark.parametrize("method", [
    "test_failed_import_runs_import_machinery_once",
    "test_extractors_loader_inherits_the_failure_cache",
    "test_extractors_parser_path_inherits_the_failure_cache",
    "test_call_graph_loader_shares_the_same_cache",
    "test_success_is_cached_and_absence_is_not_sticky",
])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_grammar_fixture_restores_cache_importer(method, caplog, failure):
    importer = importlib.import_module
    namespace = native._ts_cache.importlib
    grammar = native._ts_cache._GRAMMAR_CACHE
    missing = object()
    parsers = getattr(native._ts_cache._TS_PARSER_LOCAL, "parsers", missing)
    runtime = native.extractors._TS_AVAILABLE
    helper = native.patch_module_attribute
    entered, imports = [], []

    def checked(patch, module, binding, name, value):
        assert module is native._ts_cache
        assert (binding, name) == ("importlib", "import_module")

        def observed(name, *args, **kwargs):
            imports.append(name)
            return value(name, *args, **kwargs)

        private = helper(patch, module, binding, name, observed)
        entered.append(private)
        assert importlib.import_module is importer
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "patch_module_attribute", checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                fresh = native.fresh_caches.__wrapped__(body)
                if method == "test_success_is_cached_and_absence_is_not_sticky":
                    getattr(native, method)(fresh, body)
                else:
                    counter = native.import_counter.__wrapped__(body)
                    if method == "test_failed_import_runs_import_machinery_once":
                        getattr(native, method)(fresh, counter, caplog)
                    else:
                        gate = native.runtime_gate_open.__wrapped__(body)
                        getattr(native, method)(fresh, counter, gate)
                assert len(entered) == len(imports) == 1
                assert imports[0].startswith("tree_sitter_")
                assert importlib.import_module("json") is json
                assert len(imports) == 1
                if failure:
                    raise failure("owned body failure")
        assert native._ts_cache.importlib is namespace
        assert importlib.import_module is importer
        assert native._ts_cache._GRAMMAR_CACHE is grammar
        assert getattr(native._ts_cache._TS_PARSER_LOCAL, "parsers", missing) is parsers
        assert native.extractors._TS_AVAILABLE is runtime
    assert native.patch_module_attribute is helper
