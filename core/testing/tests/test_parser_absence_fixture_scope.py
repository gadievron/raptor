"""Missing-parser imports are scoped to the actual inventory consumers."""
import builtins
from contextlib import nullcontext

import pytest

from core.inventory.tests import test_ts_cache as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_missing_parser_fixture_restores_consumers_and_caches(failure):
    importer = builtins.__import__
    graph = native.call_graph
    cache = native._ts_cache
    cached = cache.cached_parser
    grammar = cache._GRAMMAR_CACHE
    missing = object()
    parsers = getattr(cache._TS_PARSER_LOCAL, "parsers", missing)
    view = native.module_function_view
    views = []
    refusals = []

    def checked(module, *, bindings=None, import_hook=None):
        assert builtins.__import__ is importer
        assert module in (cache, graph)

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            try:
                return import_hook(name, *args, **kwargs)
            except ImportError as exc:
                assert name == "tree_sitter"
                assert str(exc) == "forced absent: tree_sitter"
                refusals.append(name)
                raise

        private = view(module, bindings=bindings, import_hook=observed)
        if module is graph:
            assert private._get_ts_parser.__code__ is graph._get_ts_parser.__code__
            assert private._ts_cache is views[0]
        else:
            assert private.cached_parser.__code__ is cached.__code__
        views.append(private)
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "module_function_view", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                fresh = native.fresh_caches.__wrapped__(patch)
                native.test_missing_tree_sitter_raises_from_call_graph_seam(fresh, patch)
                assert len(views) == 2
                assert refusals == ["tree_sitter"]
                assert cache._TS_PARSER_LOCAL.parsers == {}
                assert builtins.__import__ is importer
                if failure:
                    raise failure("owned body failure")
        assert native.call_graph is graph
        assert cache.cached_parser is cached
        assert cache._GRAMMAR_CACHE is grammar
        assert getattr(cache._TS_PARSER_LOCAL, "parsers", missing) is parsers
    assert native.module_function_view is view
    assert builtins.__import__ is importer
