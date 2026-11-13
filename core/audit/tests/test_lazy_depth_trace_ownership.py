"""Lazy-depth memory proofs retire tracing inside their existing cache owner."""

from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_return_domain_lazy_depth as native
from core.testing.module_views import module_function_view


@contextmanager
def cache_owner():
    domain, constants = native.rd._DOMAIN_CACHE, native.rd._CONSTANTS_CACHE
    lock = native.rd._DOMAIN_CACHE_LOCK
    old_domain, old_constants = dict(domain), dict(constants)
    try:
        with contextmanager(native.clear_return_domain_caches.__wrapped__)():
            assert native.rd._DOMAIN_CACHE is not domain
            assert native.rd._CONSTANTS_CACHE is not constants
            assert native.rd._DOMAIN_CACHE_LOCK is lock
            yield
    finally:
        assert native.rd._DOMAIN_CACHE is domain and native.rd._CONSTANTS_CACHE is constants
        assert native.rd._DOMAIN_CACHE_LOCK is lock
        assert domain == old_domain and constants == old_constants
        assert all(domain[key] is value for key, value in old_domain.items())
        assert all(constants[key] is value for key, value in old_constants.items())


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_lazy_depth_start_fault_retires_owned_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    original = tracemalloc.start
    failure = error("owned lazy depth trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    view = module_function_view(native, bindings={"tracemalloc": trace})
    assert view.test_definitionless_conditional_file_avoids_dense_depth_table.__code__ is native.test_definitionless_conditional_file_avoids_dense_depth_table.__code__
    try:
        with cache_owner():
            with pytest.raises(error) as caught:
                view.test_definitionless_conditional_file_avoids_dense_depth_table(tmp_path)
            assert caught.value is failure and reached == [after]
            assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_lazy_depth_scan_fault_preserves_real_warmup_and_cache_owner(error, tmp_path):
    assert not tracemalloc.is_tracing()
    canonical = native.rd
    original_scan, original_clear = canonical._constants_for_root, canonical.clear_cache
    producer = ModuleType("return_domain")
    vars(producer).update(vars(canonical))
    failure = error("owned lazy depth measured scan fault")
    reached = []

    def scan(root, budget):
        assert root == tmp_path and type(budget) is canonical._Budget
        assert (root / "a.c").read_text() == "#if defined(FEATURE)\nint ordinary;\n#endif\n" * 30000
        reached.append(("scan", tracemalloc.is_tracing()))
        if len(reached) == 1:
            assert reached == [("scan", False)]
            result = original_scan(root, budget)
            assert result == {} and str(root) in canonical._CONSTANTS_CACHE
            return result
        assert reached == [("scan", False), ("clear", False), ("scan", True)]
        assert not canonical._CONSTANTS_CACHE
        raise failure

    def clear():
        assert not tracemalloc.is_tracing() and str(tmp_path) in canonical._CONSTANTS_CACHE
        reached.append(("clear", False))
        original_clear()
        assert not canonical._DOMAIN_CACHE and not canonical._CONSTANTS_CACHE

    producer._constants_for_root = scan
    producer.clear_cache = clear
    view = module_function_view(native, bindings={"rd": producer})
    try:
        with cache_owner():
            with pytest.raises(error) as caught:
                view.test_definitionless_conditional_file_avoids_dense_depth_table(tmp_path)
            assert caught.value is failure
            assert reached == [("scan", False), ("clear", False), ("scan", True)]
            assert not tracemalloc.is_tracing()
        assert native.rd is canonical
        assert canonical._constants_for_root is original_scan and canonical.clear_cache is original_clear
    finally:
        tracemalloc.stop()


def test_lazy_depth_borrowed_trace_skip_preserves_session_and_owned_cache(tmp_path):
    assert not tracemalloc.is_tracing()
    try:
        with cache_owner():
            tracemalloc.start(25)
            retained = bytearray(8192)
            provenance = tracemalloc.get_object_traceback(retained)
            peak = tracemalloc.get_traced_memory()[1]
            assert provenance is not None
            with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
                native.test_definitionless_conditional_file_avoids_dense_depth_table(tmp_path)
            assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
            assert tracemalloc.get_object_traceback(retained) == provenance
            assert tracemalloc.get_traced_memory()[1] >= peak
            assert not native.rd._DOMAIN_CACHE and not native.rd._CONSTANTS_CACHE
            assert list(tmp_path.iterdir()) == []
    finally:
        tracemalloc.stop()
