"""Constant metadata memory fixtures own partial allocation tracing."""

from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_constant_enum_lazy_coordinates as enums
from core.audit.tests import test_constant_lazy_file_metadata as metadata
from core.testing.module_views import module_function_view

CASES = {
    "enum": (enums, "test_implicit_only_file_avoids_unused_coordinate_tables"),
    "metadata": (metadata, "test_conditional_file_without_definitions_avoids_dense_metadata"),
}


def case_view(case, **bindings):
    module, name = CASES[case]
    view = module_function_view(module, bindings=bindings)
    invoke = getattr(view, name)
    assert invoke.__code__ is getattr(module, name).__code__
    return invoke


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(case, after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    module, _ = CASES[case]
    failure = error("owned constant metadata trace startup fault")
    original = tracemalloc.start
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    invoke = case_view(case, tracemalloc=trace)
    try:
        with pytest.raises(error) as caught:
            invoke(tmp_path)
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and module.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_scan_fault_after_real_warmup_retires_trace(case, error, tmp_path):
    assert not tracemalloc.is_tracing()
    module, _ = CASES[case]
    failure = error("owned constant metadata scan fault")
    canonical = module.cr
    original = canonical._scan_definitions
    producer = ModuleType("constant_resolution")
    vars(producer).update(vars(canonical))
    reached = []

    def scan(root):
        assert root == tmp_path
        text = (root / "a.c").read_text()
        if case == "enum":
            assert text == "#if defined(FEATURE)\nenum state { READY, RUNNING, DONE };\n#endif\n" * 20000
        else:
            assert text == "/* define */\n" + "#ifdef FEATURE\nint ordinary;\n#endif\n" * 30000
        reached.append(tracemalloc.is_tracing())
        if len(reached) == 1:
            assert reached == [False]
            result = original(root)
            assert result == {}
            return result
        assert reached == [False, True]
        raise failure

    producer._scan_definitions = scan
    invoke = case_view(case, cr=producer)
    try:
        with pytest.raises(error) as caught:
            invoke(tmp_path)
        assert caught.value is failure and reached == [False, True]
        assert not tracemalloc.is_tracing()
        assert module.cr is canonical and canonical._scan_definitions is original
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
def test_borrowed_trace_skip_preserves_session(case, tmp_path):
    assert not tracemalloc.is_tracing()
    module, name = CASES[case]
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
            getattr(module, name)(tmp_path)
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
        assert list(tmp_path.iterdir()) == []
    finally:
        tracemalloc.stop()
