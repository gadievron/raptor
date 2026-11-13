"""Short-string probe modes own their lexer bindings and allocation tracer."""

from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
import tracemalloc

import pytest

from core.audit.tests import test_source_view_c_short_strings as native
from core.testing.module_views import module_function_view


@contextmanager
def owned_case(mode, **bindings):
    canonical = native.sv
    thresholds = (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER)
    view = module_function_view(native, bindings={
        "_owned_fixture": native.string_probe_mode.__wrapped__, **bindings,
    })
    assert view._owned_fixture.__code__ is native.string_probe_mode.__wrapped__.__code__
    try:
        with pytest.MonkeyPatch.context() as patch:
            view._owned_fixture(SimpleNamespace(param=mode), patch)
            assert view.sv is not canonical
            expected = (0, 1) if mode == "probe" else thresholds
            assert (view.sv._C_RANGE_MIN_SOURCE, view.sv._C_RANGE_MIN_CHARS_PER_MARKER) == expected
            assert view.sv._scan_c_family.__code__ is canonical._scan_c_family.__code__
            assert view.sv._scan_c_family.__globals__ is vars(view.sv)
            assert view.sv._C_IDENTITY_SPECS is canonical._C_IDENTITY_SPECS
            yield view
    finally:
        assert view.sv is canonical and native.sv is canonical
        assert (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER) == thresholds


@pytest.mark.parametrize("mode", ["normal", "probe"])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
def test_actual_fixture_restores_binding_and_preserves_lexer(mode, error):
    failure = error("owned probe body fault") if error else None

    def exercise():
        with owned_case(mode) as view:
            result = view.sv.sanitized_view_with_status('before(); "short"; live();', "a.c")
            assert result.text == 'before(); "     "; live();'
            assert not result.ambiguous
            if failure:
                raise failure
    if error:
        with pytest.raises(error) as caught:
            exercise()
        assert caught.value is failure
    else:
        exercise()


@pytest.mark.parametrize("mode", ["normal", "probe"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_fixture_publication_fault_restores_binding(mode, after, error):
    canonical = native.sv
    thresholds = (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER)
    view = module_function_view(native, bindings={"_owned_fixture": native.string_probe_mode.__wrapped__})
    failure = error("owned probe publication fault")
    reached = []
    try:
        with pytest.MonkeyPatch.context() as patch:
            class Publication:
                def setitem(self, mapping, key, value):
                    assert mapping is vars(view) and key == "sv"
                    assert value is not canonical
                    reached.append(True)
                    if after:
                        patch.setitem(mapping, key, value)
                    raise failure

            with pytest.raises(error) as caught:
                view._owned_fixture(SimpleNamespace(param=mode), Publication())
            assert caught.value is failure and reached == [True]
            assert (view.sv is canonical) is (not after)
    finally:
        assert view.sv is canonical and native.sv is canonical
        assert (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER) == thresholds


@pytest.mark.parametrize("mode", ["normal", "probe"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(mode, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned short string trace startup fault")
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
    try:
        with owned_case(mode, tracemalloc=trace) as view:
            with pytest.raises(error) as caught:
                view.test_long_escaped_literals_keep_probe_workspace_bounded()
            assert caught.value is failure and reached == [after]
            assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("mode", ["normal", "probe"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_renderer_fault_retires_owned_trace(mode, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned short string renderer fault")
    reached = []

    def fail(source, filename):
        assert tracemalloc.is_tracing() and filename == "a.c"
        assert source == 'before(); "' + "\\n" * 50000 + '"; live();'
        reached.append(True)
        raise failure

    try:
        with owned_case(mode) as view:
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(view.sv, "sanitized_view_with_status", fail)
                with pytest.raises(error) as caught:
                    view.test_long_escaped_literals_keep_probe_workspace_bounded()
                assert caught.value is failure and reached == [True]
                assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("mode", ["normal", "probe"])
def test_borrowed_trace_skip_preserves_session(mode):
    assert not tracemalloc.is_tracing()
    try:
        with owned_case(mode) as view:
            tracemalloc.start(25)
            retained = bytearray(8192)
            provenance = tracemalloc.get_object_traceback(retained)
            peak = tracemalloc.get_traced_memory()[1]
            assert provenance is not None
            with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
                view.test_long_escaped_literals_keep_probe_workspace_bounded()
            assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
            assert tracemalloc.get_object_traceback(retained) == provenance
            assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
