"""Marker-cursor fixtures own their lexer namespace through failures."""

import pytest

from core.audit.tests import test_source_view_c_marker_cursors as native
from core.testing.module_views import module_function_view


def fixture_view():
    view = module_function_view(native, bindings={
        "_owned_fixture": native.force_marker_cursors.__wrapped__,
    })
    assert view._owned_fixture.__code__ is native.force_marker_cursors.__wrapped__.__code__
    return view


@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
def test_fixture_restores_binding_and_preserves_cursor_path(error):
    canonical = native.sv
    thresholds = (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER)
    view = fixture_view()
    failure = error("owned cursor fixture body fault") if error else None

    def exercise():
        try:
            with pytest.MonkeyPatch.context() as patch:
                view._owned_fixture(patch)
                assert view.sv is not canonical
                assert (view.sv._C_RANGE_MIN_SOURCE, view.sv._C_RANGE_MIN_CHARS_PER_MARKER) == (0, 1)
                assert view.sv._scan_c_family.__code__ is canonical._scan_c_family.__code__
                assert view.sv._scan_c_family.__globals__ is vars(view.sv)
                assert view.sv._C_IDENTITY_SPECS is canonical._C_IDENTITY_SPECS
                assert (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER) == thresholds
                source = 'leading(); /* hidden_comment */ live_one(); "literal"; live_two();'
                for keep_strings in (False, True):
                    view.test_cached_positions_inside_comments_and_literals(source, keep_strings)
                if failure:
                    raise failure
        finally:
            assert view.sv is canonical and native.sv is canonical
            assert (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER) == thresholds

    if error:
        with pytest.raises(error) as caught:
            exercise()
        assert caught.value is failure
    else:
        exercise()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_publication_fault_restores_binding(after, error):
    canonical = native.sv
    thresholds = (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER)
    view = fixture_view()
    failure = error("owned cursor fixture publication fault")
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
                view._owned_fixture(Publication())
            assert caught.value is failure and reached == [True]
            assert (view.sv is canonical) is (not after)
    finally:
        assert view.sv is canonical and native.sv is canonical
        assert (canonical._C_RANGE_MIN_SOURCE, canonical._C_RANGE_MIN_CHARS_PER_MARKER) == thresholds
