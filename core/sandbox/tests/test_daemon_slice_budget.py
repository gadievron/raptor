"""Compute slices admit selected length before copying a capture prefix."""

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("kind", [bytes, str])
def test_partial_slice_refuses_before_copying_operator(kind):
    copied = []

    class Captured(kind):
        def __getitem__(self, key):
            copied.append(key)
            raise AssertionError("oversized partial slice reached copying operator")

    source = b"ABCDE" if kind is bytes else "ABCDE"
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    with pytest.raises(ValueError, match="byte budget"):
        private._safe_eval("raw[1:-1]", {"raw": Captured(source)})
    assert copied == []


@pytest.mark.parametrize("source", [b"ABCDE", "Aé界DE"])
@pytest.mark.parametrize("selection", [slice(None, 2), slice(None, None, 3), slice(-2, None),
                                      slice(4, 0, -3), slice(10, 20), slice(None, None, -3),
                                      slice(1, 1), slice(1, 4, 2)])
def test_admitted_slices_match_builtin(source, selection):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    result = private._safe_eval("raw[start:stop:step]", {
        "raw": source, "start": selection.start, "stop": selection.stop, "step": selection.step,
    })
    assert result == source[selection]


@pytest.mark.parametrize("expression,error", [("raw[::0]", ValueError),
                                               ("raw[::'x']", TypeError),
                                               ("raw[1.5:]", TypeError)])
def test_invalid_slice_parameters_keep_builtin_error(expression, error):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    with pytest.raises(error):
        private._safe_eval(expression, {"raw": b"ABCDE"})


def test_scalar_indexing_remains_available():
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    assert private._safe_eval("raw[-1]", {"raw": b"ABCDE"}) == ord("E")
