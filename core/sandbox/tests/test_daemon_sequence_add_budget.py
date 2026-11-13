"""Sequence addition admits output size before allocating its concatenation."""

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("kind", [bytes, str])
def test_over_budget_addition_refuses_before_operator(kind):
    additions = []

    class Captured(kind):
        def __add__(self, other):
            additions.append(len(self) + len(other))
            raise AssertionError("oversized sequence addition reached operator")

    source = b"AB" if kind is bytes else "AB"
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    with pytest.raises(ValueError, match="byte budget"):
        private._safe_eval("left + right", {"left": Captured(source), "right": source})
    assert additions == []


@pytest.mark.parametrize("left,right,expected", [
    (b"A", b"B", b"AB"), ("A", "B", "AB"), (b"", b"AB", b"AB"),
    ("AB", "", "AB"), ("é", "界", "é界"), (4, 5, 9), (True, True, 2),
])
def test_admitted_addition_keeps_builtin_results(left, right, expected):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    assert private._safe_eval("left + right", {"left": left, "right": right}) == expected


@pytest.mark.parametrize("left,right", [(b"A", "B"), ("A", b"B"), (b"A", 1)])
def test_mixed_types_keep_operator_type_error(left, right):
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    with pytest.raises(TypeError):
        private._safe_eval("left + right", {"left": left, "right": right})


def test_large_receive_binding_can_be_sliced_before_addition():
    private = module_function_view(daemon, bindings={"_INT_BIT_CEILING": 16})
    assert private._safe_eval("raw[:1] + raw[:1]", {"raw": b"ABtail"}) == b"AA"
