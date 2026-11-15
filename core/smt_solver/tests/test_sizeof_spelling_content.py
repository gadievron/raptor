import pytest

from core.smt_solver.sizeof_model import builtin_integer_sizeof


def test_sizeof_uses_stored_integer_spelling():
    class Spelling(str):
        def __eq__(self, other):
            return other == "char"

    assert builtin_integer_sizeof(Spelling("long"), "lp64") == 8


@pytest.mark.parametrize("spelling,abi,expected", [
    ("char", "lp64", 1), ("signed char", "lp64", 1),
    ("unsigned char", "llp64", 1), ("long", "lp64", 8),
    ("long", "llp64", 4), ("_Bool", "lp64", None),
    ("bool", "lp64", None), ("float", "lp64", None),
    ("char", "unknown", None),
])
def test_sizeof_preserves_declared_storage(spelling, abi, expected):
    class Spelling(str):
        def __eq__(self, other):
            raise AssertionError("custom equality must not select storage")
        def __str__(self):
            raise AssertionError("custom conversion must not select storage")
        def split(self, *args):
            raise AssertionError("custom tokenization must not select storage")

    assert builtin_integer_sizeof(Spelling(spelling), abi) == expected


def test_nontext_spelling_remains_unresolved():
    assert builtin_integer_sizeof(None, "lp64") is None
