"""A narrowing observation must use the visible variable's own declaration."""

import pytest

from core.audit import condition_smt


@pytest.fixture(autouse=True)
def syntax_without_solver(monkeypatch):
    from core.audit.condition_extraction import _get_parser

    if _get_parser("c") is None:
        pytest.skip("C grammar required for lexical binding tests")
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


@pytest.mark.parametrize(
    "source,found",
    [
        (
            "int Other(size_t value) { return 0; }\nint Read(int value) { int small = value; return small; }",
            False,
        ),
        (
            "int Other(int value) { return 0; }\nint Read(size_t value) { int small = value; return small; }",
            True,
        ),
        (
            "int Read(int value) { int small = value; return small; }\nvoid Other(void) { size_t value = 0; }",
            False,
        ),
        (
            "void Other(void) { size_t value = 0; }\nint Read(int value) { int small = value; return small; }",
            False,
        ),
        (
            "int Read(size_t value) { int small = value; return small; }\nvoid Other(void) { int value = 0; }",
            True,
        ),
        (
            "int Read(size_t value) { { int value = 0; int small = value; } return 0; }",
            False,
        ),
        (
            "int Read(int value) { { size_t value = 0; int small = value; } return 0; }",
            True,
        ),
        (
            "int Read(int value) { { size_t value = 0; } int small = value; return small; }",
            False,
        ),
        (
            "int Read(size_t value) { { int value = 0; } int small = value; return small; }",
            True,
        ),
        (
            "int Read(size_t value) { int small = value; { int value = 0; } return small; }",
            True,
        ),
        (
            "int Read(int value) { int small = value; { size_t value = 0; } return small; }",
            False,
        ),
        ("int Read(void) { size_t value; int small = value; return small; }", True),
        ("int Read(void) { int value; int small = value; return small; }", False),
        (
            "int Read(size_t value) { { Unknown value; int small = value; } return 0; }",
            False,
        ),
        (
            "int Read(size_t value) { { int *value; int small = value; } return 0; }",
            False,
        ),
        (
            "int Read(size_t value) { for(int value = 0; value < 1; value++) { int small = value; } return 0; }",
            False,
        ),
        (
            "int Read(int value) { for(size_t value = 0; value < 1; value++) { int small = value; } return 0; }",
            True,
        ),
        ("size_t value;\nint Read(void) { int small = value; return small; }", True),
        (
            "size_t value;\nint Read(int value) { int small = value; return small; }",
            False,
        ),
        (
            "int Read(size_t value) { { int small = value, value = 0; } return 0; }",
            True,
        ),
        (
            "int Read(size_t value) { { int value = 0, small = value; int later = value; } return 0; }",
            False,
        ),
    ],
)
def test_initializer_uses_lexically_visible_type(source, found):
    assert condition_smt.check_integer_narrowing(source).narrowing_found is found


def test_long_signature_is_not_limited_to_the_first_500_characters():
    source = (
        "int Read("
        + ", ".join(f"int parameter_{i}" for i in range(50))
        + ", size_t value) {\nint small = value;\nreturn small;\n}"
    )
    assert condition_smt.check_integer_narrowing(source).narrowing_found


@pytest.mark.parametrize(
    "body",
    [
        "{ label: int value = 0; int small = value; }",
        "{ enum { value = 0 }; int small = value; }",
        "{ int (*value)(int); int small = value; }",
        "switch (flag) { case 0: int value = 0; int small = value; }",
    ],
)
def test_unsupported_and_labeled_bindings_still_mask_outer_names(body):
    source = f"int Read(size_t value, int flag) {{ {body} return 0; }}"
    assert not condition_smt.check_integer_narrowing(source).narrowing_found
