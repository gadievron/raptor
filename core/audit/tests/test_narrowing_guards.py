"""Only range-correct guards controlling this conversion earn protection."""

import pytest

from core.audit import condition_smt
from core.audit.narrowing_guards import NarrowingGuardContext, integer_range


@pytest.fixture(autouse=True)
def no_solver_process(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def check(
    prefix, *, source_type="size_t", suffix="", dest_type="int", initializer="wide"
):
    source = f"int Read({source_type} wide) {{\n{prefix}\n    {dest_type} small = {initializer};\n{suffix}\n    return 0;\n}}"
    return condition_smt.check_integer_narrowing(source)


@pytest.mark.parametrize(
    "prefix",
    [
        "if (wide > INT_MAX) log_value(wide);",
        "if (wide < INT_MAX) log_value(wide);",
        "if (wide > TOO_LARGE) return 0;",
        "if (wide > LONG_MAX) return 0;",
        "if (wide < INT_MAX) return 0;",
        "if (wide > INT_MAX) { if (flag) return 0; }",
        "if (flag) { if (wide > INT_MAX) return 0; }",
        "if (wide > INT_MAX) return 0;\nwide++;",
        "if (wide > INT_MAX) return 0;\nwide = get_count();",
        "if (wide > INT_MAX) return 0;\nupdate_count(&wide);",
        "if (wide > INT_MAX) return 0;\nRESET(wide);",
        "if (wide > INT_MAX) return 0;\nfor (;;) { wide++; break; }",
        "if (wide > INT_MAX) goto next;\nnext: ;",
        "min(wide, INT_MAX);",
        "clamp(wide, 0, INT_MAX);",
    ],
)
def test_incidental_partial_or_stale_checks_do_not_hide_a_candidate(prefix):
    assert check(prefix).narrowing_found


@pytest.mark.parametrize(
    "prefix",
    [
        "if (wide > INT_MAX) return 0;",
        "if (wide > INT_MAX) { return 0; }",
        "if (wide > INT_MAX) { log_value(wide); return 0; }",
        "if (wide >= 2147483648) return 0;",
        "if (INT_MAX < wide) return 0;",
        "if (wide > 0x7fffffff) return 0;",
        "if (wide > INT32_MAX) return 0;",
        "if (!(wide <= INT_MAX)) return 0;",
        "if (wide != 0) return 0;",
        "if (wide > INT_MAX) return 0;\nsize_t copy = wide; copy = wide;",
        "if (wide <= INT_MAX) {",
        "if (wide > INT_MAX) { return 0; } else {",
    ],
)
def test_recognized_unsigned_to_signed_guards_remain_protective(prefix):
    suffix = "}" if prefix.endswith("{") else ""
    assert not check(prefix, suffix=suffix).narrowing_found


@pytest.mark.parametrize(
    "prefix,protected",
    [
        ("if (wide > INT_MAX) return 0;", False),
        ("if (wide < INT_MIN) return 0;", False),
        ("if (wide > INT_MAX || wide < INT_MIN) return 0;", True),
        ("if (wide > INT_MAX) return 0;\nif (wide < INT_MIN) return 0;", True),
        ("if (wide >= INT_MIN && wide <= INT_MAX) {", True),
        ("if (wide < INT_MIN && wide > INT_MAX) return 0;", False),
        ("if (wide < 0U) return 0;\nif (wide > INT_MAX) return 0;", False),
    ],
)
def test_signed_source_needs_both_destination_bounds(prefix, protected):
    suffix = "}" if prefix.endswith("{") else ""
    assert (
        check(prefix, source_type="int64_t", suffix=suffix).narrowing_found
        is not protected
    )


@pytest.mark.parametrize("initializer", ["wide + 1", "wide * 2", "wide - 1"])
def test_guarding_an_operand_does_not_establish_the_expression_range(initializer):
    assert check(
        "if (wide > INT_MAX) return 0;", initializer=initializer
    ).narrowing_found


def test_protection_is_not_tied_to_a_fifteen_line_window():
    assert not check(
        "if (wide > INT_MAX) return 0;\n" + "int unrelated = 0;\n" * 20
    ).narrowing_found


@pytest.mark.parametrize("directive", [
    "#define INT_MAX 9999999999\n",
    "\t#\tdefine\tINT_MAX 9999999999\r\n",
    "#undef INT_MAX\n",
])
def test_macro_override_does_not_borrow_the_standard_limit(directive):
    assert check(
        directive + "if (wide > INT_MAX) return 0;"
    ).narrowing_found


def test_second_initializer_cannot_reuse_a_check_before_mutation():
    source = """int Read(size_t wide) {
    if (wide > INT_MAX) return 0;
    int ignored = (wide = get_count()), small = wide;
    int final = wide;
    return final;
}
"""
    assert condition_smt.check_integer_narrowing(source).narrowing_found


def test_missing_parser_earns_no_guard_credit(monkeypatch):
    monkeypatch.setattr("core.audit.condition_extraction._get_parser", lambda *a: None)
    assert check("if (wide > INT_MAX) return 0;").narrowing_found


def test_parse_error_earns_no_guard_credit():
    assert check("if (wide > INT_MAX) return 0;\nbroken {{{").narrowing_found


def test_context_reuses_one_parse(monkeypatch):
    from core.audit import condition_extraction

    parser = condition_extraction._get_parser("c")
    calls = []

    class CountingParser:
        def parse(self, data):
            calls.append(data)
            return parser.parse(data)

    monkeypatch.setattr(
        condition_extraction, "_get_parser", lambda *a: CountingParser()
    )
    source = (
        "int Read(size_t wide) {\n if(wide > INT_MAX) return 0;\n int small = wide;\n}"
    )
    context = NarrowingGuardContext(source)
    kwargs = dict(
        variable="wide",
        line=2,
        column=len(" int small ="),
        source_range=integer_range("size_t", 64),
        dest_range=integer_range("int", 32),
        source_type="size_t",
    )
    assert context.protects(**kwargs)
    assert context.protects(**kwargs)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "source_type,prefix,protected",
    [
        ("uint32_t", "if (wide > UINT8_MAX) return 0;", True),
        ("int64_t", "if (wide < 0 || wide > 255) return 0;", True),
        ("int64_t", "if (wide > 255) return 0;", False),
        ("size_t", "if (wide > -1) return 0;", False),
    ],
)
def test_unsigned_destination_and_c_comparison_limits(source_type, prefix, protected):
    assert (
        check(prefix, source_type=source_type, dest_type="uint8_t").narrowing_found
        is not protected
    )


def test_a_type_from_another_function_cannot_establish_this_guard():
    source = """int Other(size_t wide) { return 0; }
int Read(int64_t wide) {
    if (wide > INT_MAX) return 0;
    int small = wide;
    return small;
}
"""
    assert condition_smt.check_integer_narrowing(source).narrowing_found


@pytest.mark.parametrize(
    "prefix",
    [
        "if (wide > INT_MAX || RESET(wide)) return 0;",
        "if (wide <= INT_MAX && RESET(wide)) {",
    ],
)
def test_mutation_inside_a_condition_invalidates_earlier_comparisons(prefix):
    assert check(prefix, suffix="}" if prefix.endswith("{") else "").narrowing_found


@pytest.mark.parametrize("breaker", ["\f", "\v", "\r"], ids=["form-feed", "vertical-tab", "bare-cr"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_non_lf_whitespace_does_not_shift_guard_offsets(breaker, newline):
    source = (
        "int Read(size_t wide) {\n"
        f"    int ignored = 0;{breaker}\n"
        "    if (wide > INT_MAX) return 0;\n"
        "    int small = wide;\n"
        "    return 0;\n}\n"
    ).replace("\n", newline)
    result = condition_smt.check_integer_narrowing(source)
    assert not result.narrowing_found, result.reasoning
    unguarded = source.replace("if (wide > INT_MAX) return 0;", "")
    candidate = condition_smt.check_integer_narrowing(unguarded)
    assert candidate.narrowing_found, candidate.reasoning
    assert candidate.assign_line == 4
