"""Non-code and neighboring statements cannot supply a narrowing operand."""

import pytest

from core.audit import condition_smt, sweep


@pytest.fixture(autouse=True)
def no_solver_process(monkeypatch):
    # Check source extraction independently of solver availability; candidate
    # admission happens before the (unchanged) width query.
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


@pytest.mark.parametrize("declaration", [
    "int small = 0; wide++;",
    "int small = 0; wide = 2;",
    "int small = 0; return wide != 0;",
    "int small = 0, another = 0; wide++;",
    "int small = 0; // wide is documented here",
    "int small = 0; /* wide */",
    'int small = 0; const char *label = "wide";',
    "int small = 0 /* wide */;",
    "int small = 0, unrelated = wide != 0;",
])
def test_neighboring_tokens_do_not_become_initializer_operands(declaration):
    source = f"int Read(size_t wide) {{\n    {declaration}\n    return small;\n}}"
    assert not condition_smt.check_integer_narrowing(source).narrowing_found


@pytest.mark.parametrize("comment", [
    "// if (wide > INT_MAX) return 0;",
    "/* if (wide > INT_MAX) return 0; */",
    'const char *example = "if (wide > INT_MAX)";',
])
def test_documented_guard_does_not_hide_an_actual_conversion(comment):
    source = f"int Read(size_t wide) {{\n    {comment}\n    int small = wide;\n    return small;\n}}"
    result = condition_smt.check_integer_narrowing(source)
    assert result.narrowing_found
    assert result.assign_line == 3
    assert result.source_type == "size_t"
    assert result.dest_type == "int"


def test_commented_declaration_cannot_replace_the_parameter_type():
    source = """int Read(int wide) {
/*
    size_t wide = 0;
*/
    int small = wide;
    return small;
}
"""
    assert not condition_smt.check_integer_narrowing(source).narrowing_found


@pytest.mark.parametrize("prefix", ["int first = 0; ", "", "/* note */ "])
def test_later_typed_declaration_is_still_checked(prefix):
    source = f"int Read(size_t wide) {{\n    {prefix}int small = wide;\n    return small;\n}}"
    result = condition_smt.check_integer_narrowing(source)
    assert result.narrowing_found
    assert result.assign_line == 2


def test_local_types_from_later_declarations_are_retained():
    source = """int Read(void) {
    int first = 0; size_t wide = read_count();
    int small = wide;
    return small;
}
"""
    assert condition_smt.check_integer_narrowing(source).narrowing_found


@pytest.mark.parametrize("code,found", [("int small = 0; wide++;", False), ("int small = wide;", True)])
def test_smt_producer_uses_the_bounded_initializer(code, found):
    source = f"int Read(size_t wide) {{\n    {code}\n    return small;\n}}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read",
                                      verb="check-integer-narrowing", source=source, hypothesis="claim")
    assert (result.outcome == "confirmed") is found
    assert result.details.get("narrowing_found") is found


@pytest.mark.parametrize("expression", ["call(1, 2)", "array[(1, 2)]", "(Point){1, 2}"])
def test_initializer_delimiters_inside_nested_expressions(expression):
    from core.audit.initializer import initializer_text
    assert initializer_text(expression + "; unrelated();") == expression
