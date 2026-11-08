"""Only a result value, with builtin operator semantics, excludes a lead."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def source_for(expression, prefix=""):
    return prefix + f"\nint Read(unsigned long wide){{\nint small={expression};\nreturn small;\n}}"


def check(expression, language="cpp", prefix=""):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    source = source_for(expression, prefix)
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language=language, function_name="Read")


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("expression", [
    "({wide; 0;})", "({wide += 1; 0;})", "({wide; wide > 0;})",
    "({unsigned long temporary=wide; (void)temporary; 0;})",
    "({wide; ({wide; 0;});})",
])
def test_discarded_statement_expression_values_are_not_narrowed(language, expression):
    assert not check(expression, language).narrowing_found


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("expression", [
    "({0; wide;})", "({0; wide += 1;})", "({0; ({wide;});})",
])
def test_final_statement_expression_values_remain_candidates(language, expression):
    assert check(expression, language).narrowing_found


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_a_real_inner_narrowing_site_is_not_erased_with_the_outer_value(language):
    result = check("({int inner=wide; (void)inner; 0;})", language)
    assert result.narrowing_found
    assert "'inner'" in result.reasoning


@pytest.mark.parametrize("expression", [
    "wide and 1", "wide or 0", "not wide", "wide not_eq 0",
    "(wide += 1) and 1", "(wide > 0) and 1", "not (wide + 1)",
    "static_cast<int>(wide) > 0", "(int)wide > 0", "int(wide) > 0",
    "wide && noexcept(wide += 1)", "wide and requires { wide += 1; }",
])
def test_builtin_cpp_boolean_results_do_not_narrow_the_wide_value(expression):
    assert not check(expression).narrowing_found


@pytest.mark.parametrize("expression", ["wide bitand wide", "wide bitor 1", "wide xor 1", "compl wide"])
def test_integer_valued_alternative_operators_remain_candidates(expression):
    assert check(expression).narrowing_found


@pytest.mark.parametrize("operator,spelling", [
    ("<", "<"), (">", ">"), ("<=", "<="), (">=", ">="),
    ("==", "=="), ("!=", "!="), ("&&", "&&"), ("||", "||"),
    ("!=", "not_eq"), ("&&", "and"), ("||", "or"),
])
def test_overloaded_cpp_predicate_operators_can_return_wide_integers(operator, spelling):
    prefix = f"struct Token {{}};\nunsigned long operator{operator}(unsigned long value, Token){{return value;}}"
    assert check(f"wide {spelling} Token{{}}", prefix=prefix).narrowing_found


@pytest.mark.parametrize("operator,spelling", [("!", "!"), ("!", "not"), ("&", "&")])
def test_overloaded_unary_operators_can_return_wide_integers(operator, spelling):
    prefix = f"struct Token {{ unsigned long value; unsigned long operator{operator}() const {{return value;}} }};"
    assert check(f"{spelling} Token{{wide}}", prefix=prefix).narrowing_found


@pytest.mark.parametrize("expression,prefix", [
    ("wide < token", "struct Token {}; using Alias=Token; Alias token; unsigned long operator<(unsigned long value, Token){return value;}"),
    ("wide && opaque()", "struct Token {}; Token opaque(); unsigned long operator&&(unsigned long value, Token){return value;}"),
])
def test_unresolved_cpp_operator_types_retain_possible_leads(expression, prefix):
    assert check(expression, prefix=prefix).narrowing_found


@pytest.mark.parametrize("expression,prefix,expected", [
    ("({wide; 0;})", "", "inconclusive"),
    ("wide and 1", "", "inconclusive"),
    ("wide && Token{}", "struct Token {}; unsigned long operator&&(unsigned long value, Token){return value;}", "confirmed"),
])
def test_result_boundaries_reach_the_diagnostic_consumer(tmp_path, expression, prefix, expected):
    check(expression, prefix=prefix)
    subject = tmp_path / "record.cpp"
    subject.write_text(source_for(expression, prefix), encoding="utf-8")
    result = sweep._run_smt_verb_inner(
        file_path=str(subject), function_name="Read", verb="check-integer-narrowing",
        source=subject.read_text(encoding="utf-8"), hypothesis="narrowing conversion",
    )
    assert result.outcome == expected
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("scope", ["member", "namespace"])
def test_global_builtin_names_cannot_hide_an_overloaded_operand(scope):
    prefix = "struct Token {}; unsigned long operator<(unsigned long value, Token){return value;} int token;\n"
    body = "int Read(unsigned long wide){int small=wide < token;return small;}"
    source = prefix + ("struct Owner {Token token;" + body + "};" if scope == "member"
                       else "namespace Scope {Token token;" + body + "}")
    parser = _get_parser("cpp")
    if parser is None:
        pytest.skip("C++ grammar required")
    assert not parser.parse(source.encode()).root_node.has_error
    assert condition_smt.check_integer_narrowing(source, language="cpp", function_name="Read").narrowing_found


def test_builtin_local_operands_still_establish_a_boolean_result():
    assert not check("({int local=0; wide and local;})").narrowing_found


def test_imported_enumerators_cannot_borrow_an_outer_builtin_type():
    source = """enum class E { token };
unsigned long operator<(unsigned long value, E){return value;}
int Read(unsigned long wide){
    int token=0;
    {using enum E; int small=wide < token; return small;}
}
"""
    parser = _get_parser("cpp")
    if parser is None:
        pytest.skip("C++ grammar required")
    assert not parser.parse(source.encode()).root_node.has_error
    assert condition_smt.check_integer_narrowing(source, language="cpp", function_name="Read").narrowing_found
