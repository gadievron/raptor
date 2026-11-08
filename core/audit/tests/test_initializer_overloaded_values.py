"""C++ value-returning overloads must not borrow builtin operand filtering."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


TOKEN = """struct Token {
    unsigned long value;
    unsigned long operator=(int) const {return value;}
    unsigned long operator[](unsigned long index) const {return index;}
};
unsigned long operator,(unsigned long value, Token){return value;}
"""


def source_for(expression, local="", prefix=""):
    return TOKEN + prefix + f"\nint Read(unsigned long wide){{\n{local}\nint small={expression};\nreturn small;\n}}"


def check(expression, local="", prefix=""):
    parser = _get_parser("cpp")
    if parser is None:
        pytest.skip("C++ grammar required")
    source = source_for(expression, local, prefix)
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language="cpp", function_name="Read")


@pytest.mark.parametrize("expression", [
    "(wide, Token{})", "(Token{wide}=0)", "Token{}[wide]",
    "((wide), Token{})", "((Token{wide})=0)",
])
def test_overloaded_value_results_remain_narrowing_candidates(expression):
    assert check(expression).narrowing_found


@pytest.mark.parametrize("expression,local", [
    ("(wide, 0)", ""),
    ("(wide=0)", ""),
    ("(reference=0)", "unsigned long &reference=wide;"),
    ("(*(cursor+wide)=0)", "unsigned long *cursor=&wide;"),
    ("(array[wide]=0)", "unsigned long array[2]={};"),
    ("array[wide]", "int array[2]={};"),
    ("wide && cursor", "unsigned long *cursor=&wide;"),
    ("wide and array", "int array[2]={};"),
    ("wide not_eq reference", "unsigned long &reference=wide;"),
])
def test_builtin_storage_does_not_supply_a_discarded_integer(expression, local):
    assert not check(expression, local).narrowing_found


@pytest.mark.parametrize("expression,local", [
    ("(wide, token)", "Token token{};"),
    ("token[wide]", "Token token{};"),
    ("token[wide]", "Token target{}; Token &token=target;"),
    ("(wide, token)", "using Alias=Token; Alias token{};"),
    ("token[wide]", "using Alias=Token; Alias token{};"),
])
def test_class_references_and_aliases_keep_possible_overloads(expression, local):
    assert check(expression, local).narrowing_found


@pytest.mark.parametrize("expression,expected", [
    ("(wide, Token{})", "confirmed"),
    ("(Token{wide}=0)", "confirmed"),
    ("Token{}[wide]", "confirmed"),
    ("(wide, 0)", "inconclusive"),
])
def test_overload_results_reach_the_diagnostic_consumer(tmp_path, expression, expected):
    check(expression)
    subject = tmp_path / "record.cpp"
    subject.write_text(source_for(expression), encoding="utf-8")
    result = sweep._run_smt_verb_inner(
        file_path=str(subject), function_name="Read", verb="check-integer-narrowing",
        source=subject.read_text(encoding="utf-8"), hypothesis="narrowing conversion",
    )
    assert result.outcome == expected
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)
