"""Assignment values and Boolean requirements have different narrowing roles."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def source_for(expression):
    return f"int Read(unsigned long wide){{\nint small={expression};\nreturn small;\n}}"


def check(expression, language):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    source = source_for(expression)
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language=language)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("operator,operand", [
    ("+=", "1"), ("-=", "1"), ("*=", "2"), ("/=", "1"),
    ("%=", "0x100000000UL"), ("<<=", "1"), (">>=", "1"),
    ("&=", "0xffffffffUL"), ("|=", "1"), ("^=", "1"),
])
def test_compound_assignment_returns_a_value_from_its_left_operand(language, operator, operand):
    result = check(f"(wide {operator} {operand})", language)
    assert result.narrowing_found
    assert (result.source_type, result.dest_type) == ("unsigned long", "int")
    assert result.assign_line == 2


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("expression", [
    "((wide) += 1)", "((wide += 1), wide)", "(wide += 1) + 0",
    "(wide += 1) * 2", "(wide += (1 + 1))",
])
def test_nested_assignment_results_keep_their_possible_value_use(language, expression):
    assert check(expression, language).narrowing_found


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("expression", [
    "(wide = 1)", "((wide += 1), 0)", "sizeof(wide += 1)",
    "(wide += 1) > 0", "(wide += 1) ? 0 : 1",
])
def test_assignment_mentions_that_do_not_supply_the_result_stay_excluded(language, expression):
    assert not check(expression, language).narrowing_found


@pytest.mark.parametrize("expression", [
    "requires { wide + 1; }",
    "requires { wide += 1; }",
    "requires { { wide += 1 }; }",
    "requires { requires sizeof(wide) > 0; }",
    "(requires { wide + 1; }) + 0",
    "noexcept(wide += 1)",
])
def test_cpp_boolean_requirements_do_not_supply_the_wide_integer(expression):
    assert not check(expression, "cpp").narrowing_found


def test_a_value_after_a_requirement_is_still_a_candidate():
    assert check("(requires { wide += 1; }, wide)", "cpp").narrowing_found


@pytest.mark.parametrize("expression,expected", [
    ("(wide += 1)", "confirmed"),
    ("requires { wide += 1; }", "inconclusive"),
])
def test_assignment_value_changes_reach_the_diagnostic_consumer(expression, expected):
    check(expression, "cpp")
    result = sweep._run_smt_verb_inner(
        file_path="record.cpp", function_name="Read", verb="check-integer-narrowing",
        source=source_for(expression), hypothesis="narrowing conversion",
    )
    assert result.outcome == expected
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)
