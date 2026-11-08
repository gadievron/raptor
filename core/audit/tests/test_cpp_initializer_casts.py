"""C++ cast syntax carries its operand value without inventing call results."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)
    if _get_parser("cpp") is None:
        pytest.skip("C++ grammar required")


def source_for(expression):
    source = "void Read(unsigned long wide){\nint small=" + expression + ";\n}"
    assert not _get_parser("cpp").parse(source.encode()).root_node.has_error
    return source


@pytest.mark.parametrize("expression", [
    "static_cast<int>(wide)",
    "static_cast<unsigned char>(wide)",
    "int(wide)",
    "int((wide))",
    "static_cast<int>((wide + 1))",
    "static_cast<int>(int(wide))",
])
def test_explicit_builtin_and_named_casts_retain_narrowing_candidates(expression):
    result = condition_smt.check_integer_narrowing(source_for(expression), language="cpp")
    assert result.narrowing_found and result.source_type == "unsigned long"


@pytest.mark.parametrize("expression", [
    "forward(wide)",
    "forward<int>(wide)",
    "static_cast<int>(forward(wide))",
    "int(forward(wide))",
    "static_cast<int>(wide>0)",
    "int(wide>0)",
    "noexcept(wide)",
    "sizeof(static_cast<int>(wide))",
])
def test_calls_boolean_results_and_unevaluated_mentions_do_not_supply_the_wide_value(expression):
    assert not condition_smt.check_integer_narrowing(source_for(expression), language="cpp").narrowing_found


def test_the_real_audit_producer_keeps_cast_observations_diagnostic():
    result = sweep._run_smt_verb_inner(file_path="unit.cpp", function_name="Read", verb="check-integer-narrowing",
                                     source=source_for("static_cast<int>(wide)"), hypothesis="integer narrowing")
    assert result.outcome == "confirmed"
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)
