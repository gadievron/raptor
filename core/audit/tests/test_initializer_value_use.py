"""Grouping must preserve narrowing leads without borrowing unrelated values."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.narrowing_guards import NarrowingGuardContext, integer_range


@pytest.fixture(autouse=True)
def no_solver_process(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


@pytest.fixture
def c_parser():
    from core.audit.condition_extraction import _get_parser

    parser = _get_parser("c")
    if parser is None:
        pytest.skip("C grammar required for syntax-aware value-use tests")
    return parser


def source_for(expression):
    return f"int Read(size_t wide) {{\n    int small = {expression};\n    return small;\n}}"


@pytest.mark.parametrize(
    "expression",
    [
        "wide",
        "(wide)",
        "((wide))",
        "wide + 1",
        "(wide + 1)",
        "forward(wide) + (wide)",
        "(int)(wide)",
        "((int)wide)",
        "flag ? wide : 0",
        "wide ?: 0",
        "(0, wide)",
        "(other = wide)",
        "values[0] + wide",
        "sizeof(int[wide])",
        "_Generic(wide, int: wide, default: wide)",
    ],
)
def test_runtime_value_uses_remain_candidates(expression, c_parser):
    result = condition_smt.check_integer_narrowing(source_for(expression))
    assert result.narrowing_found
    assert result.source_type == "size_t"
    assert result.dest_type == "int"
    assert result.assign_line == 2


@pytest.mark.parametrize(
    "expression",
    [
        "forward(wide)",
        "forward((wide))",
        "(forward(wide))",
        "forward(wide) + forward(wide)",
        "sizeof(wide)",
        "sizeof((wide))",
        "sizeof(wide + 1)",
        "sizeof wide",
        "_Alignof(wide)",
        "(wide > 0)",
        "wide > 0",
        "!wide",
        "wide && 1",
        "(wide, 0)",
        "wide ? 0 : 1",
        "values[wide]",
        "record.wide",
        "record->wide",
        "&wide",
        "_Generic(wide, int: 0, default: 1)",
        "wide = 0",
    ],
)
def test_arguments_selectors_and_unevaluated_mentions_are_not_conversions(
    expression, c_parser
):
    assert not condition_smt.check_integer_narrowing(
        source_for(expression)
    ).narrowing_found


@pytest.mark.parametrize("reason", ["missing", "error"])
def test_unknown_syntax_keeps_a_diagnostic_lead(monkeypatch, reason):
    from core.audit import condition_extraction

    if reason == "missing":
        monkeypatch.setattr(condition_extraction, "_get_parser", lambda *a: None)
    else:

        def broken(*args):
            raise RuntimeError("parser unavailable")

        monkeypatch.setattr(condition_extraction, "_get_parser", broken)
    result = condition_smt.check_integer_narrowing(source_for("(wide)"))
    assert result.narrowing_found
    assert not evidence_grade.is_verification_evidence("smt:check-integer-narrowing")


def test_value_and_guard_checks_share_one_bounded_parse(monkeypatch, c_parser):
    from core.audit import condition_extraction

    calls = []

    class CountingParser:
        def parse(self, data):
            calls.append(data)
            return c_parser.parse(data)

    monkeypatch.setattr(
        condition_extraction, "_get_parser", lambda *a: CountingParser()
    )
    context = NarrowingGuardContext(source_for("forward(wide) + (wide)"))
    location = dict(variable="wide", line=1, column=len("    int small ="))
    assert not context.protects(
        **location,
        source_range=integer_range("size_t", 64),
        dest_range=integer_range("int", 32),
        source_type="size_t",
    )
    assert context.may_use_value(**location)
    assert context.may_use_value(**location)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "expression,found", [("(wide)", True), ("forward((wide))", False)]
)
def test_real_producer_retains_grouped_leads_without_verdict_authority(
    expression, found, c_parser
):
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name="Read",
        verb="check-integer-narrowing",
        source=source_for(expression),
        hypothesis="claim",
    )
    assert result.outcome == ("confirmed" if found else "inconclusive")
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)
