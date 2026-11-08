"""Builtin C type spelling must not change a diagnostic narrowing width."""

import pytest

from core.audit import condition_smt
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def check(source, language="c"):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language=language)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("source_type,dest_type,source_width,dest_width", [
    ("int", "short int", 32, 16),
    ("int", "unsigned short int", 32, 16),
    ("int", "short unsigned int", 32, 16),
    ("int", "int short unsigned", 32, 16),
    ("int", "signed short int", 32, 16),
    ("long int", "int", 64, 32),
    ("long signed int", "signed", 64, 32),
    ("unsigned long long int", "unsigned", 64, 32),
    ("long long unsigned int", "short unsigned", 64, 16),
    ("short unsigned int", "signed char", 16, 8),
])
def test_complete_builtin_spelling_selects_the_width(
    language, source_type, dest_type, source_width, dest_width,
):
    result = check(
        f"void Read({source_type} wide){{\n{dest_type} small=wide;\n}}", language,
    )
    assert result.narrowing_found
    assert (result.source_type, result.dest_type) == (source_type, dest_type)
    assert (result.source_width, result.dest_width) == (source_width, dest_width)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("dest_type", [
    "long int", "signed long int", "long signed int", "long long int",
    "unsigned long int", "long unsigned int", "int unsigned long long",
])
def test_explicit_int_does_not_turn_a_64_bit_destination_into_32_bits(language, dest_type):
    result = check(f"void Read(unsigned long long wide){{\n{dest_type} small=wide;\n}}", language)
    assert not result.narrowing_found


@pytest.mark.parametrize("source_type,dest_type,guard", [
    ("unsigned long int", "unsigned short int", "if(wide>65535)return;"),
    ("long unsigned int", "short unsigned int", "if(wide>65535)return;"),
    ("int unsigned long", "int unsigned short", "if(wide>65535)return;"),
    ("long signed int", "signed char", "if(wide < -128 || wide > 127)return;"),
])
def test_guard_ranges_use_the_full_signedness_spelling(source_type, dest_type, guard):
    result = check(f"void Read({source_type} wide){{\n{guard}\n{dest_type} small=wide;\n}}")
    assert not result.narrowing_found


@pytest.mark.parametrize("dest_type", ["short int", "signed short int", "int short"])
def test_an_unsigned_16_bit_bound_does_not_protect_a_signed_destination(dest_type):
    source = f"void Read(unsigned long int wide){{\nif(wide>65535)return;\n{dest_type} small=wide;\n}}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("source_type", ["long unsigned int", "int unsigned long", "long long unsigned int"])
def test_reordered_unsigned_source_cannot_borrow_a_negative_signed_interval(source_type):
    source = f"void Read({source_type} wide){{\nif(wide < -128 || wide > -1)return;\nsigned char small=wide;\n}}"
    assert check(source).narrowing_found


def test_solver_width_model_receives_the_complete_type_spelling(monkeypatch):
    calls = []

    def record(*args):
        calls.append(args)
        return None

    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", record)
    result = check("void Read(unsigned long long int wide){\nshort unsigned int small=wide;\n}")
    assert result.narrowing_found
    assert calls == [("wide", "unsigned long long int", "short unsigned int", 64, 16, 2)]


@pytest.mark.parametrize("dest_type,expected", [("short unsigned int", "confirmed"), ("long unsigned int", "inconclusive")])
def test_complete_spelling_reaches_the_consumer_as_a_diagnostic(dest_type, expected):
    from core.audit import sweep, evidence_grade

    source = f"void Read(unsigned long long int wide){{\n{dest_type} small=wide;\n}}"
    check(source)  # require a working grammar for the production dispatch too
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="check-integer-narrowing",
        source=source, hypothesis="narrowing conversion",
    )
    assert result.outcome == expected
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)


def test_native_width_model_uses_the_same_builtin_type_parser():
    pytest.importorskip("z3")
    result = condition_smt._z3_integer_narrowing_check(
        "wide", "unsigned long long int", "short unsigned int", 2,
    )
    assert result.solver_status == "sat"
    assert (result.source_width, result.dest_width) == (64, 16)
    assert 65535 < result.witness["wide"] < 1 << 64
