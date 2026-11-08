"""Narrowing observations follow complete initialisers, not physical lines."""

import pytest

from core.audit import condition_smt, evidence_grade, sweep
from core.audit.condition_extraction import _get_parser


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def check(source, language="c", **kwargs):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language=language, **kwargs)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("declaration,line", [
    ("int small =\n wide;", 2),
    ("int small\n = wide;", 2),
    ("int\n small = wide;", 3),
    ("unsigned\n int small =\n wide;", 3),
    ("int first=0, small=wide;", 2),
    ("int first=0,\n small=wide;", 3),
    ("int first=0, small=\n wide;", 2),
    ("int first=0, /* boundary */ small=(\n wide\n);", 2),
])
def test_multiline_and_later_declarators_are_candidates(language, declaration, line):
    result = check(f"void Read(unsigned long wide){{\n{declaration}\n}}", language)
    assert result.narrowing_found
    assert (result.source_width, result.dest_width) == (64, 32)
    assert result.assign_line == line


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("declaration", [
    "int small =\n 0; wide++;",
    "int first=0, small=\n wide != 0;",
    "int first=0, small=\n sizeof(wide);",
    "int small=0, unrelated=\n wide != 0;",
    "int small =\n forward(wide);",
])
def test_complete_initialisers_keep_non_value_mentions_excluded(language, declaration):
    source = "int forward(unsigned long);\nvoid Read(unsigned long wide){\n" + declaration + "\n}"
    assert not check(source, language).narrowing_found


@pytest.mark.parametrize("declaration", ["int small=\nwide;", "int first=0, small=\nwide;"])
def test_multiline_values_retain_supported_guard_credit(declaration):
    source = f"void Read(unsigned long wide){{\nif(wide>INT_MAX)return;\n{declaration}\n}}"
    assert not check(source).narrowing_found


def test_a_mutation_in_an_earlier_declarator_invalidates_the_guard():
    source = "void Read(unsigned long wide){\nif(wide>INT_MAX)return;\nint first=(wide+=1)>0, small=\nwide;\n}"
    result = check(source)
    assert result.narrowing_found
    assert "'small'" in result.reasoning


def test_later_declarators_use_their_own_lexical_binding():
    source = "void Read(unsigned long wide){\n{int first=0, wide=0, small=\nwide;}\n}"
    assert not check(source).narrowing_found


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_multiline_candidates_stay_with_the_selected_function(language):
    source = "void Other(unsigned long wide){int first=0, small=\nwide;}\nvoid Read(int wide){int small=\nwide;}"
    assert not check(source, language, function_name="Read").narrowing_found
    assert check(source, language, function_name="Other").narrowing_found


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_character_columns_survive_utf8_identifiers_and_line_endings(newline):
    source = "void Read(unsigned long wide){\nint café=0, small=\nwide;\n}".replace("\n", newline)
    result = check(source)
    assert result.narrowing_found
    assert result.assign_line == 2


def test_all_initialisers_share_one_parse(monkeypatch):
    from core.audit import condition_extraction

    parser = _get_parser("c")
    if parser is None:
        pytest.skip("C grammar required")
    calls = []

    class CountingParser:
        def parse(self, data):
            calls.append(data)
            return parser.parse(data)

    monkeypatch.setattr(condition_extraction, "_get_parser", lambda *a: CountingParser())
    result = condition_smt.check_integer_narrowing(
        "void Read(unsigned long wide){\nint first=0, second=0, small=\nwide;\n}", language="c",
    )
    assert result.narrowing_found
    assert len(calls) == 1


@pytest.mark.parametrize("reason", ["missing", "error"])
def test_unavailable_syntax_retains_the_existing_lexical_fallback(monkeypatch, reason):
    from core.audit import condition_extraction

    if reason == "missing":
        monkeypatch.setattr(condition_extraction, "_get_parser", lambda *a: None)
    else:
        class BrokenParser:
            def parse(self, data):
                raise ValueError("owned parse failure")

        monkeypatch.setattr(condition_extraction, "_get_parser", lambda *a: BrokenParser())
    result = condition_smt.check_integer_narrowing(
        "void Read(unsigned long wide){\nint small=wide;\n}", language="c",
    )
    assert result.narrowing_found
    assert result.solver_status is None


def test_complete_initialiser_reaches_the_consumer_without_proof_authority():
    source = "void Read(unsigned long wide){\nint first=0, small=\nwide;\n}"
    check(source)
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="check-integer-narrowing",
        source=source, hypothesis="narrowing conversion",
    )
    assert result.outcome == "confirmed"
    assert result.details["assign_line"] == 2
    assert result.details["oracle_scope"] == "type-width-only"
    assert not evidence_grade.is_verification_evidence(result.rule_id)
