"""Tests for core.audit.postcondition_verify."""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.postcondition_verify import (
    FunctionRole,
    Postcondition,
    PostconditionKind,
    PostconditionViolation,
    ViolationKind,
    check_completeness,
    check_composition_violations,
    check_ordering_violations,
    classify_function_role,
    extract_postconditions,
    format_postcondition_context,
    verify_postconditions,
)


class TestClassifyRole:
    def test_sanitiser(self):
        assert classify_function_role("sanitize_input") == FunctionRole.SANITISER

    def test_sanitiser_british(self):
        assert classify_function_role("sanitise_html") == FunctionRole.SANITISER

    def test_validator_with_bool(self):
        assert classify_function_role(
            "validate_token", return_type="bool",
        ) == FunctionRole.VALIDATOR

    def test_validator_by_name(self):
        assert classify_function_role("is_valid_email") == FunctionRole.VALIDATOR

    def test_encoder(self):
        assert classify_function_role("encode_base64") == FunctionRole.ENCODER

    def test_decoder(self):
        assert classify_function_role("deserialize_json") == FunctionRole.DESERIALISER

    def test_unrelated(self):
        assert classify_function_role("process_data") is None

    def test_unsafe_not_classified_as_sanitiser(self):
        assert classify_function_role("mark_unsafe") != FunctionRole.SANITISER

    def test_unchecked_not_classified_as_validator(self):
        assert classify_function_role("unchecked_cast") != FunctionRole.VALIDATOR

    def test_summary_text_contributes(self):
        assert classify_function_role(
            "process",
            summary_text="sanitizes user input by stripping HTML",
        ) == FunctionRole.SANITISER


class TestExtractPostconditions:
    def _make_summary(self, postconds=None, summary_text=""):
        return SimpleNamespace(
            postconditions=postconds or [],
            summary=summary_text,
        )

    def test_extracts_from_summary_postconditions(self):
        pc = SimpleNamespace(guarantee="output contains no HTML tags")
        summary = self._make_summary(postconds=[pc])
        gaps = [{"name": "strip_html", "file": "util.c"}]
        summaries = {"util.c:strip_html": summary}
        result = extract_postconditions(gaps, summaries)
        assert len(result) == 1
        assert result[0].function == "strip_html"
        assert "HTML" in result[0].claimed_guarantee

    def test_infers_for_sanitiser_without_postconditions(self):
        summary = self._make_summary(summary_text="cleans input")
        gaps = [{"name": "sanitize_input", "file": "auth.c"}]
        summaries = {"auth.c:sanitize_input": summary}
        result = extract_postconditions(gaps, summaries)
        assert len(result) == 1
        assert result[0].source == "inferred"
        assert result[0].role == FunctionRole.SANITISER

    def test_skips_non_security_functions(self):
        summary = self._make_summary(summary_text="processes data")
        gaps = [{"name": "process_data", "file": "util.c"}]
        summaries = {"util.c:process_data": summary}
        result = extract_postconditions(gaps, summaries)
        assert len(result) == 0


class TestOrderingViolations:
    def test_no_violation_when_safety_is_last(self):
        pc = Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="safe output",
            role=FunctionRole.SANITISER,
        )
        result = check_ordering_violations(
            pc, ["normalize_unicode", "sanitize_chars"],
        )
        assert result is None

    def test_violation_when_transform_after_safety(self):
        pc = Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="safe output",
            role=FunctionRole.SANITISER,
        )
        result = check_ordering_violations(
            pc, ["strip_metacharacters", "normalize_unicode"],
        )
        assert result is not None
        assert result.violation_kind == ViolationKind.ORDERING
        assert "normalize" in result.description

    def test_no_violation_with_single_call(self):
        pc = Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="safe output",
            role=FunctionRole.SANITISER,
        )
        result = check_ordering_violations(pc, ["sanitize_chars"])
        assert result is None

    def test_empty_sequence(self):
        pc = Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="safe",
            role=FunctionRole.SANITISER,
        )
        assert check_ordering_violations(pc, []) is None


class TestCompositionViolations:
    def test_no_violation_when_guarantee_covers(self):
        pc = Postcondition(
            function="sanitize", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="output is sanitized and safe",
            role=FunctionRole.SANITISER,
        )
        violations = check_composition_violations(
            pc, "exec_cmd", "b.c",
            ["input must be sanitized"],
        )
        assert len(violations) == 0

    def test_violation_when_guarantee_misses(self):
        pc = Postcondition(
            function="format_input", file="a.c",
            kind=PostconditionKind.ENCODING_GUARANTEE,
            description="", claimed_guarantee="output is properly formatted",
            role=FunctionRole.ENCODER,
        )
        violations = check_composition_violations(
            pc, "exec_cmd", "b.c",
            ["input must be sanitized for shell metacharacters"],
        )
        assert len(violations) == 1
        assert violations[0].violation_kind == ViolationKind.COMPOSITION
        assert violations[0].consumer_function == "exec_cmd"


class TestCompletenessCheck:
    def test_no_gap(self):
        pc = Postcondition(
            function="strip", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="no metacharacters",
            role=FunctionRole.SANITISER,
        )
        result = check_completeness(
            pc, ["ascii", "unicode", "url_encoded"],
            known_representations=["ascii", "unicode", "url_encoded"],
        )
        assert result is None

    def test_missing_representations(self):
        pc = Postcondition(
            function="strip", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="no metacharacters",
            role=FunctionRole.SANITISER,
        )
        result = check_completeness(
            pc, ["ascii"],
            known_representations=["ascii", "unicode", "url_encoded"],
        )
        assert result is not None
        assert result.violation_kind == ViolationKind.COMPLETENESS
        assert "2 representations" in result.description


class TestVerifyPostconditions:
    def test_basic_verification(self):
        summary = SimpleNamespace(
            postconditions=[SimpleNamespace(guarantee="output is safe")],
            summary="sanitises input",
        )
        gaps = [{"name": "sanitize_html", "file": "util.c", "callees": []}]
        summaries = {"util.c:sanitize_html": summary}
        result = verify_postconditions(gaps, summaries)
        assert result.functions_checked == 1
        assert result.functions_with_postconditions >= 1

    def test_empty_input(self):
        result = verify_postconditions([], {})
        assert result.functions_checked == 0
        assert len(result.violations) == 0


class TestFormatContext:
    def test_empty(self):
        assert format_postcondition_context([], []) == ""

    def test_with_postconditions(self):
        pcs = [Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="output is safe",
            role=FunctionRole.SANITISER,
        )]
        text = format_postcondition_context(pcs, [])
        assert "Postcondition verification" in text
        assert "clean()" in text

    def test_with_violations(self):
        pc = Postcondition(
            function="clean", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="", claimed_guarantee="output is safe",
            role=FunctionRole.SANITISER,
        )
        viols = [PostconditionViolation(
            function="clean", file="a.c",
            violation_kind=ViolationKind.ORDERING,
            postcondition=pc,
            description="transform after sanitise",
            confidence="high",
        )]
        text = format_postcondition_context([], viols)
        assert "violations" in text
        assert "HIGH" in text

    def test_violation_to_dict(self):
        pc = Postcondition(
            function="f", file="a.c",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="d", claimed_guarantee="g",
        )
        v = PostconditionViolation(
            function="f", file="a.c",
            violation_kind=ViolationKind.ORDERING,
            postcondition=pc, description="test",
            consumer_function="g", consumer_file="b.c",
        )
        d = v.to_dict()
        assert d["violation_kind"] == "ordering"
        assert d["consumer_function"] == "g"
        assert "postcondition" in d


class TestSiblingOrdering:
    def test_detects_ordering_mismatch(self):
        from core.audit.postcondition_verify import check_sibling_ordering

        siblings = [
            {"name": "render_html", "file": "v.py",
             "call_sequence": ["strip_html", "normalize_unicode"]},
            {"name": "render_xml", "file": "v.py",
             "call_sequence": ["normalize_unicode", "strip_html"]},
        ]
        violations = check_sibling_ordering(siblings)
        assert len(violations) == 1
        assert "ordering mismatch" in violations[0].description

    def test_no_mismatch_same_order(self):
        from core.audit.postcondition_verify import check_sibling_ordering

        siblings = [
            {"name": "a", "file": "f.py",
             "call_sequence": ["sanitize", "encode"]},
            {"name": "b", "file": "f.py",
             "call_sequence": ["sanitize", "encode"]},
        ]
        assert check_sibling_ordering(siblings) == []

    def test_single_sibling(self):
        from core.audit.postcondition_verify import check_sibling_ordering

        assert check_sibling_ordering([{"name": "a", "call_sequence": ["x"]}]) == []

    def test_falls_back_to_callees(self):
        from core.audit.postcondition_verify import check_sibling_ordering

        siblings = [
            {"name": "a", "file": "f.py",
             "callees": ["strip", "encode"]},
            {"name": "b", "file": "f.py",
             "callees": ["encode", "strip"]},
        ]
        violations = check_sibling_ordering(siblings)
        assert len(violations) == 1


class TestSiblingSanitizerStrength:
    def test_detects_weak_among_strong(self):
        from core.audit.postcondition_verify import check_sibling_sanitizer_strength

        siblings = [
            {"name": "render_html", "file": "v.py", "sanitizer": "escape_html"},
            {"name": "render_json", "file": "v.py", "sanitizer": "escape_html"},
            {"name": "render_xml", "file": "v.py", "sanitizer": "strip_tags"},
        ]
        violations = check_sibling_sanitizer_strength(siblings)
        assert len(violations) == 1
        assert "weak sanitizer" in violations[0].description
        assert "strip_tags" in violations[0].description
        assert violations[0].confidence == "high"

    def test_no_violation_all_strong(self):
        from core.audit.postcondition_verify import check_sibling_sanitizer_strength

        siblings = [
            {"name": "a", "file": "f.py", "sanitizer": "escape_html"},
            {"name": "b", "file": "f.py", "sanitizer": "htmlspecialchars"},
        ]
        assert check_sibling_sanitizer_strength(siblings) == []

    def test_single_strong_medium_confidence(self):
        from core.audit.postcondition_verify import check_sibling_sanitizer_strength

        siblings = [
            {"name": "a", "file": "f.py", "sanitizer": "escape_html"},
            {"name": "b", "file": "f.py", "sanitizer": "strip_tags"},
        ]
        violations = check_sibling_sanitizer_strength(siblings)
        assert len(violations) == 1
        assert violations[0].confidence == "medium"

    def test_detects_from_callees(self):
        from core.audit.postcondition_verify import check_sibling_sanitizer_strength

        siblings = [
            {"name": "a", "file": "f.py", "callees": ["escape_html", "log"]},
            {"name": "b", "file": "f.py", "callees": ["strip_tags", "log"]},
        ]
        violations = check_sibling_sanitizer_strength(siblings)
        assert len(violations) == 1

    def test_no_sanitizer_no_violation(self):
        from core.audit.postcondition_verify import check_sibling_sanitizer_strength

        siblings = [
            {"name": "a", "file": "f.py"},
            {"name": "b", "file": "f.py"},
        ]
        assert check_sibling_sanitizer_strength(siblings) == []
