"""Named narrowing probes must not borrow observations from neighboring code."""

import pytest

from core.audit import condition_smt, evidence_grade, orchestrator as orch, sweep
from core.audit.narrowing_guards import NarrowingGuardContext, integer_range


C_SOURCE = """size_t shared;
int Neighbor(size_t value) {
    int small = value;
    return small;
}
int Read(int value) {
    int same_width = value;
    return same_width;
}
int ReadShared(void) {
    int small = shared;
    return small;
}
"""
GO_SOURCE = """package example
import "strconv"
func Neighbor(text string) uint32 {
    value, _ := strconv.Atoi(text)
    small := uint32(value)
    return small
}
func Read(value int) int {
    return value
}
"""


@pytest.fixture(autouse=True)
def no_solver(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


@pytest.mark.parametrize(
    "name,found",
    [
        ("Read", False),
        ("Neighbor", True),
        ("ReadShared", True),
        ("Missing", False),
        ("", False),
    ],
)
def test_c_observation_belongs_to_the_requested_function(name, found):
    result = condition_smt.check_integer_narrowing(
        C_SOURCE, function_name=name, language="c"
    )
    assert result.narrowing_found is found
    if name == "ReadShared":
        assert result.source_type == "size_t"  # preserve surrounding type context
        assert result.assign_line == 11


@pytest.mark.parametrize(
    "name,found", [("Read", False), ("Neighbor", True), ("Missing", False), ("", False)]
)
def test_go_observation_belongs_to_the_requested_function(name, found):
    result = condition_smt.check_integer_narrowing(
        GO_SOURCE, function_name=name, language="go"
    )
    assert result.narrowing_found is found
    if found:
        assert result.assign_line == 5


def test_go_does_not_borrow_a_parse_variable_from_another_function():
    source = """package example
func Neighbor(text string) { value, _ := strconv.Atoi(text) }
func Read(value int32) { small := uint32(value) }
"""
    assert not condition_smt.check_integer_narrowing(
        source, function_name="Read", language="go"
    ).narrowing_found


def test_unscoped_api_still_supports_file_wide_candidate_collection():
    assert condition_smt.check_integer_narrowing(C_SOURCE).narrowing_found
    assert condition_smt.check_integer_narrowing(GO_SOURCE).narrowing_found


@pytest.mark.parametrize("name", ["Read", "A.Read", "B::Read", "Other.Read"])
def test_cpp_methods_require_a_unique_name(name):
    source = """struct A { int Read(int value) { return value; } };
struct B { int Read(size_t value) { int small = value; return small; } };
"""
    result = condition_smt.check_integer_narrowing(
        source, function_name=name, language="cpp"
    )
    assert result.narrowing_found is (name == "B::Read")
    if name == "Read":
        assert "ambiguous" in result.reasoning


@pytest.mark.parametrize(
    "name,found", [("Read", False), ("Box.Read", True), ("Other.Read", False)]
)
def test_go_receiver_names_disambiguate_methods(name, found):
    source = """package example
func(b *Box) Read(text string) uint32 { value, _ := strconv.Atoi(text); small := uint32(value); return small }
func(b *Other) Read(value int) int { return value }
"""
    result = condition_smt.check_integer_narrowing(
        source, function_name=name, language="go"
    )
    assert result.narrowing_found is found


def test_a_nested_named_function_is_not_its_enclosing_function():
    source = "int Read(void) { int Nested(size_t value) { int small = value; return small; } return 0; }"
    assert not condition_smt.check_integer_narrowing(
        source, function_name="Read", language="c"
    ).narrowing_found
    assert condition_smt.check_integer_narrowing(
        source, function_name="Nested", language="c"
    ).narrowing_found


@pytest.mark.parametrize("language,source", [("c", C_SOURCE), ("go", GO_SOURCE)])
def test_named_probe_declines_when_parser_is_unavailable(monkeypatch, language, source):
    monkeypatch.setattr("core.audit.condition_extraction._get_parser", lambda *a: None)
    result = condition_smt.check_integer_narrowing(
        source, function_name="Neighbor", language=language
    )
    assert not result.narrowing_found
    assert "unavailable" in result.reasoning


def test_naming_and_type_checks_reuse_one_parse(monkeypatch):
    from core.audit import condition_extraction

    parser = condition_extraction._get_parser("c")
    calls = []

    class CountingParser:
        def parse(self, source):
            calls.append(source)
            return parser.parse(source)

    monkeypatch.setattr(
        condition_extraction, "_get_parser", lambda *a: CountingParser()
    )
    context = NarrowingGuardContext(C_SOURCE)
    scope = context.function_scope("Neighbor")
    assert scope.status == "selected"
    location = dict(line=2, column=len("    int small ="))
    assert context.in_function(**location, scope=scope)
    assert context.visible_types(**location)["value"] == "size_t"
    assert context.may_use_value("value", **location)
    assert not context.protects(
        "value",
        **location,
        source_range=integer_range("size_t", 64),
        dest_range=integer_range("int", 32),
        source_type="size_t",
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "name,found", [("Read", False), ("Neighbor", True), ("Missing", False)]
)
def test_real_worker_keeps_attribution_and_diagnostic_authority(name, found):
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name=name,
        verb="check-integer-narrowing",
        source=C_SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == ("confirmed" if found else "inconclusive")
    assert result.function_name == name
    assert not evidence_grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("phase", ["screen", "clean"])
def test_audit_callers_pass_the_requested_identity(tmp_path, monkeypatch, phase):
    calls = []
    original = condition_smt.check_integer_narrowing

    def observed(source, **kwargs):
        calls.append(kwargs)
        return original(source, **kwargs)

    monkeypatch.setattr(condition_smt, "check_integer_narrowing", observed)
    monkeypatch.setattr(orch, "_read_raw_source", lambda *a, **kw: C_SOURCE)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=None)
    result = orch.OrchestratorResult()
    if phase == "screen":
        gap = {"file": "record.c", "name": "Read", "line_start": 6}
        kept = orch._pre_loop_smt_screen([gap], config, result)
        assert kept == [gap]
        assert not gap.get("_smt_pre_evidence", "").startswith(
            "smt:check-integer-narrowing"
        )
    else:
        outcome = orch.ReviewOutcome(
            file="record.c", function="Read", line=6, status="clean", body="review"
        )
        result.outcomes = [outcome]
        result.clean = 1
        orch._promote_smt_clean(result, config)
        assert result.outcomes[0].status == "clean"
    assert calls == [{"function_name": "Read", "language": "c"}]


@pytest.mark.parametrize("name", ["", None])
def test_worker_cannot_opt_into_file_wide_analysis_with_a_missing_name(name):
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name=name,
        verb="check-integer-narrowing",
        source=C_SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
