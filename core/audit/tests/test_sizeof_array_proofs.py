"""LLM-suggested array accesses gain ABI-bound, replayed positive witnesses."""

import pytest

from core.audit import array_bounds, orchestrator as orch, sweep
from core.audit.evidence_grade import is_verification_evidence

SOURCE = "int Read(unsigned int Index){int Data[sizeof(long)]={0};if(Index<8)return Data[Index];return 0;}"
HYPOTHESIS = "out-of-bounds read at `Data[Index]`"


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize(
    "abi,extent,violated", [("ilp32", 4, True), ("llp64", 4, True), ("lp64", 8, False)]
)
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_sizeof_extent_changes_the_actual_access_obligation(
    abi, extent, violated, language
):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    result = array_bounds.check_array_bounds(
        SOURCE, HYPOTHESIS, language=language, integer_abi=abi
    )
    assert result["violation"] is violated, result
    assert result["source_access"]["extent"] == extent
    if violated:
        assert extent <= result["witness_index"] < 8


@pytest.mark.parametrize(
    "operand", ["Data", "long*", "_Bool", "int[Index]", "struct S"]
)
def test_missing_storage_or_runtime_extents_stay_unavailable(operand):
    result = array_bounds.check_array_bounds(
        SOURCE.replace("sizeof(long)", f"sizeof({operand})"),
        HYPOTHESIS,
        language="c",
        integer_abi="ilp32",
    )
    assert result["array_bounds_status"] == "unavailable", result
    assert result["violation"] is None


@pytest.mark.parametrize(
    "abi,expected", [("ilp32", ["smt:check-array-bounds"]), ("lp64", [])]
)
def test_hypothesis_reaches_the_positive_audit_channel(
    tmp_path, monkeypatch, abi, expected
):
    (tmp_path / "a.c").write_text(SOURCE)
    monkeypatch.setattr(
        sweep,
        "_smt_verb_in_subprocess",
        lambda **request: sweep._run_smt_verb_inner(**request),
    )
    config = orch.OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out", integer_abi=abi
    )
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-oob"}}],
        config=config,
        file_path="a.c",
        function_name="Read",
        source=SOURCE,
        hypothesis=HYPOTHESIS,
    )
    assert result == expected
    assert not any(row.verdict == "refuted" for row in result.outcomes)
    if expected:
        assert is_verification_evidence(result[0])


@pytest.mark.parametrize("guarded", [False, True])
def test_sizeof_allocation_prefix_allows_checked_integer_overflow(guarded):
    guard = "if(Value==2147483647)return 0;" if guarded else ""
    source = (
        "int Read(int Value){int Data[sizeof(long)]={0};" + "if(Value<0)return 0;" + guard + "return Value+1;}"
    )
    result = sweep._run_smt_verb_inner(
        file_path="a.c",
        function_name="Read",
        verb="check-overflow",
        source=source,
        hypothesis="integer overflow in `Value + 1`",
        integer_abi="ilp32",
    )
    assert result.outcome == ("refuted" if guarded else "confirmed"), result.details
    if not guarded:
        assert is_verification_evidence(result.rule_id)


def test_alignment_is_not_promoted_to_an_exact_size_fact():
    pytest.importorskip("tree_sitter_cpp")
    from core.audit.arithmetic_prefix import PrefixIntegerModel
    from core.audit.condition_extraction import _get_parser
    from core.smt_solver.integer_abi import resolve_integer_abi

    data = b"int Read(){return alignof(long);}"
    root = _get_parser("cpp").parse(data).root_node
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "alignof_expression":
            model = PrefixIntegerModel(data, "cpp", resolve_integer_abi("lp64"))
            assert model.size_domain(node) == (1, 8)
            return
        pending.extend(node.named_children)
    pytest.fail("alignment expression not bound")


@pytest.mark.slow
@pytest.mark.parametrize(
    "abi,expected", [("ilp32", "confirmed"), ("lp64", "inconclusive")]
)
def test_native_sizeof_array_counterexample(abi, expected):
    result = sweep.run_smt_verb_direct(
        file_path="a.c",
        function_name="Read",
        verb="check-array-bounds",
        source=SOURCE,
        hypothesis=HYPOTHESIS,
        integer_abi=abi,
    )
    assert result.outcome == expected, result
    if expected == "confirmed":
        assert 4 <= result.details["witness_index"] < 8
