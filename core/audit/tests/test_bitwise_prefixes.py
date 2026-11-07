"""Bitwise prefix bounds are proved in the actual promoted frame and consumed."""

from types import SimpleNamespace

import pytest

from core.audit import sweep
from core.audit.arithmetic_bitwise_domains import bitwise_domain
from core.audit.arithmetic_prefix_obligations import PrefixProofBudget
from core.audit.arithmetic_types import IntegerType

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def dependencies(monkeypatch, request):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    from core.audit import arithmetic_prefix_obligations

    if not request.node.get_closest_marker("slow"):
        # Domain semantics are independent of host scheduling at 100 ms.
        monkeypatch.setattr(arithmetic_prefix_obligations, "_BUDGET_MS", 5000)


@pytest.mark.parametrize("operator", ["&", "|", "^"])
@pytest.mark.parametrize(
    "signed,domains",
    [
        (True, [(-8, 7), (0, 3)]),
        (True, [(-8, -1), (-2, 5)]),
        (True, [(0, 3), (1, 6)]),
        (True, [(-8, 7), (-8, 7)]),
        (False, [(0, 15), (0, 3)]),
        (False, [(2, 7), (4, 15)]),
        (False, [(0, 0), (0, 0)]),
    ],
    ids=[
        "signed-mask",
        "signed-negative",
        "signed-positive",
        "signed-full",
        "unsigned-mask",
        "unsigned-partial",
        "unsigned-zero",
    ],
)
def test_proved_domains_contain_every_independent_four_bit_result(
    operator, signed, domains
):
    kind = IntegerType(4, signed, 4, signed)
    result = bitwise_domain(
        SimpleNamespace(proofs=PrefixProofBudget()), operator, kind, domains
    )
    assert result is not None
    low, high = result
    for a in range(domains[0][0], domains[0][1] + 1):
        for b in range(domains[1][0], domains[1][1] + 1):
            expected = {"&": a & b, "|": a | b, "^": a ^ b}[operator]
            assert low <= expected <= high, (a, b, operator, result)
    if operator == "&" and domains[1] == (0, 3):
        assert result == (0, 3)


@pytest.mark.parametrize("result", ["unknown", "sat"])
def test_unproved_interval_is_never_admitted(monkeypatch, result):
    import z3
    from core.audit import arithmetic_prefix_obligations as obligations

    monkeypatch.setattr(obligations, "check_solver", lambda solver: getattr(z3, result))
    domain = bitwise_domain(
        SimpleNamespace(proofs=PrefixProofBudget()),
        "&",
        IntegerType(32, True, 32, True),
        [(-(1 << 31), (1 << 31) - 1), (31, 31)],
    )
    assert domain is None


def test_mask_proof_respects_shared_check_cap():
    budget = PrefixProofBudget()
    budget.checks = 8
    assert (
        bitwise_domain(
            SimpleNamespace(proofs=budget),
            "&",
            IntegerType(32, False, 32, False),
            [(0, (1 << 32) - 1), (31, 31)],
        )
        is None
    )
    assert budget.checks == 8


PREFIXES = [
    pytest.param(
        "unsigned Local=Extra&(Count&31);", "int Extra,int Count", id="nested-mask"
    ),
    pytest.param(
        "unsigned Local=Extra<<(Count&31);",
        "unsigned Extra,int Count",
        id="masked-shift",
    ),
    pytest.param(
        "unsigned Local=(Extra|16)^7;", "unsigned Extra", id="unsigned-or-xor"
    ),
    pytest.param("int Local=(Count&31)+1;", "int Count", id="signed-bounded-add"),
    pytest.param("int Local=(Count|1)^3;", "int Count", id="signed-full-domain"),
]


def overflow_source(prefix, extra):
    return (
        "unsigned Read(unsigned Value,unsigned Step,"
        + extra
        + "){"
        + prefix
        + "if(Value<10 && Step<10){return Value+Step;}return 0;}"
    )


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("prefix,extra", PREFIXES)
def test_bitwise_prefix_reaches_overflow_verification_and_auxiliary_disproof(
    prefix, extra, language
):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    source = overflow_source(prefix, extra)
    hypothesis = "integer overflow in `Value + Step`"
    reply = sweep._run_smt_verb_inner(
        file_path="record." + language,
        function_name="Read",
        verb="check-overflow",
        source=source,
        hypothesis=hypothesis,
        integer_abi="ilp32",
    )
    assert reply.outcome == "refuted", reply.details
    assert (
        reply.details["source_scope"]["query_contract"]
        == "common-width-integer-operands-v19"
    )
    from core.audit.condition_smt import disprove_integer_overflow

    result = disprove_integer_overflow(
        hypothesis,
        source,
        file_path="record." + language,
        function_name="Read",
        integer_abi="ilp32",
    )
    assert result.disproved is True, result


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("prefix,extra", PREFIXES)
def test_bitwise_prefix_reaches_bounds_verification(prefix, extra, language):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    from core.audit.array_bounds import check_array_bounds

    source = (
        "int Read(int Index,"
        + extra
        + "){int Data[4]={0};"
        + prefix
        + "if(Index>=0 && Index<=4){return Data[Index];}return 0;}"
    )
    result = check_array_bounds(
        source,
        "out-of-bounds read at Data[Index]",
        language=language,
        integer_abi="lp64",
    )
    assert result["array_bounds_status"] == "checked" and result["violation"] is True, (
        result
    )
    assert result["witness_index"] == 4


@pytest.mark.parametrize(
    "prefix,extra",
    [
        ("int Local=Extra<<(Count&31);", "int Extra,int Count"),
        ("unsigned Local=Extra<<(Count|32);", "unsigned Extra,unsigned Count"),
        ("int Local=(Count&31)+(Extra*2);", "int Extra,int Count"),
        ("unsigned Local=Extra&(Count++);", "unsigned Extra,unsigned Count"),
        ("unsigned Local=Extra&Count;", "unsigned Extra,int Count"),
        ("unsigned Local=Extra&unknown();", "unsigned Extra"),
    ],
    ids=[
        "signed-shift-ub",
        "invalid-count",
        "nested-overflow",
        "mutation",
        "mixed-sign",
        "call",
    ],
)
def test_bitwise_wrapper_does_not_hide_undefined_or_unmodeled_operands(prefix, extra):
    reply = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name="Read",
        verb="check-overflow",
        source=overflow_source(prefix, extra),
        hypothesis="integer overflow in `Value + Step`",
        integer_abi="ilp32",
    )
    assert reply.outcome == "inconclusive", reply.details


@pytest.mark.parametrize("verb", ["check-overflow", "check-array-bounds"])
def test_literal_caller_consumes_bitwise_prefix_obligations(verb):
    from core.audit.literal_call import check_literal_calls, literal_call_witness_valid

    if verb == "check-overflow":
        source = (
            "unsigned long Read(unsigned long Value,unsigned long Step,int Count){unsigned Local=Count&31;"
            "if(Value>0){return Value*Step;}return 0;}\n"
            "unsigned long Caller(void){return Read(65536,65536,0);}"
        )
        hypothesis = "integer overflow in `Value * Step`"
        abi = "ilp32"
    else:
        source = (
            "int Read(int Index,int Count){int Data[4]={0};unsigned Local=Count&31;"
            "if(Index>=0 && Index<=4){return Data[Index];}return 0;}\n"
            "int Caller(void){return Read(4,0);}"
        )
        hypothesis, abi = "out-of-bounds read at Data[Index]", "lp64"
    reply = check_literal_calls(source, "Read", verb, hypothesis, abi, [2])
    assert reply["status"] == "checked" and len(reply["calls"]) == 1, reply
    call = reply["calls"][0]
    assert call["verdict"] == "violation"
    assert literal_call_witness_valid(reply, call, verb, hypothesis, abi)
    assert reply["binding"]["query_contract"] == "common-width-literal-frame-v6"


@pytest.mark.parametrize(
    "abi,mask,outcome",
    [
        ("i16", 15, "refuted"),
        ("i16", 31, "inconclusive"),
        ("ilp32", 31, "refuted"),
        ("lp64", 63, "inconclusive"),
    ],
)
def test_masked_shift_respects_target_int_width(abi, mask, outcome):
    source = overflow_source(
        f"unsigned Local=Extra<<(Count&{mask});", "unsigned Extra,int Count"
    )
    reply = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name="Read",
        verb="check-overflow",
        source=source,
        hypothesis="integer overflow in `Value + Step`",
        integer_abi=abi,
    )
    assert reply.outcome == outcome, reply.details


@pytest.mark.parametrize(
    "verb,version",
    [
        ("check-overflow", "common-width-integer-operands-v18"),
        ("check-array-bounds", "common-width-array-guards-v7"),
    ],
)
def test_previous_worker_contract_cannot_supply_bitwise_results(
    monkeypatch, verb, version
):
    from dataclasses import asdict

    from core.audit.probe_function_scope import source_binding

    source = overflow_source("int Local=Count&31;", "int Count")
    hypothesis = "integer overflow in `Value + Step`"
    if verb == "check-array-bounds":
        source = "int Read(int Index){int Data[4]={0};int Local=Index&3;if(Index<=4 && Index>=0)return Data[Index];return 0;}"
        hypothesis = "out-of-bounds read at Data[Index]"
    binding = source_binding(
        source, "Read", verb=verb, integer_abi="ilp32", hypothesis=hypothesis
    )
    binding["query_contract"] = version
    old = sweep.SweepResult(
        tool="smt",
        file_path="record.c",
        function_name="Read",
        rule_id="smt:" + verb,
        outcome="confirmed",
        details={"source_scope": binding},
        matches=[{"model": {}}],
    )
    monkeypatch.setattr(
        "core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old)
    )
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb=verb,
        source=source,
        hypothesis=hypothesis,
        integer_abi="ilp32",
    )
    assert result.outcome == "inconclusive" and result.matches == []
    assert result.details["source_scope_status"] == "unbound-worker-result"


@pytest.mark.parametrize("verb", ["check-overflow", "check-array-bounds"])
@pytest.mark.parametrize("stale", [False, True], ids=["current", "stale"])
def test_real_caller_gate_consumes_current_bitwise_proof_only(
    tmp_path, monkeypatch, verb, stale
):
    from core.audit import condition_smt
    from core.audit.smt_promotion_gate import evaluate_caller_gate

    if verb == "check-overflow":
        source = (
            "unsigned Read(unsigned Value,unsigned Step,int Count){unsigned Local=Count&31;"
            "if(Value>0 && Step>0)return Value*Step;return 0;}\n"
            "unsigned Caller(void){return Read(65536,65536,0);}"
        )
        hypothesis = "integer overflow in `Value * Step`"
    else:
        source = (
            "int Read(int Index,int Count){int Data[4]={0};int Local=Count&31;"
            "if(Index>=0 && Index<=4)return Data[Index];return 0;}\n"
            "int Caller(void){return Read(4,0);}"
        )
        hypothesis = "out-of-bounds read at Data[Index]"
    (tmp_path / "record.c").write_text(source)
    calls = []

    def dispatch(tag, args):
        calls.append(tag)
        result = condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        if stale:
            result["binding"]["query_contract"] = "common-width-literal-frame-v5"
        return result

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    result = evaluate_caller_gate(
        tmp_path,
        "record.c",
        "Read",
        verb,
        hypothesis,
        source=source,
        def_span=(1, 1),
        integer_abi="ilp32",
    )
    assert result.action == ("hold" if stale else "promote"), result.reason
    assert calls == ["literal_call"]


@pytest.mark.slow
@pytest.mark.parametrize("verb", ["check-overflow", "check-array-bounds"])
def test_native_confined_worker_consumes_bitwise_prefix(verb):
    source = overflow_source("int Local=Count&31;", "int Count")
    hypothesis, expected = "integer overflow in `Value + Step`", "refuted"
    if verb == "check-array-bounds":
        source = "int Read(int Index){int Data[4]={0};int Local=Index&3;if(Index>=0 && Index<=4)return Data[Index];return 0;}"
        hypothesis, expected = "out-of-bounds read at Data[Index]", "confirmed"
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb=verb,
        source=source,
        hypothesis=hypothesis,
        integer_abi="ilp32",
    )
    assert result.outcome == expected, result.details


@pytest.mark.parametrize("defined", [False, True])
def test_audit_chain_promotes_bounds_evidence_only_after_masked_shift_is_defined(
    tmp_path, monkeypatch, defined
):
    from core.audit import evidence_grade, orchestrator as orch

    count = "(Count&31)" if defined else "(Count|32)"
    source = (
        "int Read(int Index,unsigned Extra,unsigned Count){int Data[4]={0};"
        "unsigned Local=Extra<<" + count + ";"
        "if(Index>=0 && Index<=4){return Data[Index];}return 0;}"
    )
    (tmp_path / "record.c").write_text(source)
    calls = []

    def dispatch(**request):
        calls.append(request["verb"])
        return sweep._run_smt_verb_inner(**request)

    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", dispatch)
    config = orch.OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32"
    )
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-oob"}}],
        config=config,
        file_path="record.c",
        function_name="Read",
        line_start=1,
        source=source,
        hypothesis="out-of-bounds read at Data[Index]",
    )
    assert calls[0] == "check-array-bounds"
    if defined:
        assert result == ["smt:check-array-bounds"]
        assert evidence_grade.is_verification_evidence(result[0])
    else:
        assert "check-oob" in calls
        assert not any(evidence_grade.is_verification_evidence(rule) for rule in result)
