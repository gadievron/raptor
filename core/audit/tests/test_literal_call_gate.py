"""Caller promotion needs a bound tuple and a matching confined observation."""

from copy import deepcopy

import pytest

from core.audit import condition_smt, orchestrator as orch
from core.audit.literal_call import check_literal_calls
from core.audit.smt_promotion_gate import evaluate_caller_gate
from core.audit.tests.test_literal_call import ARRAY, HYPOTHESIS


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip("tree_sitter_c")


def fixture(tmp_path, monkeypatch, args="4, 1"):
    source = ARRAY + f"\nint Drive(void) {{ return Read({args}); }}\n"
    (tmp_path / "record.c").write_text(source)
    requests = []
    def worker(tag, args, **kwargs):
        requests.append((tag, args))
        return condition_smt._z3_dispatch_json({"tag": tag, "args": args})
    monkeypatch.setattr(condition_smt, "_run_z3_child", worker)
    return source, requests


def gate(tmp_path, source, **kwargs):
    return evaluate_caller_gate(tmp_path, "record.c", "Read", "check-array-bounds", HYPOTHESIS,
                                source=source, def_span=(1, 1), integer_abi="ilp32", **kwargs)


@pytest.mark.parametrize("args,action", [("4, 1", "promote"), ("4, 0", "hold"), ("3, 1", "hold")])
def test_gate_uses_the_whole_actual_tuple(tmp_path, monkeypatch, args, action):
    source, requests = fixture(tmp_path, monkeypatch, args)
    decision = gate(tmp_path, source)
    assert decision.action == action, decision.reason
    assert len(requests) == 1 and requests[0][0] == "literal_call"
    assert decision.details["proof_scope"] == "caller-entry-source-model"
    assert decision.site_count == 1
    if action == "promote":
        assert "record.c:2" in decision.citation and "Drive entry" in decision.citation
        assert decision.details["calls"][0]["arguments"] == {"Index": 4, "Flag": 1}
    else:
        assert decision.channel_outcome == "inconclusive"
        assert "application-entry reachability remain unresolved" in decision.reason


@pytest.mark.parametrize("field", ["source_sha256", "function", "hypothesis_sha256", "integer_abi", "site_lines", "language", "query_contract"])
def test_mismatched_worker_reply_never_promotes(tmp_path, monkeypatch, field):
    source, _ = fixture(tmp_path, monkeypatch)
    reply = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    reply["binding"][field] = "mismatched"
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: deepcopy(reply))
    decision = gate(tmp_path, source)
    assert decision.action == "hold"
    assert "binding mismatched" in decision.reason


@pytest.mark.parametrize("reply", [None, [], {}, {"status": "checked", "calls": []}])
def test_missing_or_failed_worker_keeps_the_receipt_held(tmp_path, monkeypatch, reply):
    source, _ = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: reply)
    assert gate(tmp_path, source).action == "hold"


def test_stale_callee_source_stops_before_worker(tmp_path, monkeypatch):
    source, requests = fixture(tmp_path, monkeypatch)
    stale = source.replace("Index <= 4", "Index < 4")
    assert gate(tmp_path, stale).action == "hold"
    assert requests == []


def test_cross_file_and_external_calls_do_not_gain_same_file_authority(tmp_path, monkeypatch):
    (tmp_path / "record.c").write_text(ARRAY + "\n")
    (tmp_path / "other.c").write_text("int Drive(void) { return Read(4, 1); }\n")
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: pytest.fail("unsupported cross-file call"))
    decision = gate(tmp_path, ARRAY)
    assert decision.action == "hold"
    assert "cross-file and external callers remain unresolved" in decision.reason


def test_unbound_worker_site_cannot_borrow_a_valid_source_manifest(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    reply = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    reply["calls"][0]["line"] = 1
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: reply)
    decision = gate(tmp_path, source)
    assert decision.action == "hold" and "unbound call obligation" in decision.reason


def test_orchestrator_passes_target_abi_into_the_gate(tmp_path, monkeypatch):
    source, requests = fixture(tmp_path, monkeypatch)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32")
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="clean", line=1)
    decision = orch._smt_caller_gate_decision(config, outcome, "check-array-bounds", HYPOTHESIS, source, line_end=1)
    assert decision.action == "promote", decision.reason
    assert requests[0][1]["integer_abi"]["name"] == "ilp32"


@pytest.mark.slow
@pytest.mark.parametrize("args,action", [("4, 1", "promote"), ("4, 0", "hold"), ("3, 1", "hold")])
def test_native_confined_literal_call_proof(tmp_path, args, action):
    source = ARRAY + f"\nint Drive(void) {{ return Read({args}); }}\n"
    (tmp_path / "record.c").write_text(source)
    decision = gate(tmp_path, source)
    assert decision.action == action, decision.reason
    assert decision.details["calls"][0]["arguments"]["Index"] == int(args[0])
    assert decision.details["binding"]["integer_abi"]["name"] == "ilp32"


def test_unknown_abi_does_not_dispatch_numeric_proofs(tmp_path, monkeypatch):
    source, requests = fixture(tmp_path, monkeypatch)
    decision = evaluate_caller_gate(tmp_path, "record.c", "Read", "check-array-bounds", HYPOTHESIS,
                                    source=source, def_span=(1, 1))
    assert decision.action == "hold"
    assert requests == []


def test_source_budget_stops_before_scope_parsing_and_worker(tmp_path, monkeypatch):
    source, requests = fixture(tmp_path, monkeypatch)
    from core.audit import literal_call_gate
    monkeypatch.setattr(literal_call_gate, "MAX_SOURCE_CHARS", 4)
    monkeypatch.setattr(literal_call_gate, "source_for_function", lambda *a: pytest.fail("over-budget source parsed"))
    decision = gate(tmp_path, source)
    assert decision.action == "hold" and "proof budget" in decision.reason
    assert requests == []


def test_wrong_scope_cannot_reuse_a_matching_query_manifest(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    reply = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    reply["proof_scope"] = "application-entry-reachable"
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: reply)
    assert gate(tmp_path, source).action == "hold"


@pytest.mark.parametrize("args,expected", [("4, 1", "finding"), ("4, 0", "suspicious"), ("3, 1", "suspicious")])
def test_source_array_cwe_dispatch_and_verdict_artifact_use_the_literal_gate(tmp_path, monkeypatch, args, expected):
    pytest.importorskip("z3")
    from core.audit import sweep
    source, _ = fixture(tmp_path, monkeypatch, args)
    seen = []
    def worker(**request):
        seen.append(request["verb"])
        return sweep._run_smt_verb_inner(**request)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", worker)
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, integer_abi="ilp32")
    hypothesis = {"mechanism": HYPOTHESIS, "confidence": "refuted"}
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="clean", line=1,
                                hypotheses=[hypothesis], review_result={"hypotheses": [hypothesis], "cwe": "CWE-125"})
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    checklist = {"files": [{"path": "record.c", "items": [{"name": "Read", "line_start": 1, "line_end": 1}]}]}
    orch._promote_clean_refuted(result, config, checklist=checklist)
    assert seen == ["check-array-bounds"]
    final = result.outcomes[0]
    assert final.status == expected, final.body
    artifact = final.review_result["smt_caller_gate"]
    assert artifact["details"]["proof_scope"] == "caller-entry-source-model"
    assert artifact["action"] == ("promote" if expected == "finding" else "hold")
    assert result.findings == int(expected == "finding")


@pytest.mark.parametrize("changed", ["missing-arguments", "guard-violation", "in-bounds", "wrong-index", "bool-index", "missing-parameter", "type-disagreement"])
def test_bound_but_invalid_counterexamples_cannot_promote(tmp_path, monkeypatch, changed):
    source, _ = fixture(tmp_path, monkeypatch)
    reply = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    call = reply["calls"][0]
    if changed == "missing-arguments":
        del call["arguments"]
    elif changed == "guard-violation":
        call["arguments"]["Flag"] = 0
    elif changed == "in-bounds":
        call["arguments"]["Index"] = call["witness_index"] = 3
    elif changed == "wrong-index":
        call["witness_index"] = 5
    elif changed == "bool-index":
        call["witness_index"] = True
    elif changed == "missing-parameter":
        del call["arguments"]["Flag"]
    else:
        reply["parameter_types"] = (("Index", "unsigned"), ("Flag", "int"))
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: reply)
    decision = gate(tmp_path, source)
    assert decision.action == "hold"
    assert "independent tuple validation" in decision.reason


@pytest.mark.slow
@pytest.mark.parametrize("step,action", [("-1", "promote"), ("0", "hold")])
def test_native_confined_literal_overflow_proof(tmp_path, step, action):
    source = ("int Read(int Value, int Step) { if(Value >= 1) return Value - Step; return 0; }\n"
              f"int Drive(void) {{ return Read(2147483647, {step}); }}\n")
    (tmp_path / "record.c").write_text(source)
    decision = evaluate_caller_gate(tmp_path, "record.c", "Read", "check-overflow", "integer overflow in `Value - Step`",
                                    source=source, def_span=(1, 1), integer_abi="ilp32")
    assert decision.action == action, decision.reason
    value = decision.details["calls"][0]["mathematical_result"]
    assert value == 2147483647 - int(step)


def test_write_cwe_cannot_mint_a_finding_from_a_read_only_obligation(tmp_path, monkeypatch):
    pytest.importorskip("z3")
    from core.audit import sweep
    _, requests = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", lambda **request: sweep._run_smt_verb_inner(**request))
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "smt", "config": {"verb": "check-array-bounds"}}])
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, integer_abi="ilp32")
    hypothesis = {"mechanism": HYPOTHESIS, "confidence": "refuted"}
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="clean", line=1,
                                hypotheses=[hypothesis], review_result={"hypotheses": [hypothesis], "cwe": "CWE-787"})
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    checklist = {"files": [{"path": "record.c", "items": [{"name": "Read", "line_start": 1, "line_end": 1}]}]}
    orch._promote_clean_refuted(result, config, checklist=checklist)
    assert result.findings == 0
    assert result.outcomes[0].status == "suspicious"
    assert requests == []


def test_literal_proof_does_not_enumerate_the_project(tmp_path, monkeypatch):
    from core.audit import api_boundary
    source, _ = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(api_boundary, "enumerate_call_sites_with_report", lambda *a, **kw: pytest.fail("literal proof scanned the project"))
    decision = gate(tmp_path, source, inventory={"deliberately": "unrelated snapshot"})
    assert decision.action == "promote", decision.reason
    assert decision.site_count == 1


def test_same_file_candidate_exhaustion_is_not_truncated_to_a_proof(tmp_path, monkeypatch):
    source, requests = fixture(tmp_path, monkeypatch)
    source += "\n" + "\n".join(f"int Other{n}(void) {{ return Read(4,1); }}" for n in range(41))
    (tmp_path / "record.c").write_text(source)
    decision = gate(tmp_path, source)
    assert decision.action == "hold" and "candidate budget exhausted" in decision.reason
    assert requests == []


def test_unicode_before_the_callee_does_not_shift_candidate_lines(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    source = "/* λ */\n" + source
    (tmp_path / "record.c").write_text(source)
    decision = evaluate_caller_gate(tmp_path, "record.c", "Read", "check-array-bounds", HYPOTHESIS,
                                    source=source, def_span=(2, 2), integer_abi="ilp32")
    assert decision.action == "promote", decision.reason
    assert decision.details["calls"][0]["line"] == 3


@pytest.mark.parametrize("args,status", [("4, 1", "finding"), ("4, 0", "suspicious")])
def test_proof_artifacts_survive_missing_review_metadata(tmp_path, monkeypatch, args, status):
    pytest.importorskip("z3")
    from core.audit import sweep
    fixture(tmp_path, monkeypatch, args)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", lambda **request: sweep._run_smt_verb_inner(**request))
    monkeypatch.setattr(orch, "_effective_cwe", lambda *a: "CWE-125")
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, integer_abi="ilp32")
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="clean", line=1,
                                hypotheses=[{"mechanism": HYPOTHESIS, "confidence": "refuted"}])
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    checklist = {"files": [{"path": "record.c", "items": [{"name": "Read", "line_start": 1, "line_end": 1}]}]}
    orch._promote_clean_refuted(result, config, checklist=checklist)
    final = result.outcomes[0]
    assert final.status == status
    assert final.review_result["smt_caller_gate"]["details"]["proof_scope"] == "caller-entry-source-model"


def test_same_line_wrapper_is_not_excluded_with_the_callee(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    source = ARRAY + " int Drive(void) { return Read(4,1); }\n"
    (tmp_path / "record.c").write_text(source)
    decision = gate(tmp_path, source)
    assert decision.action == "promote", decision.reason
    assert decision.details["calls"][0]["line"] == 1
    assert decision.details["calls"][0]["caller"] == "Drive"


def test_comment_call_shapes_do_not_exhaust_the_candidate_budget(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    source += "\n/* " + "Read(4,1);" * 41 + " */\n"
    (tmp_path / "record.c").write_text(source)
    assert gate(tmp_path, source).action == "promote"


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_forward_call_without_visible_signature_cannot_promote(monkeypatch, language):
    from core.audit.literal_call_gate import evaluate_literal_caller_gate

    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    callee = "int Read(int Value, int Step) { if(Value >= 1) return Value - Step; return 0; }"
    wrapper = "int Drive(void) { return Read(2147483647, -1); }"
    hypothesis = "integer overflow in `Value - Step`"
    requests = []

    def dispatch(tag, args, **kwargs):
        requests.append(args)
        return condition_smt._z3_dispatch_json({"tag": tag, "args": args})

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    forward = wrapper + "\n" + callee
    refused = evaluate_literal_caller_gate(
        "record." + language, "Read", "check-overflow", hypothesis,
        defining_source=forward, source=forward, integer_abi="ilp32",
    )
    assert len(requests) == 1
    assert refused.action == "hold" and refused.channel_outcome == "inconclusive"
    assert refused.details["status"] == "checked" and refused.details["calls"] == []
    ordered = callee + "\n" + wrapper
    admitted = evaluate_literal_caller_gate(
        "record." + language, "Read", "check-overflow", hypothesis,
        defining_source=ordered, source=ordered, integer_abi="ilp32",
    )
    assert len(requests) == 2
    assert admitted.action == "promote" and admitted.channel_outcome == "confirmed"
    assert admitted.details["calls"][0]["mathematical_result"] == 2147483648


def test_previous_visibility_contract_cannot_supply_a_receipt(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    old = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    assert old["calls"][0]["verdict"] == "violation"
    old["binding"]["query_contract"] = "common-width-literal-frame-v9"
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *args, **kwargs: deepcopy(old))
    refused = gate(tmp_path, source)
    assert refused.action == "hold"
    assert "binding mismatched" in refused.reason
