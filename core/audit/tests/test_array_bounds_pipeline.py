"""Source array proofs keep their actual provenance and cannot refute a function."""

from dataclasses import asdict

import pytest

from core.audit import evidence_grade as grade, orchestrator as orch, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding, source_for_function
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_promotion_gate import receipt_preconditions
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult

SOURCE = "int Read(int Index) { int Data[4]={0}; if(Index >= 0 && Index <= 4) return Data[Index]; return 0; }"
HYPOTHESIS = "out-of-bounds read at `Data[Index]`"


@pytest.fixture
def prerequisites():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize("safe", [False, True])
def test_source_worker_confirms_only_a_real_violation(prerequisites, safe):
    text = SOURCE.replace("Index <= 4", "Index < 4") if safe else SOURCE
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-array-bounds",
                                     source=text, hypothesis=HYPOTHESIS, integer_abi="ilp32")
    assert result.outcome == ("inconclusive" if safe else "confirmed")
    assert result.rule_id == "smt:check-array-bounds"
    assert result.details["violation"] is (not safe)
    assert result.details["oracle_scope"] == "fixed-local-array-access"
    if not safe:
        assert result.details["witness_index"] == 4
        assert grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("fallback", [False, True])
def test_only_the_producer_receipt_grants_verification(monkeypatch, fallback):
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    assert grade.is_verification_evidence("smt:check-array-bounds")
    assert orch._promotion_grade_receipt("smt:check-array-bounds")
    assert not grade.is_verification_evidence("smt:check-oob")
    for suffix in (":witness", ":model", ":guessed"):
        assert not grade.is_verification_evidence("smt:check-array-bounds" + suffix)


@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
def test_positive_access_proofs_never_authorize_negative_claim_receipts(suffix):
    identity = SourceIdentity("source", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis=HYPOTHESIS)
    rule = "smt:check-array-bounds" + suffix
    negative = ClaimRefutation(**scope, source_identity=identity, checks=(ProbeOutcome("smt", "refuted", rule),))
    assert not negative.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("smt", "refuted", rule)
    assert chain.refutation_record(**scope) is None


@pytest.mark.parametrize("changed", ["abi", "hypothesis", "version", "source"])
def test_parent_rejects_mismatched_array_proofs(prerequisites, monkeypatch, changed):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-array-bounds", integer_abi="ilp32", hypothesis=HYPOTHESIS)
    if changed == "abi":
        binding["integer_abi"]["int_bits"] = 64
    elif changed == "hypothesis":
        binding["hypothesis_sha256"] = "other"
    elif changed == "version":
        binding["query_contract"] = "old"
    else:
        binding["sha256"] = "other"
    worker = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", outcome="confirmed",
                               rule_id="smt:check-array-bounds", details={"source_scope": binding}, matches=[{}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(worker))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-array-bounds",
                                        source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="ilp32")
    assert result.outcome == "inconclusive" and not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "inconclusive"])
def test_parent_caps_safe_site_results_even_from_a_matching_worker(prerequisites, monkeypatch, verdict):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-array-bounds", integer_abi="ilp32", hypothesis=HYPOTHESIS)
    worker = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", outcome=verdict,
                               rule_id="smt:check-array-bounds", details={"source_scope": binding}, matches=[{}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(worker))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-array-bounds",
                                        source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="ilp32")
    assert result.outcome == ("confirmed" if verdict == "confirmed" else "inconclusive")
    if verdict != "confirmed":
        assert not result.matches


def test_unknown_abi_stops_before_parser_vocabulary_or_child(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("an unknown ABI should not dispatch a source proof")
    monkeypatch.setattr(sweep, "_verb_vocab", forbidden)
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", forbidden)
    monkeypatch.setattr("core.audit.probe_function_scope.source_for_function", forbidden)
    for runner in (sweep._run_smt_verb_inner, sweep._smt_verb_in_subprocess):
        result = runner(file_path="record.c", function_name="Read", verb="check-array-bounds", source=SOURCE, hypothesis=HYPOTHESIS)
        assert result.outcome == "inconclusive"
        assert result.details["integer_abi_status"] == "unavailable"


@pytest.mark.parametrize("requested", ["check-oob", "check-array-bounds"])
def test_existing_audit_chain_reaches_the_source_proof_and_preserves_its_receipt(prerequisites, tmp_path, monkeypatch, requested):
    (tmp_path / "record.c").write_text(SOURCE)
    calls = []
    def worker(**request):
        calls.append(request["verb"])
        return sweep._run_smt_verb_inner(**request)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", worker)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32")
    result = orch._run_tool_chain([{"type": "smt", "config": {"verb": requested}}], config=config,
                                 file_path="record.c", function_name="Read", line_start=1, source=SOURCE, hypothesis=HYPOTHESIS)
    assert calls == ["check-array-bounds"]
    assert result == ["smt:check-array-bounds"]
    assert grade.is_verification_evidence(result[0])


def test_an_unsupported_object_keeps_the_existing_diagnostic_fallback(prerequisites, monkeypatch):
    calls = []
    def worker(**request):
        calls.append(request["verb"])
        return sweep._run_smt_verb_inner(**request)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", worker)
    result = sweep.run_smt_verb_direct(file_path="record.c", function_name="Read", verb="check-oob",
                                     source="int Read(int *Data, int Index) { return Data[Index]; }",
                                     hypothesis=HYPOTHESIS, integer_abi="ilp32")
    assert calls == ["check-array-bounds", "check-oob"]
    assert not grade.is_verification_evidence(result.rule_id)


def test_dispatch_and_caller_obligations_use_the_access_parameter():
    assert hypothesis_to_smt_verb(HYPOTHESIS) == "check-array-bounds"
    assert hypothesis_to_smt_verb("buffer overflow via memcpy") == "check-oob"
    contracts = receipt_preconditions("check-array-bounds", HYPOTHESIS, ["Index"], SOURCE)
    assert len(contracts) == 1 and contracts[0].param == "Index" and contracts[0].kind == "bounded"


@pytest.mark.slow
def test_real_confined_json_worker_returns_the_bound_counterexample(prerequisites):
    result = sweep.run_smt_verb_direct(file_path="record.c", function_name="Read", verb="check-array-bounds",
                                      source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="ilp32")
    assert result.outcome == "confirmed", result.errors
    assert result.details["witness_index"] == 4
    assert result.details["source_scope"]["integer_abi"]["name"] == "ilp32"


def test_old_overflow_worker_cannot_restore_dropped_reaching_facts(prerequisites, monkeypatch):
    text = "int Read(unsigned short Value, int Flag) { if(Flag > 10 && Flag < 5) return Value * Value; return 0; }"
    hypothesis = "integer overflow in `Value * Value`"
    _, selected = source_for_function(text, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", integer_abi="ilp32", hypothesis=hypothesis)
    binding["query_contract"] = "explicit-arithmetic-claim-v6"
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", outcome="confirmed",
                            rule_id="smt:check-overflow", details={"source_scope": binding}, matches=[{}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    observed = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                           source=text, hypothesis=hypothesis, integer_abi="ilp32")
    assert observed.outcome == "inconclusive" and not observed.matches
