"""Concrete callers can prove unguarded arithmetic without abstract SAT."""

import pytest

from core.audit import condition_smt, sweep
from core.audit.literal_call import check_literal_calls
from core.audit.literal_call_observation import complete_literal_overflow_observation, read_literal_call_source

CALLEE = "int Add(int Value, int Step) { return Value + Step; }"
CLAIM = "integer overflow in `Value + Step`"


@pytest.fixture
def workers(monkeypatch):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    requests = []
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", lambda **args: sweep._run_smt_verb_inner(**args))
    def dispatch(tag, args, **kwargs):
        requests.append((tag, args))
        return condition_smt._z3_dispatch_json({"tag": tag, "args": args})
    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    return requests


def observe(tmp_path, args="2147483647, 1", **kwargs):
    (tmp_path / "unit.c").write_text(CALLEE + f"\nint Drive(void) {{ return Add({args}); }}\n")
    return sweep.run_smt_verb_direct(file_path="unit.c", function_name="Add", verb="check-overflow",
                                     source=CALLEE, hypothesis=CLAIM, target_path=str(tmp_path),
                                     integer_abi="ilp32", **kwargs)


@pytest.mark.parametrize("args,expected", [("2147483647, 1", "confirmed"), ("1, 1", "inconclusive"),
                                          ("-2147483647, -2", "confirmed"), ("0, 0", "inconclusive")])
def test_complete_tuple_can_confirm_when_callee_has_no_guards(tmp_path, workers, args, expected):
    result = observe(tmp_path, args)
    assert result.outcome == expected, result.details
    assert len(workers) == 1
    if expected == "confirmed":
        assert result.rule_id == "smt:check-overflow:literal-call"
        assert result.details["proof_scope"] == "caller-entry-source-model"
        assert result.details["calls"][0]["arguments"]["Step"] == int(args.split(",")[1])
        assert result.details["callee_observation"]["summary"].startswith("no source-level guard")


def test_function_memo_entry_excludes_caller_proof(tmp_path, workers):
    result = observe(tmp_path, include_callers=False)
    assert result.outcome == "inconclusive"
    assert workers == []


@pytest.mark.parametrize("outcome", ["confirmed", "refuted", "error"])
def test_caller_fallback_does_not_override_other_definitive_results(tmp_path, monkeypatch, outcome):
    result = sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Add", outcome=outcome,
                               rule_id="smt:check-overflow")
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **kw: pytest.fail("unexpected worker"))
    assert complete_literal_overflow_observation(result, target_path=tmp_path, file_path="unit.c",
                                                 function_name="Add", source=CALLEE, hypothesis=CLAIM,
                                                 integer_abi="ilp32") is result


@pytest.mark.parametrize("source", ["int Add(int Value, int Step) { return Value - Step; }", "", "int Other(void){return 0;}"])
def test_stale_or_missing_callee_never_borrows_current_call(tmp_path, workers, source):
    (tmp_path / "unit.c").write_text(CALLEE + "\nint Drive(void){return Add(2147483647,1);}")
    initial = sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Add", outcome="inconclusive", rule_id="smt:check-overflow")
    result = complete_literal_overflow_observation(initial, target_path=tmp_path, file_path="unit.c",
                                                  function_name="Add", source=source, hypothesis=CLAIM, integer_abi="ilp32")
    assert result is initial and workers == []


@pytest.mark.parametrize("content", [b"x" * 262145, b"a\n" + b"x" * 262145, b"\xff", b"\xce\xbb" * 65537])
def test_whole_file_reader_declines_truncated_or_invalid_source(tmp_path, content):
    (tmp_path / "unit.c").write_bytes(content)
    assert read_literal_call_source(tmp_path, "unit.c") is None


def test_reader_never_reads_an_escaping_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.c").write_text(CALLEE)
    (root / "link.c").symlink_to(tmp_path / "outside.c")
    assert read_literal_call_source(root, "../outside.c") is None
    assert read_literal_call_source(root, "link.c") is None


@pytest.mark.parametrize("fallback", [False, True])
def test_literal_receipt_is_positive_only_and_has_explicit_fallback_grade(monkeypatch, fallback):
    from core.audit import evidence_grade
    from core.audit.smt_evidence import is_non_refuting_smt_rule
    if fallback:
        monkeypatch.setattr(evidence_grade, "_channel_detection_classifier", lambda _: None)
    assert evidence_grade.is_verification_evidence("smt:check-overflow:literal-call")
    assert is_non_refuting_smt_rule("smt:check-overflow:literal-call")


@pytest.mark.parametrize("verdict", ["clean", "finding", "suspicious"])
def test_persisted_function_hash_cannot_reauthorize_a_caller_proof(tmp_path, verdict):
    from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
    from core.audit.tests.test_verdict_reuse import _entry, _write_target
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=["clean-refuted:smt:check-overflow:literal-call"])
    entry.verdict = verdict
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "literal caller proof requires full source revalidation"
    assert _reuse_block_class(reason) == "literal_caller"


def test_caller_edits_cannot_reuse_a_function_scoped_sweep_memo(tmp_path, workers, monkeypatch):
    from core.audit import orchestrator as orch
    from core.audit.sweep_memo import SweepMemo
    callee_requests = []
    def callee_worker(**request):
        callee_requests.append(request)
        return sweep._run_smt_verb_inner(**request)
    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", callee_worker)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32")
    config.sweep_memo = SweepMemo()
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]
    for step, expected in [(0, []), (1, ["smt:check-overflow:literal-call"]), (0, [])]:
        (tmp_path / "unit.c").write_text(CALLEE + f"\nint Drive(void) {{ return Add(2147483647,{step}); }}\n")
        actual = orch._run_tool_chain(chain, config=config, file_path="unit.c", function_name="Add",
                                      source=CALLEE, hypothesis=CLAIM, line_start=1)
        assert actual == expected
    assert len(callee_requests) == 1
    assert len(workers) == 3  # current caller snapshot checked on every invocation


@pytest.mark.parametrize("step,status", [(1, "finding"), (0, "clean")])
def test_clean_refuted_lane_reaches_independent_unguarded_call_proof(tmp_path, workers, monkeypatch, step, status):
    from core.audit import orchestrator as orch
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [])
    (tmp_path / "unit.c").write_text(CALLEE + f"\nint Drive(void) {{ return Add(2147483647,{step}); }}\n")
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, integer_abi="ilp32")
    hypothesis = {"mechanism": CLAIM, "confidence": "refuted"}
    outcome = orch.ReviewOutcome(file="unit.c", function="Add", status="clean", body="clean", line=1,
                                hypotheses=[hypothesis], review_result={"hypotheses": [hypothesis], "cwe": "CWE-190"})
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    checklist = {"files": [{"path": "unit.c", "items": [{"name": "Add", "line_start": 1, "line_end": 1}]}]}
    orch._promote_clean_refuted(result, config, checklist=checklist)
    final = result.outcomes[0]
    assert final.status == status, final.body
    if status == "finding":
        assert final.evidence_tool == "clean-refuted:smt:check-overflow:literal-call"
        artifact = final.review_result["smt_caller_gate"]["details"]
        assert artifact["proof_scope"] == "caller-entry-source-model"
        assert artifact["calls"][0]["mathematical_result"] == 2147483648
        assert "Drive entry" in final.body
    assert result.findings == int(status == "finding")


@pytest.mark.parametrize("damage", ["binding", "witness", "scope", "crash"])
def test_unavailable_or_invalid_literal_proof_preserves_inconclusive(tmp_path, workers, monkeypatch, damage):
    reply = check_literal_calls(CALLEE + "\nint Drive(void){return Add(2147483647,1);}\n", "Add",
                                "check-overflow", CLAIM, "ilp32", [2])
    if damage == "binding":
        reply["binding"]["source_sha256"] = "stale"
    elif damage == "witness":
        reply["calls"][0]["arguments"]["Step"] = 0
    elif damage == "scope":
        reply["proof_scope"] = "application-entry"
    def dispatch(*args, **kwargs):
        if damage == "crash":
            raise RuntimeError("owned test failure")
        return reply
    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    assert observe(tmp_path).outcome == "inconclusive"


@pytest.mark.slow
@pytest.mark.parametrize("step,outcome", [(1, "confirmed"), (0, "inconclusive")])
def test_native_workers_can_prove_a_concrete_unguarded_overflow(tmp_path, step, outcome):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    result = observe(tmp_path, f"2147483647, {step}")
    assert result.outcome == outcome, result.details
    if outcome == "confirmed":
        assert result.details["proof_scope"] == "caller-entry-source-model"
        assert result.details["calls"][0]["mathematical_result"] == 2147483648


@pytest.mark.parametrize("receipt", ["smt:check-overflow:literal-call:witness", "smt:check-overflow:literal-call:reachable",
                                     "smt:check-overflow:invented:literal-call"])
@pytest.mark.parametrize("fallback", [False, True])
def test_unminted_literal_proof_suffixes_do_not_gain_authority(monkeypatch, receipt, fallback):
    from core.audit import evidence_grade
    if fallback:
        monkeypatch.setattr(evidence_grade, "_channel_detection_classifier", lambda _: None)
    assert not evidence_grade.is_verification_evidence(receipt)


def test_literal_receipt_cannot_clear_a_claim_even_if_a_consumer_supplies_refuted():
    from core.audit.verification_results import ToolChainResult
    result = ToolChainResult(file="unit.c", function="Add", line_start=1, hypothesis=CLAIM)
    result.observe("smt", "refuted", "smt:check-overflow:literal-call")
    assert result.refutations(file="unit.c", function="Add", line_start=1, hypothesis=CLAIM) == ()


def test_oversized_line_cannot_hide_the_rest_of_the_translation_unit(tmp_path, workers):
    from core.audit.smt_promotion_gate import evaluate_caller_gate
    from core.source.contained import DEFAULT_MAX_SOURCE_CHARS
    source = CALLEE + "\nint Drive(void){ return Add(2147483647,1); }\n"
    # The old text reader returned the valid prefix after dropping this
    # over-cap partial line. A proof consumer needs the truncation bit.
    (tmp_path / "unit.c").write_text(source + "/*" + "x" * DEFAULT_MAX_SOURCE_CHARS + "*/\n")
    decision = evaluate_caller_gate(tmp_path, "unit.c", "Add", "check-overflow", CLAIM,
                                    source=CALLEE, integer_abi="ilp32")
    assert decision.action == "hold" and workers == []
