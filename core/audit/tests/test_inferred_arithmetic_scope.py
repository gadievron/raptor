"""Heuristic arithmetic models do not establish source access semantics."""

from dataclasses import asdict

import pytest

from core.audit import evidence_grade as grade, orchestrator as orch, sweep
from core.audit.probe_function_scope import source_binding, source_for_function
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult

VERBS = ("check-oob", "check-overflow-to-oob", "check-negative-bypass")
@pytest.fixture
def c_parser():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


CASES = [
    pytest.param("check-oob", "unsigned Read(unsigned idx, unsigned buflen) { if(idx <= buflen) return 1; return 0; }",
                 "`idx` is an index into buffer of size `buflen`", True, id="no-access-sat"),
    pytest.param("check-oob", "unsigned Read(unsigned idx, unsigned buflen) { if(idx < buflen) return 1; return 0; }",
                 "`idx` is an index into buffer of size `buflen`", False, id="no-access-unsat"),
    pytest.param("check-negative-bypass", "int Read(int amount, int limit) { return amount + limit; }",
                 "negative `amount` bypass `limit` check", True, id="no-conversion-or-guard"),
    pytest.param("check-overflow-to-oob", "unsigned Read(unsigned count, unsigned elem_size, unsigned index) { if(count > 0) return index; return 0; }",
                 "overflow of `count` * `elem_size` at `index`", True, id="no-allocation-or-access"),
]


@pytest.mark.parametrize("verb,source,hypothesis,feasible", CASES)
@pytest.mark.parametrize("abi", [None, "ilp32", "lp64"])
def test_real_math_does_not_establish_missing_source_semantics(c_parser, verb, source, hypothesis, feasible, abi):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb=verb,
                                     source=source, hypothesis=hypothesis, integer_abi=abi)
    assert result.outcome == ("confirmed" if feasible else "inconclusive")
    assert result.details["feasible"] is feasible
    assert result.details["oracle_scope"] == "inferred-arithmetic-model"
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
@pytest.mark.parametrize("fallback", [False, True])
def test_model_receipts_cannot_gain_verification(monkeypatch, verb, suffix, fallback):
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    receipt = f"smt:{verb}{suffix}"
    assert sweep.get_smt_verb_role(verb + suffix) == "detection"
    assert sweep.is_detection_rule_id(receipt)
    assert not grade.is_tool_evidence(receipt)
    assert not orch._promotion_grade_receipt(receipt)
    assert grade.is_verification_evidence(receipt + "+lifecycle")
    assert grade.is_verification_evidence("smt:check-overflow")


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
def test_source_identity_cannot_authorize_model_refutation(verb, suffix):
    identity = SourceIdentity("source", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    receipt = f"smt:{verb}{suffix}"
    negative = ClaimRefutation(**scope, source_identity=identity,
                               checks=(ProbeOutcome("smt", "refuted", receipt),))
    assert not negative.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("smt", "refuted", receipt)
    assert not chain.refutations(**scope)
    assert chain.refutation_record(**scope) is None


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "inconclusive"])
def test_parent_caps_bound_old_worker_models(c_parser, monkeypatch, verb, verdict):
    source = "int Read(void) { return 0; }"
    _, selected = source_for_function(source, "record.c", "Read")
    result = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                              outcome=verdict, rule_id=f"smt:{verb}", matches=[{"model": {"x": 1}}],
                              details={"source_scope": source_binding(selected, "Read", verb=verb, hypothesis="claim")})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(result))
    observed = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb=verb,
                                            source=source, hypothesis="claim")
    assert observed.outcome == ("confirmed" if verdict == "confirmed" else "inconclusive")
    assert observed.details["oracle_scope"] == "inferred-arithmetic-model"
    if verdict != "confirmed":
        assert not observed.matches


def test_missing_element_size_stops_before_solver(c_parser, monkeypatch):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("missing element size must not be replaced with four")

    monkeypatch.setattr(smt_verbs, "check_overflow_to_oob", forbidden)
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="check-overflow-to-oob",
        source="unsigned Read(unsigned count, unsigned index) { if(count > 0) return index; return 0; }",
        hypothesis="overflow in count at index",
    )
    assert result.outcome == "inconclusive"
    assert not result.errors


@pytest.mark.parametrize("verb,suffix", [(verb, suffix) for verb in VERBS for suffix in ("", ":witness")])
def test_old_clean_model_receipts_require_fresh_review(tmp_path, verb, suffix):
    from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
    from core.audit.tests.test_verdict_reuse import _entry, _write_target

    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=[f"semgrep:lead + smt:{verb}{suffix}"],
                   body="review", clean_basis="verdict")
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "diagnostic SMT receipt requires fresh review"
    assert _reuse_block_class(reason) == "diagnostic_smt"


@pytest.mark.parametrize("verb,source,hypothesis,feasible", CASES)
def test_tool_chain_retains_only_diagnostic_model_evidence(c_parser, tmp_path, monkeypatch, verb, source, hypothesis, feasible):
    pytest.importorskip("z3")
    (tmp_path / "record.c").write_text(source)
    monkeypatch.setattr(orch, "run_smt_verb_direct", sweep._run_smt_verb_inner)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32")
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis=hypothesis)
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": verb}}], config=config, source=source,
        file_path=scope["file"], function_name=scope["function"],
        line_start=scope["line_start"], hypothesis=hypothesis,
    )
    assert bool(result) is feasible
    assert not any(grade.is_verification_evidence(receipt) for receipt in result)
    assert not result.refutations(**scope)
    assert result.refutation_record(**scope) is None


@pytest.mark.parametrize("feasible", [True, False])
def test_explicit_math_api_keeps_its_numeric_result(feasible):
    pytest.importorskip("z3")
    from packages.exploit_feasibility.smt_verbs import check_oob, check_overflow_to_oob, check_negative_bypass

    guard = "idx <= size" if feasible else "idx < size"
    assert check_oob("size", "idx", guards=[guard])["feasible"] is feasible
    guard = "amount < 0" if feasible else "amount >= 0"
    assert check_negative_bypass("amount", "limit", guards=[guard])["feasible"] is feasible
    guards = ["count > 0"] if feasible else ["count <= 10", "elem_size <= 4", "elem_size > 0"]
    assert check_overflow_to_oob("count", "elem_size", "idx", guards=guards)["feasible"] is feasible


@pytest.mark.parametrize("verdict", ["suspicious", "finding"])
def test_diagnostic_receipts_do_not_invalidate_nonclean_reviews(tmp_path, verdict):
    from core.audit.gaps import _reuse_ineligibility
    from core.audit.tests.test_verdict_reuse import _entry, _write_target

    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, evidence_tools=["smt:check-oob"], body="review")
    assert _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None) is None
