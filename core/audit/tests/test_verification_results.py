"""Explicit negative outcomes retain the claim and occurrence they tested."""

from copy import deepcopy

import pytest

from core.audit import orchestrator as orch
from core.audit.sweep import SweepResult
from core.audit.verification_results import ToolChainResult


SCOPE = {"file": "record.c", "function": "Read", "line_start": 8,
         "hypothesis": "integer overflow in length"}


def negative():
    result = ToolChainResult(**SCOPE)
    result.observe("smt", "refuted", "check-overflow", "overflow constraint is unsatisfiable")
    return result


def test_empty_confirmation_list_contains_no_negative_evidence():
    result = ToolChainResult(**SCOPE)
    assert result == []
    assert not result.refutations(**SCOPE)
    assert result.refutation_record(**SCOPE) is None


@pytest.mark.parametrize("verdict", ["inconclusive", "error", "skipped", "unexpected"])
def test_only_an_explicit_refutation_can_supply_negative_evidence(verdict):
    result = ToolChainResult(**SCOPE)
    result.observe("smt", verdict, "check-overflow")
    assert not result.refutations(**SCOPE)


@pytest.mark.parametrize("change", [
    {"file": "different.c"}, {"function": "Other"},
    {"line_start": 18}, {"hypothesis": "null dereference"},
])
def test_negative_evidence_cannot_move_to_another_claim_or_occurrence(change):
    assert not negative().refutations(**dict(SCOPE, **change))


def test_explicit_refutation_has_a_durable_receipt_shape():
    record = negative().refutation_record(**SCOPE)
    assert record["action"] == "ihv_refutation"
    assert {k: record[k] for k in SCOPE} == SCOPE
    assert record["checks"] == [{"tool": "smt", "verdict": "refuted", "rule_id": "check-overflow",
                                  "reason": "overflow constraint is unsatisfiable"}]


def test_unidentified_negative_has_no_refutation_authority():
    result = ToolChainResult(**SCOPE)
    result.observe("smt", "refuted", "")
    assert not result.refutations(**SCOPE)


@pytest.mark.parametrize("with_receipt", [False, True])
def test_conflicting_observations_do_not_claim_refutation(with_receipt):
    result = negative()
    result.observe("semgrep", "confirmed", "candidate")
    if with_receipt:
        result.append("semgrep:candidate")
    assert not result.refutations(**SCOPE)


def test_positive_list_compatibility_and_copy_isolation():
    result = ToolChainResult(["semgrep:r"], **SCOPE)
    result.observe("semgrep", "confirmed", "r")
    copied = deepcopy(result)
    copied.append("smt:check-overflow")
    copied.outcomes.clear()
    assert list(result) == ["semgrep:r"]
    assert len(result.outcomes) == 1


@pytest.mark.parametrize("verdict", ["refuted", "inconclusive", "error", "skipped", "novel"])
def test_real_dispatcher_retains_the_actual_checker_outcome(tmp_path, monkeypatch, verdict):
    (tmp_path / SCOPE["file"]).write_text("\n" * 7 + "int Read(void) { return 0; }\n")
    monkeypatch.setattr(orch, "run_smt_verb_direct", lambda **kw: SweepResult(
        tool="smt", file_path=SCOPE["file"], function_name=SCOPE["function"],
        outcome=verdict, rule_id="check-overflow", details={"reason": "checker result"},
    ))
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}],
        config=config, file_path=SCOPE["file"], function_name=SCOPE["function"],
        source="int Read(void) { return 0; }", hypothesis=SCOPE["hypothesis"],
        line_start=SCOPE["line_start"],
    )
    assert result == []
    assert len(result.outcomes) == 1
    assert result.outcomes[0].verdict == ("error" if verdict == "novel" else verdict)
    assert bool(result.refutations(**SCOPE)) == (verdict == "refuted")


def test_no_dispatch_handler_is_not_a_refutation(tmp_path, monkeypatch):
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "unhandled-check", "config": {}}])
    outcome = orch.ReviewOutcome(file=SCOPE["file"], function=SCOPE["function"],
                                line=SCOPE["line_start"], hypothesis=SCOPE["hypothesis"],
                                status="suspicious", body="unresolved claim")
    result = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult())
    assert result.status == "suspicious"
    assert not result.review_result.get("immediate_verified")
    assert not result.review_result.get("ihv_all_refuted")
    assert "unhandled-check" not in (result.tools_dispatched or set())
    assert result.tools_skipped == {"unhandled-check"}


def test_negative_result_with_checker_errors_is_not_a_refutation(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "run_smt_verb_direct", lambda **kw: SweepResult(
        tool="smt", file_path=SCOPE["file"], function_name=SCOPE["function"],
        outcome="refuted", rule_id="check-overflow", errors=["partial analysis"],
    ))
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}],
        config=config, file_path=SCOPE["file"], function_name=SCOPE["function"],
        source="", hypothesis=SCOPE["hypothesis"], line_start=SCOPE["line_start"],
    )
    assert result.outcomes[0].verdict == "error"
    assert not result.refutations(**SCOPE)


def test_an_explicit_refutation_is_not_erased_by_an_unrelated_failed_probe():
    result = negative()
    result.observe("codeql", "error", "another-check", "checker unavailable")
    assert len(result.refutations(**SCOPE)) == 1


@pytest.mark.parametrize("guarded", [False, True])
def test_live_semgrep_verdict_reaches_ihv_with_its_receipt(tmp_path, monkeypatch, guarded):
    from packages.semgrep.runner import is_available
    from core.audit.record import load_audit_log

    if not is_available():
        pytest.skip("requires local Semgrep; no model calls")
    body = ('_, err := decode("bad"); if err != nil { return err }; return nil'
            if guarded else '_, _ = decode("bad"); return nil')
    source = ('package p\nimport "errors"\n'
              'func decode(s string) (int, error) { return 0, errors.New("invalid") }\n'
              'func Read() error { ' + body + ' }\n')
    (tmp_path / "record.go").write_text(source)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    rule = tmp_path / "discard.yaml"
    rule.write_text('rules:\n- id: explicit-error-discard\n  languages: [go]\n'
                    '  message: decode error is discarded\n  severity: WARNING\n'
                    '  pattern: _, _ = decode(...)\n')
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir, immediate_verify=True)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [
        {"type": "semgrep", "config": {"rule": str(rule)}},
    ])
    outcome = orch.ReviewOutcome(file="record.go", function="Read", line=4,
                                hypothesis="Read discards the error from decode", status="suspicious",
                                body="The decode error may be discarded.")
    result = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult(), source=source)
    assert result.status == ("clean" if guarded else "finding")
    assert result.review_result["immediate_verified"] is True
    refutations = [r for r in load_audit_log(out_dir) if r["action"] == "ihv_refutation"]
    if guarded:
        assert len(refutations) == 1
        assert refutations[0]["line_start"] == 4
        assert refutations[0]["checks"][0]["tool"] == "semgrep"
        assert refutations[0]["checks"][0]["rule_id"] == str(rule)
    else:
        assert result.evidence_tool.startswith("semgrep:")
        assert not refutations


@pytest.mark.parametrize("available", [True, False])
def test_source_invalidation_withdraws_confirmations_and_refutations_without_erasing_history(available):
    from core.audit.refutation_source import SourceIdentity

    initial = SourceIdentity("a" * 64, (1, 2, 3, 4, 5))
    current = SourceIdentity("b" * 64, (1, 2, 3, 4, 6)) if available else None
    result = ToolChainResult(["semgrep:fixture"], **SCOPE, source_identity=initial)
    result.observe("semgrep", "confirmed", "fixture", "original witness")
    result.observe("smt", "refuted", "check-overflow", "original negative")
    result.observe("codeql", "error", "fixture", "unavailable")
    originals = tuple(result.outcomes)
    assert result.invalidate_for_source(current)
    assert result == []
    assert [probe.verdict for probe in result.outcomes] == ["inconclusive", "inconclusive", "error"]
    assert [probe.verdict for probe in originals] == ["confirmed", "refuted", "error"]
    assert "original witness" in result.outcomes[0].reason
    assert result.source_identity == initial
    assert not result.refutations(**SCOPE)
    assert not result.invalidate_for_source(current)


@pytest.mark.parametrize("known", [False, True])
def test_source_invalidation_does_not_invent_freshness_for_unknown_or_unchanged_inputs(known):
    from core.audit.refutation_source import SourceIdentity

    current = SourceIdentity("a" * 64, (1, 2, 3, 4, 5))
    result = ToolChainResult(["semgrep:fixture"], **SCOPE, source_identity=current if known else None)
    result.observe("semgrep", "confirmed", "fixture")
    assert not result.invalidate_for_source(current)
    assert result == ["semgrep:fixture"]
    assert result.outcomes[0].verdict == "confirmed"
