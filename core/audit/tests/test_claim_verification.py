"""Immediate verification binds each receipt to the claim it tested."""

from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification, supported_claims, unverified_critique


WEAK = "smt:check-early-release"
OTHER_WEAK = "codeql-llm:dataflow"
STRONG = "semgrep:explicit-error-discard"


def select(*records):
    return supported_claims(
        records, receipt_can_promote=orch._promotion_grade_receipt,
    )


@pytest.mark.parametrize("receipts", [
    (WEAK,), (OTHER_WEAK,), (WEAK, WEAK),
    ("llm-claimed:semgrep",), ("invented:proof",),
    ("invented:a", "unknown:b"), ("llm-claimed:smt", OTHER_WEAK),
])
def test_weak_or_unrecognised_evidence_cannot_confirm_a_claim(receipts):
    assert select(ClaimVerification({"mechanism": "overflow"}, receipts)) == []


def test_two_weak_receipts_cannot_corroborate_different_claims():
    assert select(
        ClaimVerification({"mechanism": "race"}, (WEAK,)),
        ClaimVerification({"mechanism": "injection"}, (OTHER_WEAK,)),
    ) == []


def test_weak_channels_cannot_confirm_even_within_a_single_claim():
    record = ClaimVerification({"mechanism": "race"}, (WEAK, OTHER_WEAK))
    assert select(record) == []


def test_strong_receipt_is_selected_ahead_of_a_weak_lead_on_the_same_claim():
    result = select(ClaimVerification({"mechanism": "discarded error"}, (WEAK, STRONG)))
    assert result[0].receipts == (STRONG,)


def aggregate(tmp_path, records, *, status="clean"):
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status=status, body="completed review",
        hypothesis="original primary", review_result={"hypothesis": "original primary", "cwe_class": "CWE-190"},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.out_dir.mkdir(exist_ok=True)
    result = orch.OrchestratorResult()
    out = orch._aggregate_ihv_verdicts(
        outcome, result, [r.hypothesis for r in records], records, config,
    )
    return out, result, outcome


@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_detection_lead_does_not_become_a_verified_finding(tmp_path, status):
    out, result, _ = aggregate(tmp_path, [ClaimVerification({"mechanism": "race"}, (WEAK,))], status=status)
    assert out.status == status
    assert not out.review_result.get("immediate_verified")
    assert out.review_result["ihv_tools"] == [WEAK]
    assert result.immediate_verified == 0


def test_receipt_for_secondary_claim_cannot_be_exported_as_primary(tmp_path):
    records = [
        ClaimVerification({"mechanism": "unproven race", "cwe": "CWE-362"}, (WEAK,)),
        ClaimVerification({"mechanism": "discarded error", "cwe": "CWE-252"}, (STRONG,)),
    ]
    out, result, prior = aggregate(tmp_path, records)
    assert out.status == "finding"
    assert out.hypothesis == out.review_result["hypothesis"] == "discarded error"
    assert out.review_result["cwe"] == out.review_result["cwe_class"] == "CWE-252"
    assert out.evidence_tool == STRONG
    assert result.immediate_verified == 1
    assert prior.hypothesis == prior.review_result["hypothesis"] == "original primary"


def test_blocked_claim_does_not_hide_another_supported_claim(tmp_path, monkeypatch):
    seen = []

    def gate(outcome, config, **kwargs):
        seen.append(outcome.hypothesis)
        return "caller-attributed" if outcome.hypothesis == "caller bug" else None

    monkeypatch.setattr(orch, "_ihv_context_gate", gate)
    out, _, _ = aggregate(tmp_path, [
        ClaimVerification({"mechanism": "caller bug"}, (STRONG,)),
        ClaimVerification({"mechanism": "local bug"}, (STRONG,)),
    ])
    assert seen == ["caller bug", "local bug"]
    assert out.status == "finding"
    assert out.hypothesis == "local bug"
    assert "ihv_gate_blocked" not in out.review_result


def test_function_local_proof_cannot_verify_a_cross_function_premise(tmp_path, monkeypatch):
    notes = []
    monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *a, **kw: notes.append(a[1]))
    claim = {"mechanism": "overflow", "counter_scope": "cross_function",
             "counter": "The caller clamps the length before calling."}
    out, result, _ = aggregate(tmp_path, [ClaimVerification(claim, (STRONG,))])
    assert out.status == "clean"
    assert out.review_result["ihv_gate_blocked"] == "cross-function-premise"
    assert out.hypothesis == out.review_result["hypothesis"] == "original primary"
    assert out.review_result["cwe_class"] == "CWE-190"
    assert result.immediate_verified == 0
    assert notes == [claim]


def test_extraction_preserves_the_counter_on_each_claim():
    primary = {"mechanism": "overflow", "confidence": "high", "counter_scope": "cross_function",
               "counter": "Caller bounds the input."}
    secondary = {"mechanism": "race", "confidence": "medium", "counter_scope": "local",
                 "counter": "A shared lock covers both accesses."}
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="reviewed",
                                hypothesis="overflow", hypotheses=[primary, secondary])
    claims = orch._extract_all_hypotheses(outcome)
    assert [(h["counter"], h["counter_scope"]) for h in claims] == [
        (h["counter"], h["counter_scope"]) for h in [primary, secondary]
    ]


def test_synthesis_is_given_the_selected_claim_not_the_original_primary(tmp_path, monkeypatch):
    import core.audit.checker_synthesis as synthesis

    seen = []

    def synthesize(outcome, config, **kwargs):
        seen.append((outcome.hypothesis, dict(outcome.review_result)))
        return SimpleNamespace(confirmed=True, stamp=STRONG, cost_usd=0)

    monkeypatch.setattr(synthesis, "synthesize_verification_rule", synthesize)
    original = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="reviewed",
                                 hypothesis="original", review_result={"hypothesis": "original", "cwe_class": "CWE-190"})
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    receipt = orch._try_ihv_synthesis(original, config, orch.OrchestratorResult(),
                                    {"mechanism": "selected secondary"}, "CWE-252", "source")
    assert receipt == STRONG
    assert seen[0][0] == seen[0][1]["hypothesis"] == "selected secondary"
    assert seen[0][1]["cwe_class"] == "CWE-252"
    assert original.hypothesis == original.review_result["hypothesis"] == "original"


def test_confirmation_and_refutation_cannot_coexist_in_one_record():
    with pytest.raises(ValueError):
        ClaimVerification({"mechanism": "overflow"}, (STRONG,), refuted=True)


def test_record_snapshots_the_claim_it_verified():
    hypothesis = {"mechanism": "overflow"}
    record = ClaimVerification(hypothesis, (STRONG,))
    hypothesis["mechanism"] = "unrelated race"
    assert record.hypothesis["mechanism"] == "overflow"


@pytest.mark.parametrize("mutate_input", [False, True])
def test_nested_claim_data_cannot_change_after_verification(mutate_input):
    hypothesis = {"mechanism": "discarded error", "assumptions": [{"callee": "decode"}]}
    record = ClaimVerification(hypothesis, (STRONG,))
    exposed = hypothesis if mutate_input else record.hypothesis
    exposed["assumptions"][0]["callee"] = "unrelated"
    exposed["assumptions"].append({"caller": "invented"})
    assert record.hypothesis == {
        "mechanism": "discarded error", "assumptions": [{"callee": "decode"}],
    }


def test_mutating_a_selected_claim_cannot_rebind_its_receipts(tmp_path):
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.json import load_json

    record = ClaimVerification({"mechanism": "discarded error", "cwe": "CWE-252"}, (STRONG,))
    selected = select(record)[0]
    selected.verification.hypothesis.update({"mechanism": "unrelated race", "cwe": "CWE-362"})
    out, _, _ = aggregate(tmp_path, [record], status="suspicious")
    assert out.hypothesis == out.review_result["hypothesis"] == "discarded error"
    assert out.review_result["cwe_class"] == "CWE-252"
    assert out.evidence_tool == STRONG
    write_graded_findings(export_findings([out]), tmp_path)
    finding = load_json(tmp_path / "findings-graded.json")["findings"][0]
    assert finding["hypothesis"] == "discarded error"
    assert finding["discovery"]["evidence_tool"] == STRONG


def test_a_consumer_cannot_erase_a_recorded_cross_function_premise(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *a, **kw: None)
    claim = {"mechanism": "overflow", "counter_scope": "cross_function",
             "counter": "The caller clamps the length before calling."}
    record = ClaimVerification(claim, (STRONG,))
    record.hypothesis.update({"counter_scope": "local", "counter": ""})
    out, result, _ = aggregate(tmp_path, [record], status="suspicious")
    assert out.status == "suspicious"
    assert out.review_result["ihv_gate_blocked"] == "cross-function-premise"
    assert not out.review_result.get("immediate_verified")
    assert result.immediate_verified == 0


def test_immediate_dispatch_keeps_secondary_receipts_bound_to_their_claim(tmp_path, monkeypatch):
    primary = {"mechanism": "unproven race", "confidence": "high", "cwe": "CWE-362"}
    secondary = {"mechanism": "discarded error", "confidence": "medium", "cwe": "CWE-252"}
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status="clean", body="reviewed",
        hypothesis=primary["mechanism"], hypotheses=[primary, secondary],
        review_result={"hypothesis": primary["mechanism"], "cwe": primary["cwe"]},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "semgrep"}])
    seen = []

    def run_chain(chain, **kwargs):
        seen.append(kwargs["hypothesis"])
        return [WEAK] if kwargs["hypothesis"] == primary["mechanism"] else [STRONG]

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    out = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult())
    assert seen == [primary["mechanism"], secondary["mechanism"]]
    assert out.status == "finding"
    assert out.hypothesis == out.review_result["hypothesis"] == secondary["mechanism"]
    assert out.review_result["cwe"] == secondary["cwe"]
    assert out.evidence_tool == STRONG


@pytest.mark.parametrize("record", [
    {"refuted": True, "reason": "Caller guards the value"},
    {"verdict": "refuted", "defeating_mechanism": "named guard"},
    {"verdict": "refuted", "adjudication": "confirmed", "refuted": True},
    {"verdict": "stands"},
    {"verdict": "needs_evidence", "needs_evidence": True},
])
def test_critique_boundary_is_advisory_and_idempotent(record):
    from copy import deepcopy

    before = deepcopy(record)
    assessed = unverified_critique(record)
    assert record == before
    assert assessed["adjudication"] == "unverified"
    assert assessed["refuted"] is False
    assert unverified_critique(assessed) == assessed
    assert assessed.get("defeating_mechanism") == record.get("defeating_mechanism")


@pytest.mark.parametrize("edit_stage", ["result_handoff", "context_gate"])
def test_confirmation_snapshot_must_still_match_when_aggregation_promotes(tmp_path, monkeypatch, edit_stage):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ToolChainResult

    path = tmp_path / "record.c"
    source = "int Read(void) { return 0; }\n"
    path.write_text(source)
    initial = capture_source_identity(tmp_path, path.name)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    config.out_dir.mkdir()
    outcome = orch.ReviewOutcome(file=path.name, function="Read", line=1, status="suspicious",
        body="An unresolved concern.", hypothesis="discarded error",
        review_result={"hypothesis": "discarded error", "cwe": "CWE-252"})
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "semgrep", "config": {}}])
    calls = []

    def run_chain(chain, **kwargs):
        calls.append(kwargs)
        result = ToolChainResult([STRONG], file=path.name, function="Read", line_start=1,
                                 hypothesis="discarded error", source_identity=initial)
        if edit_stage == "result_handoff":
            path.write_text(source + "// changed after the checker completed\n")
        return result

    def gate(*args, **kwargs):
        if edit_stage == "context_gate":
            path.write_text(source + "// changed during context validation\n")
        return None

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    monkeypatch.setattr(orch, "_ihv_context_gate", gate)
    counts = orch.OrchestratorResult()
    final = orch._verify_hypotheses_immediate(outcome, config, counts, source=source)
    assert final.status == "suspicious"
    assert not final.evidence_tool
    assert not final.review_result.get("immediate_verified")
    assert counts.immediate_verified == 0
    assert len(calls) == 1


@pytest.mark.parametrize("changed", ["unchanged", "file", "function", "occurrence", "hypothesis", "missing_file", "missing_function", "missing_hypothesis"])
def test_returned_confirmation_cannot_transfer_to_another_claim_occurrence(tmp_path, monkeypatch, changed):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ToolChainResult

    source = "int Read() { return 0; }\nint Read(int n) { return n; }\nint Other() { return 0; }\n"
    (tmp_path / "record.cpp").write_text(source)
    (tmp_path / "other.cpp").write_text("int Read() { return 0; }\n")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    config.out_dir.mkdir()
    outcome = orch.ReviewOutcome(file="record.cpp", function="Read", line=1, status="suspicious",
        body="An unresolved concern.", hypothesis="discarded error",
        review_result={"hypothesis": "discarded error", "cwe": "CWE-252"})
    bound = {"file": outcome.file, "function": outcome.function, "line_start": outcome.line,
             "hypothesis": outcome.hypothesis}
    if changed == "file":
        bound["file"] = "other.cpp"
    elif changed == "function":
        bound.update(function="Other", line_start=3)
    elif changed == "occurrence":
        bound["line_start"] = 2
    elif changed == "hypothesis":
        bound["hypothesis"] = "a different concern"
    elif changed.startswith("missing_"):
        bound[changed.removeprefix("missing_")] = ""
    receipt = ToolChainResult([STRONG], **bound,
                              source_identity=capture_source_identity(tmp_path, bound["file"]))
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "semgrep", "config": {}}])
    monkeypatch.setattr(orch, "_run_tool_chain", lambda *a, **kw: receipt)
    monkeypatch.setattr(orch, "_ihv_context_gate", lambda *a, **kw: None)
    counts = orch.OrchestratorResult()
    final = orch._verify_hypotheses_immediate(outcome, config, counts, source=source)
    assert final.status == ("finding" if changed == "unchanged" else "suspicious")
    assert bool(final.review_result.get("immediate_verified")) is (changed == "unchanged")
    assert counts.immediate_verified == (1 if changed == "unchanged" else 0)
    assert final.hypothesis == outcome.hypothesis


@pytest.mark.parametrize("field,value", [
    ("file", "other.c"), ("function", "Other"), ("line", 2),
    ("hypothesis", "revised concern"), ("review_hypothesis", "revised concern"),
])
def test_context_gate_cannot_reassign_a_bound_confirmation(tmp_path, monkeypatch, field, value):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import VerificationScope

    (tmp_path / "record.c").write_text("int Read(void) { return 0; }\n")
    binding = VerificationScope("record.c", "Read", 0, "discarded error",
                                capture_source_identity(tmp_path, "record.c"))
    record = ClaimVerification({"mechanism": "discarded error"}, (STRONG,), binding=binding)
    reached = []

    def gate(candidate, *args, **kwargs):
        reached.append(candidate.hypothesis)
        if field == "review_hypothesis":
            candidate.review_result["hypothesis"] = value
        else:
            setattr(candidate, field, value)
        return None

    monkeypatch.setattr(orch, "_ihv_context_gate", gate)
    out, result, _ = aggregate(tmp_path, [record], status="suspicious")
    assert reached == ["discarded error"]
    assert out.status == "suspicious" and not out.evidence_tool
    assert not out.review_result.get("immediate_verified")
    assert out.hypothesis == "original primary"
    assert result.immediate_verified == 0
    assert out.review_result["ihv_hypotheses_confirmed"] == 0


def test_rejected_scope_does_not_hide_a_valid_secondary_claim(tmp_path, monkeypatch):
    from core.audit.verification_results import VerificationScope

    reached = []
    monkeypatch.setattr(orch, "_ihv_context_gate", lambda candidate, *a, **kw: reached.append(candidate.hypothesis))
    records = [
        ClaimVerification({"mechanism": "wrong occurrence"}, (STRONG,),
                          binding=VerificationScope("record.c", "Read", 9, "wrong occurrence")),
        ClaimVerification({"mechanism": "local concern"}, (STRONG,),
                          binding=VerificationScope("record.c", "Read", 0, "local concern")),
    ]
    out, result, _ = aggregate(tmp_path, records, status="suspicious")
    assert reached == ["local concern"]
    assert out.status == "finding" and out.hypothesis == "local concern"
    assert result.immediate_verified == 1
    assert out.review_result["ihv_hypotheses_confirmed"] == 1
    assert out.review_result["ihv_tools"] == [STRONG, STRONG]


@pytest.mark.parametrize("identity_case", ["missing", "changed", "unchanged", "unknown"])
def test_bound_confirmation_checks_source_availability_without_inventing_identity(tmp_path, identity_case):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import VerificationScope

    path = tmp_path / "record.c"
    path.write_text("int Read(void) { return 0; }\n")
    identity = capture_source_identity(tmp_path, path.name)
    if identity_case == "missing":
        path.unlink()
    elif identity_case == "changed":
        path.write_text("int Read(void) { return 1; }\n")
    elif identity_case == "unknown":
        identity = None
    record = ClaimVerification({"mechanism": "discarded error"}, (STRONG,),
        binding=VerificationScope(path.name, "Read", 0, "discarded error", identity))
    out, result, _ = aggregate(tmp_path, [record], status="suspicious")
    admitted = identity_case in {"unchanged", "unknown"}
    assert out.status == ("finding" if admitted else "suspicious")
    assert result.immediate_verified == int(admitted)
    assert record.binding.source_identity == identity
    assert record.receipts == (STRONG,)
    assert out.review_result["ihv_tools"] == [STRONG]


def test_receipt_binding_is_immutable_and_not_reconstructed_from_consumer():
    from dataclasses import FrozenInstanceError
    from core.audit.verification_results import ToolChainResult

    result = ToolChainResult([STRONG], file="a.c", function="Read", line_start=2, hypothesis="error")
    record = ClaimVerification({"mechanism": "error"}, tuple(result), binding=result.binding)
    with pytest.raises(FrozenInstanceError):
        record.binding.hypothesis = "other"
    with pytest.raises(FrozenInstanceError):
        record.binding = None
    with pytest.raises(AttributeError):
        result.scope = ("b.c", "Other", 3, "other")
    with pytest.raises(AttributeError):
        result.source_identity = None
    assert record.binding.scope == ("a.c", "Read", 2, "error")


def test_rejection_during_a_later_gate_updates_returned_blocked_counts(tmp_path, monkeypatch):
    from core.audit.verification_results import VerificationScope

    reached = []

    def gate(candidate, *args, **kwargs):
        reached.append(candidate.hypothesis)
        if candidate.hypothesis == "first concern":
            return "refuting-counter"
        candidate.hypothesis = "changed concern"
        return None

    monkeypatch.setattr(orch, "_ihv_context_gate", gate)
    records = [ClaimVerification({"mechanism": name}, (STRONG,),
        binding=VerificationScope("record.c", "Read", 0, name)) for name in ("first concern", "second concern")]
    out, result, _ = aggregate(tmp_path, records, status="suspicious")
    assert reached == ["first concern", "second concern"]
    assert out.status == "suspicious" and out.hypothesis == "original primary"
    assert out.review_result["ihv_hypotheses_confirmed"] == 1
    assert out.review_result["ihv_gate_blocked"] == "refuting-counter"
    assert result.immediate_verified == 0


def test_admission_source_withdrawal_reaches_normal_json_without_erasing_checker_result(tmp_path):
    from core.audit.check_trace import record_check_observation
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ToolChainResult
    from core.json import load_json

    source = tmp_path / "record.c"
    source.write_text("int Read(void) { return 0; }\n")
    initial = capture_source_identity(tmp_path, source.name)
    checked = ToolChainResult([STRONG], file=source.name, function="Read", line_start=0,
                              hypothesis="discarded error", source_identity=initial)
    (tmp_path / "out").mkdir()
    record_check_observation(tmp_path / "out", checked, tool="semgrep", verdict="confirmed",
                             rule_id=STRONG.split(":", 1)[1], result=SimpleNamespace(outcome="confirmed"))
    source.write_text("int Read(void) { return 1; }\n")
    record = ClaimVerification({"mechanism": "discarded error"}, tuple(checked), binding=checked.binding)
    out, _, _ = aggregate(tmp_path, [record], status="suspicious")
    write_graded_findings(export_findings([out]), tmp_path / "out")
    sidecar = load_json(tmp_path / "out" / "verification-checks.json")
    checker = next(c for c in sidecar["checks"] if c["tool"] == "semgrep")
    withdrawal = next(c for c in sidecar["checks"] if c["tool"] == "source_binding")
    assert checker["outcome"] == "confirmed"
    assert checker["source_applicability"]["status"] == "invalidated"
    assert withdrawal["id"] in checker["source_applicability"]["validation_ids"]
    assert withdrawal["scope"] == checker["scope"]
    assert withdrawal["result"]["data"]["details"]["phase"] == "claim_admission"
    assert out.status == "suspicious" and not out.evidence_tool


@pytest.mark.parametrize("bound", [True, False])
def test_rejected_claim_scope_keeps_producer_identity_separate_in_normal_json(tmp_path, bound):
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.audit.verification_results import VerificationScope
    from core.json import load_json

    binding = VerificationScope("other.c", "Other", 8, "producer concern") if bound else None
    record = ClaimVerification({"mechanism": "consumer concern"}, (STRONG,), binding=binding)
    out = orch.ReviewOutcome(file="record.c", function="Read", line=1, status="suspicious",
                            body="Unresolved", hypothesis="consumer concern")
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    cfg.out_dir.mkdir()
    if bound:
        orch._aggregate_ihv_verdicts(out, orch.OrchestratorResult(), [record.hypothesis], [record], cfg)
    else:
        # A legacy record can still be rejected for a revised consumer claim;
        # missing producer scope must remain missing in its diagnostic event.
        orch._record_ihv_scope_rejection(record, out, cfg, hypothesis="revised concern", reason="claim-revised")
    write_graded_findings(export_findings([out]), cfg.out_dir)
    checks = load_json(cfg.out_dir / "verification-checks.json")["checks"]
    rejected = next(c for c in checks if c["tool"] == "claim_binding")
    assert rejected["outcome"] == "inconclusive"
    assert rejected["scope"]["file"] == ("other.c" if bound else "")
    assert rejected["scope"]["function"] == ("Other" if bound else "")
    details = rejected["result"]["data"]["details"]
    assert details["attempted_scope"]["file"] == "record.c"
    assert details["producer_scope_recorded"] is bound
    assert details["prior_receipts"] == [STRONG]


@pytest.mark.parametrize("source_drift", [False, True])
def test_failed_rejection_recording_cannot_restore_confirmation(tmp_path, monkeypatch, source_drift):
    from core.audit import check_trace
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import VerificationScope

    path = tmp_path / "record.c"
    path.write_text("int Read(void) { return 0; }\n")
    identity = capture_source_identity(tmp_path, path.name)
    binding = VerificationScope(path.name, "Read", 0 if source_drift else 9, "discarded error", identity)
    if source_drift:
        path.write_text("int Read(void) { return 1; }\n")
    reached = []

    def unavailable(*args, **kwargs):
        reached.append(kwargs)
        raise OSError("owned recording failure")

    seam = "record_source_invalidation" if source_drift else "record_claim_scope_rejection"
    monkeypatch.setattr(check_trace, seam, unavailable)
    record = ClaimVerification({"mechanism": "discarded error"}, (STRONG,), binding=binding)
    out, result, _ = aggregate(tmp_path, [record], status="suspicious")
    assert len(reached) == 1
    assert out.status == "suspicious" and not out.evidence_tool
    assert result.immediate_verified == 0
    assert out.review_result["ihv_tools"] == [STRONG]


def test_aggregation_retains_all_input_observations_in_signed_trail(tmp_path):
    from core.audit.record import load_verified_audit_log

    records = [
        ClaimVerification({"mechanism": "unproven race", "cwe": "CWE-362"}, (WEAK,)),
        ClaimVerification({"mechanism": "discarded error", "cwe": "CWE-252"}, (STRONG,)),
        ClaimVerification({"mechanism": "a proposed refutation"}, refuted=True),
        ClaimVerification({"mechanism": "an untested theory"}),
    ]
    out, result, _ = aggregate(tmp_path, records)
    assert out.status == "finding" and out.hypothesis == "discarded error"
    events = [e for e in load_verified_audit_log(tmp_path / "out")
              if e.get("action") == "ihv_claim_observations"]
    assert len(events) == 1
    event = events[0]
    observations = event["observations"]["data"]["details"]
    assert [row["hypothesis"] for row in observations] == [r.hypothesis for r in records]
    assert event["role"] == "unadjudicated_observation"
    assert observations[0]["receipt_labels"] == [WEAK]
    assert observations[1]["receipt_labels"] == [STRONG]
    assert observations[2]["proposed_refutation"] is True
    assert event["producer_bindings"] == [None] * 4, "do not invent producer scope"
    assert result.immediate_verified == 1


def test_claim_observation_proposal_is_not_a_scoped_refutation(tmp_path):
    record = ClaimVerification({"mechanism": "unsupported withdrawal"}, refuted=True)
    out, result, _ = aggregate(tmp_path, [record], status="suspicious")
    assert out.status == "suspicious" and not out.review_result.get("immediate_verified")
    assert result.immediate_verified == 0


def test_claim_snapshot_keeps_stale_producer_binding(tmp_path):
    from dataclasses import asdict

    from core.json import dumps_artifact, loads

    from core.audit.record import load_verified_audit_log
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import VerificationScope

    path = tmp_path / "record.c"
    path.write_text("int Read(void) { return 0; }\n")
    identity = capture_source_identity(tmp_path, path.name)
    binding = VerificationScope(path.name, "Read", 0, "discarded error", identity)
    path.write_text("int Read(void) { return 1; }\n")
    out, result, _ = aggregate(tmp_path, [ClaimVerification(
        {"mechanism": "discarded error"}, (STRONG,), binding=binding)], status="suspicious")
    event = next(e for e in load_verified_audit_log(tmp_path / "out")
                 if e.get("action") == "ihv_claim_observations")
    assert event["producer_bindings"] == [loads(dumps_artifact(asdict(binding)))]
    assert event["producer_bindings"][0]["source_identity"] != loads(dumps_artifact(
        asdict(capture_source_identity(tmp_path, path.name))))
    assert out.status == "suspicious" and result.immediate_verified == 0


def test_claim_snapshot_write_failure_does_not_change_verdict(tmp_path, monkeypatch, caplog):
    from core.audit import check_trace

    reached = []

    def unavailable(*args, **kwargs):
        reached.append(kwargs)
        raise OSError("scripted observation write failure")

    monkeypatch.setattr(check_trace, "append_audit_log", unavailable)
    out, result, _ = aggregate(tmp_path, [ClaimVerification({"mechanism": "race"}, (WEAK,))],
                               status="suspicious")
    assert len(reached) == 1
    assert out.status == "suspicious" and result.immediate_verified == 0
    assert "could not record IHV claim observations" in caplog.text


def test_claim_reporter_failure_cannot_change_aggregation(tmp_path, monkeypatch, caplog):
    from core.audit import check_trace

    def unavailable(*args, **kwargs):
        raise RuntimeError("scripted reporter failure")

    monkeypatch.setattr(check_trace, "record_claim_observations", unavailable)
    out, result, _ = aggregate(tmp_path, [ClaimVerification({"mechanism": "race"}, (WEAK,))],
                               status="suspicious")
    assert out.status == "suspicious" and result.immediate_verified == 0
    assert "could not retain IHV claim observations" in caplog.text


def test_claim_reporter_does_not_swallow_cancellation(tmp_path, monkeypatch):
    from core.audit import check_trace

    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(check_trace, "record_claim_observations", cancelled)
    with pytest.raises(KeyboardInterrupt):
        aggregate(tmp_path, [ClaimVerification({"mechanism": "race"}, (WEAK,))])
