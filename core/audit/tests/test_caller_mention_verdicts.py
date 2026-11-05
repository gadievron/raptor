"""Caller prose cannot adjudicate ownership of a mechanically tested claim."""

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification

STRONG = "semgrep:explicit-error-discard"
WEAK = "smt:check-early-release"
LOCAL = "Read discards the conversion error"


def aggregate(tmp_path, *, body="", hypothesis=LOCAL, records=None, inherited=False,
              callers=None, status="suspicious", joern=None):
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", line=1, status=status,
        hypothesis=hypothesis, body=body,
        review_result={"hypothesis": hypothesis, "cwe_class": "CWE-252",
                       "callers": callers if callers is not None else [{"name": "parse_record"}]},
        caller_attributed=inherited,
        attributed_caller="old_caller" if inherited else "",
    )
    result = orch.OrchestratorResult()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    if records is None:
        records = [ClaimVerification({"mechanism": hypothesis, "cwe": "CWE-252"}, (STRONG,))]
    final = orch._aggregate_ihv_verdicts(
        outcome, result, [r.hypothesis for r in records], records, config,
        joern_server=joern,
    )
    return final, result


@pytest.mark.parametrize("body", [
    "Called by parse_record with the input text.",
    "parse_record checks its own arguments; Read still discards the error.",
    "This is not a bug in parse_record; the error is discarded inside Read.",
    "parse_record is mentioned only in the call graph.",
    "The parse_record_fast helper is unrelated to this defect.",
    "The caller parse_record passes the correct input.",
])
@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_context_mentions_do_not_suppress_supported_claim(tmp_path, body, status):
    out, result = aggregate(tmp_path, body=body, status=status)
    assert out.status == "finding"
    assert out.hypothesis == LOCAL
    assert out.evidence_tool == STRONG
    assert out.review_result["immediate_verified"]
    assert "ihv_gate_blocked" not in out.review_result
    assert result.immediate_verified == 1


def test_caller_name_in_hypothesis_is_also_context(tmp_path):
    claim = "Read discards the error returned to parse_record"
    out, _ = aggregate(tmp_path, hypothesis=claim)
    assert out.status == "finding"
    assert out.hypothesis == claim
    assert out.caller_attributed  # Annotation retained; no adjudication authority.
    assert out.attributed_caller == "parse_record"


def test_inherited_caller_flag_cannot_veto_another_claim(tmp_path):
    out, _ = aggregate(tmp_path, inherited=True, callers=[])
    assert out.status == "finding"
    assert "ihv_gate_blocked" not in out.review_result


@pytest.mark.parametrize("bad_caller", [
    None, "parse_record", 7, {}, {"name": None}, {"name": 7},
    {"name": ["parse_record"]},
])
def test_malformed_diagnostic_context_cannot_abort_promotion(tmp_path, bad_caller):
    out, result = aggregate(
        tmp_path, body="Called by parse_record.",
        callers=[bad_caller, {"name": "parse_record"}],
    )
    assert out.status == "finding"
    assert out.attributed_caller == "parse_record"
    assert result.immediate_verified == 1


def test_primary_caller_discussion_cannot_block_supported_secondary(tmp_path):
    primary = "parse_record may violate its own input contract"
    secondary = {"mechanism": LOCAL, "cwe": "CWE-252"}
    out, _ = aggregate(tmp_path, hypothesis=primary, body="Caller parse_record was reviewed.", records=[
        ClaimVerification({"mechanism": primary, "cwe": "CWE-20"}, (WEAK,)),
        ClaimVerification(secondary, (STRONG,)),
    ])
    assert out.status == "finding"
    assert out.hypothesis == out.review_result["hypothesis"] == LOCAL
    assert out.review_result["cwe_class"] == "CWE-252"
    assert out.evidence_tool == STRONG


@pytest.mark.parametrize("body", [
    "Called by parse_record.", "The defect belongs to parse_record.",
])
@pytest.mark.parametrize("receipts", [(), (WEAK,), ("llm-claimed:semgrep",)])
def test_caller_prose_cannot_supply_missing_confirmation(tmp_path, body, receipts):
    out, result = aggregate(tmp_path, body=body, records=[
        ClaimVerification({"mechanism": LOCAL}, receipts),
    ])
    assert out.status == "suspicious"
    assert not out.review_result.get("immediate_verified")
    assert result.immediate_verified == 0


def test_cross_function_premise_still_blocks_local_proof(tmp_path, monkeypatch):
    notes = []
    monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *args, **kwargs: notes.append(args[1]))
    claim = {"mechanism": LOCAL, "counter_scope": "cross_function",
             "counter": "parse_record guarantees the conversion cannot fail."}
    out, result = aggregate(tmp_path, body="Called by parse_record.", records=[
        ClaimVerification(claim, (STRONG,)),
    ])
    assert out.status == "suspicious"
    assert out.review_result["ihv_gate_blocked"] == "cross-function-premise"
    assert result.immediate_verified == 0
    assert notes == [claim]


def test_guarded_sink_check_is_not_short_circuited_by_caller_hint(tmp_path, monkeypatch):
    checked = []
    def guard(function, server, **kwargs):
        checked.append(function)
        return "guarded"
    monkeypatch.setattr(orch, "_guard_blocks_promotion", guard)
    out, result = aggregate(tmp_path, body="Called by parse_record.", joern=object())
    assert checked == ["Read"]
    assert out.status == "suspicious"
    assert out.review_result["ihv_gate_blocked"] == "guarded-sink:guarded"
    assert result.immediate_verified == 0


def test_specific_counter_still_blocks_promotion(tmp_path):
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status="suspicious", body="Called by parse_record.",
        review_result={"callers": [{"name": "parse_record"}], "hypotheses": [{
            "mechanism": LOCAL, "confidence": "high",
            "counter": "The conversion result is consumed by the error handling branch.",
        }]},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    assert orch._ihv_context_gate(outcome, config) == "refuting-counter"
