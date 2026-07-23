"""Direct unit tests for validation_handoff.build_validation_handoff."""

from __future__ import annotations

from core.evidence import EvidenceTier, make_evidence
from packages.binary_analysis.validation_handoff import build_validation_handoff

SHA = "a" * 64


def _make_ev(tier: EvidenceTier) -> object:
    return make_evidence(
        SHA, kind="test", source="test", summary="test",
        tier=tier, confidence="candidate", reproducible=True, tool="test",
    )


def test_static_only_status_when_no_runtime():
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map={},
        evidence=[_make_ev(EvidenceTier.HEADER_BACKED)],
        decompilations={},
    )
    assert result["status"] == "static_only"
    assert result["can_promote_findings"] is False
    assert len(result["validation_contract"]) > 0


def test_runtime_observed_status():
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map={},
        evidence=[_make_ev(EvidenceTier.OBSERVED_RUNTIME)],
        decompilations={},
    )
    assert result["status"] == "runtime_observed_but_not_validated"


def test_full_evidence_status():
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map={},
        evidence=[
            _make_ev(EvidenceTier.OBSERVED_RUNTIME),
            _make_ev(EvidenceTier.REPLAYED_CRASH),
            _make_ev(EvidenceTier.SMT_PROVED),
        ],
        decompilations={},
    )
    assert result["status"] == "evidence_present_but_root_cause_binding_required"


def test_candidate_flows_list_missing_evidence():
    context_map = {
        "candidate_flows": [{
            "id": "CF-1",
            "source_function": "fn_recv",
            "source_name": "recv_handler",
            "sink": "strcpy",
            "relationship": "may_reach",
            "evidence_tier": "xref_backed",
        }],
        "runtime_input_flows": [],
    }
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map=context_map,
        evidence=[_make_ev(EvidenceTier.XREF_BACKED)],
        decompilations={},
    )
    flows = result["candidate_flows"]
    assert len(flows) == 1
    assert flows[0]["can_promote_to_finding"] is False
    assert "runtime_input_callsite" in flows[0]["missing_evidence"]
    assert "root_cause_binding" in flows[0]["missing_evidence"]


def test_next_actions_include_trace_parser_by_default():
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map={},
        evidence=[],
        decompilations={},
    )
    actions = result["next_actions"]
    kinds = [a["kind"] for a in actions]
    assert "trace_parser" in kinds
    assert "smt" in kinds


def test_next_actions_include_fuzz_for_direct_harness():
    result = build_validation_handoff(
        target_path="/bin/test",
        binary_sha256=SHA,
        context_map={"fuzz_suitability": {"strategy": "direct_harness"}},
        evidence=[],
        decompilations={},
    )
    kinds = [a["kind"] for a in result["next_actions"]]
    assert "fuzz_replay" in kinds
