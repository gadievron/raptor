"""Build the honest handoff from binary mapping into validation.

Black-box analysis should say what evidence exists and what evidence is still
missing before a candidate flow can become a finding. This module deliberately
does not manufacture verdicts from imports or decompiler output.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from .evidence import EvidenceRecord, EvidenceTier


def build_validation_handoff(
    *,
    target_path: str,
    binary_sha256: str,
    context_map: dict[str, Any],
    evidence: list[EvidenceRecord],
    decompilations: dict[str, Any],
) -> dict[str, Any]:
    tiers = {tier.value: 0 for tier in EvidenceTier}
    for record in evidence:
        tiers[record.tier.value] = tiers.get(record.tier.value, 0) + 1

    observed_functions = {
        str(item.get("function_id") or "")
        for item in context_map.get("runtime_input_flows", [])
        if isinstance(item, dict)
    }
    has_replay = tiers.get(EvidenceTier.REPLAYED_CRASH.value, 0) > 0
    has_smt = tiers.get(EvidenceTier.SMT_PROVED.value, 0) > 0
    has_runtime = tiers.get(EvidenceTier.OBSERVED_RUNTIME.value, 0) > 0

    flows = []
    for flow in context_map.get("candidate_flows", []):
        if not isinstance(flow, dict):
            continue
        missing: list[str] = []
        if str(flow.get("source_function") or "") not in observed_functions:
            missing.append("runtime_input_callsite")
        if not has_replay:
            missing.append("replayed_crash_or_debugger_witness")
        if not has_smt:
            missing.append("explicit_constraint_check_if_the_claim_depends_on_path_feasibility")
        missing.append("root_cause_binding")
        flows.append({
            "id": flow.get("id"),
            "source_function": flow.get("source_function"),
            "source_name": flow.get("source_name"),
            "sink": flow.get("sink"),
            "relationship": flow.get("relationship"),
            "static_evidence_tier": flow.get("evidence_tier"),
            "current_claim": "call_graph_candidate_only",
            "missing_evidence": missing,
            "can_promote_to_finding": False,
        })

    if has_runtime and has_replay and has_smt:
        status = "evidence_present_but_root_cause_binding_required"
    elif has_runtime:
        status = "runtime_observed_but_not_validated"
    else:
        status = "static_only"

    fuzz_suitability = context_map.get("fuzz_suitability") or {}
    if fuzz_suitability.get("runtime_strategy", "direct_process") == "direct_process":
        next_actions = [{
            "kind": "trace_parser",
            "why": "Observe which recovered functions actually call input and parser APIs, then fold that evidence back into this run.",
            "command": "/binary trace-parser <run-dir> --duration 30",
        }]
    else:
        next_actions = [{
            "kind": "runtime_harness",
            "why": str(fuzz_suitability.get("runtime_reason") or "A harness is needed before runtime tracing."),
            "command": "/binary report <run-dir>",
        }]
    if fuzz_suitability.get("strategy") == "direct_harness":
        next_actions.append({
            "kind": "fuzz_replay",
            "why": "A concrete harness boundary exists, so a campaign can produce replayable crash witnesses.",
            "command": f"/binary fuzz {shlex.quote(str(target_path))} --duration 60",
        })
    elif fuzz_suitability.get("should_run_fuzz_plan"):
        next_actions.append({
            "kind": "fuzz_plan",
            "why": "Check the host and input mode before committing to a whole-target campaign.",
            "command": f"/binary fuzz {shlex.quote(str(target_path))} --plan-only",
        })
    else:
        next_actions.append({
            "kind": "harness_strategy",
            "why": str(fuzz_suitability.get("reason") or "A narrow harness is needed before fuzzing is meaningful."),
            "command": "/binary harness <run-dir>",
        })
    next_actions.append({
        "kind": "smt",
        "why": "Check explicit path conditions only after a trace or crash gives us something concrete to ask.",
        "command": "/binary map <binary> --constraint-file <conditions.json> --out <run-dir>",
    })

    return {
        "schema_version": 1,
        "target_path": str(Path(target_path)),
        "binary_sha256": binary_sha256,
        "status": status,
        "can_promote_findings": False,
        "evidence_available": {
            "tiers": tiers,
            "decompiled_functions": int(decompilations.get("coverage", {}).get("decompiled_functions", 0)),
            "runtime_input_flows": len(context_map.get("runtime_input_flows", [])),
            "fuzz_witnesses": len(context_map.get("fuzz_witnesses", [])),
            "constraints_present": bool(context_map.get("constraints")),
        },
        "candidate_flows": flows,
        "validation_contract": [
            "A header-backed import is not a vulnerability.",
            "A decompiler-inferred body is not proof of attacker control.",
            "An xref-backed call edge is not taint proof.",
            "A candidate flow needs runtime input evidence plus a root-cause witness before it can become a finding.",
            "Replay and SMT evidence strengthen a claim only when they are bound to the same flow.",
        ],
        "fuzz_suitability": fuzz_suitability,
        "next_actions": next_actions,
    }


__all__ = ["build_validation_handoff"]
