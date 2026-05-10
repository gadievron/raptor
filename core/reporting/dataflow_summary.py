"""Console renderer for the IRIS dataflow_validation summary block.

Shared between `/agentic` (raptor_agentic.py) and `/analyze`
(packages/llm_analysis/agent.py) so both surfaces show the same
Tier 1/2/3/4 + path_conditions telemetry. Pre-extraction this
lived inline in raptor_agentic.py only — operators running
/analyze standalone after /scan didn't see whether IRIS validated
findings, whether the LLM populated path_conditions, or whether
Tier 4 SMT fired.

The helper returns a list of pre-formatted lines (with leading
indent baked in) rather than printing directly. Callers print
them — easier to test, easier to splice into different output
contexts (markdown report, log streamer, etc.).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def render_dataflow_validation_lines(
    dv: Optional[Dict[str, Any]],
    *,
    indent: str = "   ",
) -> List[str]:
    """Render the IRIS dataflow validation summary as a list of lines.

    Args:
        dv: The dataflow_validation dict from the orchestration
            result (typically `orchestration_result["dataflow_validation"]`
            or `report["dataflow_validation"]`). May be None / empty;
            both cases produce no output.
        indent: Leading whitespace for each line. Default matches
            raptor_agentic.py's existing report cadence ("   ").

    Returns:
        List of formatted strings ready to print. Empty list when
        validation didn't run AND no skipped_reason was recorded
        (caller should print nothing).

    Output shape (when populated):
        Dataflow validated: N (+M cache hits)
          by tier: A Tier 1 (free), B Tier 2 (LLM), C Tier 3 (LLM retry)
          Tier 4 SMT: X refuted, Y witness, Z disagreement
          path_conditions populated: N (CWE-190=2, CWE-476=1)
          downgrades: K flagged · applied: H hard, S soft (consensus override)

    Or when explicitly skipped:
        Dataflow validation skipped: <reason>

    Or when validation never ran (no CodeQL DB, no findings, etc.):
        (empty list)
    """
    if not dv:
        return []

    n_validated = dv.get("n_validated", 0)
    n_cache_hits = dv.get("n_cache_hits", 0)
    skipped_reason = dv.get("skipped_reason", "")

    if not n_validated and not n_cache_hits:
        # Validation didn't actually run on any finding. Surface the
        # reason if one was recorded (operator can tell IRIS noticed
        # but couldn't help — vs the silent "no findings to validate"
        # case which is genuinely no signal).
        if skipped_reason:
            return [f"{indent}Dataflow validation skipped: {skipped_reason}"]
        return []

    out: List[str] = []

    # Header line — matches the existing summary cadence
    # ("Exploits generated: N", "Patches generated: N", …).
    cache_suffix = (
        f" (+{n_cache_hits} cache hit{'s' if n_cache_hits != 1 else ''})"
        if n_cache_hits else ""
    )
    out.append(f"{indent}Dataflow validated: {n_validated}{cache_suffix}")

    # Tier breakdown: Tier 1 is free CodeQL; Tier 2/3 burn LLM tokens;
    # Tier 4 is free SMT (Z3 only) refining Tier 1/2/3 verdicts when
    # the LLM extracted path_conditions. Worth showing the split so
    # operators can tell whether --deep-validate is paying off.
    n_tier1 = dv.get("n_tier1_prebuilt", 0)
    n_tier2 = dv.get("n_tier2_template", 0)
    n_tier3 = dv.get("n_tier3_retry", 0)
    tier_parts: List[str] = []
    if n_tier1:
        tier_parts.append(f"{n_tier1} Tier 1 (free)")
    if n_tier2:
        tier_parts.append(f"{n_tier2} Tier 2 (LLM)")
    if n_tier3:
        tier_parts.append(f"{n_tier3} Tier 3 (LLM retry)")
    if tier_parts:
        out.append(f"{indent}  by tier: {', '.join(tier_parts)}")

    # Tier 4 (SMT) sub-line — separate because outcomes are additive
    # on top of Tier 1/2/3 (a finding's verdict may be confirmed-by-
    # Tier-1 AND witness-attached-by-Tier-4) so mixing them into the
    # per-tier counts would double-count.
    n_smt_refuted = dv.get("n_tier4_smt_refuted", 0)
    n_smt_witness = dv.get("n_tier4_smt_witness", 0)
    n_smt_disagree = dv.get("n_tier4_smt_disagree", 0)
    smt_parts: List[str] = []
    if n_smt_refuted:
        smt_parts.append(f"{n_smt_refuted} refuted")
    if n_smt_witness:
        smt_parts.append(f"{n_smt_witness} witness")
    if n_smt_disagree:
        smt_parts.append(f"{n_smt_disagree} disagreement")
    if smt_parts:
        out.append(f"{indent}  Tier 4 SMT: {', '.join(smt_parts)}")

    # path_conditions population telemetry — answers "is the LLM
    # actually emitting the SMT-checkable conditions the schema asks
    # for?" Without this signal, a Tier 4 of all-zeros is ambiguous
    # between "LLM never populates" and "LLM populates but everything
    # resolves to no_check". Surface only when there's a non-zero
    # count to report.
    n_pc_pop = dv.get("n_path_conditions_populated", 0)
    if n_pc_pop:
        cwe_breakdown = dv.get("path_conditions_by_cwe", {}) or {}
        if cwe_breakdown:
            cwe_str = ", ".join(
                f"{c}={n}"
                for c, n in sorted(cwe_breakdown.items(), key=lambda kv: -kv[1])
            )
            out.append(
                f"{indent}  path_conditions populated: {n_pc_pop} ({cwe_str})"
            )
        else:
            out.append(f"{indent}  path_conditions populated: {n_pc_pop}")

    # Downgrade outcome: distinguish "recommended" from "applied"
    # (the latter is post-reconciliation with consensus/judge). Soft
    # downgrades = recommendation overruled by consensus/judge.
    n_recommended = dv.get("n_recommended_downgrades", 0)
    n_hard = dv.get("n_applied_downgrades", 0)
    n_soft = dv.get("n_soft_downgrades", 0)
    if n_recommended:
        outcome: List[str] = [f"{n_recommended} flagged"]
        if n_hard or n_soft:
            bits: List[str] = []
            if n_hard:
                bits.append(f"{n_hard} hard")
            if n_soft:
                bits.append(f"{n_soft} soft (consensus override)")
            outcome.append(f"applied: {', '.join(bits)}")
        out.append(f"{indent}  downgrades: {' · '.join(outcome)}")

    return out
