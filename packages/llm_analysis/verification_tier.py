"""Evidence tiering for /analyze findings.

Static mechanical receipts can earn tool_backed; uncorroborated findings remain
llm_only. Execution of LLM-generated code observes that artifact, not necessarily
the declared target. No trusted target-execution issuer is available on this
path, so serialized execute_outcome/evidence_grade/intent/hash fields cannot
mint confirmed or a dynamic mechanical verdict-store receipt. This also applies
to legacy records and model-supplied claims. A genuine target-bound execution
integration would need its own independently validated issuer, not a JSON flag.

The existing dataflow/fail-open classifications below are unchanged. This module
grades evidence, not the truth or exploitability of an unresolved finding.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.audit.pipeline import VerificationTier

# ``dataflow_validation.method`` values produced by mechanical
# validators (packages.llm_analysis.dataflow_validation._attach_result
# stamps ``method`` from the tier that actually produced the verdict).
# ``codeql-iris`` means a prebuilt pack-resident query; LLM-authored
# queries stamp ``codeql-iris-llm`` and never qualify. agent.py's
# ``validate_dataflow`` LLM dict carries neither ``method`` nor
# ``tier`` and likewise never qualifies here.
_MECHANICAL_METHODS = frozenset({"codeql-iris", "structural-treesitter"})

# ``dataflow_validation.tier`` labels whose CodeQL query text is
# LLM-AUTHORED (Tier 2 template predicates, Tier 3 compile-retry, the
# legacy free-form fallback). CodeQL executing the query is mechanical;
# the QUERY is not. Shared with the producer (_attach_result derives
# the honest ``method`` stamp from this set) and consumed here as a
# belt-and-braces veto so a miswired method stamp can never launder an
# LLM-shaped verdict into ``tool_backed``.
LLM_AUTHORED_DV_TIERS = frozenset({
    "template", "retry", "template-failed", "fallback",
})

_TIER_ORDER = {
    VerificationTier.CONFIRMED.value: 0,
    VerificationTier.TOOL_BACKED.value: 1,
    VerificationTier.LLM_ONLY.value: 2,
    VerificationTier.SPECULATIVE.value: 3,
}


def unbound_smt_refutation(dv: dict[str, Any]) -> bool:
    """Recognise saved Tier 4 refutations derived only from LLM predicates."""
    if dv.get("verdict") != "refuted":
        return False
    evidence = dv.get("evidence")
    if isinstance(evidence, (list, tuple)) and any(
        isinstance(item, dict) and item.get("tool") == "smt"
        and item.get("rule") == "path-feasibility:refuted"
        for item in evidence
    ):
        return True
    reasoning = dv.get("reasoning")
    return isinstance(reasoning, str) and (
        "[smt] inconclusive → refuted: unsat path conditions" in reasoning.splitlines()
    )


def dataflow_premises_mechanical(dv: dict[str, Any]) -> bool:
    """True when a ``dataflow_validation`` block's verdict rests on
    MECHANICAL query premises.

    The single premise-honesty predicate, shared by the tier
    derivation below and by the reconciliation step
    (``dataflow_validation.reconcile_dataflow_validation``): a verdict
    qualifies only when its ``tier`` is not LLM-authored AND either
    its ``method`` names a mechanical validator or the tier is the
    prebuilt ``iris_tier1`` lane. A block carrying neither ``method``
    nor a recognised tier fails CLOSED — an unstamped verdict cannot
    prove its premises were mechanical, so it never earns mechanical
    authority (it keeps its steering/dispute weight downstream).
    """
    if unbound_smt_refutation(dv):
        return False
    dv_tier = dv.get("tier")
    return dv_tier not in LLM_AUTHORED_DV_TIERS and (
        dv.get("method") in _MECHANICAL_METHODS
        or dv_tier == "iris_tier1"
    )


def derive_verification_tier(finding: dict[str, Any]) -> str:
    """Derive the evidence tier for one finding dict.

    ``finding`` is the ``VulnerabilityContext.to_dict()`` shape (keys
    ``analysis`` / ``execute_outcome`` / ``intent_match``). Pure
    inspection — safe on partial dicts; anything unrecognised degrades
    to ``llm_only``.
    """
    # Receipts live under ``analysis`` in the in-process agent shape;
    # the cc-dispatch merge copies result keys onto the finding's top
    # level instead. Check both, analysis first.
    analysis = finding.get("analysis") or {}

    # Generated-artifact execution and saved labels cannot establish target
    # participation. Do not promote them, even with a mechanical waitstatus,
    # an intent match or a claimed target hash/receipt in this dictionary.

    # Fail-open channel receipt (core.orchestration.fail_open_channel):
    # a mechanical confirmed/refuted adjudication with role + handler +
    # fallibility receipts. Detection-grade role variants (the
    # ``-naming`` rule-id suffix) stay llm_only — an uncorroborated
    # naming-stem role must not launder the verdict into tool_backed.
    fo = analysis.get("fail_open") or finding.get("fail_open") or {}
    if isinstance(fo, dict) and fo.get("outcome") in (
            "confirmed", "refuted"):
        # isinstance guard keeps the "pure inspection — safe on
        # partial dicts" promise: a non-string rule_id in a receipt
        # grades like a missing one instead of raising.
        rule = fo.get("rule_id")
        if not isinstance(rule, str):
            rule = ""
        if not rule.endswith("-naming"):
            return VerificationTier.TOOL_BACKED.value

    dv = (
        analysis.get("dataflow_validation")
        or finding.get("dataflow_validation")
        or {}
    )
    if isinstance(dv, dict) and dv.get("verdict") in ("confirmed", "refuted"):
        if dataflow_premises_mechanical(dv):
            return VerificationTier.TOOL_BACKED.value

    return VerificationTier.LLM_ONLY.value


def mechanical_receipt(finding: dict[str, Any], verdict: str) -> str:
    """The evidence-grade tool stamp backing one stored verdict, or ``""``.

    Companion to :func:`derive_verification_tier` for the SAGE
    verdict-store path: the store's ``evidence_tool`` receipt must name
    a mechanical receipt the finding dict actually carries AND whose
    direction matches the verdict being stored. Unbound predicate models
    grant no receipt, and a mechanical refutation must never receipt an
    ``exploitable``. Direction-mismatched or absent receipts return
    ``""``: the verdict still stores (hint tier, lower confidence), it
    just earns no cross-run skip.

    Spellings returned are enumerated members of the evidence-grade
    admission surface (``core.audit.evidence_grade``), so the recall
    side grades them honestly: mechanical-premise receipts satisfy
    ``is_tool_evidence`` and may earn the cross-run skip, while the
    LLM-authored-premise dataflow receipt (``codeql-llm:dataflow``)
    is registry-enumerated DETECTION-role — visible provenance that
    corroborates and aggregates but never skips or convicts alone.
    The ``structural-treesitter`` dataflow method mints no
    verification grade until its spellings are enumerated in the
    registry — fail-closed by construction, so it returns ``""``
    (hint tier).
    """
    confirming = verdict == "exploitable"
    refuting = verdict in ("false_positive", "not_exploitable")
    if not confirming and not refuting:
        return ""

    analysis = finding.get("analysis") or {}

    # No dynamic receipt can be derived from the serialized artifact outcome.
    # Only the independently classified static receipts below remain eligible.

    fo = analysis.get("fail_open") or finding.get("fail_open") or {}
    if isinstance(fo, dict):
        fo_outcome = fo.get("outcome")
        rule = fo.get("rule_id")
        if not isinstance(rule, str):
            rule = ""
        direction_ok = (
            (confirming and fo_outcome == "confirmed")
            or (refuting and fo_outcome == "refuted")
        )
        if direction_ok and rule and not rule.endswith("-naming"):
            return f"fail_open:{rule}"

    dv = (
        analysis.get("dataflow_validation")
        or finding.get("dataflow_validation")
        or {}
    )
    if isinstance(dv, dict):
        if unbound_smt_refutation(dv):
            return ""
        dv_verdict = dv.get("verdict")
        dv_tier = dv.get("tier")
        direction_ok = (
            (confirming and dv_verdict == "confirmed")
            or (refuting and dv_verdict == "refuted")
        )
        if direction_ok and dv_tier not in LLM_AUTHORED_DV_TIERS and (
            dv.get("method") == "codeql-iris" or dv_tier == "iris_tier1"
        ):
            # codeql-iris = prebuilt pack-resident query: mechanical
            # premises. structural-treesitter (no enumerated spelling)
            # does not mint a receipt here.
            return "codeql:dataflow"
        if direction_ok and (
            dv.get("method") == "codeql-iris-llm"
            or dv_tier in LLM_AUTHORED_DV_TIERS
        ):
            # LLM-authored query predicates: CodeQL ran mechanically,
            # but the premises are model text. The spelling is
            # enumerated DETECTION-role in the exact-spelling registry
            # (core.audit.evidence_grade) — the stored verdict keeps
            # honest provenance and the receipt corroborates or
            # aggregates downstream, but it never grades as
            # verification alone and never earns the cross-run skip.
            return "codeql-llm:dataflow"

    return ""


def sort_results_by_tier(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable-sort report results: confirmed, tool_backed, then the
    rest. Findings without a tier (prep-only mode) keep their relative
    order at the end."""
    return sorted(
        results,
        key=lambda r: _TIER_ORDER.get(
            r.get("verification_tier", ""), len(_TIER_ORDER),
        ),
    )


def tier_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    """Per-tier counts over report results (untiered entries omitted)."""
    counts = Counter(
        r["verification_tier"] for r in results if r.get("verification_tier")
    )
    return dict(counts)
