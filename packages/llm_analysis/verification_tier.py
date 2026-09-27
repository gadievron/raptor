"""Mechanical evidence tiering for /analyze verdicts.

/analyze's mechanical gates are negative-only (reachability
suppression, binary-oracle, sanitizer vertex-cut, dedup) — a positive
``is_true_positive`` verdict reaches the report on LLM say-so. This
module labels each reported finding with the same ``verification_tier``
vocabulary /audit uses (``core.audit.pipeline.VerificationTier``), so
report readers can tell a mechanically corroborated verdict from a
bare LLM opinion. Labeling only: nothing here suppresses or demotes a
finding — the tier distribution is the calibration data a future hard
gate would need.

Receipts that qualify (all derived from fields the finding dict
actually carries; tier assignment is pure dict inspection, no LLM):

* ``confirmed`` — the sandboxed execution oracle observed a bug
  trigger for this finding's exploit (``execute_outcome`` in
  ``exit_signal`` / ``sanitizer_report`` / ``flag_captured``) with
  MECHANICAL-grade evidence (``execute_detail.evidence_grade ==
  "mechanical"`` — the waitstatus oracle saw a real WIFSIGNALED, not a
  target-forgeable exit code or stderr substring; see
  ``exploit_verify``), and the intent judge did not rule the run
  ``off_target`` (an off-target crash proves a different bug, not this
  one). Heuristic-grade or ungraded dynamic outcomes deliberately do
  NOT confirm: a hostile scanned repo can mint them with a printed
  fake sanitizer report or an exit(139).
* ``tool_backed`` — a static mechanical validator corroborated the
  verdict beyond the original detector match: an SMT sat witness on
  the finding's path conditions (``analysis.smt_witness.model``), or a
  dataflow validation verdict produced by a mechanical method
  (``method`` of ``codeql-iris`` / ``structural-treesitter``, or the
  IRIS Tier 1 pre-flight's ``tier: iris_tier1`` record), or a
  fail-open channel receipt whose role evidence is registry-grade
  (``fail_open`` outcome ``confirmed``/``refuted`` without the
  ``-naming`` detection-variant rule id). A mechanical
  ``refuted`` also earns ``tool_backed`` — the tier grades the
  evidence, not the verdict's sign. Deep-validation verdicts whose
  QUERY was LLM-authored (Tier 2 template predicates, Tier 3 retry,
  the legacy fallback) are NOT mechanical even though CodeQL executed
  them — they carry ``method: codeql-iris-llm`` plus an
  LLM-authored ``tier`` label and stay ``llm_only``.
* ``llm_only`` — the LLM affirmed (or denied) and nothing mechanical
  corroborates.

Non-receipts, deliberately: the original SARIF rule hit (it produced
the candidate — it cannot also corroborate it), ``exploit_compiled``
(a building PoC proves the code compiles, not that the bug is real),
and ``intent_match`` (an LLM judge).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.audit.pipeline import VerificationTier

# Execution-oracle outcomes that constitute an observed bug trigger
# (mirrors core.labeled_attempts' VERIFIED set for the sandbox oracle).
_DYNAMIC_OUTCOMES = frozenset({
    "exit_signal", "sanitizer_report", "flag_captured",
})

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

    outcome = finding.get("execute_outcome")
    if outcome in _DYNAMIC_OUTCOMES:
        # Evidence-grade gate: only mechanical-grade execution evidence
        # (waitstatus-oracle-anchored — see exploit_verify) may confirm.
        # Absent or heuristic grades fall through to the tool_backed /
        # llm_only receipts below — fail-safe, because a hostile target
        # forges the heuristic shapes (fake sanitizer stderr, exit(139))
        # without any prompt injection.
        exec_detail = finding.get("execute_detail")
        grade = (
            exec_detail.get("evidence_grade")
            if isinstance(exec_detail, dict) else None
        )
        if grade == "mechanical":
            intent = finding.get("intent_match") or {}
            if intent.get("verdict") != "off_target":
                return VerificationTier.CONFIRMED.value

    smt = analysis.get("smt_witness") or finding.get("smt_witness") or {}
    if isinstance(smt, dict) and smt.get("model"):
        return VerificationTier.TOOL_BACKED.value

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
    direction matches the verdict being stored — an SMT sat witness
    (the path is satisfiable) must never receipt a ``false_positive``
    suppression, and a mechanical refutation must never receipt an
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
    The ``structural-treesitter`` dataflow method has no enumerated
    spelling today and deliberately returns ``""`` (named residual —
    hint tier until the registry learns a spelling for it).
    """
    confirming = verdict == "exploitable"
    refuting = verdict in ("false_positive", "not_exploitable")
    if not confirming and not refuting:
        return ""

    analysis = finding.get("analysis") or {}

    if confirming:
        # Mechanical-grade execution oracle only (same gate as the
        # CONFIRMED tier): heuristic shapes are target-forgeable.
        outcome = finding.get("execute_outcome")
        if outcome in _DYNAMIC_OUTCOMES:
            exec_detail = finding.get("execute_detail")
            grade = (
                exec_detail.get("evidence_grade")
                if isinstance(exec_detail, dict) else None
            )
            intent = finding.get("intent_match") or {}
            if grade == "mechanical" and intent.get("verdict") != "off_target":
                if outcome == "sanitizer_report":
                    return "dynamic:sanitizer"
                if outcome == "exit_signal":
                    return "dynamic:crash"
                return "dynamic"

        # An SMT model is a sat witness on the path conditions —
        # confirming direction only.
        smt = analysis.get("smt_witness") or finding.get("smt_witness") or {}
        if isinstance(smt, dict) and smt.get("model"):
            return "smt"

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
