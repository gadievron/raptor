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
  ``exit_signal`` / ``sanitizer_report`` / ``flag_captured``), and the
  intent judge did not rule the run ``off_target`` (an off-target
  crash proves a different bug, not this one).
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
  evidence, not the verdict's sign.
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
# validators (packages.llm_analysis.dataflow_validation._attach_result).
# The LLM-backed deep-validation dict carries neither ``method`` nor
# ``tier`` and therefore never qualifies here.
_MECHANICAL_METHODS = frozenset({"codeql-iris", "structural-treesitter"})

_TIER_ORDER = {
    VerificationTier.CONFIRMED.value: 0,
    VerificationTier.TOOL_BACKED.value: 1,
    VerificationTier.LLM_ONLY.value: 2,
    VerificationTier.SPECULATIVE.value: 3,
}


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
        rule = fo.get("rule_id") or ""
        if not rule.endswith("-naming"):
            return VerificationTier.TOOL_BACKED.value

    dv = (
        analysis.get("dataflow_validation")
        or finding.get("dataflow_validation")
        or {}
    )
    if isinstance(dv, dict) and dv.get("verdict") in ("confirmed", "refuted"):
        if (
            dv.get("method") in _MECHANICAL_METHODS
            or dv.get("tier") == "iris_tier1"
        ):
            return VerificationTier.TOOL_BACKED.value

    return VerificationTier.LLM_ONLY.value


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
