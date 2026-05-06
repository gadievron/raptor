"""Multi-model substrate adapter for /agentic findings.

Bridges /agentic's per-finding verdict shape into the substrate's
``BaseVerdictAdapter``. PR3 Option A migrates only ``select_primary``;
Options B and C will migrate the dispatch loop and reviewers.

Schema mapping:
    item_id            ← finding_id
    normalize_verdict  ← derived from is_exploitable (True → positive,
                         else → negative; matches legacy's truthy check)
    select_primary     ← overridden to mirror legacy _select_primary_result
                         exactly — see method docstring for the quirks.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.llm.multi_model import BaseVerdictAdapter


class FindingAdapter(BaseVerdictAdapter):
    """Adapter for /agentic finding-shaped items.

    Items are dicts with at minimum ``finding_id`` and ``is_exploitable``.
    """

    def item_id(self, item: Dict[str, Any]) -> str:
        fid = item.get("finding_id")
        if not isinstance(fid, str) or not fid:
            raise ValueError(
                f"finding missing required 'finding_id' field: "
                f"{sorted(item.keys())}"
            )
        return fid

    def normalize_verdict(self, item: Dict[str, Any]) -> str:
        # Mirror legacy ``_select_primary_result``'s truthy check:
        # ``r.get("is_exploitable", False)`` defaults missing to False
        # (negative-equivalent). The substrate's BaseVerdictAdapter
        # default would have mapped missing → "unknown" (rank 1, between
        # positive and negative), but legacy treats missing as definite
        # negative. Preserve that rule here.
        return "positive" if item.get("is_exploitable") else "negative"

    def extract_analysis_record(
        self, result: Dict[str, Any], model_name: str,
    ) -> Dict[str, Any]:
        """Per-model record stored under ``multi_model_analyses``.

        Matches /agentic's existing inline shape (preserved verbatim
        from the manual loop in orchestrator.py): model + is_exploitable
        + exploitability_score + ruling + full reasoning. Differs from
        the substrate's default in two ways:
        - includes ``ruling`` (free-form LLM verdict string) instead
          of substrate's normalized ``verdict``;
        - reasoning is NOT truncated (substrate truncates to 600 chars
          by default).
        """
        return {
            "model": model_name,
            "is_exploitable": result.get("is_exploitable"),
            "exploitability_score": result.get("exploitability_score"),
            "ruling": result.get("ruling"),
            "reasoning": result.get("reasoning", ""),
        }

    def select_primary_with_error_fallback(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Filter error entries, then ``select_primary``.

        /agentic's caller may pass result lists that contain error
        entries (dicts with an ``"error"`` key). The substrate's
        dispatch loop normally filters these upstream, but /agentic
        does its own dispatch and hands the unfiltered list directly
        to selection. Mirrors legacy ``_select_primary_result``'s
        error handling: errors skipped during selection; if every
        result is an error, return a copy of the first error.

        After PR3 Option B (orchestrator on substrate dispatch), this
        wrapper becomes redundant and can be removed.
        """
        if not model_results:
            raise ValueError("select_primary_with_error_fallback called with empty list")
        non_error = [r for r in model_results if "error" not in r]
        if non_error:
            return self.select_primary(non_error)
        return dict(model_results[0])

    def select_primary(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Mirror ``_select_primary_result`` behaviour exactly.

        Two legacy quirks the substrate's default ``select_primary``
        does NOT preserve, so we override:

        1. ``_quality`` defaults to 1.0 when missing (legacy treated
           "no quality field" as "perfect quality"). Substrate's default
           treats missing as 0.0 (no info). Effect: when one model has
           ``_quality=0.85`` and another lacks the field, legacy picks
           the one without it (1.0 > 0.85); substrate picks the 0.85.
        2. ``is_exploitable`` is truthy-checked, not strictly compared
           to True. Truthy non-bool values (``"yes"``, ``1``) rank as
           positive in legacy. (Already covered by normalize_verdict.)

        These divergences are theoretical for clean LLM output, but we
        preserve them to keep PR3 Option A a strict lift-and-shift.
        """
        if not model_results:
            raise ValueError("select_primary called with empty list")

        def sort_key(r: Dict[str, Any]):
            # Verdict rank via normalize_verdict so the adapter's
            # verdict semantics live in one place. positive→0, anything
            # else→1 (mirrors legacy's truthy check via normalize_verdict).
            verdict_rank = 0 if self.normalize_verdict(r) == "positive" else 1
            # _quality defaults to 1.0 (legacy quirk)
            q_raw = r.get("_quality", 1.0)
            quality = q_raw if isinstance(q_raw, (int, float)) and not isinstance(q_raw, bool) else 0.0
            # exploitability_score: legacy uses ``r.get("...", 0) or 0``
            # so None or 0 both fall back to 0.
            score = r.get("exploitability_score", 0) or 0
            return (verdict_rank, -quality, -score)

        return dict(sorted(model_results, key=sort_key)[0])
