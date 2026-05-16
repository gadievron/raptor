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

    # Quality floor for primary selection. Results from
    # response_validation with quality < floor are heavily
    # malformed (missing required fields, partial responses,
    # truncated mid-JSON). Promoting one to primary just because
    # its truthy-positive `is_exploitable` outranks a clean
    # negative is exactly the failure mode that surfaced in the
    # bug-hunt review: low-quality positive verdicts are usually
    # the LLM hallucinating or partially answering, not a real
    # signal. 0.3 picked to match the LOW threshold elsewhere in
    # the pipeline (RetryTask.LOW = 0.3 — same "definitely
    # ambiguous" boundary).
    _PRIMARY_QUALITY_FLOOR = 0.3

    def select_primary(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Mirror ``_select_primary_result`` behaviour with a
        quality floor on primary promotion.

        Selection key (lexicographic):

        1. **Above-floor flag.** Results with `_quality >=
           PRIMARY_QUALITY_FLOOR` rank ABOVE results below it,
           regardless of their verdict. Pre-fix a positive
           verdict with quality=0.05 (mostly-empty malformed
           response) won over a clean negative — exactly the
           wrong direction. Post-fix the clean negative wins;
           the malformed positive falls to the bottom of the
           pile but is still selectable if it's the only one
           (preserves "always return *something*").
        2. Verdict rank — positive (truthy is_exploitable)
           ranks above negative.
        3. -quality (higher quality wins ties).
        4. -score (higher exploitability_score wins remaining ties).

        Two legacy quirks preserved from `_select_primary_result`:
        - `_quality` defaults to 1.0 when missing (legacy treated
          "no quality field" as "perfect quality").
        - `is_exploitable` is truthy-checked (covered by
          normalize_verdict).
        """
        if not model_results:
            raise ValueError("select_primary called with empty list")

        def sort_key(r: Dict[str, Any]):
            # _quality defaults to 1.0 (legacy quirk)
            q_raw = r.get("_quality", 1.0)
            quality = q_raw if isinstance(q_raw, (int, float)) and not isinstance(q_raw, bool) else 0.0
            # Above-floor flag — primary axis. 0 = above floor
            # (preferred), 1 = below floor (last resort).
            below_floor = 0 if quality >= self._PRIMARY_QUALITY_FLOOR else 1
            # Verdict rank via normalize_verdict so the adapter's
            # verdict semantics live in one place. positive→0,
            # anything else→1 (mirrors legacy's truthy check via
            # normalize_verdict).
            verdict_rank = 0 if self.normalize_verdict(r) == "positive" else 1
            # exploitability_score: legacy uses ``r.get("...", 0) or 0``
            # so None or 0 both fall back to 0.
            score = r.get("exploitability_score", 0) or 0
            return (below_floor, verdict_rank, -quality, -score)

        return dict(sorted(model_results, key=sort_key)[0])
