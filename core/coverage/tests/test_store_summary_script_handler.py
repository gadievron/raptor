"""Stamped script-handler spans join the coverage review denominators.

Gap selection schedules stamped handler interstitials for review, but
the store view kept them out of llm_reviewable / functions_reviewed /
llm_gap / review_gap — on script-heavy trees a large share of the
scheduled units was invisible in every denominator, so the report
claimed completion the review loop never had. Stamp-gated in the
conservative direction: True joins the denominators; False, absent
(pre-stamp checklists) and forged values keep the glue exclusion.
"""

from __future__ import annotations

from core.coverage.store import CoverageStore
from core.coverage.store_summary import (
    file_breakdown,
    format_store_view,
    store_view,
)


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _checklist(handler_stamp=True) -> dict:
    handler = {"name": "interstitial:8-9", "kind": "interstitial",
               "line_start": 8, "line_end": 9}
    if handler_stamp is not None:
        handler["script_handler"] = handler_stamp
    return {"files": [
        {"path": "mod/save.php", "language": "php", "lines": 20, "items": [
            {"name": "helper", "kind": "function",
             "line_start": 4, "line_end": 6},
            {"name": "interstitial:1-3", "kind": "interstitial",
             "line_start": 1, "line_end": 3, "script_handler": False},
            handler,
        ]},
    ]}


class TestStoreView:
    def test_stamped_handler_joins_reviewable_and_gap(self, tmp_path):
        v = store_view(_store(tmp_path), _checklist())
        # helper + the stamped handler span; the wiring span stays out.
        assert v["llm_reviewable"] == 2
        gap = {g["function"] for g in v["llm_gap_functions"]}
        assert gap == {"helper", "interstitial:8-9"}
        review = {g["function"] for g in v["review_gap"]}
        assert "interstitial:8-9" in review
        assert "interstitial:1-3" not in review
        # Completeness counts keep every kind, unchanged.
        assert v["total_functions"] == 3
        assert v["items_by_kind"] == {"function": 1, "interstitial": 2}
        # The rendered report stays coherent with the shifted numbers.
        out = format_store_view(v)
        assert "Items: 3 total" in out

    def test_reviewed_handler_counts_as_reviewed(self, tmp_path):
        s = _store(tmp_path)
        s.mark("mod/save.php", 8, 9, "claude:audit")   # llm, analysed depth
        v = store_view(s, _checklist())
        assert v["llm_reviewable"] == 2
        assert v["functions_reviewed"] == 1
        gap = {g["function"] for g in v["llm_gap_functions"]}
        assert gap == {"helper"}

    def test_unstamped_interstitial_keeps_glue_exclusion(self, tmp_path):
        v = store_view(_store(tmp_path), _checklist(handler_stamp=None))
        assert v["llm_reviewable"] == 1
        gap = {g["function"] for g in v["llm_gap_functions"]}
        assert gap == {"helper"}
        review = {g["function"] for g in v["review_gap"]}
        assert "interstitial:8-9" not in review

    def test_stamped_false_and_forged_stay_out(self, tmp_path):
        v = store_view(_store(tmp_path), _checklist(handler_stamp=False))
        assert v["llm_reviewable"] == 1
        v = store_view(_store(tmp_path), _checklist(handler_stamp="true"))
        assert v["llm_reviewable"] == 1


class TestFileBreakdown:
    def test_stamped_handler_joins_per_file_reviewable(self, tmp_path):
        s = _store(tmp_path)
        s.mark("mod/save.php", 8, 9, "claude:audit")
        rows = file_breakdown(s, _checklist())
        row = next(r for r in rows if r["path"] == "mod/save.php")
        assert row["items"] == 3
        assert row["reviewable"] == 2
        assert row["llm"] == 1

    def test_unstamped_keeps_old_per_file_denominator(self, tmp_path):
        rows = file_breakdown(
            _store(tmp_path), _checklist(handler_stamp=None))
        row = next(r for r in rows if r["path"] == "mod/save.php")
        assert row["reviewable"] == 1
