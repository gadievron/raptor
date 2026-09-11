"""Tests for _detect_multi_model_collapse — orchestrator's secondary
guard against silent-fallback collapsing the multi-model panel.

The PRIMARY guard is ``exclude_fallback_to`` in the LLM client (see
core/llm/tests/test_exclude_fallback.py). This detector catches the
corner case the primary guard can't: independent fallback paths
converging on the same external model.
"""

from __future__ import annotations

from packages.llm_analysis.orchestrator import _detect_multi_model_collapse


class TestDetectMultiModelCollapse:
    def test_no_collapse_when_all_panels_have_n_distinct(self):
        results = {
            "f1": {
                "multi_model_analyses": [
                    {"model": "pro"},
                    {"model": "flash"},
                ],
            },
            "f2": {
                "multi_model_analyses": [
                    {"model": "pro"},
                    {"model": "flash"},
                ],
            },
        }
        assert _detect_multi_model_collapse(results, n_analysis_models=2) == []

    def test_detects_finding_with_duplicate_panel(self):
        results = {
            "f1": {
                "multi_model_analyses": [
                    {"model": "haiku"},
                    {"model": "haiku"},  # duplicate — convergence
                ],
            },
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        assert collapsed == [("f1", ["haiku"])]

    def test_partial_collapse_some_findings_ok(self):
        results = {
            "f1": {
                "multi_model_analyses": [
                    {"model": "pro"},
                    {"model": "flash"},
                ],
            },
            "f2": {
                "multi_model_analyses": [
                    {"model": "haiku"},
                    {"model": "haiku"},
                ],
            },
            "f3": {
                "multi_model_analyses": [
                    {"model": "pro"},
                    {"model": "flash"},
                ],
            },
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        # Only f2 collapsed
        assert len(collapsed) == 1
        assert collapsed[0][0] == "f2"

    def test_three_model_panel_with_two_distinct_contributors(self):
        # 3 requested, 2 actual contributors (one model showed up twice)
        results = {
            "f1": {
                "multi_model_analyses": [
                    {"model": "pro"},
                    {"model": "flash"},
                    {"model": "flash"},  # convergence
                ],
            },
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=3)
        assert collapsed == [("f1", ["flash", "pro"])]

    def test_single_surviving_result_flagged_as_collapse(self):
        # ``multi_model_analyses`` is only attached when 2+ records
        # survived — a finding with a single surviving result in a
        # multi-model run is the WORST collapse (the other model's
        # work was lost, e.g. cancelled by an abort) and must be
        # flagged, not silently reported as clean multi-model.
        # Errored findings are excluded: they surface via
        # findings_failed, not as collapse.
        results = {
            "f1": {"is_exploitable": True, "analysed_by": "pro"},
            "f2": {
                "multi_model_analyses": [
                    {"model": "haiku"},
                    {"model": "haiku"},
                ],
            },
            "f3": {"error": "boom", "analysed_by": "pro"},
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        assert ("f1", ["pro"]) in collapsed
        assert ("f2", ["haiku"]) in collapsed
        assert all(fid != "f3" for fid, _ in collapsed)

    def test_unknown_model_labels_excluded_from_distinct_count(self):
        # ``?`` and None aren't real model identities — drop from counting
        # so they don't artificially inflate the distinct contributor set.
        results = {
            "f1": {
                "multi_model_analyses": [
                    {"model": "?"},
                    {"model": "haiku"},
                    {"model": None},
                ],
            },
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        # Only "haiku" is a real contributor; n=2 requested → collapsed
        assert collapsed == [("f1", ["haiku"])]

    def test_non_dict_analysis_entry_skipped(self):
        # Defensive: malformed multi_model_analyses entries shouldn't
        # crash the detector.
        results = {
            "f1": {
                "multi_model_analyses": [
                    "garbage",
                    {"model": "haiku"},
                    None,
                ],
            },
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        # 1 valid contributor of 2 requested → collapsed
        assert collapsed == [("f1", ["haiku"])]

    def test_empty_results_returns_empty(self):
        assert _detect_multi_model_collapse({}, n_analysis_models=2) == []

    def test_non_list_multi_model_analyses_does_not_crash(self):
        # If multi_model_analyses got malformed (not a list), the
        # finding is treated like any single-surviving-result record:
        # flagged as collapsed (its panel data is missing) — and the
        # detector must not crash on the bad shape.
        results = {
            "f1": {"multi_model_analyses": "wrong shape",
                   "analysed_by": "pro"},
            "f2": {"multi_model_analyses": {"oops": "dict"}},
        }
        collapsed = _detect_multi_model_collapse(results, n_analysis_models=2)
        assert ("f1", ["pro"]) in collapsed
        assert ("f2", []) in collapsed
