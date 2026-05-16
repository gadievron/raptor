"""Tests for the IRIS dataflow_validation console renderer.

Shared between /agentic and /analyze — pre-extraction this lived
inline in raptor_agentic.py only, leaving /analyze operators
unable to see Tier 4 / path_conditions telemetry. These tests
pin both the populated and the no-op cases so neither surface
silently regresses.
"""

from core.reporting.dataflow_summary import render_dataflow_validation_lines


class TestRenderDataflowValidationLines:

    def test_empty_dict_renders_nothing(self):
        assert render_dataflow_validation_lines({}) == []

    def test_none_renders_nothing(self):
        """Caller may pass None when validation never ran (no
        orchestration result, prep-only mode, etc.)."""
        assert render_dataflow_validation_lines(None) == []

    def test_no_validations_no_skip_reason_renders_nothing(self):
        """Validation was set up but no finding entered the loop
        (eligibility filter, etc.) — silent rather than printing
        a misleading 'Dataflow validated: 0' line."""
        dv = {"n_validated": 0, "n_cache_hits": 0, "skipped_reason": ""}
        assert render_dataflow_validation_lines(dv) == []

    def test_skipped_reason_surfaces_when_no_validation_ran(self):
        """When the orchestrator set skipped_reason but no finding
        was validated, surface the reason — operator can tell IRIS
        noticed but couldn't help."""
        dv = {"n_validated": 0, "skipped_reason": "no_database"}
        out = render_dataflow_validation_lines(dv, indent="   ")
        assert out == ["   Dataflow validation skipped: no_database"]

    def test_simple_validation_run(self):
        dv = {
            "n_validated": 3,
            "n_cache_hits": 0,
        }
        out = render_dataflow_validation_lines(dv, indent="   ")
        # Only the header — no tier breakdown, no SMT, no
        # path_conditions, no downgrades (all defaulted to 0).
        assert out == ["   Dataflow validated: 3"]

    def test_cache_hits_pluralised(self):
        dv = {"n_validated": 1, "n_cache_hits": 1}
        out = render_dataflow_validation_lines(dv)
        assert "(+1 cache hit)" in out[0]
        assert "hits)" not in out[0]

        dv = {"n_validated": 1, "n_cache_hits": 5}
        out = render_dataflow_validation_lines(dv)
        assert "(+5 cache hits)" in out[0]

    def test_tier_breakdown_only_lists_non_zero_tiers(self):
        dv = {
            "n_validated": 5,
            "n_tier1_prebuilt": 2,
            "n_tier2_template": 0,
            "n_tier3_retry": 1,
        }
        out = render_dataflow_validation_lines(dv, indent="   ")
        tier_line = [l for l in out if "by tier:" in l][0]
        assert "2 Tier 1" in tier_line
        assert "Tier 2" not in tier_line  # zero — omitted
        assert "1 Tier 3" in tier_line

    def test_tier_breakdown_omitted_when_all_zero(self):
        dv = {
            "n_validated": 1,
            "n_tier1_prebuilt": 0,
            "n_tier2_template": 0,
            "n_tier3_retry": 0,
        }
        out = render_dataflow_validation_lines(dv)
        assert not any("by tier:" in l for l in out)

    def test_tier4_smt_subline_when_any_outcome_fired(self):
        dv = {
            "n_validated": 2,
            "n_tier4_smt_witness": 1,
            "n_tier4_smt_refuted": 1,
        }
        out = render_dataflow_validation_lines(dv)
        smt_line = [l for l in out if "Tier 4 SMT:" in l][0]
        assert "1 refuted" in smt_line
        assert "1 witness" in smt_line
        assert "disagreement" not in smt_line  # zero — omitted

    def test_path_conditions_with_cwe_breakdown(self):
        """Sorted by count descending — most common CWE first so
        operators see the dominant pattern at a glance."""
        dv = {
            "n_validated": 5,
            "n_path_conditions_populated": 4,
            "path_conditions_by_cwe": {"CWE-190": 1, "CWE-476": 3},
        }
        out = render_dataflow_validation_lines(dv)
        pc_line = [l for l in out if "path_conditions populated:" in l][0]
        assert "4" in pc_line
        # Sort: CWE-476 first (count 3), CWE-190 second (count 1).
        idx_476 = pc_line.index("CWE-476")
        idx_190 = pc_line.index("CWE-190")
        assert idx_476 < idx_190, "CWE breakdown should be sorted by count desc"

    def test_path_conditions_without_cwe_breakdown(self):
        dv = {
            "n_validated": 3,
            "n_path_conditions_populated": 2,
            "path_conditions_by_cwe": {},
        }
        out = render_dataflow_validation_lines(dv)
        pc_line = [l for l in out if "path_conditions populated:" in l][0]
        assert pc_line.endswith(": 2")  # no parenthetical breakdown

    def test_downgrades_recommended_only(self):
        dv = {
            "n_validated": 3,
            "n_recommended_downgrades": 2,
        }
        out = render_dataflow_validation_lines(dv)
        dl = [l for l in out if "downgrades:" in l][0]
        assert "2 flagged" in dl
        assert "applied:" not in dl

    def test_downgrades_recommended_and_applied(self):
        dv = {
            "n_validated": 5,
            "n_recommended_downgrades": 3,
            "n_applied_downgrades": 2,
            "n_soft_downgrades": 1,
        }
        out = render_dataflow_validation_lines(dv)
        dl = [l for l in out if "downgrades:" in l][0]
        assert "3 flagged" in dl
        assert "2 hard" in dl
        assert "1 soft (consensus override)" in dl

    def test_indent_zero_for_analyze_style(self):
        """/analyze's report uses flat lines (no leading whitespace),
        unlike /agentic which indents under the summary header."""
        dv = {"n_validated": 1}
        out = render_dataflow_validation_lines(dv, indent="")
        assert out[0] == "Dataflow validated: 1"

    def test_full_telemetry_renders_complete_block(self):
        """End-to-end shape — what an operator sees on a real run
        with all signals firing."""
        dv = {
            "n_validated": 5,
            "n_cache_hits": 2,
            "n_tier1_prebuilt": 3,
            "n_tier2_template": 1,
            "n_tier3_retry": 1,
            "n_tier4_smt_refuted": 1,
            "n_tier4_smt_witness": 2,
            "n_tier4_smt_disagree": 0,
            "n_path_conditions_populated": 3,
            "path_conditions_by_cwe": {"CWE-190": 2, "CWE-476": 1},
            "n_recommended_downgrades": 1,
            "n_applied_downgrades": 1,
            "n_soft_downgrades": 0,
        }
        out = render_dataflow_validation_lines(dv, indent="   ")
        joined = "\n".join(out)
        assert "Dataflow validated: 5" in joined
        assert "(+2 cache hits)" in joined
        assert "Tier 1 (free)" in joined
        assert "Tier 2 (LLM)" in joined
        assert "Tier 3 (LLM retry)" in joined
        assert "1 refuted" in joined
        assert "2 witness" in joined
        assert "disagreement" not in joined
        assert "path_conditions populated: 3" in joined
        assert "CWE-190=2" in joined
        assert "1 flagged" in joined
        assert "1 hard" in joined
