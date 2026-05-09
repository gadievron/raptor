"""Tests for the IRIS dataflow-validation surfacing in raptor_agentic.

The section builder is a private helper in raptor_agentic.py. It reads
from the `dataflow_validation` block that the orchestrator writes into
the merged report (see orchestrator.py: `merged["dataflow_validation"]
= {**validation_metrics, n_applied_downgrades, n_soft_downgrades}`).

Goal: catch regressions in either direction —
  - section builder formatting (unit test on the helper)
  - the dict shape produced by the orchestrator (the keys we read here
    have to actually be there)
"""

import importlib.util
import sys
from pathlib import Path


def _load_agentic_module():
    """Import raptor_agentic without invoking its CLI entry point.

    The module lives at the repo root, not in a package. We bring it in
    via importlib so this test doesn't depend on the test runner's CWD
    or sys.path shape.
    """
    repo_root = Path(__file__).resolve().parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    spec = importlib.util.spec_from_file_location(
        "raptor_agentic_for_tests", repo_root / "raptor_agentic.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _full_metrics(**overrides):
    """Realistic shape of `merged["dataflow_validation"]` produced by the
    orchestrator. Tests override individual fields rather than building
    from scratch so missing-key regressions surface in the section
    builder rather than the test fixture.
    """
    base = {
        "n_eligible": 4,
        "n_validated": 3,
        "n_cache_hits": 0,
        "n_errors": 0,
        "n_skipped_no_db_for_language": 0,
        "n_stale_db_warnings": 0,
        "n_tier1_prebuilt": 2,
        "n_tier2_template": 1,
        "n_tier3_retry": 0,
        "n_recommended_downgrades": 1,
        "n_applied_downgrades": 1,
        "n_soft_downgrades": 0,
        "skipped_reason": "",
    }
    base.update(overrides)
    return base


def test_section_renders_full_metrics_block():
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(_full_metrics())
    assert section.title == "IRIS Dataflow Validation"
    body = section.content
    assert "Eligible findings: **4**" in body
    assert "validated: **3**" in body
    assert "Tier 1 (free, prebuilt query): 2" in body
    assert "Tier 2 (LLM-customised predicates): 1" in body
    # Tier 3 = 0 → omitted from the breakdown
    assert "Tier 3" not in body
    assert "Recommended (validation refuted claim): 1" in body
    assert "Applied hard (no consensus override): 1" in body


def test_skipped_reason_short_circuits_other_fields():
    """When the orchestrator records `skipped_reason`, the rest of the
    block is irrelevant — just surface the reason."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section({
        "skipped_reason": "no_database",
    })
    assert "no_database" in section.content
    # No tier breakdown when skipped
    assert "Tier 1" not in section.content
    assert "Eligible" not in section.content


def test_cache_hits_surface_in_header():
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(n_cache_hits=2)
    )
    assert "+2 cache hits" in section.content


def test_cache_hit_singular_grammar():
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(n_cache_hits=1)
    )
    assert "+1 cache hit)" in section.content
    # No bare 'hits' (plural) for a count of 1
    assert "+1 cache hits" not in section.content


def test_soft_downgrade_surfaces_consensus_override_explanation():
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(
            n_recommended_downgrades=2,
            n_applied_downgrades=1,
            n_soft_downgrades=1,
        )
    )
    assert "Applied soft" in section.content
    assert "consensus" in section.content.lower()


def test_recommendation_with_no_application_notes_skipped_reconciliation():
    """If validation recommended downgrades but reconciliation didn't
    apply any (consensus + judge agreed with original), the section
    explicitly notes that, so operators don't read 'recommended: 1' as
    'silently dropped'."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(
            n_recommended_downgrades=2,
            n_applied_downgrades=0,
            n_soft_downgrades=0,
        )
    )
    assert "Recommended" in section.content
    assert "not applied" in section.content


def test_errors_and_skips_surface_when_present():
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(
            n_errors=2,
            n_skipped_no_db_for_language=3,
            n_stale_db_warnings=1,
        )
    )
    assert "Errors:** 2" in section.content
    assert "Skipped (no CodeQL DB for finding's language):** 3" in section.content
    assert "Stale-DB warnings:** 1" in section.content


def test_no_tier_breakdown_when_all_zero():
    """If no tier ran (e.g. all eligible findings were cache hits),
    don't emit an empty 'By tier:' block."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(
            n_validated=0, n_cache_hits=4,
            n_tier1_prebuilt=0, n_tier2_template=0, n_tier3_retry=0,
            n_recommended_downgrades=0, n_applied_downgrades=0,
        )
    )
    # Header still renders (cache hits matter)
    assert "+4 cache hits" in section.content
    # No empty tier block
    assert "By tier:" not in section.content
    # No empty downgrade block
    assert "Downgrades:" not in section.content


def test_tier4_smt_block_renders_when_outcomes_present():
    """Tier 4 SMT outcomes (refuted / witness / disagreement) get
    their own sub-block in the report — additive on top of the
    Tier 1/2/3 verdict."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(
            n_tier4_smt_refuted=2,
            n_tier4_smt_witness=3,
            n_tier4_smt_disagree=1,
        )
    )
    body = section.content
    assert "Tier 4 SMT path-feasibility refinement" in body
    assert "Refuted (inconclusive → refuted on unsat conditions): 2" in body
    assert "Witness attached to confirmed" in body
    assert "3" in body  # witness count
    assert "SMT-CodeQL disagreement" in body


def test_tier4_smt_block_omitted_when_no_outcomes():
    """When all Tier 4 counts are zero, no Tier 4 block at all —
    avoids noise on runs where no findings carried path_conditions."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(_full_metrics())
    body = section.content
    assert "Tier 4 SMT" not in body


def test_tier4_smt_block_partial_outcomes_only_shows_present_ones():
    """Each Tier 4 outcome line is independently gated — a run with
    only witnesses (no refutations / disagreements) shows just the
    witness line."""
    mod = _load_agentic_module()
    section = mod._build_dataflow_validation_report_section(
        _full_metrics(n_tier4_smt_witness=5)
    )
    body = section.content
    assert "Tier 4 SMT" in body
    assert "Witness attached" in body
    assert "Refuted" not in body  # the standalone Tier 4 'Refuted' line
    assert "disagreement" not in body
