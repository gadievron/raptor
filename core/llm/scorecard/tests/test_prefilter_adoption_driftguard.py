"""Drift guard for the shared FP-prefilter helpers.

Pins the consumers of ``core.llm.scorecard.fast_tier_model_name`` /
``run_cheap_fp_check`` to the substrate (import-or-fail style, same
pattern as packages/llm_analysis/tests/test_preflight_cost_gate.py)
so per-package copies of the fast-tier routing rule cannot silently
reappear.

Deliberately NOT swept:

* ``packages/sca/llm/upgrade_impact_review._cheap_safe_check`` keeps
  SCA's ``run_stage`` envelope for the cheap call itself — run_stage
  layers preflight, response sanitisation and defence telemetry that
  ``run_cheap_fp_check`` does not, and dropping them would be a
  posture regression, not deduplication. Only the duplicated
  fast-tier model-name rule converged.
* ``packages/llm_analysis/prefilter.py`` — held by the concurrent
  dedup-wave1 series (audit↔agentic handoff territory) at sweep
  time; its local ``_fast_tier_model_name`` / ``_cheap_fp_check``
  copies and the missing ``record_prefilter_outcome`` call are
  documented for the wave that owns the file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]

_FAST_TIER_ADOPTERS = [
    "packages/codeql/dataflow_validator.py",
    "packages/codeql/autonomous_analyzer.py",
    "packages/sca/llm/upgrade_impact_review.py",
]


@pytest.mark.parametrize("rel_path", _FAST_TIER_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.llm\.scorecard import[\s\S]{0,120}?"
        r"\bfast_tier_model_name\b",
        src,
    ), f"{rel_path} must import fast_tier_model_name from core.llm.scorecard"


@pytest.mark.parametrize("rel_path", _FAST_TIER_ADOPTERS)
def test_no_local_fast_tier_copy(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "def _fast_tier_model_name(client)" not in src, (
        f"{rel_path} re-grew a local fast-tier model-name copy; use "
        "core.llm.scorecard.fast_tier_model_name"
    )
    # The routing rule's tell-tale body outside the substrate:
    assert "specialized_models.get(TaskType.VERDICT_BINARY)" not in src, (
        f"{rel_path} re-implements the fast-tier routing rule inline"
    )
