"""Drift guard for the core.run.retry adoption sweep.

Pins the swept attempt loops to the substrate (import-or-fail style,
same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py).

Sweep scope note: of the three loops the wave-2 handoff named, only
the codeql pack download is a plain transient-failure retry. The
cve_diff post-submit loop and the dataflow_validation compile loop
both feed the failure back into a fresh LLM/agent prompt between
attempts — generate-and-verify loops, which core/run/retry's own
docstring places out of scope (they belong with
core/orchestration/driver.py). They are deliberately NOT converged.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_RETRY_ADOPTERS = [
    "packages/codeql/query_runner.py",
]


@pytest.mark.parametrize("rel_path", _RETRY_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.run\.retry import .*\bretry_call\b", src
    ), f"{rel_path} must import retry_call from core.run.retry"


@pytest.mark.parametrize("rel_path", _RETRY_ADOPTERS)
def test_no_hand_rolled_backoff_loop(rel_path):
    """The tell-tale of a re-grown bespoke engine: a sleep on a
    doubling backoff inside an attempt loop."""
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert not re.search(r"time\.sleep\(\s*(backoff|2\s*\*\*)", src), (
        f"{rel_path} re-grew a hand-rolled backoff loop; use "
        "core.run.retry.retry_call"
    )
