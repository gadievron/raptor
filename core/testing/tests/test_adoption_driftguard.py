"""Drift guard for the core.testing adoption sweep.

Pins converged test suites to the shared scaffolding (import-or-fail
style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py) so per-suite fake/builder copies cannot
silently reappear.

Deliberately NOT swept (bespoke behaviour, not copies):

* The responder-callback ``StubProvider`` + ``_build_llm`` trios in
  packages/codeql/tests/test_scorecard_wiring.py,
  packages/llm_analysis/tests/test_prefilter_wiring.py and
  packages/sca/tests/test_scorecard_wiring.py — they route canned
  responses per call/schema and wire specialized fast-tier models,
  which FakeStructuredProvider's single canned result cannot express.
* The scripted ``TurnResponse`` replay fakes (core/llm/tool_use,
  cve_diff agent, code_understanding dispatch) — a different
  protocol family.
* core/dataflow/tests/{test_cvefix_walk,test_ghsa_harvester}.py git
  builders — their hermetic env dict is load-bearing for the
  fetch-under-test (monkeypatched into the module under test), not
  just fixture setup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# Suites that must take FakeModel from core.testing.
_FAKE_MODEL_ADOPTERS = [
    "core/llm/multi_model/tests/test_dispatch.py",
    "core/llm/multi_model/tests/test_pipelines.py",
    "packages/code_understanding/tests/test_hunt.py",
    "packages/code_understanding/tests/test_trace.py",
]

# Suites that must build their client through core.testing.
_CLIENT_BUILDER_ADOPTERS = [
    "core/llm/tests/test_structured_provider_casing.py",
    "core/llm/tests/test_structured_response_cache.py",
    "core/llm/tests/test_schema_floor.py",
]


@pytest.mark.parametrize("rel_path", _FAKE_MODEL_ADOPTERS)
def test_fake_model_from_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.testing import .*\bFakeModel\b", src
    ), f"{rel_path} must import FakeModel from core.testing"
    assert "class FakeModel" not in src, (
        f"{rel_path} re-grew a local FakeModel copy"
    )


@pytest.mark.parametrize("rel_path", _CLIENT_BUILDER_ADOPTERS)
def test_client_builder_from_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "make_test_client" in src, (
        f"{rel_path} must build its client via "
        "core.testing.make_test_client"
    )
    assert "LLMClient.__new__" not in src, (
        f"{rel_path} re-grew a hand-rolled LLMClient.__new__ builder"
    )
