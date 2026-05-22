"""Defensive tests for ``AutonomousSecurityAgentV2._judge_exploit_intent``.

Adversarial review of PR #577 surfaced type-confusion crashes
when ``vuln.metadata`` or ``vuln.analysis`` weren't the
``Optional[Dict[str, Any]]`` shape the type hint promises but
something else (list, str, etc.) — pipelines have been observed
to set these to unusual shapes in flight. Pre-fix the helper
called ``.get(...)`` unconditionally and crashed with
``AttributeError``; post-fix it gates on ``isinstance(..., dict)``
and treats anything else as "no signal."
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


# packages/llm_analysis/tests/test_agent_judge_intent_defense.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


def _stub_agent():
    """Minimal stand-in for AutonomousSecurityAgentV2 that supplies
    only ``llm`` (set to None so intent_match runs heuristic-only
    and never invokes the LLM tiebreak)."""
    agent = SimpleNamespace(llm=None)
    agent._judge_exploit_intent = (
        AutonomousSecurityAgentV2._judge_exploit_intent.__get__(
            agent, type(agent)
        )
    )
    return agent


def _make_vuln(metadata=None, analysis=None):
    """Construct a VulnerabilityContext sidestepping the full
    constructor (which needs Finding-shaped data + repo_path)."""
    vuln = VulnerabilityContext.__new__(VulnerabilityContext)
    vuln.finding_id = "FIND-0001"
    vuln.rule_id = "test/rule"
    vuln.file_path = "src/auth.c"
    vuln.start_line = 1
    vuln.end_line = 1
    vuln.level = "error"
    vuln.message = "test"
    vuln.cwe_id = "CWE-120"
    vuln.tool = "test"
    vuln.full_code = None
    vuln.surrounding_context = None
    vuln.exploitable = True
    vuln.exploitability_score = 0.8
    vuln.exploit_code = '// targets src/auth.c\npayload = "A" * 100'
    vuln.exploit_compiled = None
    vuln.exploit_compile_errors = []
    vuln.intent_match = None
    vuln.patch_code = None
    vuln.feasibility = {"status": "pending"}
    vuln.has_dataflow = False
    vuln.metadata = metadata
    vuln.analysis = analysis
    return vuln


# ----------------------------------------------------------------------
# vuln.metadata shape tolerance
# ----------------------------------------------------------------------


class TestMetadataShapeTolerance:
    def test_metadata_dict_normal(self):
        """Sanity: a proper dict metadata works (regression guard
        for the happy path)."""
        agent = _stub_agent()
        vuln = _make_vuln(metadata={"name": "check_password"})
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None
        # function_overlap should fire — function name in exploit code? No,
        # exploit doesn't mention check_password. So no overlap. But the
        # call shouldn't crash.

    def test_metadata_none(self):
        """``None`` metadata is the common default — must not crash."""
        agent = _stub_agent()
        vuln = _make_vuln(metadata=None)
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None

    @pytest.mark.parametrize("bad_metadata", [
        ["not", "a", "dict"],          # list
        "raw string",                   # string
        42,                             # int
        object(),                       # arbitrary object
    ])
    def test_metadata_non_dict_does_not_crash(self, bad_metadata):
        """Pre-fix this raised AttributeError on ``.get("name")``.
        Post-fix the helper treats non-dict metadata as "no
        function-name signal" and runs intent_match with
        ``function_name=None``."""
        agent = _stub_agent()
        vuln = _make_vuln(metadata=bad_metadata)
        # Must not raise
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None


# ----------------------------------------------------------------------
# vuln.analysis shape tolerance
# ----------------------------------------------------------------------


class TestAnalysisShapeTolerance:
    def test_analysis_dict_with_true_positive_false_skips(self):
        """Regression guard: the FP-skip path still fires when
        analysis is a proper dict."""
        agent = _stub_agent()
        vuln = _make_vuln(analysis={"is_true_positive": False})
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        # Skipped — intent_match stays None
        assert vuln.intent_match is None

    def test_analysis_dict_with_true_positive_true_runs(self):
        agent = _stub_agent()
        vuln = _make_vuln(analysis={"is_true_positive": True})
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None

    def test_analysis_dict_missing_true_positive_runs(self):
        """``is_true_positive`` not in the dict → judge runs."""
        agent = _stub_agent()
        vuln = _make_vuln(analysis={"some_other_field": "value"})
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None

    def test_analysis_none_runs(self):
        agent = _stub_agent()
        vuln = _make_vuln(analysis=None)
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None

    @pytest.mark.parametrize("bad_analysis", [
        "raw string",
        ["a", "list"],
        42,
        object(),
    ])
    def test_analysis_non_dict_does_not_crash(self, bad_analysis):
        """Pre-fix this raised AttributeError on
        ``.get("is_true_positive")``. Post-fix non-dict analysis
        is treated as "no triage signal" and the judge runs."""
        agent = _stub_agent()
        vuln = _make_vuln(analysis=bad_analysis)
        agent._judge_exploit_intent(vuln, vuln.exploit_code)
        assert vuln.intent_match is not None


# ----------------------------------------------------------------------
# Combined shape-mismatch
# ----------------------------------------------------------------------


def test_both_metadata_and_analysis_non_dict_does_not_crash():
    """Worst-case: pipeline upstream wrote both fields to unusual
    shapes. Judge still runs."""
    agent = _stub_agent()
    vuln = _make_vuln(
        metadata=["broken", "shape"],
        analysis="even more broken",
    )
    agent._judge_exploit_intent(vuln, vuln.exploit_code)
    assert vuln.intent_match is not None
