"""Tests for the /agentic fail-open pre-LLM chokepoint (step 0e).

Mirrors the guard-dominance (P23) chokepoint contract: refuted claims
skip the LLM call with an explicit receipt + suppression record;
confirmed claims ride as corroboration; the verification tier grades
registry-grade receipts ``tool_backed``. No LLM, no subprocesses.
"""

from __future__ import annotations

from pathlib import Path

import core.orchestration.fail_open_channel as foc
from packages.llm_analysis.agent import AutonomousSecurityAgentV2
from packages.llm_analysis.verification_tier import (
    derive_verification_tier,
)


def _agent(tmp_path):
    return AutonomousSecurityAgentV2(
        tmp_path, tmp_path / "out", prep_only=True,
    )


FAIL_OPEN_CLAIM = (
    "the broad except swallows the check_token exception and "
    "verify_session fails open"
)

SWALLOW_PY = '''
def check_token(tok):
    if not tok:
        raise ValueError("no token")
    return True


def verify_session(request):
    try:
        check_token(request.token)
    except Exception:
        pass
    return True
'''


def _finding(reasoning=FAIL_OPEN_CLAIM):
    return {
        "finding_id": "FIND-0001",
        "rule_id": "swallowed-exception",
        "file": "auth.py",
        "function": "verify_session",
        "line": 9,
        "message": reasoning,
        "candidate_reasoning": reasoning,
    }


class TestFailOpenAdjudicate:
    def test_delegates_with_repo_and_out_dir(self, tmp_path, monkeypatch):
        agent = _agent(tmp_path)
        seen = {}

        def fake_adjudicate(finding, target, *, out_dir=None,
                            inventory=None):
            seen["target"] = target
            seen["out_dir"] = out_dir
            return {"outcome": "refuted", "reason": "x"}

        monkeypatch.setattr(foc, "adjudicate_finding", fake_adjudicate)
        out = agent._fail_open_adjudicate(_finding())
        assert out == {"outcome": "refuted", "reason": "x"}
        assert seen["target"] == Path(tmp_path)
        assert seen["out_dir"] == agent.out_dir

    def test_end_to_end_confirmed_receipt(self, tmp_path):
        (tmp_path / "auth.py").write_text(SWALLOW_PY)
        agent = _agent(tmp_path)
        receipt = agent._fail_open_adjudicate(_finding())
        assert receipt is not None
        assert receipt["outcome"] == "confirmed"
        assert receipt["rule_id"].startswith("fail_open:")
        assert receipt["handler"]["idiom"] == "except_pass"

    def test_non_fail_open_claim_yields_nothing(self, tmp_path):
        (tmp_path / "auth.py").write_text(SWALLOW_PY)
        agent = _agent(tmp_path)
        assert agent._fail_open_adjudicate(
            _finding("integer overflow in size calculation"),
        ) is None


class TestProcessFindingsWiring:
    def test_step_0e_present_with_receipt_semantics(self):
        import inspect

        import packages.llm_analysis.agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousSecurityAgentV2)
        # The chokepoint records an explicit disqualifier, feeds the
        # suppression audit trail, skips the LLM call on refutation,
        # attaches corroboration on confirmation, and honours the
        # per-run dispatch cap.
        assert "fail_open_refutation" in src
        assert 'verdict="fail_open_refuted"' in src
        assert "fail_open_skipped_llm_calls += 1" in src
        assert "fail_open_corroborated += 1" in src
        assert "FAIL_OPEN_CHANNEL_CAP" in src
        # Claim-shape gate runs BEFORE the adjudication spend.
        assert "fail_open_binding(finding)" in src


class TestVerificationTier:
    def test_registry_grade_confirmed_receipt_is_tool_backed(self):
        finding = {
            "analysis": {"is_true_positive": True},
            "fail_open": {
                "outcome": "confirmed",
                "rule_id": "fail_open:handler-outcome",
            },
        }
        assert derive_verification_tier(finding) == "tool_backed"

    def test_refuted_receipt_is_tool_backed(self):
        # The tier grades the evidence, not the verdict's sign.
        finding = {
            "analysis": {
                "is_true_positive": False,
                "fail_open": {
                    "outcome": "refuted",
                    "rule_id": "fail_open:ignored-return",
                },
            },
        }
        assert derive_verification_tier(finding) == "tool_backed"

    def test_detection_grade_naming_receipt_stays_llm_only(self):
        # An uncorroborated naming-stem role must not launder the
        # verdict into tool_backed.
        finding = {
            "analysis": {"is_true_positive": True},
            "fail_open": {
                "outcome": "confirmed",
                "rule_id": "fail_open:handler-outcome-naming",
            },
        }
        assert derive_verification_tier(finding) == "llm_only"

    def test_inconclusive_receipt_stays_llm_only(self):
        finding = {
            "fail_open": {
                "outcome": "inconclusive",
                "rule_id": "fail_open:handler-outcome",
            },
        }
        assert derive_verification_tier(finding) == "llm_only"
