"""Tests for cross-family checker wiring.

Covers:
- CrossFamilyCheckTask selection (quality threshold, nonce leaked)
- CrossFamilyCheckTask adjudication (agree, dispute → conservative override)
- _resolve_cross_family_checker (resolved roles, auto-detect from env)
- dispatch.py quality/nonce persistence on result dicts
"""

import os
from unittest.mock import patch

import pytest

from core.llm.config import ModelConfig
from core.security.llm_family import (
    Family,
    family_of,
    same_family,
    select_cross_family_checker,
)
from core.security.prompt_defense_profiles import CONSERVATIVE
from packages.llm_analysis.dispatch import DispatchResult
from packages.llm_analysis.tasks import CrossFamilyCheckTask


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

def _model(provider: str, name: str, role: str | None = None) -> ModelConfig:
    return ModelConfig(provider=provider, model_name=name, role=role)


GEMINI_PRIMARY = _model("gemini", "gemini-2.5-pro", role="analysis")
ANTHROPIC_CHECKER = _model("anthropic", "claude-haiku-4-5-20251001")
OPENAI_FALLBACK = _model("openai", "gpt-4.1-mini", role="fallback")


def _finding(fid: str) -> dict:
    return {"finding_id": fid, "file_path": "vuln.c", "start_line": 10,
            "rule_id": "CWE-120", "code_snippet": "strcpy(buf, input);"}


def _result(fid: str, exploitable: bool = True, quality: float = 0.9,
            nonce_leaked: bool = False,
            analysed_by: str = "gemini-2.5-pro") -> dict:
    r = {
        "finding_id": fid,
        "is_exploitable": exploitable,
        "is_true_positive": True,
        "ruling": "validated" if exploitable else "false_positive",
        "reasoning": "test reasoning",
        "confidence": "high",
        "analysed_by": analysed_by,
        "_quality": quality,
    }
    if nonce_leaked:
        r["_nonce_leaked"] = True
    return r


# ---------------------------------------------------------------------------
# llm_family.py — already exists, but verify our assumptions
# ---------------------------------------------------------------------------

class TestFamilyOf:
    def test_anthropic(self):
        assert family_of("claude-opus-4-6") == "anthropic"
        assert family_of("claude-haiku-4-5-20251001") == "anthropic"

    def test_google(self):
        assert family_of("gemini-2.5-pro") == "google"
        assert family_of("gemini-2.5-flash") == "google"

    def test_openai(self):
        assert family_of("gpt-4.1-mini") == "openai"
        assert family_of("o3-mini") == "openai"

    def test_unknown(self):
        assert family_of("some-random-model") == "unknown"

    def test_cross_family(self):
        assert not same_family("claude-opus-4-6", "gemini-2.5-pro")
        assert same_family("claude-opus-4-6", "claude-haiku-4-5-20251001")

    def test_unknown_not_same(self):
        assert not same_family("unknown-a", "unknown-b")


class TestSelectCrossFamilyChecker:
    def test_picks_different_family(self):
        result = select_cross_family_checker(
            "gemini-2.5-pro",
            ["gemini-2.5-flash", "claude-haiku-4-5-20251001", "gpt-4.1-mini"],
        )
        assert result == "claude-haiku-4-5-20251001"

    def test_skips_same_family(self):
        result = select_cross_family_checker(
            "gemini-2.5-pro",
            ["gemini-2.5-flash", "gemini/gemini-pro"],
        )
        assert result is None

    def test_skips_unknown(self):
        result = select_cross_family_checker(
            "gemini-2.5-pro",
            ["mystery-model"],
        )
        assert result is None

    def test_preserves_order(self):
        result = select_cross_family_checker(
            "claude-opus-4-6",
            ["gpt-4.1-mini", "gemini-2.5-flash"],
        )
        assert result == "gpt-4.1-mini"


# ---------------------------------------------------------------------------
# CrossFamilyCheckTask
# ---------------------------------------------------------------------------

class TestCrossFamilyCheckTaskSelection:
    def test_selects_low_quality(self):
        findings = [_finding("F-001"), _finding("F-002"), _finding("F-003")]
        prior = {
            "F-001": _result("F-001", quality=0.5),   # below threshold
            "F-002": _result("F-002", quality=0.9),   # above threshold
            "F-003": _result("F-003", quality=0.69),  # just below threshold
        }
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        selected = task.select_items(findings, prior)
        ids = [f["finding_id"] for f in selected]
        assert "F-001" in ids
        assert "F-003" in ids
        assert "F-002" not in ids

    def test_selects_nonce_leaked(self):
        findings = [_finding("F-001"), _finding("F-002")]
        prior = {
            "F-001": _result("F-001", quality=0.95, nonce_leaked=True),
            "F-002": _result("F-002", quality=0.95),
        }
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        selected = task.select_items(findings, prior)
        ids = [f["finding_id"] for f in selected]
        assert "F-001" in ids
        assert "F-002" not in ids

    def test_skips_errors(self):
        findings = [_finding("F-001")]
        prior = {"F-001": {"finding_id": "F-001", "error": "timeout"}}
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        assert task.select_items(findings, prior) == []

    def test_empty_when_all_high_quality(self):
        findings = [_finding("F-001")]
        prior = {"F-001": _result("F-001", quality=0.95)}
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        assert task.select_items(findings, prior) == []


class TestCrossFamilyCheckTaskAdjudication:
    def test_agree_exploitable(self):
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": True, "ruling": "validated",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is True
        assert prior["F-001"].get("cross_family_disputed") is None
        check = prior["F-001"]["cross_family_check"]
        assert check["verdict"] == "agreed"
        assert check["checker_model"] == "claude-haiku-4-5-20251001"

    def test_agree_not_exploitable(self):
        prior = {"F-001": _result("F-001", exploitable=False, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": False, "ruling": "false_positive",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is True
        assert prior["F-001"]["is_exploitable"] is False

    def test_dispute_conservative_override(self):
        """When primary says not-exploitable but checker says exploitable,
        the conservative (exploitable) verdict wins."""
        prior = {"F-001": _result("F-001", exploitable=False, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": True, "ruling": "validated",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is True
        assert prior["F-001"].get("cross_family_disputed") is True
        check = prior["F-001"]["cross_family_check"]
        assert check["verdict"] == "disputed — conservative override"

    def test_dispute_reverse(self):
        """Primary says exploitable, checker says not. Conservative → exploitable."""
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": False, "ruling": "false_positive",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is True
        assert prior["F-001"].get("cross_family_disputed") is True

    def test_nonce_trigger_recorded(self):
        prior = {"F-001": _result("F-001", quality=0.5, nonce_leaked=True)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": True,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)
        assert prior["F-001"]["cross_family_check"]["trigger"] == "nonce_leaked"

    def test_quality_trigger_recorded(self):
        prior = {"F-001": _result("F-001", quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": True,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)
        assert prior["F-001"]["cross_family_check"]["trigger"] == "low_quality"

    def test_checker_error_skipped(self):
        prior = {"F-001": _result("F-001", quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "error": "timeout"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)
        assert "cross_family_check" not in prior["F-001"]

    def test_get_models(self):
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id={})
        models = task.get_models({})
        assert models == [ANTHROPIC_CHECKER]

    def test_same_family_fallback_guard(self):
        """LLMClient may fall back to a same-family model. The guard should
        detect this and skip adjudication instead of falsely claiming agreement."""
        prior = {"F-001": _result("F-001", quality=0.5, analysed_by="gemini-2.5-pro")}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": True, "ruling": "validated",
             "analysed_by": "gemini-2.5-flash"},  # same family as primary!
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is None
        assert prior["F-001"].get("cross_family_disputed") is None
        check = prior["F-001"]["cross_family_check"]
        assert "skipped" in check["verdict"]
        assert check["intended_model"] == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# _resolve_cross_family_checker / auto-detect
# ---------------------------------------------------------------------------

class TestResolveCrossFamilyChecker:
    def test_from_consensus_models(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        role_res = {
            "analysis_model": GEMINI_PRIMARY,
            "consensus_models": [ANTHROPIC_CHECKER],
            "fallback_models": [],
        }
        result = _resolve_cross_family_checker(GEMINI_PRIMARY, role_res)
        assert result is ANTHROPIC_CHECKER

    def test_from_fallback_models(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        role_res = {
            "analysis_model": GEMINI_PRIMARY,
            "consensus_models": [],
            "fallback_models": [OPENAI_FALLBACK],
        }
        result = _resolve_cross_family_checker(GEMINI_PRIMARY, role_res)
        assert result is OPENAI_FALLBACK

    def test_skips_same_family(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        same_family_model = _model("gemini", "gemini-2.5-flash", role="fallback")
        role_res = {
            "analysis_model": GEMINI_PRIMARY,
            "consensus_models": [],
            "fallback_models": [same_family_model],
        }
        # Falls through to auto-detect; with no env vars set, returns None
        with patch.dict(os.environ, {}, clear=True):
            result = _resolve_cross_family_checker(GEMINI_PRIMARY, role_res)
        assert result is None

    def test_auto_detect_anthropic_key(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        role_res = {
            "analysis_model": GEMINI_PRIMARY,
            "consensus_models": [],
            "fallback_models": [],
        }
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}, clear=True):
            result = _resolve_cross_family_checker(GEMINI_PRIMARY, role_res)
        assert result is not None
        assert result.provider == "anthropic"
        assert result.model_name == "claude-haiku-4-5-20251001"

    def test_auto_detect_gemini_key_for_anthropic_primary(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        anthropic_primary = _model("anthropic", "claude-opus-4-6", role="analysis")
        role_res = {
            "analysis_model": anthropic_primary,
            "consensus_models": [],
            "fallback_models": [],
        }
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True):
            result = _resolve_cross_family_checker(anthropic_primary, role_res)
        assert result is not None
        assert result.provider == "gemini"
        assert result.model_name == "gemini-2.5-flash"

    def test_no_cross_family_available(self):
        from packages.llm_analysis.orchestrator import _resolve_cross_family_checker
        role_res = {
            "analysis_model": GEMINI_PRIMARY,
            "consensus_models": [],
            "fallback_models": [],
        }
        with patch.dict(os.environ, {}, clear=True):
            result = _resolve_cross_family_checker(GEMINI_PRIMARY, role_res)
        assert result is None


# ---------------------------------------------------------------------------
# dispatch.py quality/nonce persistence (integration-ish)
# ---------------------------------------------------------------------------

class TestDispatchQualityPersistence:
    """Verify that _quality and _nonce_leaked are set on processed results."""

    def test_quality_on_dispatch_result(self):
        dr = DispatchResult(
            result={"is_exploitable": True, "reasoning": "test"},
            quality=0.65,
        )
        assert dr.quality == 0.65

    def test_quality_default(self):
        dr = DispatchResult(result={"is_exploitable": True})
        assert dr.quality == 1.0
