"""Tests for cross-family checker wiring.

Covers:
- CrossFamilyCheckTask selection (quality threshold, nonce leaked)
- CrossFamilyCheckTask adjudication (agree, dispute → conservative override)
- _resolve_cross_family_checker (resolved roles, auto-detect from env)
- dispatch.py quality/nonce persistence on result dicts
"""

import os
from unittest.mock import patch


from core.llm.config import ModelConfig
from core.security.llm_family import (
    family_of,
    same_family,
    select_cross_family_checker,
)
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

    def test_checker_abstention_does_not_flip_primary(self):
        """A nulled checker verdict (errored / refused / schema-failed
        response) is an abstention, not a vote (shared counting rule —
        correlation.py tally contract). Pre-fix it read as a "dispute"
        and the conservative override flipped a clean not-exploitable
        primary to exploitable."""
        prior = {"F-001": _result("F-001", exploitable=False, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": None, "ruling": None,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is False
        assert prior["F-001"].get("cross_family_disputed") is None
        assert prior["F-001"].get("cross_family_agreed") is None
        check = prior["F-001"]["cross_family_check"]
        assert check["verdict"] == "skipped — checker returned no verdict"

    def test_checker_abstention_does_not_dispute_exploitable_primary(self):
        """Mirror direction: primary exploitable, checker abstained —
        no dispute noise, verdict preserved."""
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": None,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is True
        assert prior["F-001"].get("cross_family_disputed") is None
        assert prior["F-001"].get("cross_family_agreed") is None

    def test_both_abstained_mints_no_agreement(self):
        """Primary nulled + checker nulled compared equal pre-fix and
        minted ``cross_family_agreed`` corroboration from zero actual
        verdicts (downstream: judge/consensus skip agreed findings)."""
        primary = _result("F-001", quality=0.5)
        primary["is_exploitable"] = None
        prior = {"F-001": primary}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": None,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is None
        assert prior["F-001"].get("cross_family_disputed") is None
        assert "skipped" in prior["F-001"]["cross_family_check"]["verdict"]

    def test_primary_abstention_not_adjudicated(self):
        """Primary nulled + checker voting: there is no primary vote
        to agree or dispute with — record but don't adjudicate,
        matching the same-family fallback shape."""
        primary = _result("F-001", quality=0.5)
        primary["is_exploitable"] = None
        prior = {"F-001": primary}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": False,
             "ruling": "false_positive",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is None
        assert prior["F-001"].get("cross_family_disputed") is None
        assert prior["F-001"].get("cross_family_agreed") is None
        check = prior["F-001"]["cross_family_check"]
        assert check["verdict"] == "skipped — primary returned no verdict"
        assert check["checker_exploitable"] is False

    def test_junk_on_both_sides_mints_no_agreement(self):
        """Identical junk shapes compared equal pre-fix ("yes" ==
        "yes") and minted ``cross_family_agreed`` from two non-verdicts
        — which then EXCLUDED the finding from both the consensus and
        judge panels (their select_items skip agreed findings). Junk is
        a non-verdict: record the check, don't adjudicate."""
        primary = _result("F-001", quality=0.5)
        primary["is_exploitable"] = "yes"
        prior = {"F-001": primary}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": "yes",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is None
        assert prior["F-001"].get("cross_family_disputed") is None
        assert "skipped" in prior["F-001"]["cross_family_check"]["verdict"]
        # The panels must still see this finding.
        from packages.llm_analysis.tasks import ConsensusTask, JudgeTask
        findings = [_finding("F-001")]
        assert ConsensusTask().select_items(findings, prior) == findings
        assert JudgeTask(results_by_id=prior).select_items(
            findings, prior) == findings

    def test_junk_checker_does_not_flip_genuine_primary(self):
        """Junk checker shape vs a genuine False primary read as a
        "dispute" pre-fix and the conservative override flipped the
        primary to exploitable — noise minted from a non-verdict."""
        prior = {"F-001": _result("F-001", exploitable=False, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": "yes",
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"]["is_exploitable"] is False
        assert prior["F-001"].get("cross_family_disputed") is None
        assert prior["F-001"].get("cross_family_agreed") is None
        check = prior["F-001"]["cross_family_check"]
        assert check["verdict"] == "skipped — checker returned no verdict"

    def test_int_bool_cross_shape_is_not_agreement(self):
        """``1 == True`` in Python: an int-shaped checker verdict
        compared equal to a genuine bool primary pre-fix and minted
        agreement across shapes. Only genuine bools vote."""
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        checker_results = [
            {"finding_id": "F-001", "is_exploitable": 1,
             "analysed_by": "claude-haiku-4-5-20251001"},
        ]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)

        assert prior["F-001"].get("cross_family_agreed") is None
        assert prior["F-001"].get("cross_family_disputed") is None
        assert "skipped" in prior["F-001"]["cross_family_check"]["verdict"]

    def test_reasoning_distance_attached_for_long_reasonings(self):
        """When primary and checker reasonings are both substantial,
        the cross-family check captures their pairwise Jaccard
        distance. High distance with verdict-agree is a tell for
        prompt-injection or systematic family bias — observational
        metadata in v1, no gate consumes it yet."""
        primary_reasoning = (
            "User input flows from request.GET['q'] into cgi_query() "
            "without sanitisation. The sink at cgi.c:142 concatenates "
            "the query string directly into the SQL statement. "
            "Classic SQL injection with attacker-controlled input."
        )
        checker_reasoning = (
            "Tainted data from request.GET reaches cgi_query in cgi.c "
            "line 142. String concatenation builds the SQL with no "
            "parameterisation, so the attacker controls the query."
        )
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        prior["F-001"]["reasoning"] = primary_reasoning
        checker_results = [{
            "finding_id": "F-001",
            "is_exploitable": True,
            "ruling": "validated",
            "reasoning": checker_reasoning,
            "analysed_by": "claude-haiku-4-5-20251001",
        }]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)
        check = prior["F-001"]["cross_family_check"]
        assert "reasoning_distance" in check
        d = check["reasoning_distance"]
        assert isinstance(d, float)
        assert 0.0 <= d <= 1.0

    def test_reasoning_distance_higher_for_divergent_reasonings(self):
        # Aligned (both SQL injection in same sink) vs divergent
        # (SQL injection vs path traversal). Pin that the distance
        # is meaningfully higher for the divergent pair.
        sql_a = (
            "SQL injection at cgi_query in cgi.c:142. Request.GET['q'] "
            "reaches the sink unsanitised, attacker controls SQL."
        )
        sql_b = (
            "Tainted request.GET reaches cgi_query in cgi.c line 142. "
            "String concatenation builds SQL without parameterisation."
        )
        path_traversal = (
            "Path traversal in upload_file at upload.c:88. The "
            "filename from multipart form data is joined with the "
            "storage path without normalisation."
        )

        def _check(primary_text: str, checker_text: str) -> float:
            prior = {"F": _result("F", exploitable=True, quality=0.5)}
            prior["F"]["reasoning"] = primary_text
            results = [{
                "finding_id": "F", "is_exploitable": True,
                "ruling": "validated", "reasoning": checker_text,
                "analysed_by": "claude-haiku-4-5-20251001",
            }]
            CrossFamilyCheckTask(
                ANTHROPIC_CHECKER, results_by_id=prior,
            ).finalize(results, prior)
            return prior["F"]["cross_family_check"]["reasoning_distance"]

        aligned = _check(sql_a, sql_b)
        divergent = _check(sql_a, path_traversal)
        assert divergent > aligned + 0.10

    def test_aggregator_prompt_mentions_reasoning_divergence(self):
        """Aggregator system prompt must reference the
        ``reasoning_divergence`` field for the per-finding metric to
        actually be load-bearing in synthesis. The metric flowing
        through the JSON payload is necessary but not sufficient —
        without prompt guidance the model has no reason to weight it.
        Source-level sentinel against accidental prompt reverts."""
        from packages.llm_analysis.tasks import AggregationTask
        prompt = AggregationTask._SYSTEM_TEXT
        # Two non-trivial substrings from the new guidance — one
        # alone could match a benign coincidence; both together pin
        # the actual instruction.
        assert "reasoning_divergence" in prompt
        assert "mean_pairwise_distance" in prompt

    def test_reasoning_distance_skipped_for_short_reasonings(self):
        # The default _result fixture uses 14-char reasoning text —
        # below the math layer's 50-char floor. Distance is unmeasurable
        # and the field is omitted (consistent with semantic_entropy's
        # "no signal" contract).
        prior = {"F-001": _result("F-001", exploitable=True, quality=0.5)}
        checker_results = [{
            "finding_id": "F-001", "is_exploitable": True,
            "ruling": "validated", "reasoning": "short text",
            "analysed_by": "claude-haiku-4-5-20251001",
        }]
        task = CrossFamilyCheckTask(ANTHROPIC_CHECKER, results_by_id=prior)
        task.finalize(checker_results, prior)
        assert "reasoning_distance" not in prior["F-001"]["cross_family_check"]

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
    """_quality / _nonce_leaked persist onto PROCESSED result dicts
    through the real ``dispatch_task`` loop — the named contract that
    feeds CrossFamilyCheckTask.select_items. The previous tests
    asserted a dataclass field the test itself had just set, so the
    persistence seam could regress without a failure."""

    @staticmethod
    def _dispatch(quality: float = 0.65, echo_prompt: bool = False):
        from packages.llm_analysis.dispatch import dispatch_task
        from packages.llm_analysis.orchestrator import CostTracker
        from packages.llm_analysis.tasks import AnalysisTask

        finding = {
            "finding_id": "F1",
            "rule_id": "CWE-120",
            "file_path": "src/parse.c",
            "start_line": 42,
            "end_line": 45,
            "level": "high",
            "message": "Potential CWE-120",
            "code": "strcpy(buf, input);",
            "surrounding_context": "void parse(char *input) { ... }",
        }

        def dispatch_fn(prompt, schema, system_prompt, temperature, model):
            content = prompt if echo_prompt else "ok"
            return DispatchResult(
                result={"content": content, "is_exploitable": True,
                        "exploitability_score": 0.9, "reasoning": "test",
                        "is_true_positive": True},
                cost=0.0, tokens=1, model="test-model", duration=0.1,
                quality=quality,
            )

        task = AnalysisTask()
        results = dispatch_task(
            task, [finding], dispatch_fn, {"analysis_model": None},
            {}, CostTracker(), max_parallel=1,
        )
        assert len(results) == 1
        return results[0]

    def test_quality_persisted_onto_processed_result(self):
        processed = self._dispatch(quality=0.65)
        assert processed["_quality"] == 0.65

    def test_nonce_leak_flag_persisted_when_response_echoes_envelope(self):
        """A response that echoes the prompt (envelope nonce included)
        must be stamped ``_nonce_leaked`` — the low-quality/leak signal
        CrossFamilyCheckTask selects on."""
        processed = self._dispatch(echo_prompt=True)
        assert processed.get("_nonce_leaked") is True

    def test_no_leak_flag_on_clean_response(self):
        processed = self._dispatch()
        assert processed.get("_nonce_leaked") is not True
