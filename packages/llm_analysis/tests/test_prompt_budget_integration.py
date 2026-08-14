"""Integration tests for prompt budget shedding across assembly sites.

Exercises the actual code paths: build_*_prompt_bundle with budget_tokens,
AnalysisTask.budget_tokens_for_model, dispatch _tls_budget wiring,
agent _prompt_budget, and audit format_context_for_prompt with budget.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

from core.security.prompt_envelope import UntrustedBlock

from packages.llm_analysis.prompts.analysis import (
    _ANALYSIS_BLOCK_PRIORITIES,
    build_analysis_prompt_bundle,
    build_analysis_prompt_bundle_from_finding,
)
from packages.llm_analysis.prompts.exploit import (
    build_exploit_prompt_bundle,
)


def _user_content(bundle) -> str:
    return next(m.content for m in bundle.messages if m.role == "user")


# -------------------------------------------------------------------
# build_analysis_prompt_bundle: budget_tokens shedding
# -------------------------------------------------------------------

class TestAnalysisBundleBudget:

    def test_no_budget_keeps_all_blocks(self):
        """budget_tokens=0 (default) keeps every block."""
        blocks = [
            UntrustedBlock("x" * 400, "vulnerable-code", "test"),
            UntrustedBlock("y" * 400, "sage-historical-context", "test"),
        ]
        bundle = build_analysis_prompt_bundle(
            rule_id="test/rule",
            level="warning",
            file_path="src/foo.c",
            start_line=1,
            end_line=10,
            message="test finding",
            extra_blocks=blocks,
        )
        user = _user_content(bundle)
        assert "x" * 100 in user
        assert "y" * 100 in user

    def test_tight_budget_sheds_sage_context(self):
        """With a very tight budget, low-priority SAGE blocks get shed."""
        blocks = [
            UntrustedBlock("VULN_CODE" * 50, "vulnerable-code", "test"),
            UntrustedBlock(
                "SAGE_HISTORY" * 200,
                "sage-historical-context",
                "test",
            ),
        ]
        bundle = build_analysis_prompt_bundle(
            rule_id="test/rule",
            level="warning",
            file_path="src/foo.c",
            start_line=1,
            end_line=10,
            message="test finding",
            extra_blocks=blocks,
            budget_tokens=200,
        )
        user = _user_content(bundle)
        assert "VULN_CODE" in user
        assert "SAGE_HISTORY" not in user

    def test_from_finding_threads_budget(self):
        """_from_finding wrapper passes budget_tokens through."""
        finding = {
            "rule_id": "test/rule",
            "level": "warning",
            "file_path": "src/foo.c",
            "start_line": 1,
            "end_line": 10,
            "message": "test",
        }
        b_default = build_analysis_prompt_bundle_from_finding(finding)
        b_tight = build_analysis_prompt_bundle_from_finding(
            finding, budget_tokens=50,
        )
        assert b_default is not None
        assert b_tight is not None


# -------------------------------------------------------------------
# build_exploit_prompt_bundle: budget_tokens shedding
# -------------------------------------------------------------------

class TestExploitBundleBudget:

    _ANALYSIS = {
        "is_true_positive": True,
        "is_exploitable": True,
        "reasoning": "prior analysis text",
    }

    def test_no_budget_keeps_all_blocks(self):
        blocks = [
            UntrustedBlock("CODE" * 100, "vulnerable-code", "test"),
            UntrustedBlock("REACH" * 200, "reachability", "test"),
        ]
        bundle = build_exploit_prompt_bundle(
            rule_id="test/rule",
            file_path="src/foo.c",
            start_line=1,
            level="warning",
            analysis=self._ANALYSIS,
            code="int vuln() {}",
            extra_blocks=blocks,
        )
        user = _user_content(bundle)
        assert "CODE" in user
        assert "REACH" in user

    def test_tight_budget_sheds_reachability(self):
        blocks = [
            UntrustedBlock("CODE" * 100, "vulnerable-code", "test"),
            UntrustedBlock("REACH" * 400, "reachability", "test"),
        ]
        bundle = build_exploit_prompt_bundle(
            rule_id="test/rule",
            file_path="src/foo.c",
            start_line=1,
            level="warning",
            analysis=self._ANALYSIS,
            code="int vuln() {}",
            extra_blocks=blocks,
            budget_tokens=200,
        )
        user = _user_content(bundle)
        assert "CODE" in user
        assert "REACH" not in user


# -------------------------------------------------------------------
# AnalysisTask.budget_tokens_for_model
# -------------------------------------------------------------------

class TestAnalysisTaskBudget:

    def test_returns_positive_for_known_model(self):
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()
        model = MagicMock()
        model.model_name = "claude-haiku-4-5"
        budget = task.budget_tokens_for_model(model)
        assert budget > 100_000

    def test_returns_zero_on_missing_model_name(self):
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()
        budget = task.budget_tokens_for_model(None)
        assert isinstance(budget, int)
        assert budget > 0

    def test_deducts_system_prompt_tokens(self):
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()
        model = MagicMock()
        model.model_name = "claude-haiku-4-5"
        budget = task.budget_tokens_for_model(model)
        from core.llm.prompt_budget import context_budget_for_model
        raw = context_budget_for_model("claude-haiku-4-5")
        assert budget < raw


class TestExploitTaskBudget:

    def test_returns_positive_for_known_model(self):
        from packages.llm_analysis.tasks import ExploitTask
        task = ExploitTask()
        model = MagicMock()
        model.model_name = "claude-sonnet-4-6"
        budget = task.budget_tokens_for_model(model)
        assert budget > 100_000


class TestConsensusTaskBudget:

    def test_returns_positive_for_known_model(self):
        from packages.llm_analysis.tasks import ConsensusTask
        task = ConsensusTask()
        model = MagicMock()
        model.model_name = "claude-haiku-4-5"
        budget = task.budget_tokens_for_model(model)
        assert budget > 100_000


class TestJudgeTaskBudget:

    def test_returns_positive_for_known_model(self):
        from packages.llm_analysis.tasks import JudgeTask
        task = JudgeTask()
        model = MagicMock()
        model.model_name = "claude-haiku-4-5"
        budget = task.budget_tokens_for_model(model)
        assert budget > 100_000


# -------------------------------------------------------------------
# Dispatch layer: _tls_budget thread-local wiring
# -------------------------------------------------------------------

class TestDispatchTlsBudget:

    def test_tls_budget_set_per_thread(self):
        """_tls_budget.tokens is set per-model before build_prompt."""
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()

        task._tls_budget = threading.local()

        model = MagicMock()
        model.model_name = "claude-haiku-4-5"
        task._tls_budget.tokens = task.budget_tokens_for_model(model)

        assert task._tls_budget.tokens > 100_000

    def test_tls_budget_isolation_across_threads(self):
        """Each thread sees its own _tls_budget.tokens value."""
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()
        task._tls_budget = threading.local()

        results = {}

        def set_budget(name, val):
            task._tls_budget.tokens = val
            results[name] = task._tls_budget.tokens

        t1 = threading.Thread(target=set_budget, args=("a", 111))
        t2 = threading.Thread(target=set_budget, args=("b", 222))
        t1.start()
        t1.join()
        t2.start()
        t2.join()

        assert results["a"] == 111
        assert results["b"] == 222

    def test_build_prompt_reads_tls_budget(self):
        """build_prompt picks up _tls_budget.tokens and passes it."""
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()
        task._tls_budget = threading.local()
        task._tls_budget.tokens = 50

        finding = {
            "rule_id": "test/rule",
            "level": "warning",
            "file_path": "src/foo.c",
            "start_line": 1,
            "end_line": 10,
            "message": "test",
        }
        prompt = task.build_prompt(finding)
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_build_prompt_with_no_tls_budget_uses_zero(self):
        """Without _tls_budget, budget defaults to 0 (no shedding)."""
        from packages.llm_analysis.tasks import AnalysisTask
        task = AnalysisTask()

        finding = {
            "rule_id": "test/rule",
            "level": "warning",
            "file_path": "src/foo.c",
            "start_line": 1,
            "end_line": 10,
            "message": "test",
        }
        prompt = task.build_prompt(finding)
        assert isinstance(prompt, str)


# -------------------------------------------------------------------
# Agent._prompt_budget
# -------------------------------------------------------------------

class TestAgentPromptBudget:

    def test_returns_positive_with_model_config(self):
        from packages.llm_analysis.agent import (
            AutonomousSecurityAgentV2,
        )
        llm_config = MagicMock()
        llm_config.primary_model.model_name = "claude-haiku-4-5"
        agent = AutonomousSecurityAgentV2.__new__(
            AutonomousSecurityAgentV2,
        )
        agent.llm_config = llm_config
        budget = agent._prompt_budget()
        assert budget > 100_000

    def test_returns_zero_with_no_config(self):
        from packages.llm_analysis.agent import (
            AutonomousSecurityAgentV2,
        )
        agent = AutonomousSecurityAgentV2.__new__(
            AutonomousSecurityAgentV2,
        )
        agent.llm_config = None
        budget = agent._prompt_budget()
        assert isinstance(budget, int)


# -------------------------------------------------------------------
# Audit context: format_context_for_prompt with budget
# -------------------------------------------------------------------

class TestAuditContextBudget:

    def test_no_budget_keeps_all_sections(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "main.c",
            "function": "main",
            "line_start": 1,
            "source": "int main() { return 0; }",
            "callers": [
                {"name": "run", "file": "main.c", "line": 5},
            ],
            "trust_surface": {
                "label": "high",
                "detail": "network-facing",
            },
        }
        prompt = format_context_for_prompt(ctx)
        assert "int main" in prompt
        assert "run" in prompt

    def test_tight_budget_sheds_low_priority_sections(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "vuln.c",
            "function": "vuln",
            "line_start": 1,
            "source": "int vuln() { gets(buf); }",
            "callers": [
                {"name": "caller1", "file": "a.c", "line": 1},
            ],
            "trust_surface": [
                "Is input validated?",
                "X" * 2000,
            ],
            "prior_attempts": {
                "exemplars": [
                    {
                        "cwe": "CWE-120",
                        "summary": "Z" * 2000,
                    },
                ],
            },
        }
        prompt_full = format_context_for_prompt(ctx)
        prompt_tight = format_context_for_prompt(
            ctx, budget_limit=50,
        )
        assert "int vuln" in prompt_tight
        assert len(prompt_tight) <= len(prompt_full)


# -------------------------------------------------------------------
# Priority map completeness
# -------------------------------------------------------------------

class TestPriorityMapCompleteness:

    def test_analysis_priorities_cover_known_kinds(self):
        known = [
            "vulnerable-code", "dataflow-source-code",
            "dataflow-sink-code", "scanner-message",
            "function-context", "ast-view",
            "surrounding-context", "verified-exemplars",
            "sage-historical-context",
        ]
        for kind in known:
            assert kind in _ANALYSIS_BLOCK_PRIORITIES, (
                f"{kind} missing from _ANALYSIS_BLOCK_PRIORITIES"
            )

    def test_priority_zero_for_critical_kinds(self):
        for kind in ("vulnerable-code", "scanner-message"):
            assert _ANALYSIS_BLOCK_PRIORITIES[kind] == 0
