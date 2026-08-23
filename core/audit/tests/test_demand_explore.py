"""Tests for core.audit.demand_explore."""

from __future__ import annotations

from core.audit.demand_explore import ExpansionBudget


class TestExpansionBudget:
    def test_initial(self):
        b = ExpansionBudget(max_expansions=10)
        assert b.remaining == 10
        assert not b.exhausted

    def test_expand_succeeds(self):
        b = ExpansionBudget(max_expansions=2)
        assert b.try_expand("func_a") is True
        assert b.remaining == 1

    def test_expand_deduplicates(self):
        b = ExpansionBudget(max_expansions=2)
        b.try_expand("func_a")
        assert b.try_expand("func_a") is True
        assert b.remaining == 1

    def test_expand_exhausted(self):
        b = ExpansionBudget(max_expansions=1)
        b.try_expand("func_a")
        assert b.try_expand("func_b") is False
        assert b.exhausted

    def test_summary(self):
        b = ExpansionBudget(max_expansions=10)
        b.try_expand("func_a")
        s = b.summary()
        assert "1/10" in s
        assert "9 remaining" in s

    def test_module_exports_only_expansion_budget(self):
        """The drifted triage-classifier duplicate of core/audit/triage.py
        (and the caller-less Joern query builder) must not resurface here —
        the live classifier is triage.py."""
        import core.audit.demand_explore as de

        for name in (
            "TriageBucket", "FunctionProfile", "classify_function",
            "TriageResult", "triage_functions", "get_token_budget",
            "save_triage", "format_triage_summary",
            "JoernQuery", "QueryType", "ExpandedContext",
        ):
            assert not hasattr(de, name), f"dead duplicate resurfaced: {name}"
