"""Tests for core.audit.cwe_dispatch."""

from core.audit.cwe_dispatch import (
    codeql_query_for_cwe,
    cocci_rule_for_cwe,
    dark_verify_applicable,
    joern_applicable,
    lookup,
    route_hypothesis_to_checkers,
    sinks_for_cwe,
    smt_verb_for_cwe,
    tool_scope_for_cwe,
)


class TestLookup:
    def test_exact(self):
        assert lookup("CWE-78") is not None

    def test_lowercase(self):
        assert lookup("cwe-78") is not None

    def test_number_only(self):
        assert lookup("78") is not None

    def test_unknown(self):
        assert lookup("CWE-99999") is None


class TestSinksForCwe:
    def test_injection_has_sinks(self):
        sinks = sinks_for_cwe("CWE-78")
        assert "popen" in sinks

    def test_integer_no_sinks(self):
        assert sinks_for_cwe("CWE-190") == []

    def test_unknown_returns_empty(self):
        assert sinks_for_cwe("CWE-99999") == []


class TestSmtVerb:
    def test_overflow(self):
        assert smt_verb_for_cwe("CWE-190") == "check-overflow"

    def test_oob(self):
        assert smt_verb_for_cwe("CWE-787") == "check-oob"

    def test_injection_no_smt(self):
        assert smt_verb_for_cwe("CWE-78") is None


class TestCocciRule:
    def test_unchecked_return(self):
        assert cocci_rule_for_cwe("CWE-252") == "unchecked_return.cocci"

    def test_null_check(self):
        assert cocci_rule_for_cwe("CWE-476") == "missing_null_check.cocci"

    def test_lock(self):
        assert cocci_rule_for_cwe("CWE-362") == "lock_imbalance.cocci"

    def test_no_cocci(self):
        assert cocci_rule_for_cwe("CWE-78") is None


class TestCodeqlQuery:
    def test_command_injection(self):
        assert codeql_query_for_cwe("CWE-78") == "cpp/command-line-injection"

    def test_sql_injection(self):
        assert codeql_query_for_cwe("CWE-89") == "py/sql-injection"

    def test_no_codeql(self):
        assert codeql_query_for_cwe("CWE-362") is None


class TestJoernApplicable:
    def test_injection_applicable(self):
        assert joern_applicable("CWE-78")

    def test_format_string_applicable(self):
        assert joern_applicable("CWE-134")

    def test_integer_not_applicable(self):
        assert not joern_applicable("CWE-190")

    def test_concurrency_not_applicable(self):
        assert not joern_applicable("CWE-362")

    def test_unknown_not_applicable(self):
        assert not joern_applicable("CWE-99999")


class TestDarkVerifyApplicable:
    def test_auth_bypass(self):
        assert dark_verify_applicable("CWE-287")

    def test_missing_auth(self):
        assert dark_verify_applicable("CWE-862")

    def test_incorrect_auth(self):
        assert dark_verify_applicable("CWE-863")

    def test_format_string(self):
        assert dark_verify_applicable("CWE-134")

    def test_integer_overflow(self):
        assert dark_verify_applicable("CWE-190")

    def test_use_after_free(self):
        assert dark_verify_applicable("CWE-416")

    def test_uninitialised(self):
        assert dark_verify_applicable("CWE-457")

    def test_buffer_overflow_not_eligible(self):
        assert not dark_verify_applicable("CWE-120")

    def test_concurrency_not_eligible(self):
        assert not dark_verify_applicable("CWE-362")

    def test_unknown_not_eligible(self):
        assert not dark_verify_applicable("CWE-99999")


class TestDarkVerifyStatuses:
    """Every dark_verify family outside the original auth trio declares
    a status filter — a clean outcome must not spend a witness call."""

    def test_expanded_families_filter_statuses(self):
        from core.audit.cwe_dispatch import dark_verify_statuses
        for cwe in ("CWE-134", "CWE-190", "CWE-416", "CWE-457"):
            assert dark_verify_statuses(cwe) == frozenset(
                {"dark", "suspicious", "finding"}
            ), cwe

    def test_auth_families_keep_unfiltered_behaviour(self):
        from core.audit.cwe_dispatch import dark_verify_statuses
        for cwe in ("CWE-287", "CWE-862", "CWE-863"):
            assert dark_verify_statuses(cwe) is None


class TestToolScope:
    def test_cwe416_has_scope(self):
        scope = tool_scope_for_cwe("CWE-416")
        assert scope is not None
        assert "use_after_free.cocci" in scope
        assert "cpp/use-after-free" in scope

    def test_normalisation(self):
        assert tool_scope_for_cwe("416") is not None
        assert tool_scope_for_cwe("cwe-416") is not None

    def test_unknown_cwe_returns_none(self):
        assert tool_scope_for_cwe("CWE-78") is None


class _FakeRouteClient:
    """Stub LLM client for route_hypothesis_to_checkers tests."""

    def __init__(self, dominated: bool):
        self._dominated = dominated

    def generate_structured(self, prompt, schema, **kwargs):
        return {
            "dominated": self._dominated,
            "reasoning": "stub",
        }


class TestRouteHypothesisToCheckers:
    def test_dominated_returns_true(self):
        client = _FakeRouteClient(dominated=True)
        r = route_hypothesis_to_checkers(
            "CWE-416",
            "kfree then dereference in same function",
            client,
        )
        assert r.dominated is True

    def test_not_dominated_returns_false(self):
        client = _FakeRouteClient(dominated=False)
        r = route_hypothesis_to_checkers(
            "CWE-416",
            "scatterlist aliasing — src and dst reference the same pages",
            client,
        )
        assert r.dominated is False

    def test_no_scope_metadata_keeps_chain(self):
        client = _FakeRouteClient(dominated=False)
        r = route_hypothesis_to_checkers(
            "CWE-78",
            "anything — no _TOOL_SCOPE entry for CWE-78",
            client,
        )
        assert r.dominated is True

    def test_llm_error_falls_back_to_true(self):
        class _BrokenClient:
            def generate_structured(self, *a, **kw):
                raise RuntimeError("boom")

        r = route_hypothesis_to_checkers(
            "CWE-416", "some hypothesis", _BrokenClient(),
        )
        assert r.dominated is True

    def test_malformed_response_falls_back_to_true(self):
        class _GarbageClient:
            def generate_structured(self, *a, **kw):
                return {"not_dominated": True}

        r = route_hypothesis_to_checkers(
            "CWE-416", "some hypothesis", _GarbageClient(),
        )
        assert r.dominated is True
