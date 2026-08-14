"""Tests for core.audit.cwe_dispatch."""

from core.audit.cwe_dispatch import (
    codeql_query_for_cwe,
    cocci_rule_for_cwe,
    dark_verify_applicable,
    joern_applicable,
    lookup,
    sinks_for_cwe,
    smt_verb_for_cwe,
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
