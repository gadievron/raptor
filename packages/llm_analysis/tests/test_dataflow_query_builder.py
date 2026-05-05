"""Tests for the mechanical CodeQL query builder (Tier 1 + Tier 2)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.dataflow_query_builder import (
    TEMPLATE_PREDICATE_SCHEMA,
    build_prebuilt_query,
    build_template_query,
    infer_cwe_from_rule_id,
    lookup_prebuilt_flow,
    supported_languages_for_template,
)


# Tier 1 ---------------------------------------------------------------------

class TestPrebuiltLookup:
    def test_python_command_injection(self):
        result = lookup_prebuilt_flow("python", "CWE-78")
        assert result is not None
        imp, mod = result
        assert "CommandInjection" in imp
        assert mod == "CommandInjectionFlow"

    def test_python_sql_injection(self):
        result = lookup_prebuilt_flow("python", "CWE-89")
        assert result is not None
        assert result[1] == "SqlInjectionFlow"

    def test_java_command_injection(self):
        result = lookup_prebuilt_flow("java", "CWE-78")
        assert result is not None

    def test_unknown_combination_returns_none(self):
        assert lookup_prebuilt_flow("python", "CWE-9999") is None
        assert lookup_prebuilt_flow("cobol", "CWE-78") is None

    def test_case_insensitive_language(self):
        assert lookup_prebuilt_flow("Python", "CWE-78") is not None
        assert lookup_prebuilt_flow("PYTHON", "CWE-78") is not None

    def test_case_insensitive_cwe(self):
        assert lookup_prebuilt_flow("python", "cwe-78") is not None
        assert lookup_prebuilt_flow("python", " CWE-78 ") is not None  # whitespace

    def test_empty_inputs(self):
        assert lookup_prebuilt_flow("", "CWE-78") is None
        assert lookup_prebuilt_flow("python", "") is None
        assert lookup_prebuilt_flow("", "") is None
        assert lookup_prebuilt_flow(None, None) is None


class TestBuildPrebuiltQuery:
    def test_basic_python_query(self):
        q = build_prebuilt_query(
            language="python",
            flow_import="semmle.python.security.dataflow.CommandInjectionQuery",
            flow_module="CommandInjectionFlow",
        )
        assert "import python" in q
        assert "import semmle.python.security.dataflow.CommandInjectionQuery" in q
        assert "import CommandInjectionFlow::PathGraph" in q
        assert "from CommandInjectionFlow::PathNode source" in q
        assert "where CommandInjectionFlow::flowPath" in q
        assert "@kind path-problem" in q
        assert "@problem.severity" in q  # required for path-problem queries

    def test_query_id_embedded(self):
        q = build_prebuilt_query(
            language="python",
            flow_import="...",
            flow_module="X",
            query_id="raptor/iris/CWE-78",
        )
        assert "raptor/iris/CWE-78" in q

    def test_unknown_language_raises(self):
        import pytest
        with pytest.raises(ValueError):
            build_prebuilt_query(
                language="cobol",
                flow_import="...",
                flow_module="X",
            )

    def test_includes_correct_lang_header(self):
        q = build_prebuilt_query(
            language="cpp",
            flow_import="semmle.code.cpp.security.X",
            flow_module="XFlow",
        )
        assert "import cpp" in q
        assert "import python" not in q


# Tier 2 ---------------------------------------------------------------------

class TestBuildTemplateQuery:
    def test_python_template(self):
        q = build_template_query(
            language="python",
            source_predicate_body="n instanceof RemoteFlowSource",
            sink_predicate_body="exists(Call c | n.asExpr() = c.getArg(0))",
        )
        assert q is not None
        assert "import python" in q
        assert "n instanceof RemoteFlowSource" in q
        assert "exists(Call c | n.asExpr() = c.getArg(0))" in q
        assert "module IrisConfig implements DataFlow::ConfigSig" in q
        assert "module IrisFlow = TaintTracking::Global<IrisConfig>" in q
        assert "import IrisFlow::PathGraph" in q

    def test_java_template(self):
        q = build_template_query(
            language="java",
            source_predicate_body="n instanceof RemoteFlowSource",
            sink_predicate_body="exists(MethodAccess m)",
        )
        assert q is not None
        assert "import java" in q
        assert "import semmle.code.java.dataflow.TaintTracking" in q

    def test_cpp_template(self):
        q = build_template_query(
            language="cpp",
            source_predicate_body="exists(FunctionCall fc)",
            sink_predicate_body="exists(FunctionCall fc | fc.getTarget().getName() = \"strcpy\")",
        )
        assert q is not None
        assert "import cpp" in q

    def test_unsupported_language_returns_none(self):
        q = build_template_query(
            language="cobol",
            source_predicate_body="x",
            sink_predicate_body="y",
        )
        assert q is None

    def test_empty_source_returns_none(self):
        q = build_template_query(
            language="python",
            source_predicate_body="",
            sink_predicate_body="x",
        )
        assert q is None

    def test_empty_sink_returns_none(self):
        q = build_template_query(
            language="python",
            source_predicate_body="x",
            sink_predicate_body="   ",
        )
        assert q is None

    def test_query_id_in_metadata(self):
        q = build_template_query(
            language="python",
            source_predicate_body="x",
            sink_predicate_body="y",
            query_id="raptor/iris/test",
        )
        assert "raptor/iris/test" in q

    def test_predicates_stripped(self):
        """Leading/trailing whitespace in predicates is stripped, so
        callers don't need to be careful about indentation."""
        q = build_template_query(
            language="python",
            source_predicate_body="   n instanceof X   \n",
            sink_predicate_body="\n  n instanceof Y  ",
        )
        # Stripped values appear in the output
        assert "n instanceof X" in q
        assert "n instanceof Y" in q

    def test_supported_languages(self):
        langs = supported_languages_for_template()
        assert "python" in langs
        assert "java" in langs
        assert "cpp" in langs
        assert "javascript" in langs
        assert "go" in langs


class TestSchemas:
    def test_template_predicate_schema_has_required_fields(self):
        assert "source_predicate_body" in TEMPLATE_PREDICATE_SCHEMA
        assert "sink_predicate_body" in TEMPLATE_PREDICATE_SCHEMA

    def test_schema_descriptions_mention_examples(self):
        # Schema descriptions should help the LLM produce well-shaped predicates
        s = TEMPLATE_PREDICATE_SCHEMA["source_predicate_body"]
        assert "Example" in s or "example" in s


class TestExpandedPrebuiltMap:
    """Smoke tests for the expanded Python prebuilt map. Each entry should
    resolve to a (import_path, flow_module) tuple and produce a syntactically
    plausible wrapper query."""

    PYTHON_CWES = [
        "CWE-78", "CWE-77", "CWE-89", "CWE-90", "CWE-94", "CWE-22",
        "CWE-79", "CWE-93", "CWE-117", "CWE-209", "CWE-312", "CWE-313",
        "CWE-327", "CWE-501", "CWE-502", "CWE-601", "CWE-611", "CWE-643",
        "CWE-776", "CWE-918", "CWE-943", "CWE-1004", "CWE-1333", "CWE-1336",
    ]

    def test_all_python_cwes_resolve(self):
        for cwe in self.PYTHON_CWES:
            result = lookup_prebuilt_flow("python", cwe)
            assert result is not None, f"missing entry: python/{cwe}"
            imp, mod = result
            assert imp.startswith("semmle.python.security.dataflow.")
            assert mod.endswith("Flow")

    def test_each_python_cwe_builds_a_query(self):
        for cwe in self.PYTHON_CWES:
            imp, mod = lookup_prebuilt_flow("python", cwe)
            q = build_prebuilt_query(
                language="python", flow_import=imp, flow_module=mod,
            )
            assert "import python" in q
            assert f"import {imp}" in q
            assert f"import {mod}::PathGraph" in q
            assert f"{mod}::flowPath(source, sink)" in q


class TestCweInference:
    """infer_cwe_from_rule_id maps Semgrep rule names to CWE strings."""

    def test_command_injection_patterns(self):
        for rule in (
            "raptor.injection.command-shell",
            "python.lang.security.audit.subprocess-shell-true",
            "OS_COMMAND_INJECTION",
            "command_injection",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-78", rule

    def test_sql_injection_patterns(self):
        for rule in (
            "raptor.sqli",
            "SQL_INJECTION",
            "python.django.sql-injection",
            "raptor.sql-injection.tainted",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-89", rule

    def test_path_traversal(self):
        for rule in (
            "python.path-traversal.tainted-path",
            "raptor.injection.directory-traversal",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-22", rule

    def test_xss_patterns(self):
        assert infer_cwe_from_rule_id("python.django.xss") == "CWE-79"
        assert infer_cwe_from_rule_id("dom-based-xss") == "CWE-79"
        assert infer_cwe_from_rule_id("cross-site-scripting") == "CWE-79"

    def test_xxe(self):
        assert infer_cwe_from_rule_id("xxe") == "CWE-611"
        assert infer_cwe_from_rule_id("xml-external-entity") == "CWE-611"

    def test_ssrf(self):
        assert infer_cwe_from_rule_id("ssrf") == "CWE-918"
        assert infer_cwe_from_rule_id("server-side-request-forgery") == "CWE-918"

    def test_deserialization(self):
        assert infer_cwe_from_rule_id("unsafe-deserialization") == "CWE-502"
        assert infer_cwe_from_rule_id("pickle.deserialization") == "CWE-502"

    def test_log_injection(self):
        assert infer_cwe_from_rule_id("log-injection") == "CWE-117"
        assert infer_cwe_from_rule_id("log-forging") == "CWE-117"

    def test_hardcoded_credentials(self):
        for rule in (
            "raptor.crypto.hardcoded-secret",
            "hardcoded-password",
            "hardcoded-token",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-798", rule

    def test_weak_crypto(self):
        for rule in (
            "weak-hash",
            "weak-crypto.python",
            "broken-crypto",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-327", rule

    def test_redos(self):
        assert infer_cwe_from_rule_id("redos") == "CWE-1333"
        assert infer_cwe_from_rule_id("polynomial-redos") == "CWE-1333"

    def test_returns_none_for_unknown(self):
        assert infer_cwe_from_rule_id("raptor.lint.style.indentation") is None
        assert infer_cwe_from_rule_id("raptor.crypto.maybe-weak-thing") is None
        assert infer_cwe_from_rule_id("") is None
        assert infer_cwe_from_rule_id(None) is None

    def test_specific_pattern_wins_over_general(self):
        # "subprocess-shell-true" should hit the command-injection
        # pattern, not be vaguely classified as something generic.
        assert infer_cwe_from_rule_id("subprocess-shell-true") == "CWE-78"
