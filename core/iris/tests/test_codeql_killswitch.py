"""Tests for the global CODEQL_ENABLED kill-switch across IRIS consumers.

When ``tuning.json`` has ``codeql_enabled: false``, every CodeQL
execution path must bail before invoking the CodeQL CLI. IRIS spec
synthesis (heuristic/LLM) and the spec store must still work — they
don't require CodeQL.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


class TestTier1CheckFindingCodeqlDisabled:
    """``tier1_check_finding`` must return ``no_check`` when CodeQL is
    globally disabled, even if IRIS_TIER1_ENABLED is True."""

    @pytest.mark.slow
    def test_returns_no_check(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.llm_analysis.dataflow_validation import tier1_check_finding

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)

        verdict = tier1_check_finding(
            {"language": "python", "cwe_id": "CWE-79", "file": "a.py",
             "function": "f"},
            codeql_dbs={"python": Path("/fake/db")},
        )
        assert verdict == "no_check"


class TestValidateDataflowClaimsCodeqlDisabled:
    """``validate_dataflow_claims`` must bail when CodeQL is disabled."""

    def test_returns_skipped_metrics(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.llm_analysis.dataflow_validation import (
            validate_dataflow_claims,
        )

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)

        metrics = validate_dataflow_claims(
            findings=[{"id": "F1"}],
            results_by_id={},
            codeql_dbs={"python": Path("/fake/db")},
            repo_path=Path("/fake/repo"),
            llm_client=None,
        )
        assert metrics["skipped_reason"] == "codeql_disabled"


class TestAnalyzeIrisPacksCodeqlDisabled:
    """``analyze_iris_packs`` must return empty when CodeQL is disabled."""

    def test_returns_empty(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)

        runner = QueryRunner.__new__(QueryRunner)
        result = runner.analyze_iris_packs(
            databases={"python": Path("./db")},
            out_dir=Path("./out"),
        )
        assert result == {}


class TestIrisStoreStillWorksWithoutCodeql:
    """Spec store operations must work even when CodeQL is disabled —
    they don't invoke the CodeQL CLI."""

    def test_save_and_load(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        from core.iris.specs import TaintSpec
        from core.iris.store import load_specs, save_specs

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)

        spec = TaintSpec(
            function="sanitise_input",
            file="src/util.py",
            role="sanitiser",
        )
        out_dir = tmp_path / "run_001"
        out_dir.mkdir()
        save_specs(out_dir, [spec])
        loaded = load_specs(out_dir)
        assert len(loaded) == 1
        assert loaded[0].function == "sanitise_input"


class TestIrisSynthesisStillWorksWithoutCodeql:
    """Heuristic synthesis must work even when CodeQL is disabled."""

    def test_heuristic_synthesis(self, monkeypatch):
        from core.config import RaptorConfig
        from core.iris.specs import CandidateFunction
        from core.iris.synthesise import synthesise_specs_heuristic

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)

        candidates = [
            CandidateFunction(
                function="sanitise_html",
                file="src/auth.py",
            ),
        ]
        specs = synthesise_specs_heuristic(candidates)
        assert len(specs) == 1
        assert specs[0].role == "sanitiser"


class TestCompileCodeqlConfigPureFunction:
    """``compile_codeql_config`` is a pure string generator — it should
    work regardless of whether CodeQL is installed/enabled."""

    def test_generates_ql_text(self, monkeypatch):
        from core.config import RaptorConfig
        from core.iris.specs import TaintSpec, compile_codeql_config

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)

        specs = [
            TaintSpec(
                function="exec_query",
                file="src/db.py",
                role="sink",
                taint_classes=["sql"],
            ),
        ]
        result = compile_codeql_config(specs)
        assert "exec_query" in result
        assert isinstance(result, str)

    def test_sinks_only_produces_select(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="exec_cmd", file="cmd.py", role="sink"),
        ]
        result = compile_codeql_config(specs)
        assert "from DataFlow::Node sink" in result
        assert "select" in result

    def test_sources_and_sinks_produces_taint_tracking(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="read_input", file="io.py", role="source"),
            TaintSpec(function="exec_cmd", file="cmd.py", role="sink"),
        ]
        result = compile_codeql_config(specs)
        assert "module Config implements DataFlow::ConfigSig" in result
        assert "TaintTracking::Global<Config>" in result
        assert "Flow::flowPath" in result
        assert "select" in result

    def test_sanitiser_added_to_config(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="read_input", file="io.py", role="source"),
            TaintSpec(function="exec_cmd", file="cmd.py", role="sink"),
            TaintSpec(function="sanitize", file="util.py", role="sanitiser"),
        ]
        result = compile_codeql_config(specs)
        assert "isBarrier" in result
        assert "sanitize" in result

    def test_language_changes_import(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="exec_cmd", file="cmd.py", role="sink"),
        ]
        cpp_result = compile_codeql_config(specs, language="cpp")
        java_result = compile_codeql_config(specs, language="java")
        assert "semmle.code.cpp" in cpp_result
        assert "semmle.code.java" in java_result

    def test_propagator_in_config(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="read_input", file="io.py", role="source"),
            TaintSpec(function="exec_cmd", file="cmd.py", role="sink"),
            TaintSpec(function="wrap_call", file="util.py", role="propagator"),
        ]
        result = compile_codeql_config(specs)
        # ConfigSig's step member — the class-based API's
        # isAdditionalTaintStep does not exist in the module API and
        # fails compilation.
        assert "isAdditionalFlowStep" in result
        assert "isAdditionalTaintStep" not in result
        assert "wrap_call" in result

    def test_sources_only_no_select(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="read_input", file="io.py", role="source"),
        ]
        result = compile_codeql_config(specs)
        assert "select" not in result


class TestCompileCodeqlConfigPropagators:
    """The propagator step disjunction inside the compiled query —
    routed through the per-language ``irisCallStep`` helper and only
    present when propagator specs are."""

    @staticmethod
    def _specs():
        from core.iris.specs import TaintSpec
        return [
            TaintSpec(function="read_input", file="src/db.py", role="source"),
            TaintSpec(function="exec_cmd", file="src/db.py", role="sink"),
            TaintSpec(function="wrap", file="src/db.py", role="propagator"),
        ]

    def test_additional_flow_step_present(self):
        from core.iris.specs import compile_codeql_config

        query = compile_codeql_config(self._specs())
        assert (
            "predicate isAdditionalFlowStep"
            "(DataFlow::Node pred, DataFlow::Node succ) {"
        ) in query

    def test_step_routed_through_lang_helper(self):
        from core.iris.specs import compile_codeql_config

        query = compile_codeql_config(self._specs())
        assert 'irisCallStep(pred, succ, "wrap")' in query

    def test_multiple_propagators_joined_with_or(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        query = compile_codeql_config([
            *self._specs(),
            TaintSpec(function="adapt", file="src/db.py",
                      role="propagator"),
        ])
        assert 'irisCallStep(pred, succ, "wrap")' in query
        assert 'irisCallStep(pred, succ, "adapt")' in query

    def test_escapes_codeql_string_chars(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        query = compile_codeql_config([
            *self._specs(),
            TaintSpec(function='we"ird\\name', file="src/db.py",
                      role="propagator"),
        ])
        assert 'irisCallStep(pred, succ, "we\\"ird\\\\name")' in query

    def test_no_propagators_no_step_predicate(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        query = compile_codeql_config([
            TaintSpec(function="read_input", file="src/db.py",
                      role="source"),
            TaintSpec(function="exec_cmd", file="src/db.py", role="sink"),
        ])
        assert "isAdditionalFlowStep" not in query


class TestLanguageRegistry:
    """Per-language QL generation. One registry row per language; the
    call-matching helpers are the only language-specific surface. The
    e2e closure test (test_codeql_e2e.py) compile-verifies every row
    against the real CLI; these pins keep the cheap invariants."""

    @staticmethod
    def _specs():
        from core.iris.specs import TaintSpec
        return [
            TaintSpec(function="read_input", file="io.c", role="source"),
            TaintSpec(function="exec_cmd", file="cmd.c", role="sink"),
        ]

    def test_unsupported_language_raises(self):
        from core.iris.specs import compile_codeql_config

        # Pre-registry this silently fell back to the cpp imports and
        # emitted un-compilable QL — the lane failed at analyze time
        # with only per-round tool errors to show for it.
        for lang in ("swift", "rust", "kotlin", "", "CPP"):
            with pytest.raises(ValueError, match="unsupported"):
                compile_codeql_config(self._specs(), language=lang)

    def test_every_language_generates_helper_routed_query(self):
        from core.iris.specs import (
            CODEQL_QUERY_LANGUAGES,
            compile_codeql_config,
        )

        assert CODEQL_QUERY_LANGUAGES == {
            "cpp", "java", "python", "javascript", "csharp", "go", "ruby",
        }
        for lang in CODEQL_QUERY_LANGUAGES:
            query = compile_codeql_config(self._specs(), language=lang)
            assert f"raptor/iris/{lang}/project-specs" in query
            # All source/sink matching routes through the language's
            # helper predicates — never a hardcoded node class.
            assert 'irisCallResult(n, "read_input")' in query
            assert 'irisCallArg(n, "exec_cmd")' in query
            assert "predicate irisCallResult" in query
            assert "predicate irisCallArg" in query

    def test_no_callnode_in_languages_lacking_it(self):
        from core.iris.specs import compile_codeql_config

        # ``DataFlow::CallNode`` exists only in the JS/Go/Ruby
        # libraries; emitting it for cpp/java/python/csharp is exactly
        # the compile failure that kept this lane dead.
        for lang in ("cpp", "java", "python", "csharp"):
            query = compile_codeql_config(self._specs(), language=lang)
            assert "DataFlow::CallNode" not in query, lang

    def test_ast_languages_match_via_as_expr(self):
        from core.iris.specs import compile_codeql_config

        for lang, call_cls in (
            ("cpp", "Call"), ("java", "MethodCall"),
            ("csharp", "MethodCall"),
        ):
            query = compile_codeql_config(self._specs(), language=lang)
            assert f"n.asExpr().({call_cls})" in query, lang

    def test_default_language_is_cpp(self):
        from core.iris.specs import compile_codeql_config

        assert compile_codeql_config(self._specs()) == \
            compile_codeql_config(self._specs(), language="cpp")
