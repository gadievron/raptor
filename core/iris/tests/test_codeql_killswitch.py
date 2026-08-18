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
        assert "isAdditionalTaintStep" in result
        assert "wrap_call" in result

    def test_sources_only_no_select(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        specs = [
            TaintSpec(function="read_input", file="io.py", role="source"),
        ]
        result = compile_codeql_config(specs)
        assert "select" not in result


class TestPropagatorPredicate:
    """``_propagator_predicate`` — generator for the
    ``isAdditionalTaintStep`` body ``compile_codeql_config`` embeds
    for propagator specs."""

    @staticmethod
    def _prop(fn):
        from core.iris.specs import TaintSpec
        return TaintSpec(function=fn, file="src/db.py", role="propagator")

    def test_single_spec_exact_shape(self):
        from core.iris.specs import _propagator_predicate

        out = _propagator_predicate([self._prop("wrap")])
        assert out == (
            '    exists(DataFlow::CallNode c | '
            'c.getTarget().hasName("wrap") '
            "and pred = c.getAnArgument() and succ = c)"
        )

    def test_multiple_specs_joined_with_or(self):
        from core.iris.specs import _propagator_predicate

        out = _propagator_predicate([
            self._prop("wrap"),
            self._prop("adapt"),
        ])
        assert out.count(" or\n") == 1
        assert 'hasName("wrap")' in out
        assert 'hasName("adapt")' in out

    def test_escapes_codeql_string_chars(self):
        from core.iris.specs import _propagator_predicate

        out = _propagator_predicate([self._prop('we"ird\\name')])
        assert 'hasName("we\\"ird\\\\name")' in out


class TestCompileCodeqlConfigPropagators:
    """The propagator step predicate inside the compiled query comes
    from ``_propagator_predicate`` and only appears when propagator
    specs are present."""

    @staticmethod
    def _specs():
        from core.iris.specs import TaintSpec
        return [
            TaintSpec(function="read_input", file="src/db.py", role="source"),
            TaintSpec(function="exec_cmd", file="src/db.py", role="sink"),
            TaintSpec(function="wrap", file="src/db.py", role="propagator"),
        ]

    def test_additional_taint_step_present(self):
        from core.iris.specs import compile_codeql_config

        query = compile_codeql_config(self._specs())
        assert (
            "predicate isAdditionalTaintStep"
            "(DataFlow::Node pred, DataFlow::Node succ) {"
        ) in query

    def test_generated_step_matches_helper_output(self):
        from core.iris.specs import (
            TaintSpec,
            _propagator_predicate,
            compile_codeql_config,
        )

        # The predicate body must be exactly what the (previously
        # inlined) loop emitted — the factoring is behaviour-neutral.
        query = compile_codeql_config(self._specs())
        wrap = TaintSpec(function="wrap", file="src/db.py",
                         role="propagator")
        assert _propagator_predicate([wrap]) in query

    def test_no_propagators_no_step_predicate(self):
        from core.iris.specs import TaintSpec, compile_codeql_config

        query = compile_codeql_config([
            TaintSpec(function="read_input", file="src/db.py",
                      role="source"),
            TaintSpec(function="exec_cmd", file="src/db.py", role="sink"),
        ])
        assert "isAdditionalTaintStep" not in query
