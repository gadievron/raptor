"""Tests for core.audit.sweep — tool-grounded sweep execution."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from core.audit.sweep import (
    SarifCache,
    SweepResult,
    mechanical_check_to_semgrep,
    run_codeql_sweep,
    run_consistency_check,
    run_smt_sweep,
)


class TestSweepResult:
    def test_to_log_entry(self):
        result = SweepResult(
            tool="semgrep",
            file_path="src/handler.c",
            function_name="parse_request",
            outcome="confirmed",
            matches=[{"line": 42}],
            rule_id="injection-rule.yaml",
        )
        entry = result.to_log_entry()
        assert entry["action"] == "sweep"
        assert entry["key"] == "src/handler.c:parse_request"
        assert entry["tool"] == "semgrep"
        assert entry["outcome"] == "confirmed"
        assert entry["match_count"] == 1
        assert entry["rule_id"] == "injection-rule.yaml"

    def test_refuted_no_matches(self):
        result = SweepResult(
            tool="coccinelle",
            file_path="src/util.c",
            function_name="helper",
            outcome="refuted",
        )
        entry = result.to_log_entry()
        assert entry["outcome"] == "refuted"
        assert "match_count" not in entry

    def test_error_with_errors(self):
        result = SweepResult(
            tool="semgrep",
            file_path="src/missing.c",
            function_name="gone",
            outcome="error",
            errors=["file not found"],
        )
        entry = result.to_log_entry()
        assert entry["outcome"] == "error"
        assert "file not found" in entry["errors"]


class TestRunSemgrepSweep:
    def test_missing_file(self, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="nonexistent.c",
            function_name="foo",
            rule_config="auto",
        )
        assert result.outcome == "error"
        assert any("not found" in e for e in result.errors)

    def test_file_exists_no_semgrep(self, tmp_path: Path, monkeypatch):
        from core.audit.sweep import run_semgrep_sweep

        (tmp_path / "test.c").write_text("int foo() { return 0; }\n")

        monkeypatch.setattr(
            "core.audit.sweep.run_semgrep_sweep.__module__",
            "core.audit.sweep",
        )

        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="test.c",
            function_name="foo",
            rule_config="auto",
        )
        # Either error (no semgrep) or refuted (no matches) — both valid
        assert result.outcome in ("error", "refuted")


class TestRunCoccinelleSweep:
    def test_missing_file(self, tmp_path: Path):
        from core.audit.sweep import run_coccinelle_sweep

        result = run_coccinelle_sweep(
            target_path=tmp_path,
            file_path="nonexistent.c",
            function_name="foo",
            cocci_rule="rule.cocci",
        )
        assert result.outcome == "error"
        assert any("not found" in e for e in result.errors)


class TestPathContainment:
    def test_path_traversal_blocked(self, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="../../etc/passwd",
            function_name="foo",
            rule_config="auto",
        )
        assert result.outcome == "error"
        assert any("escapes" in e for e in result.errors)

    def test_normal_path_allowed(self, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "test.c").write_text("int foo() {}\n")

        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="src/test.c",
            function_name="foo",
            rule_config="auto",
        )
        # Not blocked by containment — may error on semgrep
        assert result.outcome != "error" or \
            not any("escapes" in e for e in result.errors)

    def test_coccinelle_path_traversal_blocked(self, tmp_path: Path):
        from core.audit.sweep import run_coccinelle_sweep

        result = run_coccinelle_sweep(
            target_path=tmp_path,
            file_path="../../../etc/shadow",
            function_name="foo",
            cocci_rule="rule.cocci",
        )
        assert result.outcome == "error"
        assert any("escapes" in e for e in result.errors)


class TestRunSmtSweep:
    def test_unknown_verb(self):
        result = run_smt_sweep(
            file_path="a.c",
            function_name="foo",
            verb="nonexistent-verb",
            smt_args={},
        )
        assert result.outcome == "error"
        assert result.tool == "smt"
        assert any("unknown" in e.lower() for e in result.errors)

    def test_valid_verb_runs(self):
        result = run_smt_sweep(
            file_path="a.c",
            function_name="foo",
            verb="check-overflow",
            smt_args={"var": "len", "type": "int32", "op": "len*4",
                       "bound": "4294967295"},
        )
        # Either succeeds (sat/unsat) or errors (z3 not installed)
        assert result.tool == "smt"
        assert result.rule_id == "smt:check-overflow"
        assert result.outcome in ("confirmed", "refuted", "error", "inconclusive")

    def test_sweep_result_log_entry(self):
        result = run_smt_sweep(
            file_path="a.c",
            function_name="foo",
            verb="check-overflow",
            smt_args={},
        )
        entry = result.to_log_entry()
        assert entry["tool"] == "smt"
        assert entry["key"] == "a.c:foo"


class TestRunCodeqlSweep:
    def test_missing_query_file(self, tmp_path: Path):
        result = run_codeql_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="foo",
            query_path="/nonexistent/query.ql",
        )
        assert result.outcome == "error"
        assert result.tool == "codeql"
        assert any("not found" in e for e in result.errors)

    def test_no_database(self, tmp_path: Path):
        query = tmp_path / "test.ql"
        query.write_text("select 1")

        result = run_codeql_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="foo",
            query_path=str(query),
        )
        assert result.outcome == "error"
        assert result.tool == "codeql"

    @staticmethod
    def _fake_analyze(results):
        """Stand-in for codeql_augmented_run.analyze with its real
        signature: (db_path, queries, output_path, *, ...) -> AnalysisResult.
        Writes a minimal SARIF file exactly like the real function."""
        import json
        from types import SimpleNamespace

        def fake(db_path, queries, output_path, *, extension_pack=None,
                 codeql_bin="codeql", timeout_seconds=0, runner=None,
                 extra_args=()):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps({"runs": [{"results": results}]}),
                encoding="utf-8",
            )
            return SimpleNamespace(
                sarif_path=output_path,
                queries=tuple(queries),
                extension_pack=extension_pack,
                elapsed_seconds=0.0,
            )

        return fake

    @staticmethod
    def _sarif_result(uri: str, line: int) -> dict:
        return {
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }]
        }

    def _setup(self, tmp_path: Path):
        (tmp_path / "codeql-db").mkdir()
        query = tmp_path / "test.ql"
        query.write_text("select 1")
        return query

    def test_match_in_function_confirmed(self, tmp_path: Path, monkeypatch):
        query = self._setup(tmp_path)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(
            car, "analyze",
            self._fake_analyze([self._sarif_result("src/a.c", 12)]),
        )
        result = run_codeql_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="foo",
            query_path=str(query),
            line_start=10,
            line_end=20,
        )
        assert result.outcome == "confirmed"
        assert len(result.matches) == 1

    def test_match_outside_function_refuted(self, tmp_path: Path, monkeypatch):
        query = self._setup(tmp_path)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(
            car, "analyze",
            self._fake_analyze([self._sarif_result("src/a.c", 99)]),
        )
        result = run_codeql_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="foo",
            query_path=str(query),
            line_start=10,
            line_end=20,
        )
        assert result.outcome == "refuted"
        assert result.matches == []

    def test_analyze_failure_reported(self, tmp_path: Path, monkeypatch):
        query = self._setup(tmp_path)
        import core.dataflow.codeql_augmented_run as car

        def boom(db_path, queries, output_path, **kw):
            raise car.CodeQLRunError("codeql analyze exited 2")

        monkeypatch.setattr(car, "analyze", boom)
        result = run_codeql_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="foo",
            query_path=str(query),
        )
        assert result.outcome == "error"
        assert any("exited 2" in e for e in result.errors)


class TestConsistencyCheck:
    def test_invalid_function_name_rejected(self, tmp_path: Path):
        """Function names with injection characters are rejected."""
        result = run_consistency_check(
            target_path=tmp_path,
            function_name="foo; rm -rf /",
            cocci_rule="check.cocci",
        )
        assert result.outcome == "error"
        assert "invalid function name" in result.errors[0]

    def test_empty_function_name_rejected(self, tmp_path: Path):
        result = run_consistency_check(
            target_path=tmp_path,
            function_name="",
            cocci_rule="check.cocci",
        )
        assert result.outcome == "error"

    def test_coccinelle_unavailable(self, monkeypatch, tmp_path: Path):
        """When coccinelle package is not importable, returns error."""
        import sys

        monkeypatch.delitem(
            sys.modules, "packages.coccinelle.runner", raising=False,
        )
        monkeypatch.setitem(
            sys.modules, "packages.coccinelle.runner", None,
        )

        result = run_consistency_check(
            target_path=tmp_path,
            function_name="malloc",
            cocci_rule="check_return.cocci",
        )
        assert result.outcome == "error"
        assert result.tool == "coccinelle_consistency"

    def test_no_findings_means_refuted(self, monkeypatch, tmp_path: Path):
        """When coccinelle finds no inconsistencies, outcome is refuted."""
        import sys
        import types

        class FakeResult:
            matches: ClassVar[list] = []

        def fake_run_rule(target, rule, *, defines=None, timeout=300,
                          allow_scripting=False):
            return FakeResult()

        def fake_is_available():
            return True

        fake_mod = types.ModuleType("packages.coccinelle.runner")
        fake_mod.run_rule = fake_run_rule
        fake_mod.is_available = fake_is_available
        monkeypatch.setitem(sys.modules, "packages.coccinelle.runner", fake_mod)

        result = run_consistency_check(
            target_path=tmp_path,
            function_name="parse_input",
            cocci_rule="check_return.cocci",
        )
        assert result.outcome == "refuted"
        assert result.matches == []

    def test_findings_means_confirmed(self, monkeypatch, tmp_path: Path):
        """When coccinelle finds inconsistencies, outcome is confirmed."""
        import sys
        import types

        class FakeResult:
            matches: ClassVar[list] = [{"file": "src/a.c", "line": 10}]

        def fake_run_rule(target, rule, *, defines=None, timeout=300,
                          allow_scripting=False):
            return FakeResult()

        def fake_is_available():
            return True

        fake_mod = types.ModuleType("packages.coccinelle.runner")
        fake_mod.run_rule = fake_run_rule
        fake_mod.is_available = fake_is_available
        monkeypatch.setitem(sys.modules, "packages.coccinelle.runner", fake_mod)

        result = run_consistency_check(
            target_path=tmp_path,
            function_name="malloc",
            cocci_rule="check_return.cocci",
        )
        assert result.outcome == "confirmed"
        assert len(result.matches) == 1

    def test_passes_function_name_as_define(self, monkeypatch, tmp_path: Path):
        """Verifies function_name is passed as -D func=<name>."""
        import sys
        import types

        captured_defines = {}

        class FakeResult:
            matches: ClassVar[list] = []

        def fake_run_rule(target, rule, *, defines=None, timeout=300,
                          allow_scripting=False):
            captured_defines.update(defines or {})
            return FakeResult()

        def fake_is_available():
            return True

        fake_mod = types.ModuleType("packages.coccinelle.runner")
        fake_mod.run_rule = fake_run_rule
        fake_mod.is_available = fake_is_available
        monkeypatch.setitem(sys.modules, "packages.coccinelle.runner", fake_mod)

        run_consistency_check(
            target_path=tmp_path,
            function_name="process_buf",
            cocci_rule="unchecked.cocci",
        )
        assert captured_defines.get("func") == "process_buf"


class TestSarifCache:
    def _write_sarif(self, scan_dir: Path, name: str, results: list):
        import json
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test"}},
                "results": results,
            }],
        }
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / name).write_text(json.dumps(sarif))

    def _make_result(self, uri: str, line: int, rule_id: str = "test-rule"):
        return {
            "ruleId": rule_id,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
            }],
        }

    def test_empty_directory(self, tmp_path: Path):
        cache = SarifCache.from_directory(tmp_path)
        assert cache.lookup("handler.c") is None
        assert cache.miss_count == 1

    def test_loads_results_by_path(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "combined.sarif", [
            self._make_result("src/handler.c", 42),
            self._make_result("src/handler.c", 99),
            self._make_result("src/util.c", 10),
        ])
        cache = SarifCache.from_directory(tmp_path)
        hits = cache.lookup("src/handler.c")
        assert hits is not None
        assert len(hits) == 2

    def test_lookup_filters_by_line_range(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "combined.sarif", [
            self._make_result("src/handler.c", 42),
            self._make_result("src/handler.c", 99),
        ])
        cache = SarifCache.from_directory(tmp_path)
        hits = cache.lookup("src/handler.c", line_start=40, line_end=50)
        assert len(hits) == 1
        assert hits[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    def test_file_scanned_but_no_hits_returns_empty(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "combined.sarif", [
            self._make_result("src/handler.c", 42),
        ])
        cache = SarifCache.from_directory(tmp_path)
        hits = cache.lookup("src/handler.c", line_start=200, line_end=300)
        assert hits == []
        assert cache.hit_count == 1

    def test_unknown_file_returns_none(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "combined.sarif", [
            self._make_result("src/handler.c", 42),
        ])
        cache = SarifCache.from_directory(tmp_path)
        assert cache.lookup("unknown.c") is None
        assert cache.miss_count == 1

    def test_multiple_sarif_files_merged(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "semgrep.sarif", [
            self._make_result("src/handler.c", 42, "semgrep-rule"),
        ])
        self._write_sarif(tmp_path / "scan", "cocci.sarif", [
            self._make_result("src/handler.c", 55, "cocci-rule"),
        ])
        cache = SarifCache.from_directory(tmp_path)
        hits = cache.lookup("src/handler.c")
        assert len(hits) == 2

    def test_no_scan_directory(self, tmp_path: Path):
        cache = SarifCache.from_directory(tmp_path)
        assert cache.lookup("anything.c") is None

    def test_empty_cache_is_falsy(self, tmp_path: Path):
        cache = SarifCache.from_directory(tmp_path)
        assert not cache
        assert len(cache) == 0

    def test_populated_cache_is_truthy(self, tmp_path: Path):
        self._write_sarif(tmp_path / "scan", "combined.sarif", [
            self._make_result("src/handler.c", 42),
        ])
        cache = SarifCache.from_directory(tmp_path)
        assert cache
        assert len(cache) == 1


# ── Overflow-to-OOB operand extraction ──────────────────────────────


class TestExtractOverflowToOobOperands:
    def test_backtick_ids_preferred(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "The `total_records` value multiplied by `elem_size` overflows and `write_pos` indexes past the buffer"
        count, elem, index = _extract_overflow_to_oob_operands(h, "")
        assert count == "total_records"
        assert elem == "elem_size"
        assert index == "write_pos"

    def test_stop_words_not_matched(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "The loop writes buf[write_pos] where write_pos derives from total_records and elem_size without an overflow check"
        count, _elem, index = _extract_overflow_to_oob_operands(h, "")
        assert count != "and"
        assert index != "writes"
        if count is not None:
            assert count.lower() not in {"and", "the", "from", "writes"}
        if index is not None:
            assert index.lower() not in {"and", "the", "from", "writes"}

    def test_compound_identifier_matched(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "num_entries multiplied by stride_size can overflow, index_val used as array offset"
        count, elem, index = _extract_overflow_to_oob_operands(h, "")
        assert count == "num_entries"
        assert elem == "stride_size"
        assert index == "index_val"

    def test_fallback_to_source_for_count(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "the multiplication overflows and buf_offset indexes past the buffer"
        src = "int nelem = get_count();"
        count, _elem, _index = _extract_overflow_to_oob_operands(h, src)
        assert count == "nelem"

    def test_default_elem_size(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "num_items multiplied by something overflows, write_offset used as index"
        _count, elem, _index = _extract_overflow_to_oob_operands(h, "")
        assert elem == "4"


# ── Joern sweep ─────────────────────────────────────────────────────


class TestRunJoernSweep:
    def test_path_traversal_blocked(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="../../etc/passwd",
            function_name="foo",
            source_param="x",
            sink_call="memcpy",
        )
        assert result.outcome == "error"
        assert any("escapes" in e for e in result.errors)

    def test_invalid_function_name(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="foo; rm -rf /",
            source_param="x",
            sink_call="memcpy",
        )
        assert result.outcome == "error"
        assert "invalid function name" in result.errors[0]

    def test_invalid_source_param(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="foo",
            source_param='"); evil("',
            sink_call="memcpy",
        )
        assert result.outcome == "error"
        assert "invalid source_param" in result.errors[0]

    def test_invalid_sink_call(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="foo",
            source_param="x",
            sink_call="a b c",
        )
        assert result.outcome == "error"
        assert "invalid sink_call" in result.errors[0]

    def test_no_cpg_errors(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int f() {}")

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="foo",
            source_param="x",
            sink_call="memcpy",
            cpg=None,
        )
        assert result.outcome == "error"
        assert "no CPG" in result.errors[0]

    def test_qualified_sink_accepted(self, tmp_path: Path):
        from core.audit.sweep import run_joern_sweep

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int f() {}")

        result = run_joern_sweep(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="foo",
            source_param="x",
            sink_call="os.system",
            cpg=None,
        )
        assert result.outcome == "error"
        assert "no CPG" in result.errors[0]


class TestRunJoernPreSweep:
    def test_unavailable_returns_empty(self, monkeypatch, tmp_path: Path):
        from core.audit.sweep import run_joern_pre_sweep

        try:
            from packages.joern import prereqs
            monkeypatch.setattr(prereqs, "is_available", lambda: False)
        except ImportError:
            pass

        result = run_joern_pre_sweep(tmp_path, {})
        assert result == {}

    def test_non_directory_returns_empty(self, tmp_path: Path):
        from core.audit.sweep import run_joern_pre_sweep

        f = tmp_path / "file.c"
        f.write_text("int main() {}")
        result = run_joern_pre_sweep(f, {})
        assert result == {}

    def test_build_pins_frontend_from_detected_language(
        self, monkeypatch, tmp_path: Path,
    ):
        """The local CPG build must pass the curated per-profile
        joern-parse frontend for the detected dominant language."""
        from core.audit.sweep import run_joern_pre_sweep

        (tmp_path / "main.c").write_text("int main() { return 0; }")

        from packages.joern import prereqs, runner
        monkeypatch.setattr(prereqs, "is_available", lambda: True)

        captured: dict = {}

        def fake_build_cpg(target, **kwargs):
            captured.update(kwargs)
            from packages.joern.models import JoernCPG
            return JoernCPG(
                path=tmp_path / "nonexistent-cpg.bin", target=target,
            )

        monkeypatch.setattr(runner, "build_cpg", fake_build_cpg)

        result = run_joern_pre_sweep(tmp_path, {})
        assert result == {}  # fake CPG doesn't exist → empty
        assert captured.get("languages") == {"c"}


class TestMechanicalCheckToSemgrep:
    def test_unchecked_return_maps(self):
        result = mechanical_check_to_semgrep("unchecked return value")
        assert result is not None
        assert "$FUNC" in result

    def test_missing_null_check_maps(self):
        result = mechanical_check_to_semgrep("missing null check on ptr")
        assert result is not None
        assert "null" in result.lower() or "$FUNC" in result

    def test_missing_bounds_check_maps(self):
        result = mechanical_check_to_semgrep("missing bounds check on index")
        assert result is not None
        assert "$BUF" in result or "$IDX" in result

    def test_format_string_maps(self):
        result = mechanical_check_to_semgrep("format string from user")
        assert result is not None
        assert "printf" in result

    def test_unknown_check_returns_none(self):
        result = mechanical_check_to_semgrep("completely unknown check")
        assert result is None

    def test_case_insensitive(self):
        result = mechanical_check_to_semgrep("UNCHECKED RETURN value")
        assert result is not None

    def test_empty_string_returns_none(self):
        result = mechanical_check_to_semgrep("")
        assert result is None


# ── _promote_clean_refuted ──────────────────────────────────────────────


class TestPromoteCleanRefuted:
    """Tests for _promote_clean_refuted — SMT-only promotion of clean
    outcomes where the LLM generated then refuted an arithmetic hypothesis."""

    def _outcome(self, file, function, status="clean", hypotheses=None, line=0):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file=file, function=function, status=status,
            body="", hypothesis="", line=line,
        )
        o.hypotheses = hypotheses or []
        o.review_result = {"hypotheses": hypotheses or []}
        return o

    def _result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.sweep_promoted = 0
        return r

    def _config(self, tmp_path):
        from core.audit.orchestrator import OrchestratorConfig
        src = tmp_path / "src.c"
        src.write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=tmp_path, out_dir=out)

    def test_skips_non_clean(self, tmp_path):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", status="suspicious", hypotheses=[
            {"mechanism": "integer overflow", "confidence": "refuted"},
        ])
        result = self._result([outcome])
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "suspicious"

    def test_skips_no_refuted_hypotheses(self, tmp_path):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "null deref", "confidence": "confirmed"},
        ])
        result = self._result([outcome])
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"

    def test_skips_non_smt_hypotheses(self, tmp_path):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "TOCTOU race condition", "confidence": "refuted"},
        ])
        result = self._result([outcome])
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"

    def test_promotes_when_smt_confirms(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "lock not released on error", "confidence": "refuted"},
        ])
        result = self._result([outcome])

        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_smt_verb",
            lambda h: "check-lock-discipline",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["smt:check-lock-discipline"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void f() { mutex_lock(&m); return; }",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "finding"
        assert "clean-refuted:smt:check-lock-discipline" in result.outcomes[0].evidence_tool
        assert result.sweep_promoted == 1
        assert result.clean == 0
        assert result.findings == 1

    def test_no_promote_when_smt_refutes(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "integer overflow in size calc", "confidence": "refuted"},
        ])
        result = self._result([outcome])

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + 1; }",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"
        assert result.sweep_promoted == 0

    def test_blocked_by_guarded_sink(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "resource leak on error", "confidence": "refuted"},
        ])
        result = self._result([outcome])

        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_smt_verb",
            lambda h: "check-resource-leak",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["smt:check-resource-leak"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void f() { p = kmalloc(16); }",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._check_sink_guarded_cached",
            lambda fn, js: "guarded",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"

    def test_only_first_matching_hypothesis_checked(self, tmp_path, monkeypatch):
        """If the first SMT-eligible refuted hypothesis confirms, stop."""
        from core.audit.orchestrator import _promote_clean_refuted
        calls = []
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": "lock not released", "confidence": "refuted"},
            {"mechanism": "missing unlock on error", "confidence": "refuted"},
        ])
        result = self._result([outcome])

        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_smt_verb",
            lambda h: "check-lock-discipline",
        )

        def mock_chain(*a, **kw):
            calls.append(kw.get("hypothesis", ""))
            return ["smt:check-lock-discipline"]

        monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", mock_chain)
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void f() { mutex_lock(&m); return; }",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "finding"
        assert len(calls) == 1

    @pytest.mark.parametrize("mechanism,verb,smt_lane_runs", [
        # Verification-role vacuous verbs now REACH the tool chain —
        # the vacuity policy lives in the sweep layer, which returns
        # inconclusive (never confirmed) without guard premises, so
        # the chain reports no confirmation and clean stands.
        ("integer overflow in size calc", "check-overflow", True),
        ("buffer overflow in memcpy", "check-oob", True),
        # Detection-role verbs are still skipped before the SMT lane;
        # the cheap-channel lane still gets to test the hypothesis.
        ("integer overflow leading to heap", "check-overflow-to-oob", False),
    ])
    def test_vacuous_verbs_cannot_promote(
        self, tmp_path, monkeypatch, mechanism, verb, smt_lane_runs,
    ):
        """Guardless overflow/OOB SAT must not override LLM clean."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": mechanism, "confidence": "refuted"},
        ])
        result = self._result([outcome])
        calls = []

        def chain(*a, **kw):
            calls.append(kw.get("hypothesis", ""))
            # Sweep-layer vacuity policy: SAT without premises comes
            # back "inconclusive" → no confirmations from the chain.
            return []

        monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", chain)
        # Deterministic cheap-channel lane: one semgrep entry.
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "semgrep", "config": {"rule": "r.yaml"}},
            ],
        )
        # Pin the SMT-verb source to the hypothesis-string mapping so
        # the CWE-inference fallback can't supply a different verb.
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + 1; }",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"
        assert result.sweep_promoted == 0
        # SMT lane (verification-role verbs only) plus the
        # cheap-channel lane; the vacuity policy holds in both.
        assert len(calls) == (2 if smt_lane_runs else 1)


class TestRefutedHypothesisDispatch:
    """Self-refuted hypotheses with concrete mechanisms still get
    mechanical verification through cheap channels (bounded per
    function), and a tool confirmation surfaces distinctly as a
    clean → suspicious promotion with the tool receipt."""

    def _outcome(self, hypotheses, line=0):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="prior body", hypothesis="", line=line,
        )
        o.hypotheses = hypotheses
        o.review_result = {"hypotheses": hypotheses}
        return o

    def _result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        return r

    def _config(self, tmp_path):
        from core.audit.orchestrator import OrchestratorConfig
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        return OrchestratorConfig(target_path=tmp_path, out_dir=out)

    def _no_smt(self, monkeypatch):
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_smt_verb",
            lambda h: None,
        )
        # The CWE-inference fallback can also supply an SMT verb for
        # mechanisms that keyword-map to a CWE — pin it off so these
        # tests exercise the cheap-channel lane deterministically.
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + 1; }",
        )

    def test_cheap_channel_confirmation_promotes_to_suspicious(
        self, tmp_path, monkeypatch,
    ):
        """Refuted hypothesis + no SMT verb → cheap chain dispatch;
        confirmation promotes clean → suspicious with the receipt."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome([{
            "mechanism": "missing bounds check before memcpy(dst, src, len)",
            "confidence": "refuted",
            "counter": "",
        }])
        result = self._result([outcome])
        self._no_smt(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "semgrep", "config": {"rule": "r.yaml"}},
            ],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["semgrep:audit_sweep_x"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._check_sink_guarded_cached",
            lambda fn, js: "unguarded",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        rescued = result.outcomes[0]
        assert rescued.status == "suspicious"
        assert rescued.evidence_tool == "semgrep:audit_sweep_x"
        assert rescued.body.startswith("[refuted-hypothesis-confirmed")
        assert rescued.review_result["refuted_hypothesis_confirmed"] is True
        assert result.refuted_rescued == 1
        assert result.clean == 0
        assert result.suspicious == 1
        assert result.tier_counters["refuted_sweep"].confirmed == 1

    def test_high_confidence_refutation_skips_expensive_channels(
        self, tmp_path, monkeypatch,
    ):
        """A substantive counter-argument demotes to cheap channels only:
        Joern/CodeQL entries are stripped from the dispatched chain."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome([{
            "mechanism": "tainted index reaches array write in parse_hdr()",
            "confidence": "refuted",
            "counter": (
                "the caller validates idx against table_size on every "
                "path before this function is reached"
            ),
        }])
        result = self._result([outcome])
        self._no_smt(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "semgrep", "config": {"rule": "r.yaml"}},
                {"type": "joern", "config": {"sinks": ["memcpy"]}},
                {"type": "codeql", "config": {"query": "q"}},
                {"type": "coccinelle", "config": {"rule": "r.cocci"}},
            ],
        )
        dispatched = []

        def chain(chain_arg, **kw):
            dispatched.extend(e["type"] for e in chain_arg)
            return []

        monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", chain)
        _promote_clean_refuted(result, self._config(tmp_path))
        assert dispatched == ["semgrep", "coccinelle"]
        assert result.outcomes[0].status == "clean"

    def test_weak_refutation_keeps_full_chain(self, tmp_path, monkeypatch):
        """No counter-argument → weak retraction → full chain allowed."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome([{
            "mechanism": "tainted index reaches array write in parse_hdr()",
            "confidence": "refuted",
            "counter": "",
        }])
        result = self._result([outcome])
        self._no_smt(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "semgrep", "config": {"rule": "r.yaml"}},
                {"type": "joern", "config": {"sinks": ["memcpy"]}},
                {"type": "codeql", "config": {"query": "q"}},
            ],
        )
        dispatched = []

        def chain(chain_arg, **kw):
            dispatched.extend(e["type"] for e in chain_arg)
            return []

        monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", chain)
        _promote_clean_refuted(result, self._config(tmp_path))
        assert dispatched == ["semgrep", "joern", "codeql"]

    def test_dispatch_cap_and_specificity_ranking(self, tmp_path, monkeypatch):
        """At most _MAX_REFUTED_DISPATCHES_PER_FN hypotheses dispatch,
        picked by mechanism specificity (most concrete first)."""
        from core.audit.orchestrator import (
            _MAX_REFUTED_DISPATCHES_PER_FN,
            _promote_clean_refuted,
        )
        hyps = [
            {"mechanism": "bad", "confidence": "refuted", "counter": ""},
            {"mechanism": "maybe wrong somewhere", "confidence": "refuted",
             "counter": ""},
            {"mechanism": (
                "integer overflow in alloc_size = count * elem_size at "
                "line 142 feeding kmalloc()"
            ), "confidence": "refuted", "counter": ""},
            {"mechanism": (
                "use-after-free of ctx->buf when process_packet() frees "
                "it on the error path (CWE-416)"
            ), "confidence": "refuted", "counter": ""},
            {"mechanism": (
                "missing null_check() on ret of parse_config() before "
                "deref at line 88"
            ), "confidence": "refuted", "counter": ""},
        ]
        outcome = self._outcome(hyps)
        result = self._result([outcome])
        self._no_smt(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "semgrep", "config": {"rule": "r.yaml"}},
            ],
        )
        seen = []

        def chain(chain_arg, **kw):
            seen.append(kw.get("hypothesis", ""))
            return []

        monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", chain)
        _promote_clean_refuted(result, self._config(tmp_path))
        assert len(seen) == _MAX_REFUTED_DISPATCHES_PER_FN
        # The two vague mechanisms lost the specificity ranking.
        assert "bad" not in seen
        assert "maybe wrong somewhere" not in seen

    def test_detection_only_confirmation_does_not_promote(
        self, tmp_path, monkeypatch,
    ):
        """Detection-role confirmations never override an LLM clean."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome([{
            "mechanism": "overflow in size calc feeding memcpy at line 20",
            "confidence": "refuted",
            "counter": "",
        }])
        result = self._result([outcome])
        self._no_smt(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "smt", "config": {"verb": "check-overflow-to-oob"}},
            ],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["smt:check-overflow-to-oob"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._is_detection_only",
            lambda t: True,
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"
        assert result.refuted_rescued == 0


class TestSweepValidateDetectionFilter:
    """Detection-role tools must not stamp evidence in _sweep_validate."""

    def test_detection_only_tools_not_stamped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            ReviewOutcome,
            _sweep_validate,
        )
        outcome = ReviewOutcome(
            file="net/ipv4/esp4.c",
            function="esp_output_head",
            status="finding",
            body="overflow in nfrags",
            hypothesis="missing bounds check on nfrags counter",
            line=450,
        )
        outcome.review_result = {"hypothesis": outcome.hypothesis}
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        (tmp_path / "out").mkdir(exist_ok=True)

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["coccinelle:missing_bounds_check"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void f() { buf[n]; }",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: type("R", (), {"hits": []})(),
        )

        result = _sweep_validate(outcome, config)
        assert "coccinelle:missing_bounds_check" not in (result.evidence_tool or "")

    def test_verification_tools_still_stamped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            ReviewOutcome,
            _sweep_validate,
        )
        outcome = ReviewOutcome(
            file="net/ipv4/esp4.c",
            function="esp_alloc_tmp",
            status="finding",
            body="overflow",
            hypothesis="integer overflow in len calculation",
            line=47,
        )
        outcome.review_result = {"hypothesis": outcome.hypothesis}
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        (tmp_path / "out").mkdir(exist_ok=True)

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + y; }",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: type("R", (), {"hits": []})(),
        )

        result = _sweep_validate(outcome, config)
        assert "smt:check-overflow" in (result.evidence_tool or "")


# ── Vacuity policy for unconstrained-arithmetic SMT verbs ───────────────


def _z3_installed() -> bool:
    try:
        from core.smt_solver import z3_available
        return z3_available()
    except Exception:  # noqa: BLE001 — availability probe, never raise
        return False


needs_z3 = pytest.mark.skipif(not _z3_installed(), reason="z3 not installed")


class TestComparisonPremiseExtraction:
    def test_extracts_guard_mentioning_operand(self):
        from core.audit.sweep import _extract_comparison_premises
        src = "if (count < max_len) { total = count * size; }"
        premises = _extract_comparison_premises(["count", "size"], src)
        assert "count < max_len" in premises

    def test_ignores_comparisons_of_other_identifiers(self):
        from core.audit.sweep import _extract_comparison_premises
        src = "if (other < limit) { total = count * size; }"
        premises = _extract_comparison_premises(["count", "size"], src)
        assert premises == []

    def test_comments_and_strings_stripped(self):
        from core.audit.sweep import _extract_comparison_premises
        src = '// count < max\nchar *s = "count < max";\nreturn count;\n'
        assert _extract_comparison_premises(["count"], src) == []

    def test_shift_operators_not_comparisons(self):
        from core.audit.sweep import _extract_comparison_premises
        src = "x = count << 2; y = count >> 3;"
        assert _extract_comparison_premises(["count"], src) == []

    def test_deduplicates_and_caps(self):
        from core.audit.sweep import _MAX_PREMISES, _extract_comparison_premises
        lines = ["if (count < 10) {}"] * 3
        lines += [f"if (count < {i}) {{}}" for i in range(20)]
        premises = _extract_comparison_premises(["count"], "\n".join(lines))
        assert premises.count("count < 10") == 1
        assert len(premises) <= _MAX_PREMISES

    def test_literal_operands_do_not_anchor(self):
        from core.audit.sweep import _extract_comparison_premises
        # "4" is a literal operand — it must not anchor extraction.
        src = "if (x < 4) {}"
        assert _extract_comparison_premises(["4"], src) == []


class TestArithOperatorExtraction:
    def test_backtick_expression_wins(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator(
            "integer overflow in `count * size` calculation",
        ) == "*"

    def test_prose_spaced_operator(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator(
            "integer overflow when count * size exceeds uint32",
        ) == "*"

    def test_keyword_multiplication(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator(
            "multiplication of count and size can wrap",
        ) == "*"

    def test_keyword_underflow_is_subtraction(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator(
            "underflow when len is subtracted from offset",
        ) == "-"

    def test_default_is_addition(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator("integer overflow in size calc") == "+"

    def test_spaced_hyphen_is_punctuation(self):
        from core.audit.sweep import _extract_arith_operator
        assert _extract_arith_operator(
            "integer overflow in size calc - see report",
        ) == "+"


class TestPremiseGate:
    def test_no_premises_is_vacuous(self):
        from core.audit.sweep import _premise_gate
        reason = _premise_gate([], "uint32")
        assert reason is not None
        assert "no source-level guard premises" in reason

    @needs_z3
    def test_satisfiable_premises_pass(self):
        from core.audit.sweep import _premise_gate
        assert _premise_gate(["count < 100"], "uint32") is None

    @needs_z3
    def test_contradictory_premises_are_vacuous(self):
        from core.audit.sweep import _premise_gate
        reason = _premise_gate(["count > 10", "count < 5"], "uint32")
        assert reason == "vacuous premises"

    @needs_z3
    def test_unencodable_premises_inconclusive(self):
        from core.audit.sweep import _premise_gate
        reason = _premise_gate(["p->len < q->cap"], "uint32")
        assert reason is not None
        assert "unencodable" in reason or "vacuous" in reason


@needs_z3
class TestVacuousVerbPolicyDirect:
    """SAT on check-overflow / check-oob / check-overflow-to-oob can
    only mean something when source-level guard premises are encoded
    as Z3 constraints.  Exercises ``_run_smt_verb_inner`` in-process."""

    def _run(self, verb, source, hypothesis, file_path="a.c"):
        from core.audit.sweep import _run_smt_verb_inner
        return _run_smt_verb_inner(
            file_path=file_path,
            function_name="f",
            verb=verb,
            source=source,
            hypothesis=hypothesis,
        )

    def test_overflow_guardless_source_is_inconclusive(self):
        result = self._run(
            "check-overflow",
            "int f(int count, int size) { return count * size; }",
            "integer overflow in `count` * `size`",
        )
        assert result.outcome == "inconclusive"
        assert "no source-level guard premises" in (
            (result.details or {}).get("summary", "")
        )

    def test_overflow_with_open_guard_confirms(self):
        # Guard exists but doesn't bound the product: max_len is a
        # free variable, so a wrap inside the guarded space exists.
        result = self._run(
            "check-overflow",
            "int f(unsigned count, unsigned size) {\n"
            "    if (count < max_len) { return count * size; }\n"
            "    return 0;\n"
            "}\n",
            "integer overflow in `count` * `size`",
        )
        assert result.outcome == "confirmed"

    def test_overflow_with_tight_guards_refutes(self):
        # a <= 10 and b <= 10 → a + b <= 20, cannot wrap uint32.
        result = self._run(
            "check-overflow",
            "int f(unsigned a, unsigned b) {\n"
            "    if (a <= 10 && b <= 10) { return a + b; }\n"
            "    return 0;\n"
            "}\n",
            "integer overflow in `a` + `b`",
        )
        assert result.outcome == "refuted"

    def test_operator_from_hypothesis_is_honoured(self):
        # Bounds 65536 × 65536 = 2^32 wraps under '*' but the sum
        # 131072 cannot wrap under '+'.  A hardcoded '+' would refute;
        # honouring the hypothesis's '*' confirms.
        src = (
            "int f(unsigned a, unsigned b) {\n"
            "    if (a <= 65536 && b <= 65536) { return a * b; }\n"
            "    return 0;\n"
            "}\n"
        )
        mul = self._run("check-overflow", src, "integer overflow in `a` * `b`")
        assert mul.outcome == "confirmed"
        add_src = src.replace("a * b", "a + b")
        add = self._run(
            "check-overflow", add_src, "integer overflow in `a` + `b`",
        )
        assert add.outcome == "refuted"

    def test_contradictory_premises_never_refute(self):
        # Premises a > 10 AND a < 5 are jointly UNSAT — the full query
        # would be UNSAT too, but that must read as "vacuous premises"
        # (inconclusive), not as an authoritative refutation.
        result = self._run(
            "check-overflow",
            "int f(unsigned a, unsigned b) {\n"
            "    if (a > 10 && a < 5) { return a + b; }\n"
            "    return 0;\n"
            "}\n",
            "integer overflow in `a` + `b`",
        )
        assert result.outcome == "inconclusive"
        assert (result.details or {}).get("summary") == "vacuous premises"

    def test_oob_guardless_source_is_inconclusive(self):
        result = self._run(
            "check-oob",
            "int f(unsigned idx) { return arr[idx]; }",
            "`idx` is used as an array index into buffer of size `buflen`",
        )
        assert result.outcome == "inconclusive"

    def test_overflow_to_oob_guardless_is_inconclusive(self):
        result = self._run(
            "check-overflow-to-oob",
            "void f(unsigned count, unsigned index) {\n"
            "    p = malloc(count * 4);\n"
            "    p[index] = 1;\n"
            "}\n",
            "overflow of `count` * `elem_size` leads to OOB at `index`",
        )
        assert result.outcome == "inconclusive"


class TestRunSmtSweepVacuityPolicy:
    """The shim (subprocess) path applies the same centralised policy:
    sat on a vacuous verb without ``--guard`` args is inconclusive."""

    def _patch_shim(self, monkeypatch, payload):
        import core.audit.sweep as sweep_mod

        class _Proc:
            returncode = 0
            stdout = payload
            stderr = ""

        monkeypatch.setattr(
            sweep_mod.subprocess, "run", lambda *a, **kw: _Proc(),
        )

    def test_sat_without_guards_is_inconclusive(self, monkeypatch):
        self._patch_shim(monkeypatch, '{"result": "sat"}')
        result = run_smt_sweep(
            file_path="a.c", function_name="f",
            verb="check-overflow",
            smt_args={"op": "*", "operand": ["count", "size"]},
        )
        assert result.outcome == "inconclusive"

    def test_sat_with_guards_confirms(self, monkeypatch):
        self._patch_shim(monkeypatch, '{"result": "sat"}')
        result = run_smt_sweep(
            file_path="a.c", function_name="f",
            verb="check-overflow",
            smt_args={"op": "*", "operand": ["count", "size"],
                      "guard": ["count < max_len"]},
        )
        assert result.outcome == "confirmed"

    def test_unsat_stays_refuted_without_guards(self, monkeypatch):
        self._patch_shim(monkeypatch, '{"result": "unsat"}')
        result = run_smt_sweep(
            file_path="a.c", function_name="f",
            verb="check-overflow",
            smt_args={"op": "+", "operand": ["a", "b"]},
        )
        assert result.outcome == "refuted"

    def test_non_vacuous_verb_sat_still_confirms(self, monkeypatch):
        self._patch_shim(monkeypatch, '{"result": "sat"}')
        result = run_smt_sweep(
            file_path="a.c", function_name="f",
            verb="check-null-deref",
            smt_args={"ptr": "p"},
        )
        assert result.outcome == "confirmed"
