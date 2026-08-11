"""Tests for core.audit.sweep — tool-grounded sweep execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.sweep import (
    SarifCache,
    SweepResult,
    mechanical_check_to_semgrep,
    run_consistency_check,
    run_smt_sweep,
    run_codeql_sweep,
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
        import types
        import sys

        class FakeResult:
            matches = []

        def fake_run_rule(target, rule, *, defines=None, timeout=300):
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
        import types
        import sys

        class FakeResult:
            matches = [{"file": "src/a.c", "line": 10}]

        def fake_run_rule(target, rule, *, defines=None, timeout=300):
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
        import types
        import sys

        captured_defines = {}

        class FakeResult:
            matches = []

        def fake_run_rule(target, rule, *, defines=None, timeout=300):
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
        count, elem, index = _extract_overflow_to_oob_operands(h, "")
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
        count, elem, index = _extract_overflow_to_oob_operands(h, src)
        assert count == "nelem"

    def test_default_elem_size(self):
        from core.audit.sweep import _extract_overflow_to_oob_operands
        h = "num_items multiplied by something overflows, write_offset used as index"
        count, elem, index = _extract_overflow_to_oob_operands(h, "")
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
            import packages.joern.prereqs as prereqs
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

    @pytest.mark.parametrize("mechanism,verb", [
        ("integer overflow in size calc", "check-overflow"),
        ("buffer overflow in memcpy", "check-oob"),
        ("integer overflow leading to heap", "check-overflow-to-oob"),
    ])
    def test_vacuous_verbs_skipped(self, tmp_path, monkeypatch, mechanism, verb):
        """Overflow/OOB verbs are vacuous without guards — must not override LLM clean."""
        from core.audit.orchestrator import _promote_clean_refuted
        outcome = self._outcome("a.c", "f", hypotheses=[
            {"mechanism": mechanism, "confidence": "refuted"},
        ])
        result = self._result([outcome])
        calls = []
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: (calls.append(1), [f"smt:{verb}"])[1],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + 1; }",
        )
        _promote_clean_refuted(result, self._config(tmp_path))
        assert result.outcomes[0].status == "clean"
        assert result.sweep_promoted == 0
        assert len(calls) == 0


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
