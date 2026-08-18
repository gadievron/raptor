"""Tests for core.audit.codeql_validation — IRIS-style dataflow verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.audit.codeql_validation import (
    DataflowClaim,
    _count_sarif_results,
    _guard_condition_on_line,
    _path_conditions,
    _sarif_result_paths,
    _smt_prune_sarif_matches,
    extract_claims_from_review,
    generate_taint_query,
    validate_dataflow_claim,
)


def _claim(src_fn="read_input", sink_fn="system"):
    return DataflowClaim(
        source_file="src/handler.c",
        source_function=src_fn,
        sink_file="src/exec.c",
        sink_function=sink_fn,
    )


class TestGenerateTaintQuery:
    def test_contains_source_and_sink(self):
        query = generate_taint_query(_claim("read_input", "system"))
        assert 'getName() = "read_input"' in query
        assert 'getName() = "system"' in query

    def test_is_valid_ql_structure(self):
        query = generate_taint_query(_claim())
        assert "@kind path-problem" in query
        assert "DataFlow::ConfigSig" in query
        assert "isSource" in query
        assert "isSink" in query

    def test_handles_valid_identifiers(self):
        query = generate_taint_query(_claim("foo_bar", "baz_qux"))
        assert "foo_bar" in query
        assert "baz_qux" in query

    def test_rejects_injection_in_source(self):
        try:
            generate_taint_query(_claim('foo" or 1=1', "bar"))
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "identifier" in str(exc)

    def test_rejects_empty_function_name(self):
        try:
            generate_taint_query(_claim("", "bar"))
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "non-empty" in str(exc)

    def test_unsupported_language(self):
        try:
            generate_taint_query(_claim(), language="python")
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "unsupported" in str(exc)


class TestCountSarifResults:
    def test_empty_sarif(self):
        assert _count_sarif_results({}) == 0

    def test_no_codeflows(self):
        sarif = {"runs": [{"results": [{"message": {"text": "found"}}]}]}
        assert _count_sarif_results(sarif) == 0

    def test_with_codeflows(self):
        sarif = {
            "runs": [{
                "results": [
                    {"codeFlows": [{"threadFlows": []}]},
                    {"codeFlows": [{"threadFlows": []}]},
                    {"message": {"text": "no flow"}},
                ],
            }],
        }
        assert _count_sarif_results(sarif) == 2


class TestValidateDataflowClaim:
    def test_no_db_path(self):
        result = validate_dataflow_claim(_claim())
        assert result.confirmed is None
        assert "no CodeQL database" in result.error

    def test_db_not_found(self, tmp_path: Path):
        result = validate_dataflow_claim(
            _claim(), db_path=tmp_path / "nonexistent",
        )
        assert result.confirmed is None
        assert "not found" in result.error

    def test_import_error(self, tmp_path: Path, monkeypatch):
        db = tmp_path / "db"
        db.mkdir()
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if "codeql_augmented_run" in name:
                raise ImportError("not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is None
        assert "not available" in result.error
        assert result.query_text  # query should still be generated

    def test_successful_run_with_matches(self, tmp_path: Path, monkeypatch):
        from dataclasses import dataclass as dc

        from core.audit import codeql_validation

        db = tmp_path / "db"
        db.mkdir()

        sarif_data = {
            "runs": [{"results": [
                {"codeFlows": [{"threadFlows": []}]},
            ]}],
        }

        @dc
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps(sarif_data))
            return FakeResult(sarif_path=output_path)

        monkeypatch.setattr(
            codeql_validation, "validate_dataflow_claim",
            validate_dataflow_claim,
        )
        import core.dataflow.codeql_augmented_run as codeql_mod
        monkeypatch.setattr(codeql_mod, "analyze", mock_analyze)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is True
        assert result.sarif_matches == 1

    def test_successful_run_no_matches(self, tmp_path: Path, monkeypatch):
        from dataclasses import dataclass as dc

        db = tmp_path / "db"
        db.mkdir()

        @dc
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps({"runs": [{"results": []}]}))
            return FakeResult(sarif_path=output_path)

        import core.dataflow.codeql_augmented_run as codeql_mod
        monkeypatch.setattr(codeql_mod, "analyze", mock_analyze)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is False
        assert result.sarif_matches == 0


class TestGuardConditionExtraction:
    def test_if_condition(self):
        assert _guard_condition_on_line("    if (len > 16) {") == "len > 16"

    def test_while_condition(self):
        assert _guard_condition_on_line("while (i < n)") == "i < n"

    def test_for_takes_middle_clause(self):
        assert (
            _guard_condition_on_line("for (i = 0; i < count; i++) {")
            == "i < count"
        )

    def test_nested_call_stays_balanced(self):
        assert (
            _guard_condition_on_line("if (check(x, y) && len > 0) {")
            == "check(x, y) && len > 0"
        )

    def test_plain_statement_returns_none(self):
        assert _guard_condition_on_line("    x = y + 1;") is None

    def test_unbalanced_multiline_returns_none(self):
        assert _guard_condition_on_line("if (a > b &&") is None


def _sarif_with_flow(steps, *, extra_result=None):
    """SARIF with one path-problem result whose thread flow hits steps."""
    locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
            },
        }
        for uri, line in steps
    ]
    results = [{
        "ruleId": "raptor/audit-hypothesis",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": steps[-1][0]},
                "region": {"startLine": steps[-1][1]},
            },
        }],
        "codeFlows": [{"threadFlows": [{"locations": locations}]}],
    }]
    if extra_result is not None:
        results.append(extra_result)
    return {"runs": [{"results": results}]}


def _write_guarded_source(tmp_path: Path) -> Path:
    """Target tree with contradictory guards along the flow path."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vuln.c").write_text(
        "int f(int len) {\n"          # 1
        "    if (len < 0) {\n"        # 2
        "        int x = len;\n"      # 3  <- step
        "        if (len > 0) {\n"    # 4
        "            sink(x);\n"      # 5  <- step
        "        }\n"                 # 6
        "    }\n"
        "    return 0;\n"
        "}\n",
    )
    return target


class TestSarifPathExtraction:
    def test_steps_extracted(self):
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        result = sarif["runs"][0]["results"][0]
        paths = _sarif_result_paths(result)
        assert paths == [[("src/vuln.c", 3), ("src/vuln.c", 5)]]

    def test_path_conditions_harvested(self, tmp_path: Path):
        target = _write_guarded_source(tmp_path)
        conds = _path_conditions(
            [("src/vuln.c", 3), ("src/vuln.c", 5)], target, {},
        )
        texts = [c["text"] for c in conds]
        assert texts == ["len < 0", "len > 0"]

    def test_uri_escape_outside_target_ignored(self, tmp_path: Path):
        target = _write_guarded_source(tmp_path)
        (tmp_path / "outside.c").write_text("if (a > 0) {\n")
        conds = _path_conditions(
            [("../outside.c", 1)], target, {},
        )
        assert conds == []


def _stub_validate_path(feasible, *, calls=None):
    def stub(conditions, profile="uint64", timeout_ms=None, **kw):
        if calls is not None:
            calls.append(list(conditions))
        return {
            "feasible": feasible,
            "reasoning": (
                "infeasible: path conditions are mutually exclusive"
                if feasible is False else "sat"
            ),
            "unsatisfied": (
                [c["text"] for c in conditions] if feasible is False else []
            ),
            "satisfied": [],
            "unknown": [],
            "smt_available": feasible is not None,
        }
    return stub


class TestSmtPruneSarifMatches:
    def test_unsat_match_pruned_with_receipt(self, tmp_path, monkeypatch):
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(False),
        )
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert kept == 0
        assert pruned == 1
        assert len(receipts) == 1
        rec = receipts[0]
        assert rec["verdict"] == "smt_path_infeasible"
        assert rec["file"] == "src/vuln.c"
        assert rec["paths"][0]["unsatisfied"] == ["len < 0", "len > 0"]

    def test_sat_match_kept(self, tmp_path, monkeypatch):
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(True),
        )
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned, receipts) == (1, 0, [])

    def test_unknown_never_prunes(self, tmp_path, monkeypatch):
        """z3 unavailable / solver unknown must fail open."""
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(None),
        )
        kept, pruned, _ = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)

    def test_condition_free_path_kept(self, tmp_path, monkeypatch):
        """No harvestable guards → nothing to judge → match survives."""
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        # Step on line 1 (function header, no enclosing guard).
        sarif = _sarif_with_flow([("src/vuln.c", 1)])
        calls: list = []
        monkeypatch.setattr(
            smt_path_mod, "validate_path",
            _stub_validate_path(False, calls=calls),
        )
        kept, pruned, _ = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert calls == []

    @pytest.mark.skipif(
        not __import__(
            "core.smt_solver.availability", fromlist=["z3_available"],
        ).z3_available(),
        reason="z3 not installed",
    )
    def test_real_solver_kills_contradictory_guards(self, tmp_path):
        """Integration: len < 0 AND len > 0 is UNSAT for real."""
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (0, 1)
        assert receipts[0]["paths"][0]["reasoning"]


class TestValidateClaimSmtPrune:
    def _mock_analyze(self, sarif_data):
        @dataclass
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps(sarif_data))
            return FakeResult(sarif_path=output_path)

        return mock_analyze

    def test_vacuous_match_refuted_with_receipts(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(False),
        )

        result = validate_dataflow_claim(
            _claim(), db_path=db, target_path=target,
        )
        assert result.confirmed is False
        assert result.sarif_matches == 0
        assert result.smt_pruned == 1
        assert result.smt_receipts
        assert "vacuous" in result.reasoning

    def test_no_target_path_skips_prune(self, tmp_path: Path, monkeypatch):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        calls: list = []

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path",
            _stub_validate_path(False, calls=calls),
        )

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is True
        assert result.smt_pruned == 0
        assert calls == []

    def test_surviving_match_still_confirms(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(True),
        )

        result = validate_dataflow_claim(
            _claim(), db_path=db, target_path=target,
        )
        assert result.confirmed is True
        assert result.sarif_matches == 1
        assert result.smt_pruned == 0


class TestExtractClaimsFromReview:
    def test_no_claims(self):
        result = {"file": "a.c", "function": "f", "status": "clean"}
        claims = extract_claims_from_review(result)
        assert claims == []

    def test_full_claim(self):
        result = {
            "file": "a.c",
            "function": "f",
            "hypothesis": "input flows to system",
            "dataflow_source": {"file": "src/in.c", "function": "read_input"},
            "dataflow_sink": {"file": "src/exec.c", "function": "system"},
        }
        claims = extract_claims_from_review(result)
        assert len(claims) == 1
        assert claims[0].source_function == "read_input"
        assert claims[0].sink_function == "system"
        assert claims[0].description == "input flows to system"

    def test_inherits_file_from_result(self):
        result = {
            "file": "main.c",
            "dataflow_source": {"function": "src_fn"},
            "dataflow_sink": {"function": "sink_fn"},
        }
        claims = extract_claims_from_review(result)
        assert claims[0].source_file == "main.c"
        assert claims[0].sink_file == "main.c"

    def test_empty_function_name_skipped(self):
        result = {
            "file": "a.c",
            "dataflow_source": {"file": "a.c"},
            "dataflow_sink": {"function": "bar"},
        }
        claims = extract_claims_from_review(result)
        assert claims == []
