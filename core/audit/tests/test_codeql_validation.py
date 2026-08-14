"""Tests for core.audit.codeql_validation — IRIS-style dataflow verification."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.codeql_validation import (
    DataflowClaim,
    _count_sarif_results,
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
        from core.audit import codeql_validation
        from dataclasses import dataclass as dc

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
