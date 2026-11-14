"""Incomplete analyser output is unavailable, never a successful count."""
import json
from pathlib import Path

import pytest

from core.dataflow import cvefix_walk as walk


def test_failed_invocation_is_not_a_zero_count(tmp_path, monkeypatch):
    output = tmp_path / "result.sarif"
    calls = []

    def recorded_run(argv, timeout):
        calls.append((argv, timeout))
        output.write_text(json.dumps({"runs": [{
            "invocations": [{"executionSuccessful": False}], "results": [],
        }]}))
        return True

    monkeypatch.setattr(walk, "_run", recorded_run)
    result = walk._count_query(tmp_path / "db", "owned-query", output, "codeql-not-executed", 1)
    assert len(calls) == 1
    assert result is None


@pytest.mark.parametrize("invocation", [
    {"executionSuccessful": "true"},
    {"toolExecutionNotifications": [{"level": "error"}]},
    {"toolConfigurationNotifications": [{"level": "error"}]},
    {"toolExecutionNotifications": [{"level": "warning", "properties": {"coverage_limitation": "partial"}}]},
    {"toolExecutionNotifications": "malformed"},
], ids=["nonboolean-status", "execution-error", "configuration-error", "coverage-limit", "malformed-notes"])
def test_incomplete_run_refuses_even_with_results(tmp_path, monkeypatch, invocation):
    output = tmp_path / "result.sarif"
    output.write_text(json.dumps({"runs": [{"results": [{}]}, {"invocations": [invocation], "results": [{}]}]}))
    monkeypatch.setattr(walk, "_run", lambda *args: True)
    assert walk._count_query(tmp_path / "db", "owned-query", output, "not-executed", 1) is None


@pytest.mark.parametrize("document", [
    [], {"runs": None}, {"runs": {}}, {"runs": [None]},
    {"runs": [{"results": None}]}, {"runs": [{"results": "items"}]},
    {"runs": [{"results": [None]}]},
], ids=["document", "null-runs", "object-runs", "null-run", "null-results", "text-results", "null-result"])
def test_malformed_count_input_is_unavailable(tmp_path, monkeypatch, document):
    output = tmp_path / "result.sarif"
    output.write_text(json.dumps(document))
    monkeypatch.setattr(walk, "_run", lambda *args: True)
    assert walk._count_query(tmp_path / "db", "owned-query", output, "not-executed", 1) is None


@pytest.mark.parametrize("invocation", [
    {}, {"executionSuccessful": True},
    {"toolExecutionNotifications": [{"level": "warning"}]},
    {"toolExecutionNotifications": [{"properties": {"coverage_limitation": "review_candidates"}}]},
], ids=["no-status", "successful", "ordinary-warning", "legacy-review-candidates"])
@pytest.mark.parametrize("size", [0, 2])
def test_complete_output_keeps_real_counts(tmp_path, monkeypatch, invocation, size):
    output = tmp_path / "result.sarif"
    output.write_text(json.dumps({"runs": [{"invocations": [invocation], "results": [{}] * size}]}))
    monkeypatch.setattr(walk, "_run", lambda *args: True)
    assert walk._count_query(tmp_path / "db", "owned-query", output, "not-executed", 1) == size


def test_incomplete_analysis_does_not_record_successful_pair(tmp_path, monkeypatch):
    calls = []

    def recorded_run(argv, timeout):
        calls.append(argv)
        output = Path(next(arg.removeprefix("--output=") for arg in argv if arg.startswith("--output=")))
        output.write_text(json.dumps({"runs": [{"invocations": [{"executionSuccessful": False}], "results": []}]}))
        return True

    monkeypatch.setattr(walk, "_run", recorded_run)
    monkeypatch.setattr(walk, "_fetch_pair", lambda *args, **kwargs: True)
    monkeypatch.setattr(walk, "_build_db", lambda *args, **kwargs: True)
    pair = walk.CveFixPair("CVE-FIXTURE", "CWE-79", "https://example.invalid/fixture", "Python", "a" * 40, "b" * 40)
    result = walk.process_pair(pair, work_dir=tmp_path, codeql_bin="not-executed")
    assert len(calls) == 2
    assert result.status == "analyze_fail"
