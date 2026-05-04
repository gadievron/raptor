"""Tests for cross-run project correlation."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parents[3]))

from core.project.correlate import (
    correlate_project,
    _find_persistent,
    _build_trends,
    _build_tool_coverage,
)


def _make_finding(file="app.py", function="handle", line=10,
                  vuln_type="sqli", status="exploitable", score=0.9):
    return {
        "file": file,
        "function": function,
        "line": line,
        "vuln_type": vuln_type,
        "final_status": status,
        "exploitability_score": score,
    }


def _write_run(tmp_path, name, findings, command="scan"):
    """Create a fake run directory with findings.json and metadata."""
    d = tmp_path / name
    d.mkdir()
    (d / "findings.json").write_text(json.dumps({"findings": findings}))
    (d / ".raptor-run.json").write_text(json.dumps({
        "version": 1, "command": command, "status": "completed",
    }))
    return d


class TestFindPersistent:
    def test_empty(self):
        assert _find_persistent({}) == []

    def test_single_run(self):
        findings_by_run = {
            "run-1": [_make_finding()],
        }
        assert _find_persistent(findings_by_run) == []

    def test_same_finding_two_runs(self):
        f = _make_finding()
        findings_by_run = {
            "run-1": [f],
            "run-2": [f],
        }
        result = _find_persistent(findings_by_run)
        assert len(result) == 1
        assert result[0]["runs_seen"] == 2
        assert result[0]["file"] == "app.py"

    def test_different_findings(self):
        findings_by_run = {
            "run-1": [_make_finding(line=10)],
            "run-2": [_make_finding(line=20)],
        }
        assert _find_persistent(findings_by_run) == []

    def test_mixed(self):
        shared = _make_finding(line=10)
        unique = _make_finding(line=20)
        findings_by_run = {
            "run-1": [shared, unique],
            "run-2": [shared],
        }
        result = _find_persistent(findings_by_run)
        assert len(result) == 1
        assert result[0]["line"] == 10


class TestBuildTrends:
    def test_empty(self):
        assert _build_trends({}, []) == {}

    def test_single_run_no_trend(self):
        findings_by_run = {"run-1": [_make_finding()]}
        assert _build_trends(findings_by_run, [Path("run-1")]) == {}

    def test_status_progression(self):
        f1 = _make_finding(status="not_disproven", score=0.5)
        f2 = _make_finding(status="exploitable", score=0.9)
        findings_by_run = {
            "run-1": [f1],
            "run-2": [f2],
        }
        dirs = [Path("run-1"), Path("run-2")]
        trends = _build_trends(findings_by_run, dirs)
        assert len(trends) == 1
        label = list(trends.keys())[0]
        history = trends[label]
        assert history[0]["status"] == "not_disproven"
        assert history[1]["status"] == "exploitable"


class TestBuildToolCoverage:
    def test_empty(self):
        assert _build_tool_coverage([]) == {}

    def test_from_runs(self, tmp_path):
        d1 = _write_run(tmp_path, "scan-001", [
            _make_finding(file="a.py"), _make_finding(file="b.py"),
        ], command="scan")
        d2 = _write_run(tmp_path, "agentic-001", [
            _make_finding(file="b.py"), _make_finding(file="c.py"),
        ], command="agentic")

        result = _build_tool_coverage([d1, d2])
        assert "scan" in result
        assert "agentic" in result
        assert "a.py" in result["scan"]
        assert "b.py" in result["scan"]
        assert "c.py" in result["agentic"]


class TestCorrelateProject:
    def test_no_runs(self):
        project = MagicMock()
        project.get_run_dirs.return_value = []
        result = correlate_project(project)
        assert result["summary"]["runs"] == 0

    def test_full_correlation(self, tmp_path):
        shared = _make_finding(file="shared.py", line=5)
        d1 = _write_run(tmp_path, "scan-001", [shared, _make_finding(file="a.py", line=1)])
        d2 = _write_run(tmp_path, "scan-002", [shared, _make_finding(file="b.py", line=2)])

        project = MagicMock()
        project.get_run_dirs.return_value = [d1, d2]

        result = correlate_project(project)
        assert result["summary"]["runs"] == 2
        assert result["summary"]["persistent_findings"] == 1
        assert result["summary"]["total_unique_findings"] == 3
        assert len(result["persistent_findings"]) == 1
        assert result["persistent_findings"][0]["file"] == "shared.py"
