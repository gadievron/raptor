"""Tests for findings converter."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.findings import to_findings
from packages.semgrep.models import SemgrepFinding, SemgrepResult


class TestToFindings:
    def test_empty_results(self):
        assert to_findings([]) == []

    def test_no_findings_in_result(self):
        results = [SemgrepResult(name="r1", findings=[])]
        assert to_findings(results) == []

    def test_basic_finding(self):
        results = [SemgrepResult(
            name="injection",
            findings=[SemgrepFinding(
                file="src/auth.py",
                line=42,
                rule_id="raptor.sqli",
                message="SQL concatenation",
                level="error",
            )],
        )]
        out = to_findings(results)
        assert len(out) == 1
        f = out[0]
        assert f["id"] == "SEMGREP-injection-1"
        assert f["file"] == "src/auth.py"
        assert f["line"] == 42
        assert f["rule"] == "raptor.sqli"
        assert f["origin"] == "semgrep"
        assert f["level"] == "error"
        assert f["description"] == "SQL concatenation"

    def test_default_description_when_message_empty(self):
        results = [SemgrepResult(
            name="r",
            findings=[SemgrepFinding(file="a", line=1, rule_id="r1")],
        )]
        out = to_findings(results)
        assert "r1" in out[0]["description"]

    def test_id_counter_per_run(self):
        results = [SemgrepResult(
            name="r1",
            findings=[
                SemgrepFinding(file="a", line=1),
                SemgrepFinding(file="b", line=2),
                SemgrepFinding(file="c", line=3),
            ],
        )]
        out = to_findings(results)
        assert [f["id"] for f in out] == [
            "SEMGREP-r1-1", "SEMGREP-r1-2", "SEMGREP-r1-3",
        ]

    def test_separate_counters_per_run(self):
        results = [
            SemgrepResult(name="r1", findings=[SemgrepFinding(file="a", line=1)]),
            SemgrepResult(name="r2", findings=[SemgrepFinding(file="b", line=2)]),
        ]
        out = to_findings(results)
        assert out[0]["id"] == "SEMGREP-r1-1"
        assert out[1]["id"] == "SEMGREP-r2-1"

    def test_counter_continues_across_same_named_results(self):
        # Same name across multiple results — IDs should not collide.
        results = [
            SemgrepResult(name="r1", findings=[SemgrepFinding(file="a", line=1)]),
            SemgrepResult(name="r1", findings=[SemgrepFinding(file="b", line=2)]),
        ]
        out = to_findings(results)
        assert out[0]["id"] == "SEMGREP-r1-1"
        assert out[1]["id"] == "SEMGREP-r1-2"

    def test_default_name_when_unnamed(self):
        results = [SemgrepResult(name="", findings=[SemgrepFinding(file="a", line=1)])]
        out = to_findings(results)
        assert out[0]["id"] == "SEMGREP-semgrep-1"
