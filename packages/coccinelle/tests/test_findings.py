"""Tests for findings conversion."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.coccinelle.findings import to_findings
from packages.coccinelle.models import SpatchMatch, SpatchResult


class TestToFindings:
    def test_empty_results(self):
        assert to_findings([]) == []

    def test_no_matches(self):
        results = [SpatchResult(rule="r1")]
        assert to_findings(results) == []

    def test_single_match(self):
        results = [
            SpatchResult(
                rule="unchecked_return",
                matches=[SpatchMatch(file="a.c", line=10, message="not checked")],
            )
        ]
        findings = to_findings(results)
        assert len(findings) == 1
        f = findings[0]
        assert f["id"] == "COCCI-unchecked_return-1"
        assert f["file"] == "a.c"
        assert f["line"] == 10
        assert f["origin"] == "coccinelle"
        assert f["vuln_type"] == "inconsistency"
        assert f["confidence"] == "medium"
        assert f["rule"] == "unchecked_return"

    def test_multiple_results(self):
        results = [
            SpatchResult(
                rule="r1",
                matches=[
                    SpatchMatch(file="a.c", line=1),
                    SpatchMatch(file="b.c", line=2),
                ],
            ),
            SpatchResult(
                rule="r2",
                matches=[SpatchMatch(file="c.c", line=3)],
            ),
        ]
        findings = to_findings(results)
        assert len(findings) == 3
        assert findings[0]["id"] == "COCCI-r1-1"
        assert findings[1]["id"] == "COCCI-r1-2"
        assert findings[2]["id"] == "COCCI-r2-1"

    def test_default_description(self):
        results = [
            SpatchResult(
                rule="test_rule",
                matches=[SpatchMatch(file="a.c", line=1)],
            )
        ]
        findings = to_findings(results)
        assert "test_rule" in findings[0]["description"]

    def test_ids_unique_across_same_rule_results(self):
        results = [
            SpatchResult(
                rule="r1",
                matches=[SpatchMatch(file="a.c", line=1)],
            ),
            SpatchResult(
                rule="r1",
                matches=[SpatchMatch(file="b.c", line=2)],
            ),
        ]
        findings = to_findings(results)
        ids = [f["id"] for f in findings]
        assert ids == ["COCCI-r1-1", "COCCI-r1-2"]
        assert len(ids) == len(set(ids))
