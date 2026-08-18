"""Tests for mid-audit concept discovery."""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.concept_discovery import (
    InvariantCandidate,
    candidates_to_model_entries,
    discover_invariants,
)


def _outcome(status, cwe, hypothesis="", file="", function=""):
    return SimpleNamespace(
        status=status,
        cwe=cwe,
        hypothesis=hypothesis,
        file=file,
        function=function,
        review_result={"cwe": cwe},
    )


class TestDiscoverInvariants:
    def test_empty_outcomes(self):
        assert discover_invariants({}) == []

    def test_clean_outcomes_ignored(self):
        outcomes = {
            "a.c:foo": _outcome("clean", "CWE-476"),
            "a.c:bar": _outcome("clean", "CWE-476"),
            "a.c:baz": _outcome("clean", "CWE-476"),
        }
        assert discover_invariants(outcomes) == []

    def test_single_finding_below_threshold(self):
        outcomes = {
            "a.c:foo": _outcome("finding", "CWE-476", file="a.c", function="foo"),
        }
        assert discover_invariants(outcomes) == []

    def test_two_findings_same_cwe_produces_candidate(self):
        outcomes = {
            "a.c:foo": _outcome("finding", "CWE-476", file="a.c", function="foo"),
            "b.c:bar": _outcome("finding", "CWE-476", file="b.c", function="bar"),
        }
        result = discover_invariants(outcomes)
        assert len(result) == 1
        assert result[0].cwe == "CWE-476"
        assert "a.c:foo" in result[0].evidence
        assert "b.c:bar" in result[0].evidence

    def test_suspicious_counted(self):
        outcomes = {
            "a.c:foo": _outcome("suspicious", "CWE-415", file="a.c", function="foo"),
            "b.c:bar": _outcome("suspicious", "CWE-415", file="b.c", function="bar"),
        }
        result = discover_invariants(outcomes)
        assert len(result) == 1
        assert result[0].cwe == "CWE-415"

    def test_different_cwes_separate_clusters(self):
        outcomes = {
            "a.c:f1": _outcome("finding", "CWE-476", file="a.c", function="f1"),
            "b.c:f2": _outcome("finding", "CWE-476", file="b.c", function="f2"),
            "c.c:f3": _outcome("finding", "CWE-134", file="c.c", function="f3"),
            "d.c:f4": _outcome("finding", "CWE-134", file="d.c", function="f4"),
        }
        result = discover_invariants(outcomes)
        assert len(result) == 2
        cwes = {c.cwe for c in result}
        assert cwes == {"CWE-476", "CWE-134"}

    def test_dedup_against_existing_model(self):
        outcomes = {
            "a.c:foo": _outcome("finding", "CWE-476", file="a.c", function="foo"),
            "b.c:bar": _outcome("finding", "CWE-476", file="b.c", function="bar"),
        }
        existing = {
            "invariants": [
                {"id": "x", "relevant_cwes": ["CWE-476"]},
            ],
        }
        result = discover_invariants(outcomes, existing)
        assert len(result) == 0

    def test_unknown_cwe_skipped(self):
        outcomes = {
            "a.c:foo": _outcome("finding", "CWE-999", file="a.c", function="foo"),
            "b.c:bar": _outcome("finding", "CWE-999", file="b.c", function="bar"),
        }
        result = discover_invariants(outcomes)
        assert len(result) == 0

    def test_max_invariants_cap(self):
        outcomes = {}
        for cwe in ["CWE-476", "CWE-415", "CWE-416", "CWE-134", "CWE-190", "CWE-362"]:
            for i in range(3):
                key = f"f{i}.c:{cwe.lower()}"
                outcomes[key] = _outcome(
                    "finding", cwe, file=f"f{i}.c", function=cwe.lower(),
                )
        result = discover_invariants(outcomes, max_invariants=3)
        assert len(result) == 3

    def test_ordered_by_cluster_size(self):
        outcomes = {}
        for i in range(5):
            outcomes[f"a{i}.c:f"] = _outcome(
                "finding", "CWE-476", file=f"a{i}.c", function="f",
            )
        for i in range(2):
            outcomes[f"b{i}.c:g"] = _outcome(
                "finding", "CWE-134", file=f"b{i}.c", function="g",
            )
        result = discover_invariants(outcomes)
        assert result[0].cwe == "CWE-476"

    def test_api_names_extracted(self):
        outcomes = {
            "a.c:foo": _outcome(
                "finding", "CWE-476",
                hypothesis="missing null check after kmalloc",
                file="a.c", function="foo",
            ),
            "b.c:bar": _outcome(
                "finding", "CWE-476",
                hypothesis="missing null check after kmalloc in init path",
                file="b.c", function="bar",
            ),
        }
        result = discover_invariants(outcomes)
        assert len(result) == 1
        assert "kmalloc" in result[0].api_names

    def test_dict_outcomes(self):
        outcomes = {
            "a.c:foo": {
                "status": "finding",
                "file": "a.c",
                "function": "foo",
                "hypothesis": "",
                "review_result": {"cwe": "CWE-476"},
            },
            "b.c:bar": {
                "status": "finding",
                "file": "b.c",
                "function": "bar",
                "hypothesis": "",
                "review_result": {"cwe": "CWE-476"},
            },
        }
        result = discover_invariants(outcomes)
        assert len(result) == 1


class TestCandidatesToModelEntries:
    def test_basic_conversion(self):
        candidates = [
            InvariantCandidate(
                cwe="CWE-476",
                statement="must check null",
                negation="missing null check",
                description="seen 3 times",
                evidence=["a.c:foo", "b.c:bar"],
                api_names=["kmalloc"],
            ),
        ]
        entries = candidates_to_model_entries(candidates)
        assert len(entries) == 1
        e = entries[0]
        assert e["id"] == "discovered_cwe_476"
        assert e["statement"] == "must check null"
        assert e["negation"] == "missing null check"
        assert e["confidence"] == "observed"
        assert e["relevant_cwes"] == ["CWE-476"]
        assert e["mechanical_rule"] is None

    def test_evidence_capped(self):
        candidates = [
            InvariantCandidate(
                cwe="CWE-415",
                statement="s",
                negation="n",
                description="d",
                evidence=[f"f{i}.c:g" for i in range(20)],
                api_names=[],
            ),
        ]
        entries = candidates_to_model_entries(candidates)
        assert len(entries[0]["evidence"]) == 10
