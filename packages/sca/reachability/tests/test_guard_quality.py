"""Tests for guard_quality — call-site guard analysis for SCA reachability."""

import pytest

from packages.sca.reachability.guard_quality import (
    CallSiteGuardAnalysis,
    GuardQualityResult,
    _parse_evidence,
    analyze_call_site_guards,
)
from packages.sca.models import Confidence, Reachability


# ---------------------------------------------------------------------------
# Evidence parsing
# ---------------------------------------------------------------------------


class TestParseEvidence:
    def test_simple(self):
        path, line = _parse_evidence("src/app.py:42")
        assert path == "src/app.py"
        assert line == 42

    def test_nested_path(self):
        path, line = _parse_evidence("src/auth/login.py:10")
        assert path == "src/auth/login.py"
        assert line == 10

    def test_no_colon(self):
        assert _parse_evidence("nocolon") == (None, None)

    def test_non_numeric_line(self):
        assert _parse_evidence("file.py:abc") == (None, None)

    def test_empty(self):
        assert _parse_evidence("") == (None, None)

    def test_colon_at_start(self):
        assert _parse_evidence(":42") == (None, None)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class TestCallSiteGuardAnalysis:
    def test_to_dict_minimal(self):
        cs = CallSiteGuardAnalysis(
            evidence_entry="src/app.py:10",
            sink_api="eval",
            guards_found=0,
            unconditional=True,
            adequacy_verdict="insufficient",
            has_bound_guard=False,
            all_decorative=True,
        )
        d = cs.to_dict()
        assert d["evidence"] == "src/app.py:10"
        assert d["sink_api"] == "eval"
        assert d["unconditional"] is True
        assert "guard_details" not in d

    def test_to_dict_with_details(self):
        cs = CallSiteGuardAnalysis(
            evidence_entry="src/app.py:10",
            sink_api="eval",
            guards_found=1,
            unconditional=False,
            adequacy_verdict="sufficient",
            has_bound_guard=True,
            all_decorative=False,
            guard_details=[{"text": "is_admin", "category": "auth"}],
        )
        d = cs.to_dict()
        assert d["guard_details"] == [
            {"text": "is_admin", "category": "auth"},
        ]


class TestGuardQualityResult:
    def test_to_dict(self):
        result = GuardQualityResult(
            dep_key="PyPI:requests@2.28.0",
            call_sites=[
                CallSiteGuardAnalysis(
                    evidence_entry="src/app.py:10",
                    sink_api="eval",
                    guards_found=0,
                    unconditional=True,
                    adequacy_verdict="insufficient",
                    has_bound_guard=False,
                    all_decorative=True,
                ),
            ],
            any_unguarded=True,
            any_inadequate=True,
            all_adequately_guarded=False,
            summary="1/1 call site(s) unconditional; 0/1 adequately guarded",
        )
        d = result.to_dict()
        assert d["dep_key"] == "PyPI:requests@2.28.0"
        assert len(d["call_sites"]) == 1
        assert d["any_unguarded"] is True


# ---------------------------------------------------------------------------
# Integration: analyze_call_site_guards
# ---------------------------------------------------------------------------


class TestAnalyzeCallSiteGuards:
    def test_empty_when_no_cve_keys(self):
        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=["src/app.py:10"],
            ),
        }
        result = analyze_call_site_guards(
            reach, "/tmp/target",
            cve_dep_keys=None,
            affected_functions={"PyPI:foo@1.0": ["dangerous"]},
        )
        assert result == {}

    def test_empty_when_no_affected_functions(self):
        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=["src/app.py:10"],
            ),
        }
        result = analyze_call_site_guards(
            reach, "/tmp/target",
            cve_dep_keys={"PyPI:foo@1.0"},
            affected_functions=None,
        )
        assert result == {}

    def test_skips_non_likely_called(self):
        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="imported",
                confidence=Confidence("medium", reason="test"),
                evidence=["src/app.py:10"],
            ),
        }
        result = analyze_call_site_guards(
            reach, "/tmp/target",
            cve_dep_keys={"PyPI:foo@1.0"},
            affected_functions={"PyPI:foo@1.0": ["dangerous"]},
        )
        assert result == {}

    def test_skips_deps_without_cve(self):
        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=["src/app.py:10"],
            ),
        }
        result = analyze_call_site_guards(
            reach, "/tmp/target",
            cve_dep_keys={"PyPI:bar@2.0"},
            affected_functions={"PyPI:foo@1.0": ["dangerous"]},
        )
        assert result == {}

    def test_skips_deps_without_evidence(self):
        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=[],
            ),
        }
        result = analyze_call_site_guards(
            reach, "/tmp/target",
            cve_dep_keys={"PyPI:foo@1.0"},
            affected_functions={"PyPI:foo@1.0": ["dangerous"]},
        )
        assert result == {}

    def test_analyze_with_real_source(self, tmp_path):
        """End-to-end: write a source file, run analysis."""
        pytest.importorskip("tree_sitter")

        src = tmp_path / "app.py"
        src.write_text(
            "import yaml\n"
            "def load_config(path):\n"
            "    with open(path) as f:\n"
            "        return yaml.load(f)\n",
        encoding="utf-8",
        )

        reach = {
            "PyPI:pyyaml@5.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=["app.py:4"],
            ),
        }
        result = analyze_call_site_guards(
            reach, tmp_path,
            cve_dep_keys={"PyPI:pyyaml@5.0"},
            affected_functions={"PyPI:pyyaml@5.0": ["yaml.load"]},
        )
        if "PyPI:pyyaml@5.0" in result:
            r = result["PyPI:pyyaml@5.0"]
            assert r.any_unguarded
            assert not r.all_adequately_guarded

    def test_analyze_guarded_call(self, tmp_path):
        """Call behind an auth guard should show has_bound_guard."""
        pytest.importorskip("tree_sitter")

        src = tmp_path / "app.py"
        src.write_text(
            "def run(user, cmd):\n"
            "    if user.is_admin:\n"
            "        eval(cmd)\n",
        encoding="utf-8",
        )

        reach = {
            "PyPI:foo@1.0": Reachability(
                verdict="likely_called",
                confidence=Confidence("high", reason="test"),
                evidence=["app.py:3"],
            ),
        }
        result = analyze_call_site_guards(
            reach, tmp_path,
            cve_dep_keys={"PyPI:foo@1.0"},
            affected_functions={"PyPI:foo@1.0": ["eval"]},
        )
        if "PyPI:foo@1.0" in result:
            r = result["PyPI:foo@1.0"]
            assert not r.any_unguarded
            # Eval-class sinks cap at "partial": a guard that LOOKS
            # like an auth gate proves nothing about what it authorises
            # (condition_adequacy category_cap_partial). "partial" still
            # counts as adequately guarded here — only insufficient /
            # irrelevant verdicts mark a call site unguarded.
            assert r.call_sites[0].adequacy_verdict == "partial"
