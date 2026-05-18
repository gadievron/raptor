"""Tests for ``packages.checker_synthesis.models``."""

from __future__ import annotations

import json

import pytest

from packages.checker_synthesis import (
    CheckerSynthesisResult,
    Match,
    MatchTriage,
    SeedBug,
    SynthesisedRule,
)


class TestSeedBug:
    def test_minimal_construction(self):
        s = SeedBug(
            file="src/foo.py",
            function="login",
            line_start=10,
            line_end=20,
            cwe="CWE-89",
            reasoning="Tainted query string reaches cursor.execute",
        )
        assert s.file == "src/foo.py"
        assert s.snippet == ""  # default empty

    def test_frozen(self):
        s = SeedBug(
            file="x", function="f", line_start=1, line_end=2,
            cwe="CWE-78", reasoning="r",
        )
        with pytest.raises(Exception):
            s.file = "y"


class TestSynthesisedRule:
    def test_construction(self):
        r = SynthesisedRule(
            engine="semgrep", rule_id="auth.login.cwe-89.0",
            body="rules:\n  - id: tainted-query\n    patterns: ...",
            rationale="Pattern catches f-string SQL with user input",
        )
        assert r.engine == "semgrep"
        assert r.rule_id == "auth.login.cwe-89.0"


class TestCheckerSynthesisResult:
    def _seed(self):
        return SeedBug(
            file="src/foo.py", function="login",
            line_start=10, line_end=20,
            cwe="CWE-89", reasoning="r",
        )

    def test_default_failure_state(self):
        r = CheckerSynthesisResult(seed=self._seed())
        assert r.rule is None
        assert r.matches == []
        assert r.triage == []
        assert r.capped is False
        assert r.errors == []
        assert r.positive_control is False

    def test_to_dict_round_trip_no_rule(self):
        r = CheckerSynthesisResult(
            seed=self._seed(),
            errors=["LLM unavailable"],
        )
        d = r.to_dict()
        assert d["rule"] is None
        assert d["matches"] == []
        assert d["errors"] == ["LLM unavailable"]
        # JSON-serialisable.
        assert json.dumps(d)

    def test_to_dict_with_rule_and_matches(self, tmp_path):
        rule = SynthesisedRule(
            engine="semgrep", rule_id="x.0", body="rules: ...",
        )
        m = Match(file="src/bar.py", line=5, snippet="db.execute(q)")
        t = MatchTriage(
            match=m, status="variant",
            reasoning="Same pattern, different file",
        )
        r = CheckerSynthesisResult(
            seed=self._seed(),
            rule=rule,
            rule_path=tmp_path / "x.yml",
            positive_control=True,
            matches=[m],
            triage=[t],
        )
        d = r.to_dict()
        assert d["rule"]["engine"] == "semgrep"
        assert d["matches"][0]["file"] == "src/bar.py"
        assert d["triage"][0]["status"] == "variant"
        assert d["positive_control"] is True
        assert json.dumps(d)
