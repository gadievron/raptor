"""Tests for the Coccinelle and Semgrep adapters."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.hypothesis_validation.adapters import (
    CoccinelleAdapter,
    SemgrepAdapter,
)


# Coccinelle ------------------------------------------------------------------

class TestCoccinelleAdapter:
    def test_name(self):
        assert CoccinelleAdapter().name == "coccinelle"

    def test_describe_languages(self):
        cap = CoccinelleAdapter().describe()
        assert cap.languages == ["c", "cpp"]
        assert cap.syntax_example  # not empty

    def test_describe_render_includes_good_for(self):
        text = CoccinelleAdapter().describe().render_for_prompt()
        assert "Good for:" in text
        assert "Not for:" in text
        assert "Inconsistency" in text or "inconsistency" in text.lower()

    def test_run_when_unavailable(self, tmp_path):
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=False):
            ev = a.run("rule", tmp_path)
        assert not ev.success
        assert "not installed" in ev.error
        assert ev.matches == []

    def test_run_with_empty_rule(self, tmp_path):
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=True):
            ev = a.run("", tmp_path)
        assert not ev.success
        assert "empty" in ev.error.lower()

    def test_run_with_whitespace_rule(self, tmp_path):
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=True):
            ev = a.run("   \n  ", tmp_path)
        assert not ev.success

    def test_run_returns_matches_on_success(self, tmp_path):
        from packages.coccinelle.models import SpatchMatch, SpatchResult
        fake_result = SpatchResult(
            rule="r", returncode=0,
            matches=[SpatchMatch(file="a.c", line=10, rule="r", message="boom")],
            files_examined=["a.c"],
        )
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.coccinelle.run_rule", return_value=fake_result):
            ev = a.run("@r@\n@@\nx;\n", tmp_path)
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["file"] == "a.c"
        assert "1 match" in ev.summary

    def test_run_no_matches(self, tmp_path):
        from packages.coccinelle.models import SpatchResult
        fake_result = SpatchResult(rule="r", returncode=0, matches=[])
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.coccinelle.run_rule", return_value=fake_result):
            ev = a.run("@r@\n@@\nx;\n", tmp_path)
        assert ev.success
        assert ev.matches == []
        assert "no matches" in ev.summary

    def test_run_propagates_failure(self, tmp_path):
        from packages.coccinelle.models import SpatchResult
        fake_result = SpatchResult(
            rule="r", returncode=1, errors=["parse error"],
        )
        a = CoccinelleAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.coccinelle.run_rule", return_value=fake_result):
            ev = a.run("@r@\n@@\nx;\n", tmp_path)
        assert not ev.success
        assert "parse error" in ev.error

    def test_run_writes_rule_to_temp_file(self, tmp_path):
        """Adapter must hand a Path object to run_rule, since spatch needs a file."""
        from packages.coccinelle.models import SpatchResult
        captured = {}

        def fake_run_rule(*, target, rule, timeout, env, subprocess_runner=None):
            captured["rule_path"] = rule
            captured["rule_text"] = rule.read_text()
            return SpatchResult(rule="r", returncode=0)

        a = CoccinelleAdapter(sandbox=False)
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.coccinelle.run_rule", side_effect=fake_run_rule):
            a.run("MY UNIQUE RULE TEXT", tmp_path)
        assert "MY UNIQUE RULE TEXT" in captured["rule_text"]


# Semgrep ---------------------------------------------------------------------

class TestSemgrepAdapter:
    def test_name(self):
        assert SemgrepAdapter().name == "semgrep"

    def test_describe_languages(self):
        cap = SemgrepAdapter().describe()
        assert "python" in cap.languages
        assert "c" in cap.languages
        assert cap.syntax_example  # not empty

    def test_run_when_unavailable(self, tmp_path):
        a = SemgrepAdapter()
        with patch.object(a, "is_available", return_value=False):
            ev = a.run("rules: []", tmp_path)
        assert not ev.success
        assert "not installed" in ev.error

    def test_run_with_empty_rule(self, tmp_path):
        a = SemgrepAdapter()
        with patch.object(a, "is_available", return_value=True):
            ev = a.run("", tmp_path)
        assert not ev.success

    def test_run_returns_matches(self, tmp_path):
        from packages.semgrep.models import SemgrepFinding, SemgrepResult
        fake_result = SemgrepResult(
            name="r", returncode=0,
            findings=[
                SemgrepFinding(file="a.py", line=5, rule_id="r1", message="m"),
                SemgrepFinding(file="b.py", line=7, rule_id="r1", message="m"),
            ],
            files_examined=["a.py", "b.py"],
        )
        a = SemgrepAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.semgrep.run_rule", return_value=fake_result):
            ev = a.run("rules: [{...}]", tmp_path)
        assert ev.success
        assert len(ev.matches) == 2
        assert "2 findings" in ev.summary

    def test_run_no_findings(self, tmp_path):
        from packages.semgrep.models import SemgrepResult
        fake_result = SemgrepResult(name="r", returncode=0, findings=[])
        a = SemgrepAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.semgrep.run_rule", return_value=fake_result):
            ev = a.run("rules: [{...}]", tmp_path)
        assert ev.success
        assert ev.matches == []
        assert "no findings" in ev.summary

    def test_run_propagates_failure(self, tmp_path):
        from packages.semgrep.models import SemgrepResult
        fake_result = SemgrepResult(
            name="r", returncode=2, errors=["yaml parse error"],
        )
        a = SemgrepAdapter()
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.semgrep.run_rule", return_value=fake_result):
            ev = a.run("not yaml", tmp_path)
        assert not ev.success
        assert "yaml parse error" in ev.error

    def test_run_writes_rule_to_temp_file(self, tmp_path):
        from packages.semgrep.models import SemgrepResult
        captured = {}

        def fake_run_rule(*, target, config, timeout, env, subprocess_runner=None):
            captured["config"] = config
            captured["rule_text"] = Path(config).read_text()
            return SemgrepResult(name="r", returncode=0)

        a = SemgrepAdapter(sandbox=False)
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.semgrep.run_rule", side_effect=fake_run_rule):
            a.run("UNIQUE_YAML_TEXT_FOR_TEST", tmp_path)
        assert "UNIQUE_YAML_TEXT_FOR_TEST" in captured["rule_text"]
