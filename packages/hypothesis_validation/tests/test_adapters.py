"""Tests for the Coccinelle and Semgrep adapters."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

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

        def fake_run_rule(*, target, config, timeout, env,
                          subprocess_runner=None, unsandboxed=False):
            captured["config"] = config
            captured["rule_text"] = Path(config).read_text()
            return SemgrepResult(name="r", returncode=0)

        a = SemgrepAdapter(sandbox=False)
        with patch.object(a, "is_available", return_value=True), \
             patch("packages.semgrep.run_rule", side_effect=fake_run_rule):
            a.run("UNIQUE_YAML_TEXT_FOR_TEST", tmp_path)
        assert "UNIQUE_YAML_TEXT_FOR_TEST" in captured["rule_text"]


# Syntax-example validity ------------------------------------------------------

class TestSemgrepSyntaxExampleSchema:
    """The one worked example the LLM mirrors must be schema-valid
    Semgrep YAML: an unknown rule key (semgrep silently ignores them)
    would drop the metavariable constraint and make mirrored rules
    over-match, inflating confirming evidence."""

    _KNOWN_RULE_KEYS = {
        # Semgrep rule-schema keys the example may legitimately use.
        "id", "message", "severity", "languages", "metadata",
        "pattern", "patterns", "pattern-either", "pattern-regex",
        "pattern-not", "pattern-inside", "pattern-not-inside",
        "mode", "options", "paths", "fix",
    }

    def _load_rule(self):
        yaml = pytest.importorskip("yaml")
        from packages.hypothesis_validation.adapters.semgrep import (
            _SYNTAX_EXAMPLE,
        )
        doc = yaml.safe_load(_SYNTAX_EXAMPLE)
        assert isinstance(doc, dict) and "rules" in doc
        assert len(doc["rules"]) == 1
        return doc["rules"][0]

    def test_example_uses_only_known_rule_keys(self):
        rule = self._load_rule()
        unknown = set(rule) - self._KNOWN_RULE_KEYS
        assert not unknown, f"non-schema rule keys in the example: {unknown}"

    def test_example_keeps_metavariable_constraint_active(self):
        # The constraint must live inside `patterns:` where semgrep
        # actually applies it.
        rule = self._load_rule()
        patterns = rule.get("patterns")
        assert isinstance(patterns, list)
        assert any(
            isinstance(clause, dict) and "metavariable-regex" in clause
            for clause in patterns
        )


# Temp rule-file cleanup -------------------------------------------------------

class _WriteExplodingTmp:
    """Proxy around a real NamedTemporaryFile whose write() raises —
    models ENOSPC after the delete=False file already exists."""

    def __init__(self, real):
        self._real = real
        self.name = real.name

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)

    def write(self, data):
        raise OSError(28, "No space left on device")

    def close(self):
        self._real.close()


class TestTempRuleFileCleanupOnWriteFailure:
    """delete=False temp rule files must be unlinked even when the
    write itself fails — otherwise ENOSPC/EIO error paths leak
    semgrep_hv_*.yaml / cocci_hv_*.cocci files (and the fd) forever."""

    def _exploding_factory(self, created):
        from tempfile import NamedTemporaryFile as real_ntf

        def factory(*args, **kwargs):
            tmp = _WriteExplodingTmp(real_ntf(*args, **kwargs))
            created.append(Path(tmp.name))
            return tmp

        return factory

    def test_semgrep_unlinks_rule_file_when_write_fails(self, tmp_path):
        created: list[Path] = []
        a = SemgrepAdapter(sandbox=False)
        with patch.object(a, "is_available", return_value=True), \
             patch(
                 "packages.hypothesis_validation.adapters.semgrep."
                 "NamedTemporaryFile",
                 side_effect=self._exploding_factory(created),
             ):
            ev = a.run("rules: []", tmp_path)
        assert not ev.success
        assert created, "temp file was never created"
        assert not created[0].exists(), "failed-write rule file leaked"

    def test_coccinelle_unlinks_rule_file_when_write_fails(self, tmp_path):
        created: list[Path] = []
        a = CoccinelleAdapter(sandbox=False)
        with patch.object(a, "is_available", return_value=True), \
             patch(
                 "packages.hypothesis_validation.adapters.coccinelle."
                 "NamedTemporaryFile",
                 side_effect=self._exploding_factory(created),
             ):
            ev = a.run("@x@\nexpression E;\n@@\n* foo(E);\n", tmp_path)
        assert not ev.success
        assert created, "temp file was never created"
        assert not created[0].exists(), "failed-write rule file leaked"
