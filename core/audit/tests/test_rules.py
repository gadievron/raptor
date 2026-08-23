"""Tests for core.audit.rules — checker synthesis rule management."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.audit.rules import (
    save_rule,
    list_rules,
    get_rule,
    _load_manifest,
)


SAMPLE_SEMGREP_RULE = """\
rules:
  - id: unchecked-return-as-index
    pattern: |
      $IDX = $FUNC(...);
      ...
      $ARR[$IDX]
    message: "Return value used as array index without check"
    languages: [c]
    severity: WARNING
"""

SAMPLE_COCCI_RULE = """\
@@
expression E, arr;
identifier func;
@@
  E = func(...);
* arr[E]
"""


class TestSaveRule:
    def test_saves_semgrep(self, tmp_path: Path):
        path = save_rule(
            out_dir=tmp_path,
            rule_id="unchecked-return",
            tool="semgrep",
            content=SAMPLE_SEMGREP_RULE,
            description="Unchecked return used as array index",
            origin_file="src/handler.c",
            origin_function="parse_request",
            cwe="CWE-252",
        )
        assert path.exists()
        assert path.suffix == ".yaml"
        assert SAMPLE_SEMGREP_RULE in path.read_text()

    def test_saves_coccinelle(self, tmp_path: Path):
        path = save_rule(
            out_dir=tmp_path,
            rule_id="unchecked-index-cocci",
            tool="coccinelle",
            content=SAMPLE_COCCI_RULE,
            description="Unchecked return as index (Coccinelle)",
        )
        assert path.exists()
        assert path.suffix == ".cocci"

    def test_updates_manifest(self, tmp_path: Path):
        save_rule(
            out_dir=tmp_path,
            rule_id="test-rule",
            tool="semgrep",
            content="rules: []",
            description="test",
        )
        manifest = _load_manifest(tmp_path)
        assert "test-rule" in manifest
        assert manifest["test-rule"]["tool"] == "semgrep"

    def test_dedup_overwrites(self, tmp_path: Path):
        save_rule(
            out_dir=tmp_path,
            rule_id="dupe",
            tool="semgrep",
            content="version 1",
            description="first",
        )
        save_rule(
            out_dir=tmp_path,
            rule_id="dupe",
            tool="semgrep",
            content="version 2",
            description="second",
        )
        manifest = _load_manifest(tmp_path)
        assert manifest["dupe"]["description"] == "second"
        rule_path = tmp_path / "rules" / "dupe.yaml"
        assert "version 2" in rule_path.read_text()


class TestListRules:
    def test_empty(self, tmp_path: Path):
        rules = list_rules(tmp_path)
        assert rules == []

    def test_lists_saved(self, tmp_path: Path):
        save_rule(
            out_dir=tmp_path,
            rule_id="rule-a",
            tool="semgrep",
            content="rules: []",
            description="Rule A",
            cwe="CWE-78",
        )
        save_rule(
            out_dir=tmp_path,
            rule_id="rule-b",
            tool="coccinelle",
            content="@@\n@@\n",
            description="Rule B",
        )
        rules = list_rules(tmp_path)
        assert len(rules) == 2
        ids = {r["rule_id"] for r in rules}
        assert ids == {"rule-a", "rule-b"}

    def test_marks_missing_files(self, tmp_path: Path):
        save_rule(
            out_dir=tmp_path,
            rule_id="phantom",
            tool="semgrep",
            content="rules: []",
            description="will be deleted",
        )
        rule_path = tmp_path / "rules" / "phantom.yaml"
        rule_path.unlink()

        rules = list_rules(tmp_path)
        phantom = next(r for r in rules if r["rule_id"] == "phantom")
        assert phantom["exists"] is False


class TestGetRule:
    def test_gets_with_content(self, tmp_path: Path):
        save_rule(
            out_dir=tmp_path,
            rule_id="my-rule",
            tool="semgrep",
            content=SAMPLE_SEMGREP_RULE,
            description="test",
        )
        result = get_rule(tmp_path, "my-rule")
        assert result is not None
        assert result["rule_id"] == "my-rule"
        assert "unchecked-return-as-index" in result["content"]

    def test_missing(self, tmp_path: Path):
        result = get_rule(tmp_path, "nonexistent")
        assert result is None


class TestRunRuleSweep:
    """run_rule_sweep against the REAL result models: SemgrepResult
    holds SemgrepFinding dataclasses, SpatchResult holds ``matches``
    (not ``findings``) — the old code assumed dicts / a ``findings``
    attribute and broke on both engines."""

    @staticmethod
    def _install(monkeypatch, module_name, run_rule):
        import sys
        import types

        fake_mod = types.ModuleType(module_name)
        fake_mod.run_rule = run_rule
        fake_mod.is_available = lambda: True
        monkeypatch.setitem(sys.modules, module_name, fake_mod)

    def test_semgrep_rule_sweep_matches(self, monkeypatch, tmp_path: Path):
        from packages.semgrep.models import SemgrepFinding, SemgrepResult
        from core.audit.rules import run_rule_sweep

        save_rule(
            out_dir=tmp_path, rule_id="sg-rule", tool="semgrep",
            content="rules: []", description="test",
        )

        def fake_run_rule(target, config, timeout=300):
            return SemgrepResult(
                findings=[
                    SemgrepFinding(
                        file="src/a.c", line=12,
                        rule_id="sg-rule", message="hit",
                    ),
                ],
            )

        self._install(monkeypatch, "packages.semgrep.runner", fake_run_rule)

        out = run_rule_sweep(
            out_dir=tmp_path, rule_id="sg-rule", target_path=tmp_path,
        )
        assert "error" not in out
        assert out["tool"] == "semgrep"
        assert out["match_count"] == 1
        assert out["matches"][0]["file"] == "src/a.c"
        assert out["matches"][0]["line"] == 12
        assert out["matches"][0]["message"] == "hit"
        assert out["errors"] == []

    def test_coccinelle_rule_sweep_matches(self, monkeypatch, tmp_path: Path):
        from packages.coccinelle.models import SpatchMatch, SpatchResult
        from core.audit.rules import run_rule_sweep

        save_rule(
            out_dir=tmp_path, rule_id="cocci-rule", tool="coccinelle",
            content="@@\n@@\n", description="test",
        )

        def fake_run_rule(target, config, timeout=300):
            return SpatchResult(
                rule="cocci-rule",
                matches=[SpatchMatch(file="src/b.c", line=7)],
            )

        self._install(
            monkeypatch, "packages.coccinelle.runner", fake_run_rule,
        )

        out = run_rule_sweep(
            out_dir=tmp_path, rule_id="cocci-rule", target_path=tmp_path,
        )
        assert "error" not in out
        assert out["tool"] == "coccinelle"
        assert out["match_count"] == 1
        assert out["matches"][0]["file"] == "src/b.c"
        assert out["matches"][0]["line"] == 7
        assert out["errors"] == []

    def test_coccinelle_errors_surfaced(self, monkeypatch, tmp_path: Path):
        from packages.coccinelle.models import SpatchResult
        from core.audit.rules import run_rule_sweep

        save_rule(
            out_dir=tmp_path, rule_id="cocci-err", tool="coccinelle",
            content="@@\n@@\n", description="test",
        )

        def fake_run_rule(target, config, timeout=300):
            return SpatchResult(
                rule="cocci-err", returncode=-1,
                errors=["spatch timed out after 300s"],
            )

        self._install(
            monkeypatch, "packages.coccinelle.runner", fake_run_rule,
        )

        out = run_rule_sweep(
            out_dir=tmp_path, rule_id="cocci-err", target_path=tmp_path,
        )
        assert out["match_count"] == 0
        assert out["errors"] == ["spatch timed out after 300s"]


class TestAutoSynthesizeRules:
    """Verify _auto_synthesize_rules delegates to packages.checker_synthesis."""

    def test_synthesises_when_two_findings_share_cwe(self, tmp_path: Path):
        from packages.checker_synthesis import (
            CheckerSynthesisResult,
            Match,
            SynthesisedRule,
        )
        from core.audit.orchestrator import (
            OrchestratorConfig, OrchestratorResult, ReviewOutcome,
            _auto_synthesize_rules,
        )

        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
        )
        result = OrchestratorResult()
        result.outcomes = [
            ReviewOutcome(
                file="a.c", function="f1", status="finding", body="sqli",
                hypothesis="If user input has a single quote, sql injection occurs",
                review_result={"cwe": "CWE-89", "cwe_class": "CWE-89"},
            ),
            ReviewOutcome(
                file="b.c", function="f2", status="finding", body="sqli",
                hypothesis="If user input has a single quote, sql injection occurs",
                review_result={"cwe": "CWE-89", "cwe_class": "CWE-89"},
            ),
        ]

        calls = []

        def _fake_refinement(seed, **kw):
            calls.append(seed)
            return CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="synth.sqli.0", body="r",
                ),
                matches=[Match(file="c.c", line=5)],
                positive_control=True,
            )

        def _fake_llm_callable(_config):
            class _FakeClient:
                total_cost = 0.0
            return lambda p, s, sp: {"rule": "r"}, _FakeClient()

        with patch(
            "core.audit.checker_synthesis._build_llm_callable",
            side_effect=_fake_llm_callable,
        ), patch(
            "packages.checker_synthesis.synthesise_with_refinement",
            side_effect=_fake_refinement,
        ):
            _auto_synthesize_rules(result, config)

        assert len(calls) == 1
        assert calls[0].cwe == "CWE-89"

    def test_skips_when_fewer_than_two_findings(self, tmp_path: Path):
        from core.audit.orchestrator import (
            OrchestratorConfig, OrchestratorResult, ReviewOutcome,
            _auto_synthesize_rules,
        )

        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        result = OrchestratorResult()
        result.outcomes = [
            ReviewOutcome(
                file="a.c", function="f1", status="finding", body="one",
                review_result={"cwe": "CWE-89"},
            ),
        ]

        _auto_synthesize_rules(result, config)
        assert list_rules(tmp_path) == []
