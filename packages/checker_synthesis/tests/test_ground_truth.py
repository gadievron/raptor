"""Ground-truth fixture control for external synthesis seeds.

External seeds (cvefix fix-commit pairs) carry known-vulnerable /
known-fixed text instead of a file in the target repo. These tests pin
the ``ground_truth_fixtures`` path through ``synthesise_and_run``: the
positive control runs against the vulnerable fixture, the fixed form
must stay silent, and the codebase sweep still runs over the target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.checker_synthesis import (
    Match,
    SeedBug,
    synthesise_and_run,
)
from packages.checker_synthesis import synthesise as synth_mod

VULN_TEXT = "strcpy(dst, user_input); /* VULN */"
FIXED_TEXT = "strlcpy(dst, user_input, sizeof dst); /* FIXED */"


def _seed() -> SeedBug:
    return SeedBug(
        file="src/copy.c",  # NOT present in the target repo
        function="",
        line_start=1,
        line_end=1,
        cwe="CWE-120",
        reasoning="CVE fix removed an unbounded strcpy",
        snippet=VULN_TEXT,
        provenance="cvefix:cve-2024-0001",
    )


def _stub_llm(responses):
    queue = list(responses)

    def llm(prompt, schema, system_prompt):
        if not queue:
            raise AssertionError("stub LLM out of responses")
        return queue.pop(0)

    return llm


def _content_engine(monkeypatch, *, matcher, repo_matches):
    """Fake _run_engine that decides per target-file content.

    Fixture targets (temp files) are matched via ``matcher(text)``;
    directory targets (the codebase sweep) return ``repo_matches``.
    """
    calls = {"fixture_texts": [], "sweeps": 0}

    def fake_run(rule, rule_path, target):
        target = Path(target)
        if target.is_dir():
            calls["sweeps"] += 1
            return list(repo_matches), []
        text = target.read_text(encoding="utf-8")
        calls["fixture_texts"].append(text)
        if matcher(text):
            return [Match(file=str(target), line=1, snippet=text[:50])], []
        return [], []

    monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
    return calls


class TestGroundTruthControl:
    def test_unit_positive_and_negative(self, tmp_path, monkeypatch):
        _content_engine(
            monkeypatch, matcher=lambda t: "VULN" in t, repo_matches=[],
        )
        from packages.checker_synthesis.models import SynthesisedRule

        rule_path = tmp_path / "rule.yml"
        rule_path.write_text("rules: []")
        pos_ok, neg_ok, errors = synth_mod._ground_truth_control(
            _seed(), rule_path, "semgrep", VULN_TEXT, FIXED_TEXT,
        )
        assert pos_ok is True
        assert neg_ok is True
        assert not [e for e in errors if "ground-truth" in e]
        assert isinstance(
            SynthesisedRule(engine="semgrep", rule_id="x", body=""),
            SynthesisedRule,
        )

    def test_unit_negative_match_fails(self, tmp_path, monkeypatch):
        _content_engine(
            monkeypatch, matcher=lambda t: True, repo_matches=[],
        )
        rule_path = tmp_path / "rule.yml"
        rule_path.write_text("rules: []")
        pos_ok, neg_ok, errors = synth_mod._ground_truth_control(
            _seed(), rule_path, "semgrep", VULN_TEXT, FIXED_TEXT,
        )
        assert pos_ok is True
        assert neg_ok is False
        assert any("FIXED fixture" in e for e in errors)

    def test_unit_negative_engine_error_fails_closed(
        self, tmp_path, monkeypatch,
    ):
        """Engine error on the FIXED fixture returns zero matches —
        silence proves nothing and must NOT read as a verified
        negative (it used to cascade into rule_tier='library')."""
        def fake_run(rule, rule_path, target):
            text = Path(target).read_text(encoding="utf-8")
            if "VULN" in text:
                return [Match(file=str(target), line=1)], []
            return [], ["spatch: parse error in fixture"]

        monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
        rule_path = tmp_path / "rule.yml"
        rule_path.write_text("rules: []")
        pos_ok, neg_ok, errors = synth_mod._ground_truth_control(
            _seed(), rule_path, "semgrep", VULN_TEXT, FIXED_TEXT,
        )
        assert pos_ok is True
        assert neg_ok is False
        assert any("not verifiable" in e for e in errors)

    def test_unit_positive_miss_fails(self, tmp_path, monkeypatch):
        _content_engine(
            monkeypatch, matcher=lambda t: False, repo_matches=[],
        )
        rule_path = tmp_path / "rule.yml"
        rule_path.write_text("rules: []")
        pos_ok, _neg_ok, errors = synth_mod._ground_truth_control(
            _seed(), rule_path, "semgrep", VULN_TEXT, FIXED_TEXT,
        )
        assert pos_ok is False
        assert any("known-vulnerable" in e for e in errors)


class TestSynthesiseWithGroundTruth:
    def test_external_seed_sweeps_target(self, tmp_path, monkeypatch):
        variant = Match(
            file="src/other.c", line=9, snippet="strcpy(a, b)",
        )
        calls = _content_engine(
            monkeypatch,
            matcher=lambda t: "VULN" in t,
            repo_matches=[variant],
        )
        llm = _stub_llm([
            {"rule_body": "rules:\n  - id: x\n", "rationale": "r"},
        ])
        result = synthesise_and_run(
            _seed(),
            tmp_path,
            tmp_path / "out",
            llm,
            ground_truth_fixtures=(VULN_TEXT, FIXED_TEXT),
        )
        assert result.rule is not None
        assert result.positive_control is True
        assert [m.file for m in result.matches] == ["src/other.c"]
        assert calls["sweeps"] == 1
        # Both ground-truth fixtures were exercised.
        assert any("VULN" in t for t in calls["fixture_texts"])
        assert any("FIXED" in t for t in calls["fixture_texts"])

    def test_negative_match_triggers_retry_with_feedback(
        self, tmp_path, monkeypatch,
    ):
        # First rule matches everything (fails the fixed form); the
        # engine only matches VULN for the second rule.
        state = {"attempt": 0}

        def matcher(text):
            if state["attempt"] == 0:
                return True
            return "VULN" in text

        _content_engine(monkeypatch, matcher=matcher, repo_matches=[])

        prompts = []

        def llm(prompt, schema, system_prompt):
            prompts.append(prompt)
            state["attempt"] = len(prompts) - 1
            return {"rule_body": f"rules:\n  - id: r{len(prompts)}\n",
                    "rationale": "r"}

        result = synthesise_and_run(
            _seed(),
            tmp_path,
            tmp_path / "out",
            llm,
            ground_truth_fixtures=(VULN_TEXT, FIXED_TEXT),
        )
        assert result.rule is not None
        assert len(prompts) == 2
        assert "fixed form" in prompts[1] or "patched" in prompts[1]

    def test_without_ground_truth_positive_control_unchanged(
        self, tmp_path, monkeypatch,
    ):
        # Repo-anchored seed: absent seed file → positive control fails
        # (no ground-truth override).
        _content_engine(
            monkeypatch, matcher=lambda t: True, repo_matches=[],
        )
        llm = _stub_llm([
            {"rule_body": "rules:\n  - id: x\n", "rationale": "r"},
            {"rule_body": "rules:\n  - id: x\n", "rationale": "r"},
        ])
        result = synthesise_and_run(
            _seed(), tmp_path, tmp_path / "out", llm,
        )
        assert result.rule is None
        assert any("seed file not found" in e for e in result.errors)

    def test_ground_truth_negative_earns_library_tier(
        self, tmp_path, monkeypatch,
    ):
        _content_engine(
            monkeypatch,
            matcher=lambda t: "VULN" in t or "bad_fixture" in t,
            repo_matches=[],
        )
        llm = _stub_llm([
            {
                "rule_body": "rules:\n  - id: x\n",
                "rationale": "r",
                "test_positive": "x = bad_fixture()",
                "test_negative": "x = good()",
            },
        ])
        result = synthesise_and_run(
            _seed(),
            tmp_path,
            tmp_path / "out",
            llm,
            ground_truth_fixtures=(VULN_TEXT, FIXED_TEXT),
        )
        assert result.rule is not None
        assert result.dual_control is True
        # Ground-truth negative stands in for the repo-anchored
        # fix-mutant control.
        assert result.fix_mutant_control is True
        assert result.rule_tier == "library"


    def test_negative_engine_error_does_not_earn_library_tier(
        self, tmp_path, monkeypatch,
    ):
        """An engine error while checking the fixed form must fail
        closed: no fix_mutant_control credit, no library tier."""
        def fake_run(rule, rule_path, target):
            target = Path(target)
            if target.is_dir():
                return [], []
            text = target.read_text(encoding="utf-8")
            if "VULN" in text or "bad_fixture" in text:
                return [Match(file=str(target), line=1)], []
            if "FIXED" in text:
                return [], ["spatch: parse error in fixture"]
            return [], []

        monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
        llm = _stub_llm([
            {
                "rule_body": "rules:\n  - id: x\n",
                "rationale": "r",
                "test_positive": "x = bad_fixture()",
                "test_negative": "x = good()",
            },
        ] * 3)
        result = synthesise_and_run(
            _seed(),
            tmp_path,
            tmp_path / "out",
            llm,
            ground_truth_fixtures=(VULN_TEXT, FIXED_TEXT),
        )
        assert result.fix_mutant_control is not True
        assert result.rule_tier != "library"


class TestSeedProvenance:
    def test_seed_provenance_serialised(self):
        from packages.checker_synthesis.models import (
            CheckerSynthesisResult,
        )

        result = CheckerSynthesisResult(seed=_seed())
        assert result.to_dict()["seed"]["provenance"] == (
            "cvefix:cve-2024-0001"
        )

    def test_provenance_defaults_empty(self):
        seed = SeedBug(
            file="a.c", function="f", line_start=1, line_end=1,
            cwe="CWE-120", reasoning="r",
        )
        assert seed.provenance == ""


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
