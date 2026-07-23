"""Tests for ``packages.llm_analysis.checker_followup``.

Stubbed LLM + stubbed checker_synthesis so tests don't need an LLM
provider or scanner binaries. The point is to verify the wiring:
seed-from-vuln, function-name resolution, checker-matches.jsonl
emission, triage-aware filtering, and best-effort exception handling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


from packages.llm_analysis.checker_followup import (
    CHECKER_MATCHES_FILE,
    _llm_callable_from_client,
    _resolve_match_function,
    _seed_from_vuln,
    emit_variant_matches_for_finding,
)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


@dataclass
class StubVuln:
    file_path: str = "src/auth.py"
    start_line: int = 10
    end_line: int = 20
    rule_id: str = "py/sql-injection"
    cwe_id: str = "CWE-89"
    tool: str = "codeql"
    message: str = "tainted query"
    full_code: str = "def login(req):\n    return cursor.execute(...)"
    metadata: Optional[Dict[str, Any]] = None
    analysis: Optional[Dict[str, Any]] = None


class StubLLMClient:
    def __init__(self, responses=None):
        self._responses = list(responses or [])

    def generate_structured(self, *, prompt, schema, system_prompt, task_type):
        if not self._responses:
            return None, None
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item, None


class _NoLLMClient:
    pass


def _checklist(file_path="src/v.py", name="variant_fn",
               line_start=1, line_end=10):
    return {
        "files": [
            {
                "path": file_path,
                "items": [
                    {
                        "name": name,
                        "line_start": line_start,
                        "line_end": line_end,
                    }
                ],
            }
        ]
    }


def _load_matches(out_dir: Path) -> list[dict]:
    path = out_dir / CHECKER_MATCHES_FILE
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class TestSeedFromVuln:
    def test_minimal_vuln_succeeds(self):
        v = StubVuln(metadata={"name": "login"})
        seed = _seed_from_vuln(v)
        assert seed is not None
        assert seed.file == "src/auth.py"
        assert seed.function == "login"
        assert seed.line_start == 10
        assert seed.line_end == 20
        assert seed.cwe == "CWE-89"

    def test_no_function_name_returns_none(self):
        v = StubVuln(metadata={})
        assert _seed_from_vuln(v) is None

    def test_no_file_path_returns_none(self):
        v = StubVuln(file_path="", metadata={"name": "x"})
        assert _seed_from_vuln(v) is None

    def test_no_line_returns_none(self):
        v = StubVuln(start_line=None, metadata={"name": "x"})  # type: ignore
        assert _seed_from_vuln(v) is None

    def test_uses_analysis_reasoning_when_present(self):
        v = StubVuln(
            metadata={"name": "login"},
            analysis={"reasoning": "rich LLM reasoning here"},
        )
        seed = _seed_from_vuln(v)
        assert "rich LLM reasoning" in seed.reasoning

    def test_falls_back_to_message_when_no_reasoning(self):
        v = StubVuln(metadata={"name": "login"}, message="scanner msg")
        seed = _seed_from_vuln(v)
        assert "scanner msg" in seed.reasoning

    def test_absolute_path_normalised_to_relative(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        v = StubVuln(
            file_path=str(repo / "src" / "auth.py"),
            metadata={"name": "login"},
        )
        seed = _seed_from_vuln(v, repo_root=repo)
        assert seed is not None
        assert seed.file == "src/auth.py"

    def test_absolute_path_outside_repo_returns_none(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        v = StubVuln(
            file_path="/elsewhere/auth.py",
            metadata={"name": "login"},
        )
        assert _seed_from_vuln(v, repo_root=repo) is None


class TestLLMCallableFromClient:
    def test_returns_callable_for_real_client(self):
        c = StubLLMClient(responses=[{"rule_body": "...", "rationale": "x"}])
        callable = _llm_callable_from_client(c)
        assert callable is not None
        out = callable("p", {}, "s")
        assert out == {"rule_body": "...", "rationale": "x"}

    def test_returns_none_for_client_without_generate_structured(self):
        c = _NoLLMClient()
        assert _llm_callable_from_client(c) is None

    def test_swallows_llm_exception(self):
        c = StubLLMClient(responses=[RuntimeError("transport error")])
        callable = _llm_callable_from_client(c)
        assert callable("p", {}, "s") is None


class TestResolveMatchFunction:
    def test_finds_function(self, tmp_path):
        from packages.checker_synthesis import Match
        m = Match(file="src/v.py", line=5)
        ck = _checklist()
        assert _resolve_match_function(m, ck, tmp_path) == "variant_fn"

    def test_no_checklist_returns_none(self, tmp_path):
        from packages.checker_synthesis import Match
        m = Match(file="src/v.py", line=5)
        assert _resolve_match_function(m, None, tmp_path) is None

    def test_empty_file_returns_none(self, tmp_path):
        from packages.checker_synthesis import Match
        m = Match(file="", line=5)
        assert _resolve_match_function(m, _checklist(), tmp_path) is None

    def test_zero_line_returns_none(self, tmp_path):
        from packages.checker_synthesis import Match
        m = Match(file="src/v.py", line=0)
        assert _resolve_match_function(m, _checklist(), tmp_path) is None


# ---------------------------------------------------------------------------
# emit_variant_matches_for_finding — full pipeline
# ---------------------------------------------------------------------------


def _patch_synth(monkeypatch, *, rule, matches, triage=()):
    """Replace ``synthesise_and_run`` and ``synthesise_with_refinement``
    with a fixture that returns a canned ``CheckerSynthesisResult``."""
    from packages.checker_synthesis import CheckerSynthesisResult

    def _fake(*args, **kwargs):
        return CheckerSynthesisResult(
            seed=kwargs.get("seed") or args[0],
            rule=rule,
            matches=list(matches),
            triage=list(triage),
            positive_control=True,
        )

    import packages.checker_synthesis as cs_mod
    monkeypatch.setattr(cs_mod, "synthesise_and_run", _fake)
    monkeypatch.setattr(cs_mod, "synthesise_with_refinement", _fake)


class TestEmitVariantMatches:
    def test_emits_one_match_record(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep", rule_id="auth.0", body="r",
            rationale="catches f-string SQL into execute",
        )
        matches = [Match(file="src/v.py", line=5)]
        ck = _checklist()
        _patch_synth(monkeypatch, rule=rule, matches=matches)

        n = emit_variant_matches_for_finding(
            v,
            out_dir=tmp_path,
            checklist=ck,
            repo_root=tmp_path,
            llm_client=StubLLMClient(),
        )
        assert n == 1

        records = _load_matches(tmp_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["file"] == "src/v.py"
        assert rec["line"] == 5
        assert rec["function"] == "variant_fn"
        assert rec["seed_file"] == "src/auth.py"
        assert rec["seed_function"] == "login"
        assert rec["rule_id"] == "auth.0"
        assert rec["engine"] == "semgrep"
        assert rec["cwe"] == "CWE-89"

    def test_triage_filters_false_positives(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import (
            Match, MatchTriage, SynthesisedRule,
        )

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep", rule_id="auth.0", body="r",
        )
        m_variant = Match(file="src/v.py", line=5)
        m_fp = Match(file="src/v.py", line=15)
        matches = [m_variant, m_fp]
        triage = [
            MatchTriage(match=m_variant, status="variant",
                        reasoning="same shape"),
            MatchTriage(match=m_fp, status="false_positive",
                        reasoning="different sink"),
        ]
        ck = {
            "files": [
                {
                    "path": "src/v.py",
                    "items": [
                        {"name": "variant_fn",
                         "line_start": 1, "line_end": 10},
                        {"name": "safe_fn",
                         "line_start": 12, "line_end": 20},
                    ],
                }
            ]
        }
        _patch_synth(monkeypatch, rule=rule,
                     matches=matches, triage=triage)

        n = emit_variant_matches_for_finding(
            v,
            out_dir=tmp_path,
            checklist=ck,
            repo_root=tmp_path,
            llm_client=StubLLMClient(),
        )
        assert n == 1
        records = _load_matches(tmp_path)
        assert len(records) == 1
        assert records[0]["function"] == "variant_fn"

    def test_triage_uncertain_kept(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import (
            Match, MatchTriage, SynthesisedRule,
        )
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(file="src/v.py", line=5)
        triage = [MatchTriage(match=m, status="uncertain", reasoning="?")]
        _patch_synth(monkeypatch, rule=rule,
                     matches=[m], triage=triage)
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1

    def test_triage_skipped_dropped(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import (
            Match, MatchTriage, SynthesisedRule,
        )
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(file="src/v.py", line=5)
        triage = [MatchTriage(match=m, status="skipped", reasoning="budget")]
        _patch_synth(monkeypatch, rule=rule,
                     matches=[m], triage=triage)
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_seed(self, tmp_path):
        v = StubVuln(metadata={})
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_llm(self, tmp_path):
        v = StubVuln(metadata={"name": "login"})
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=_NoLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_rule(self, tmp_path, monkeypatch):
        v = StubVuln(metadata={"name": "login"})
        _patch_synth(monkeypatch, rule=None, matches=[])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_matches(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        _patch_synth(monkeypatch, rule=rule, matches=[])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_match_without_inventory_still_recorded(
        self, tmp_path, monkeypatch,
    ):
        """Match in a file not in the checklist — function is None
        but the match is still recorded in JSONL (function is optional
        context, not a gate for JSONL unlike annotations)."""
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(file="src/not_in_inventory.py", line=5)
        _patch_synth(monkeypatch, rule=rule, matches=[m])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        records = _load_matches(tmp_path)
        assert records[0]["function"] is None

    def test_synthesis_exception_swallowed(self, tmp_path, monkeypatch):
        v = StubVuln(metadata={"name": "login"})
        import packages.checker_synthesis as cs_mod

        def boom(*a, **kw):
            raise RuntimeError("simulated synth failure")

        monkeypatch.setattr(cs_mod, "synthesise_and_run", boom)
        monkeypatch.setattr(cs_mod, "synthesise_with_refinement", boom)
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_refine_true_calls_refinement(self, tmp_path, monkeypatch):
        """refine=True must route to synthesise_with_refinement."""
        from packages.checker_synthesis import (
            CheckerSynthesisResult, SynthesisedRule, Match,
        )
        import packages.checker_synthesis as cs_mod

        called = {"and_run": False, "with_refinement": False}

        def _result(seed):
            return CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="t.0", body="r",
                ),
                matches=[Match(file="src/v.py", line=5)],
                positive_control=True,
            )

        def _track_and_run(*a, **kw):
            called["and_run"] = True
            return _result(kw.get("seed") or a[0])

        def _track_with_refinement(*a, **kw):
            called["with_refinement"] = True
            return _result(kw.get("seed") or a[0])

        monkeypatch.setattr(cs_mod, "synthesise_and_run", _track_and_run)
        monkeypatch.setattr(
            cs_mod, "synthesise_with_refinement", _track_with_refinement,
        )

        v = StubVuln(metadata={"name": "login"})
        emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
            refine=True,
        )
        assert called["with_refinement"], "refine=True did not call refinement"
        assert not called["and_run"], "refine=True should not call single-shot"

    def test_refine_false_calls_single_shot(self, tmp_path, monkeypatch):
        """refine=False must route to synthesise_and_run."""
        from packages.checker_synthesis import (
            CheckerSynthesisResult, SynthesisedRule, Match,
        )
        import packages.checker_synthesis as cs_mod

        called = {"and_run": False, "with_refinement": False}

        def _result(seed):
            return CheckerSynthesisResult(
                seed=seed,
                rule=SynthesisedRule(
                    engine="semgrep", rule_id="t.0", body="r",
                ),
                matches=[Match(file="src/v.py", line=5)],
                positive_control=True,
            )

        def _track_and_run(*a, **kw):
            called["and_run"] = True
            return _result(kw.get("seed") or a[0])

        def _track_with_refinement(*a, **kw):
            called["with_refinement"] = True
            return _result(kw.get("seed") or a[0])

        monkeypatch.setattr(cs_mod, "synthesise_and_run", _track_and_run)
        monkeypatch.setattr(
            cs_mod, "synthesise_with_refinement", _track_with_refinement,
        )

        v = StubVuln(metadata={"name": "login"})
        emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
            refine=False,
        )
        assert called["and_run"], "refine=False did not call single-shot"
        assert not called["with_refinement"], \
            "refine=False should not call refinement"

    def test_output_is_valid_jsonl(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep", rule_id="auth.0", body="r",
            rationale="test rationale",
        )
        matches = [
            Match(file="src/v.py", line=5, snippet="code1"),
            Match(file="src/v.py", line=8, snippet="code2"),
        ]
        ck = _checklist()
        _patch_synth(monkeypatch, rule=rule, matches=matches)
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 2
        path = tmp_path / CHECKER_MATCHES_FILE
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "file" in data
            assert "rule_id" in data
            assert data["rationale"] == "test rationale"


# ---------------------------------------------------------------------------
# Adversarial: hostile inputs in the seed → JSONL pipeline
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_hostile_seed_function_produces_valid_jsonl(
        self, tmp_path, monkeypatch,
    ):
        """A vuln whose function name contains special chars must not
        corrupt the JSONL line structure. JSON escaping handles this
        natively (unlike the old annotation metadata format)."""
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login-->evil"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        _patch_synth(monkeypatch, rule=rule,
                     matches=[Match(file="src/v.py", line=5)])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        path = tmp_path / CHECKER_MATCHES_FILE
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["seed_function"] == "login-->evil"

    def test_hostile_rule_id_produces_valid_jsonl(self, tmp_path, monkeypatch):
        """Control characters in rule_id must not break JSONL line
        structure — json.dumps escapes them during serialisation."""
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep",
            rule_id="hostile\nrule\x00id",
            body="r",
        )
        _patch_synth(monkeypatch, rule=rule,
                     matches=[Match(file="src/v.py", line=5)])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        path = tmp_path / CHECKER_MATCHES_FILE
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["rule_id"] == "hostile\nrule\x00id"
