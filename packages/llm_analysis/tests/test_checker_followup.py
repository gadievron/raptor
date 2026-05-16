"""Tests for ``packages.llm_analysis.checker_followup``.

Stubbed LLM + stubbed checker_synthesis so tests don't need an LLM
provider or scanner binaries. The point is to verify the wiring:
seed-from-vuln, function-name resolution, annotation emission,
triage-aware filtering, and best-effort exception handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.llm_analysis.checker_followup import (
    _build_variant_body,
    _llm_callable_from_client,
    _resolve_match_function,
    _seed_from_vuln,
    emit_variant_annotations_for_finding,
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
    """Minimal stub matching ``LLMClient.generate_structured`` signature."""

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
    """A client that doesn't expose ``generate_structured`` — e.g.
    the prep-only ClaudeCodeProvider."""
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
        # Returns None when the underlying client raises.
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
# emit_variant_annotations_for_finding — full pipeline
# ---------------------------------------------------------------------------


def _patch_synth(monkeypatch, *, rule, matches, triage=()):
    """Replace ``synthesise_and_run`` with a fixture that returns a
    canned ``CheckerSynthesisResult``."""
    from packages.checker_synthesis import (
        CheckerSynthesisResult,
        SynthesisedRule,
    )
    from packages.llm_analysis import checker_followup as mod

    def _fake(*args, **kwargs):
        return CheckerSynthesisResult(
            seed=kwargs.get("seed") or args[0],
            rule=rule,
            matches=list(matches),
            triage=list(triage),
            positive_control=True,
        )

    # synthesise_and_run is imported lazily inside the function.
    # Patch the symbol that the helper imports.
    import packages.checker_synthesis as cs_mod
    monkeypatch.setattr(cs_mod, "synthesise_and_run", _fake)


class TestEmitVariantAnnotations:
    def test_emits_one_annotation_per_match(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import Match, SynthesisedRule
        from core.annotations import iter_all_annotations

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep", rule_id="auth.0", body="r",
            rationale="catches f-string SQL into execute",
        )
        # Variant in another function in another file.
        matches = [Match(file="src/v.py", line=5)]

        # Plant the inventory entry that resolves the match's function.
        ck = _checklist()
        _patch_synth(monkeypatch, rule=rule, matches=matches)

        n = emit_variant_annotations_for_finding(
            v,
            out_dir=tmp_path,
            checklist=ck,
            repo_root=tmp_path,
            llm_client=StubLLMClient(),
        )
        assert n == 1

        anns = list(iter_all_annotations(tmp_path / "annotations"))
        assert len(anns) == 1
        ann = anns[0]
        assert ann.function == "variant_fn"
        assert ann.metadata["status"] == "suspicious"
        assert ann.metadata["source"] == "llm"
        assert ann.metadata["variant_of_function"] == "login"
        assert ann.metadata["variant_of_file"] == "src/auth.py"
        assert ann.metadata["rule_id"] == "auth.0"
        assert ann.metadata["engine"] == "semgrep"
        assert ann.metadata["cwe"] == "CWE-89"
        assert "Candidate variant" in ann.body

    def test_triage_filters_false_positives(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import (
            Match, MatchTriage, SynthesisedRule,
        )
        from core.annotations import iter_all_annotations

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

        n = emit_variant_annotations_for_finding(
            v,
            out_dir=tmp_path,
            checklist=ck,
            repo_root=tmp_path,
            llm_client=StubLLMClient(),
        )
        # variant kept, false_positive dropped.
        assert n == 1
        anns = list(iter_all_annotations(tmp_path / "annotations"))
        assert len(anns) == 1
        assert anns[0].function == "variant_fn"

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
        n = emit_variant_annotations_for_finding(
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
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_seed(self, tmp_path):
        v = StubVuln(metadata={})  # no function name
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_llm(self, tmp_path):
        v = StubVuln(metadata={"name": "login"})
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=_NoLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_rule(self, tmp_path, monkeypatch):
        v = StubVuln(metadata={"name": "login"})
        _patch_synth(monkeypatch, rule=None, matches=[])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_no_matches(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        _patch_synth(monkeypatch, rule=rule, matches=[])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_returns_zero_when_match_has_no_inventory_entry(
        self, tmp_path, monkeypatch,
    ):
        """Match in a file that's not in the checklist — function name
        unresolvable, annotation skipped silently."""
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        # Match in an unrelated file.
        m = Match(file="src/not_in_inventory.py", line=5)
        _patch_synth(monkeypatch, rule=rule, matches=[m])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_synthesis_exception_swallowed(self, tmp_path, monkeypatch):
        v = StubVuln(metadata={"name": "login"})
        import packages.checker_synthesis as cs_mod

        def boom(*a, **kw):
            raise RuntimeError("simulated synth failure")

        monkeypatch.setattr(cs_mod, "synthesise_and_run", boom)
        # Must not raise.
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Adversarial: hostile inputs in the seed → annotation pipeline
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_hostile_seed_function_sanitised_in_metadata(
        self, tmp_path, monkeypatch,
    ):
        """A vuln whose function name contains HTML-comment delimiters
        would corrupt the on-disk metadata format if not sanitised. The
        sanitiser strips ``-->`` from metadata values."""
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login-->evil"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        _patch_synth(monkeypatch, rule=rule,
                     matches=[Match(file="src/v.py", line=5)])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        from core.annotations import iter_all_annotations
        ann = list(iter_all_annotations(tmp_path / "annotations"))[0]
        # ``-->`` stripped from metadata value.
        assert "-->" not in ann.metadata["variant_of_function"]

    def test_hostile_rule_id_sanitised(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import Match, SynthesisedRule
        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(
            engine="semgrep",
            rule_id="hostile\nrule\x00id",
            body="r",
        )
        _patch_synth(monkeypatch, rule=rule,
                     matches=[Match(file="src/v.py", line=5)])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=_checklist(),
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        from core.annotations import iter_all_annotations
        ann = list(iter_all_annotations(tmp_path / "annotations"))[0]
        assert "\n" not in ann.metadata["rule_id"]
        assert "\x00" not in ann.metadata["rule_id"]


# ---------------------------------------------------------------------------
# Body composition
# ---------------------------------------------------------------------------


class TestBuildVariantBody:
    def test_includes_seed_location(self):
        from packages.checker_synthesis import (
            Match, SeedBug, SynthesisedRule,
        )
        seed = SeedBug(
            file="src/auth.py", function="login",
            line_start=10, line_end=20,
            cwe="CWE-89", reasoning="r",
        )
        rule = SynthesisedRule(
            engine="semgrep", rule_id="auth.0", body="...",
            rationale="rationale here",
        )
        m = Match(file="src/v.py", line=5,
                   snippet="cursor.execute(f'...')")
        body = _build_variant_body(seed, rule, m)
        assert "src/auth.py:10-20" in body
        assert "login" in body
        assert "rationale here" in body
        assert "CWE-89" in body
        assert "auth.0" in body
        assert "cursor.execute" in body

    def test_no_snippet_no_snippet_section(self):
        from packages.checker_synthesis import (
            Match, SeedBug, SynthesisedRule,
        )
        seed = SeedBug(
            file="x", function="f", line_start=1, line_end=2,
            cwe="", reasoning="",
        )
        rule = SynthesisedRule(engine="semgrep", rule_id="r", body="b")
        m = Match(file="src/v.py", line=5)  # no snippet
        body = _build_variant_body(seed, rule, m)
        assert "Match snippet" not in body
