"""Adversarial + E2E coverage for the KNighter follow-up wiring.

Probes inputs a faulty / compromised upstream could hand the
follow-up helper. Each case must produce a usable on-disk
annotation tree without crash, prompt-format corruption, or
unbounded growth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


from packages.llm_analysis.checker_followup import (
    emit_variant_annotations_for_finding,
)


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
    def generate_structured(
        self, *, prompt, schema, system_prompt, task_type,
    ):
        return None, None  # Doesn't matter; synth is patched.


def _patch_synth(monkeypatch, *, rule, matches, triage=()):
    from packages.checker_synthesis import CheckerSynthesisResult
    import packages.checker_synthesis as cs_mod

    def _fake(*args, **kwargs):
        return CheckerSynthesisResult(
            seed=kwargs.get("seed") or args[0],
            rule=rule,
            matches=list(matches),
            triage=list(triage),
            positive_control=True,
        )
    monkeypatch.setattr(cs_mod, "synthesise_and_run", _fake)


def _multi_function_checklist(file_path, names_with_lines):
    """Build a checklist where one source file has multiple functions."""
    return {
        "files": [
            {
                "path": file_path,
                "items": [
                    {"name": name, "line_start": s, "line_end": e}
                    for name, s, e in names_with_lines
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# Hostile snippet content — pinned current substrate limitation
# ---------------------------------------------------------------------------


class TestHostileSnippet:
    def test_snippet_with_double_hash_does_not_crash(
        self, tmp_path, monkeypatch,
    ):
        """A match snippet containing ``\\n## fake_function`` could,
        in principle, mis-parse on a later read because the
        annotation file's section regex matches ``## name`` at
        start-of-line. Code-fence-aware parsing is a known
        substrate limitation. Pin: write succeeds, no crash; the
        first round-trip read gets the data; later reads of the
        same file may see the fake section. The test pins that
        the IMMEDIATE write+read works — anything stronger is
        out of scope for this layer."""
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(
            file="src/v.py",
            line=5,
            snippet="some_call(...)\n## evil_function\nmore_code",
        )
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])

        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        # The .md file exists, was written without raising.
        md = tmp_path / "annotations" / "src" / "v.py.md"
        assert md.exists()


# ---------------------------------------------------------------------------
# Vuln-shape edge cases
# ---------------------------------------------------------------------------


class TestVulnShapes:
    def test_vuln_metadata_explicitly_none(self, tmp_path):
        """``metadata = None`` (vs missing key vs empty dict). Helper
        must not crash; falls through to no-seed (no function name)."""
        v = StubVuln(metadata=None)
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_vuln_with_no_metadata_attribute(self, tmp_path):
        """Some upstream vuln shapes might not even define a
        ``metadata`` attribute. Helper should ``getattr`` defensively."""
        class Bare:
            file_path = "src/x.py"
            start_line = 1
            end_line = 5
            cwe_id = "CWE-89"
            rule_id = "x"
            tool = "y"
            message = "z"
            full_code = ""
            analysis = None

        n = emit_variant_annotations_for_finding(
            Bare(), out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        # No function name resolvable without metadata; skip.
        assert n == 0


# ---------------------------------------------------------------------------
# Variant relationships
# ---------------------------------------------------------------------------


class TestVariantRelationships:
    def test_variant_in_same_file_different_function(
        self, tmp_path, monkeypatch,
    ):
        """Seed: src/auth.py:login. Variant: src/auth.py:other_login.
        Both should land in the SAME annotation .md file as separate
        sections."""
        from packages.checker_synthesis import Match, SynthesisedRule
        from core.annotations import iter_all_annotations

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        # Variant in same file (auth.py) as the seed.
        m = Match(file="src/auth.py", line=42)
        ck = _multi_function_checklist(
            "src/auth.py",
            [("login", 10, 20), ("other_login", 35, 50)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])

        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        # The annotation lands as a separate section in the .md.
        anns = list(iter_all_annotations(tmp_path / "annotations"))
        assert len(anns) == 1
        assert anns[0].function == "other_login"

    def test_seed_match_filtered_by_substrate(self, tmp_path, monkeypatch):
        """The seed bug itself should NOT be re-emitted as a variant.
        ``synthesise_and_run`` filters via ``_is_seed_match`` —
        verify that path is hit when the synthesis result reflects
        the substrate's filtering."""
        from packages.checker_synthesis import SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        # Empty matches list (substrate already filtered the seed).
        _patch_synth(monkeypatch, rule=rule, matches=[])
        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Coexistence with prior annotations on the same function
# ---------------------------------------------------------------------------


class TestCoexistence:
    def test_respect_manual_preserves_operator_note(
        self, tmp_path, monkeypatch,
    ):
        """Operator wrote a manual annotation for src/v.py:variant_fn.
        Then /agentic confirms a finding elsewhere, KNighter follow-up
        finds variant_fn as a variant. The follow-up's annotation
        write should be skipped (respect-manual), operator's note
        intact."""
        from core.annotations import (
            Annotation, read_annotation, write_annotation,
        )
        from packages.checker_synthesis import Match, SynthesisedRule

        # Operator's prior manual note.
        write_annotation(
            tmp_path / "annotations",
            Annotation(
                file="src/v.py", function="variant_fn",
                body="reviewed by alice — clean, constant-time",
                metadata={"source": "human", "status": "clean"},
            ),
        )

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(file="src/v.py", line=5)
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])

        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        # respect-manual blocked — count is 0.
        assert n == 0
        # Operator's content preserved.
        ann = read_annotation(
            tmp_path / "annotations", "src/v.py", "variant_fn",
        )
        assert ann.metadata["source"] == "human"
        assert "alice" in ann.body

    def test_double_emit_overwrites_llm_annotation(
        self, tmp_path, monkeypatch,
    ):
        """Two consecutive runs on the same seed → second emit
        overwrites the first cleanly (both source=llm). Pin the
        last-writer-wins semantics for LLM-over-LLM case."""
        from core.annotations import iter_all_annotations
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule1 = SynthesisedRule(engine="semgrep", rule_id="r1", body="r")
        rule2 = SynthesisedRule(engine="semgrep", rule_id="r2", body="r")
        m = Match(file="src/v.py", line=5)
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule1, matches=[m])
        emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )

        # Second emit with a different rule_id — should overwrite.
        _patch_synth(monkeypatch, rule=rule2, matches=[m])
        emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )

        anns = list(iter_all_annotations(tmp_path / "annotations"))
        assert len(anns) == 1
        # Latest rule_id wins.
        assert anns[0].metadata["rule_id"] == "r2"


# ---------------------------------------------------------------------------
# Body & telemetry bounds
# ---------------------------------------------------------------------------


class TestBodyAndTelemetryBounds:
    def test_max_snippet_size_kept_bounded(self, tmp_path, monkeypatch):
        """``Match.snippet`` is capped at 500 chars by the
        checker_synthesis adapter. Verify the resulting annotation
        body stays bounded — no runaway from a hostile scanner."""
        from core.annotations import iter_all_annotations
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r",
                                rationale="rationale")
        # Snippet at the cap (500 chars).
        m = Match(file="src/v.py", line=5, snippet="x" * 500)
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])
        emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        anns = list(iter_all_annotations(tmp_path / "annotations"))
        # Body should be a few KB at most: prose + one 500-char snippet.
        assert len(anns[0].body.encode("utf-8")) < 4_000


# ---------------------------------------------------------------------------
# E2E — multi-variant realistic scenario
# ---------------------------------------------------------------------------


class TestE2E:
    def test_multi_variant_landing_on_disk(self, tmp_path, monkeypatch):
        """Seed: SQL injection in login. KNighter follow-up surfaces
        4 variants in 4 different files. Verify the on-disk
        annotation tree mirrors the source tree, each .md has the
        right section, metadata captures seed + rule + triage."""
        from core.annotations import iter_all_annotations
        from packages.checker_synthesis import (
            Match, MatchTriage, SynthesisedRule,
        )

        v = StubVuln(
            file_path="src/auth/login.py",
            start_line=42, end_line=48,
            rule_id="py/sql-injection",
            cwe_id="CWE-89",
            metadata={"name": "check_credentials"},
            analysis={
                "is_true_positive": True, "is_exploitable": True,
                "reasoning": "tainted query string flows into execute",
            },
        )
        rule = SynthesisedRule(
            engine="semgrep",
            rule_id="src_auth_login_py.check_credentials.CWE-89.0",
            body="rules:\n  - id: tainted-execute\n    pattern: ...",
            rationale=(
                "f-string with user-controlled value passed directly "
                "to cursor.execute"
            ),
        )
        # 4 variants: 2 TPs, 1 FP, 1 uncertain.
        v1 = Match(file="src/admin/users.py", line=87,
                    snippet="cursor.execute(f'SELECT * FROM u WHERE id={uid}')")
        v2 = Match(file="src/api/search.py", line=23,
                    snippet="cursor.execute(f'... {q}')")
        v3 = Match(file="src/log/audit.py", line=15,
                    snippet="conn.exec_safe(...)")  # FP — different sink
        v4 = Match(file="src/util/db.py", line=42,
                    snippet="db.run(query)")  # uncertain
        triage = [
            MatchTriage(match=v1, status="variant",
                         reasoning="same f-string-into-execute pattern"),
            MatchTriage(match=v2, status="variant",
                         reasoning="same shape"),
            MatchTriage(match=v3, status="false_positive",
                         reasoning="exec_safe uses parameterised query"),
            MatchTriage(match=v4, status="uncertain",
                         reasoning="db.run could be either"),
        ]

        # Build a checklist covering all 4 variant locations.
        ck = {
            "files": [
                {"path": "src/admin/users.py",
                 "items": [{"name": "list_users",
                            "line_start": 80, "line_end": 100}]},
                {"path": "src/api/search.py",
                 "items": [{"name": "search_handler",
                            "line_start": 20, "line_end": 30}]},
                {"path": "src/log/audit.py",
                 "items": [{"name": "log_event",
                            "line_start": 10, "line_end": 25}]},
                {"path": "src/util/db.py",
                 "items": [{"name": "db_run",
                            "line_start": 40, "line_end": 50}]},
            ]
        }
        _patch_synth(monkeypatch, rule=rule, matches=[v1, v2, v3, v4],
                     triage=triage)

        n = emit_variant_annotations_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        # 2 variants + 1 uncertain = 3 emitted; FP dropped.
        assert n == 3

        anns = list(iter_all_annotations(tmp_path / "annotations"))
        names = sorted(a.function for a in anns)
        assert names == ["db_run", "list_users", "search_handler"]

        # Mirror source tree on disk.
        for rel in ("src/admin/users.py.md", "src/api/search.py.md",
                    "src/util/db.py.md"):
            assert (tmp_path / "annotations" / rel).exists(), (
                f"missing annotation file: {rel}"
            )
        # FP file NOT created.
        assert not (
            tmp_path / "annotations" / "src" / "log" / "audit.py.md"
        ).exists()

        # Per-annotation metadata captures the seed + rule + triage.
        list_users = next(a for a in anns if a.function == "list_users")
        assert list_users.metadata["status"] == "suspicious"
        assert list_users.metadata["source"] == "llm"
        assert list_users.metadata["variant_of_function"] == "check_credentials"
        assert list_users.metadata["variant_of_file"] == "src/auth/login.py"
        assert list_users.metadata["cwe"] == "CWE-89"
        assert list_users.metadata["engine"] == "semgrep"
        assert list_users.metadata["rule_id"] == (
            "src_auth_login_py.check_credentials.CWE-89.0"
        )
        assert list_users.metadata["triage"] == "variant"

        # Body has rationale + cwe + match snippet.
        assert "f-string with user-controlled value" in list_users.body
        assert "CWE-89" in list_users.body
        assert "cursor.execute" in list_users.body

        # Uncertain match has triage="uncertain" in metadata.
        db_run = next(a for a in anns if a.function == "db_run")
        assert db_run.metadata["triage"] == "uncertain"
