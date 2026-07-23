"""Adversarial + E2E coverage for the KNighter follow-up wiring.

Probes inputs a faulty / compromised upstream could hand the
follow-up helper. Each case must produce a usable
checker-matches.jsonl without crash or unbounded growth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from packages.llm_analysis.checker_followup import (
    CHECKER_MATCHES_FILE,
    emit_variant_matches_for_finding,
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
        return None, None


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
    monkeypatch.setattr(cs_mod, "synthesise_with_refinement", _fake)


def _multi_function_checklist(file_path, names_with_lines):
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


def _load_matches(out_dir):
    path = out_dir / CHECKER_MATCHES_FILE
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Hostile snippet content
# ---------------------------------------------------------------------------


class TestHostileSnippet:
    def test_snippet_with_newlines_valid_json(
        self, tmp_path, monkeypatch,
    ):
        """A match snippet containing newlines must serialise to
        valid JSON (escaped). No crash, no format corruption."""
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

        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        records = _load_matches(tmp_path)
        assert len(records) == 1
        assert "\n" in records[0]["snippet"]


# ---------------------------------------------------------------------------
# Vuln-shape edge cases
# ---------------------------------------------------------------------------


class TestVulnShapes:
    def test_vuln_metadata_explicitly_none(self, tmp_path):
        v = StubVuln(metadata=None)
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0

    def test_vuln_with_no_metadata_attribute(self, tmp_path):
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

        n = emit_variant_matches_for_finding(
            Bare(), out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Variant relationships
# ---------------------------------------------------------------------------


class TestVariantRelationships:
    def test_variant_in_same_file_different_function(
        self, tmp_path, monkeypatch,
    ):
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        m = Match(file="src/auth.py", line=42)
        ck = _multi_function_checklist(
            "src/auth.py",
            [("login", 10, 20), ("other_login", 35, 50)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])

        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 1
        records = _load_matches(tmp_path)
        assert records[0]["function"] == "other_login"

    def test_seed_match_filtered_by_substrate(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r")
        _patch_synth(monkeypatch, rule=rule, matches=[])
        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist={},
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Append semantics (replaces annotation coexistence tests)
# ---------------------------------------------------------------------------


class TestAppendSemantics:
    def test_multiple_runs_append(self, tmp_path, monkeypatch):
        """Two consecutive runs on the same seed -> both entries
        appear in the JSONL (append, not overwrite)."""
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule1 = SynthesisedRule(engine="semgrep", rule_id="r1", body="r")
        rule2 = SynthesisedRule(engine="semgrep", rule_id="r2", body="r")
        m = Match(file="src/v.py", line=5)
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule1, matches=[m])
        emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )

        _patch_synth(monkeypatch, rule=rule2, matches=[m])
        emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )

        records = _load_matches(tmp_path)
        assert len(records) == 2
        assert records[0]["rule_id"] == "r1"
        assert records[1]["rule_id"] == "r2"


# ---------------------------------------------------------------------------
# Body & telemetry bounds
# ---------------------------------------------------------------------------


class TestBodyAndTelemetryBounds:
    def test_max_snippet_size_kept_bounded(self, tmp_path, monkeypatch):
        from packages.checker_synthesis import Match, SynthesisedRule

        v = StubVuln(metadata={"name": "login"})
        rule = SynthesisedRule(engine="semgrep", rule_id="x", body="r",
                               rationale="rationale")
        m = Match(file="src/v.py", line=5, snippet="x" * 500)
        ck = _multi_function_checklist(
            "src/v.py", [("variant_fn", 1, 10)],
        )
        _patch_synth(monkeypatch, rule=rule, matches=[m])
        emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        records = _load_matches(tmp_path)
        assert len(records[0]["snippet"]) == 500


# ---------------------------------------------------------------------------
# E2E — multi-variant realistic scenario
# ---------------------------------------------------------------------------


class TestE2E:
    def test_multi_variant_landing_on_disk(self, tmp_path, monkeypatch):
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
        v1 = Match(file="src/admin/users.py", line=87,
                   snippet="cursor.execute(f'SELECT * FROM u WHERE id={uid}')")
        v2 = Match(file="src/api/search.py", line=23,
                   snippet="cursor.execute(f'... {q}')")
        v3 = Match(file="src/log/audit.py", line=15,
                   snippet="conn.exec_safe(...)")
        v4 = Match(file="src/util/db.py", line=42,
                   snippet="db.run(query)")
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

        n = emit_variant_matches_for_finding(
            v, out_dir=tmp_path, checklist=ck,
            repo_root=tmp_path, llm_client=StubLLMClient(),
        )
        # 2 variants + 1 uncertain = 3 emitted; FP dropped.
        assert n == 3

        records = _load_matches(tmp_path)
        functions = sorted(r["function"] for r in records)
        assert functions == ["db_run", "list_users", "search_handler"]

        list_users_rec = next(r for r in records if r["function"] == "list_users")
        assert list_users_rec["seed_function"] == "check_credentials"
        assert list_users_rec["seed_file"] == "src/auth/login.py"
        assert list_users_rec["cwe"] == "CWE-89"
        assert list_users_rec["engine"] == "semgrep"
        assert list_users_rec["rule_id"] == (
            "src_auth_login_py.check_credentials.CWE-89.0"
        )
        assert list_users_rec["triage"] == "variant"

        db_run_rec = next(r for r in records if r["function"] == "db_run")
        assert db_run_rec["triage"] == "uncertain"
