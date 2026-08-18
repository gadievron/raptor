"""Same-run analysis of checker-synthesis variant matches (Mode 2).

``checker-matches.jsonl`` used to have zero readers — variant matches
were written and dropped, with the docstring promising a "next run"
consumer that did not exist. These tests pin the same-run route:
``load_variant_candidates`` (bounded, checklist-resolved, provenance-
marked) and ``AutonomousSecurityAgentV2._review_variant_matches``
(review with the originating hypothesis as enveloped context).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.llm_analysis.checker_followup import (
    CHECKER_MATCHES_FILE,
    MAX_VARIANT_REVIEWS_PER_RUN,
    _record_matches,
    load_variant_candidates,
)


def _checklist() -> dict:
    return {
        "files": [
            {
                "path": "src/parse.c",
                "functions": [
                    {
                        "name": "parse_header",
                        "line_start": 10,
                        "line_end": 40,
                    },
                    {
                        "name": "parse_body",
                        "line_start": 42,
                        "line_end": 90,
                    },
                ],
            },
            {
                "path": "src/seed.c",
                "functions": [
                    {
                        "name": "seed_fn",
                        "line_start": 1,
                        "line_end": 30,
                    },
                ],
            },
        ]
    }


def _record(**kw) -> dict:
    base = {
        "file": "src/parse.c",
        "line": 20,
        "function": "parse_header",
        "snippet": "memcpy(dst, src, n)",
        "seed_file": "src/seed.c",
        "seed_function": "seed_fn",
        "seed_line_start": 5,
        "seed_line_end": 12,
        "cwe": "CWE-787",
        "rule_id": "synth-rule-1",
        "engine": "semgrep",
        "rationale": "unchecked memcpy into fixed buffer",
        "seed_reasoning": "the seed finding wrote past dst",
        "triage": "variant",
    }
    base.update(kw)
    return base


def _write_matches(out_dir: Path, records: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / CHECKER_MATCHES_FILE, "a", encoding="utf-8") as f:
        f.writelines(json.dumps(rec) + "\n" for rec in records)


class TestLoadVariantCandidates:
    def test_converts_record_to_reviewable_finding(self, tmp_path):
        _write_matches(tmp_path, [_record()])
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        assert len(cands) == 1
        c = cands[0]
        assert c["file"] == "src/parse.c"
        assert c["startLine"] == 20
        assert c["tool"] == "checker-synthesis"
        assert c["cwe_id"] == "CWE-787"
        assert c["rule_id"] == "synth-rule-1"
        assert c["metadata"]["name"] == "parse_header"
        assert c["metadata"]["from_synthesis"] is True
        assert c["metadata"]["seed_function"] == "seed_fn"
        assert c["metadata"]["synthesis_engine"] == "semgrep"

    def test_originating_hypothesis_carried_as_context(self, tmp_path):
        _write_matches(tmp_path, [_record()])
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        ctx = cands[0]["synthesis_context"]
        assert "unchecked memcpy" in ctx
        assert "the seed finding wrote past dst" in ctx
        assert "Originating hypothesis" in ctx

    def test_bounded(self, tmp_path):
        records = [
            _record(line=11 + i) for i in range(30)
        ]
        checklist = {
            "files": [
                {
                    "path": "src/parse.c",
                    "functions": [
                        {
                            "name": f"fn{i}",
                            "line_start": 11 + i,
                            "line_end": 11 + i,
                        }
                        for i in range(30)
                    ],
                }
            ]
        }
        _write_matches(tmp_path, records)
        cands = load_variant_candidates(
            tmp_path, checklist=checklist, repo_root=tmp_path,
        )
        assert len(cands) == MAX_VARIANT_REVIEWS_PER_RUN

    def test_duplicate_functions_collapse(self, tmp_path):
        _write_matches(tmp_path, [_record(line=15), _record(line=25)])
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        assert len(cands) == 1

    def test_exclude_keys_skip_already_analyzed(self, tmp_path):
        _write_matches(tmp_path, [_record()])
        cands = load_variant_candidates(
            tmp_path,
            checklist=_checklist(),
            repo_root=tmp_path,
            exclude_keys={("src/parse.c", "parse_header")},
        )
        assert cands == []

    def test_seed_own_function_skipped(self, tmp_path):
        _write_matches(
            tmp_path,
            [_record(file="src/seed.c", line=8, function="seed_fn")],
        )
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        assert cands == []

    def test_triaged_fp_and_skipped_dropped(self, tmp_path):
        _write_matches(
            tmp_path,
            [
                _record(triage="false_positive"),
                _record(line=50, triage="skipped"),
            ],
        )
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        assert cands == []

    def test_unresolvable_site_dropped(self, tmp_path):
        _write_matches(tmp_path, [_record(file="unknown.c", line=999)])
        cands = load_variant_candidates(
            tmp_path, checklist=_checklist(), repo_root=tmp_path,
        )
        assert cands == []

    def test_malformed_lines_survivable(self, tmp_path):
        out = tmp_path
        out.mkdir(exist_ok=True)
        with open(out / CHECKER_MATCHES_FILE, "w", encoding="utf-8") as f:
            f.write("not json\n")
            f.write("[1,2,3]\n")
            f.write(json.dumps(_record()) + "\n")
        cands = load_variant_candidates(
            out, checklist=_checklist(), repo_root=tmp_path,
        )
        assert len(cands) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        assert (
            load_variant_candidates(
                tmp_path, checklist=_checklist(), repo_root=tmp_path,
            )
            == []
        )


class _StubMatch:
    def __init__(self, file: str, line: int, snippet: str = "s"):
        self.file = file
        self.line = line
        self.snippet = snippet


class _StubRule:
    rule_id = "synth-rule-9"
    engine = "semgrep"
    rationale = "rule rationale"


class _StubResult:
    def __init__(self, matches):
        self.matches = matches
        self.triage = []
        self.rule = _StubRule()


class _StubSeed:
    file = "src/seed.c"
    function = "seed_fn"
    line_start = 5
    line_end = 12
    cwe = "CWE-787"
    reasoning = "R" * 900


class TestRecordCarriesSeedReasoning:
    def test_seed_reasoning_written_and_bounded(self, tmp_path):
        n = _record_matches(
            seed=_StubSeed(),
            result=_StubResult([_StubMatch("src/parse.c", 20)]),
            out_dir=tmp_path,
            checklist=None,
            repo_root=tmp_path,
        )
        assert n == 1
        rec = json.loads(
            (tmp_path / CHECKER_MATCHES_FILE).read_text().splitlines()[0]
        )
        assert rec["seed_reasoning"] == "R" * 500


class TestReviewVariantMatches:
    def _agent(self, tmp_path):
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2

        agent = object.__new__(AutonomousSecurityAgentV2)
        agent.repo_path = tmp_path
        agent.out_dir = tmp_path / "out"
        agent.out_dir.mkdir(parents=True, exist_ok=True)
        return agent

    def test_reviews_candidates_with_enveloped_context(
        self, tmp_path, monkeypatch,
    ):
        agent = self._agent(tmp_path)
        _write_matches(agent.out_dir, [_record()])

        captured = {}

        def fake_analyze(vuln, extra_context_blocks=()):
            captured["vuln"] = vuln
            captured["blocks"] = extra_context_blocks
            vuln.exploitable = True
            vuln.analysis = {"is_exploitable": True}
            return True

        agent.analyze_vulnerability = fake_analyze
        agent._emit_journal_entry = lambda vuln, checklist: True

        stats = agent._review_variant_matches(
            _checklist(), exclude_keys=set(), emit_journal=True,
        )
        assert stats["candidates"] == 1
        assert stats["analyzed"] == 1
        assert stats["exploitable"] == 1
        assert stats["journal_entries"] == 1
        assert len(stats["results"]) == 1

        vuln = captured["vuln"]
        assert vuln.tool == "checker-synthesis"
        assert vuln.metadata["from_synthesis"] is True

        blocks = captured["blocks"]
        assert len(blocks) == 1
        from core.security.prompt_envelope import UntrustedBlock

        assert isinstance(blocks[0], UntrustedBlock)
        assert "Originating hypothesis" in blocks[0].content
        assert blocks[0].origin == "checker-synthesis"

    def test_no_journal_when_disabled(self, tmp_path):
        agent = self._agent(tmp_path)
        _write_matches(agent.out_dir, [_record()])

        def fake_analyze(vuln, extra_context_blocks=()):
            vuln.analysis = {"is_exploitable": False}
            return True

        journal_calls = []
        agent.analyze_vulnerability = fake_analyze
        agent._emit_journal_entry = (
            lambda vuln, checklist: journal_calls.append(1) or True
        )

        stats = agent._review_variant_matches(
            _checklist(), exclude_keys=set(), emit_journal=False,
        )
        assert stats["analyzed"] == 1
        assert stats["journal_entries"] == 0
        assert journal_calls == []

    def test_analysis_failure_is_survivable(self, tmp_path):
        agent = self._agent(tmp_path)
        _write_matches(
            agent.out_dir, [_record(), _record(line=50)],
        )

        calls = []

        def flaky_analyze(vuln, extra_context_blocks=()):
            calls.append(vuln.file_path)
            if len(calls) == 1:
                raise RuntimeError("boom")
            vuln.analysis = {}
            return True

        agent.analyze_vulnerability = flaky_analyze
        agent._emit_journal_entry = lambda vuln, checklist: False

        stats = agent._review_variant_matches(
            _checklist(), exclude_keys=set(), emit_journal=True,
        )
        assert stats["candidates"] == 2
        assert stats["analyzed"] == 1

    def test_no_candidates_no_analysis(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.analyze_vulnerability = None  # would explode if called
        stats = agent._review_variant_matches(
            _checklist(), exclude_keys=set(), emit_journal=True,
        )
        assert stats == {
            "candidates": 0,
            "analyzed": 0,
            "exploitable": 0,
            "journal_entries": 0,
            "results": [],
        }


class TestProcessFindingsWiring:
    def test_variant_review_is_wired_into_process_findings(self):
        import inspect

        from packages.llm_analysis import agent as agent_mod

        src = inspect.getsource(
            agent_mod.AutonomousSecurityAgentV2.process_findings
        )
        assert "_review_variant_matches" in src
        # Gated off in prep-only mode and when synthesis is disabled.
        assert "synthesise_checkers" in src

    def test_analyze_vulnerability_threads_extra_blocks(self):
        import inspect

        from packages.llm_analysis import agent as agent_mod

        src = inspect.getsource(
            agent_mod.AutonomousSecurityAgentV2.analyze_vulnerability
        )
        assert "extra_blocks.extend(extra_context_blocks)" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
