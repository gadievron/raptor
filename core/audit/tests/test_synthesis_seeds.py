"""External ground-truth seed sources for checker synthesis.

``_seed_from_outcome`` (this run's review outcomes) was effectively
the only amplification seed constructor — RAPTOR could synthesize
checkers only from bugs it had just found itself. These tests pin the
new bounded seed sources (journal current+prior runs, crash RCAs,
cvefix fixture pairs), their provenance, and the orchestrator hook
that queues sweep hits into the same-run second-pass review.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit.synthesis_seeds import (
    MAX_SEEDS_PER_SOURCE,
    ExternalSeed,
    collect_external_seeds,
    seeds_from_crash_contexts,
    seeds_from_cvefix_corpus,
    seeds_from_journal,
)
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)


def _entry(**kw) -> ReviewJournalEntry:
    base = {
        "ts": now_iso(),
        "run_id": "run-1",
        "file": "src/a.c",
        "function": "f",
        "verdict": "finding",
        "source_hash": "abc",
        "line_start": 1,
        "line_end": 3,
        "cwe": "CWE-787",
        "hypotheses": [{"mechanism": "unchecked memcpy into dst"}],
        "body": "confirmed OOB write",
    }
    base.update(kw)
    return ReviewJournalEntry(**base)


def _target(tmp_path) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True, exist_ok=True)
    (target / "src" / "a.c").write_text(
        "int f(void) {\n  return 0;\n}\n"
    )
    return target


class TestJournalSeeds:
    def test_current_run_finding_becomes_seed(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        append_entry(out, _entry())
        target = _target(tmp_path)
        seeds = seeds_from_journal(out, None, target)
        assert len(seeds) == 1
        seed = seeds[0].seed
        assert seed.file == "src/a.c"
        assert seed.function == "f"
        assert seed.cwe == "CWE-787"
        assert "memcpy" in seed.reasoning
        assert seed.provenance == "journal:current"
        assert "return 0" in seed.snippet
        assert seeds[0].positive_fixture is None

    def test_prior_run_findings_via_project_index(self, tmp_path):
        project = tmp_path / "project"
        prior_run = project / "old-run"
        prior_run.mkdir(parents=True)
        append_entry(prior_run, _entry(run_id="old-run"))
        merge_into_index(project, prior_run)
        target = _target(tmp_path)
        seeds = seeds_from_journal(None, project, target)
        assert len(seeds) == 1
        assert seeds[0].seed.provenance == "journal:old-run"

    def test_non_findings_skipped(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        append_entry(out, _entry(verdict="suspicious"))
        append_entry(out, _entry(verdict="clean", function="g"))
        assert seeds_from_journal(out, None, _target(tmp_path)) == []

    def test_missing_cwe_skipped(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        append_entry(out, _entry(cwe=None))
        assert seeds_from_journal(out, None, _target(tmp_path)) == []

    def test_exclude_keys_and_bound(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        for i in range(6):
            append_entry(out, _entry(function=f"f{i}"))
        target = _target(tmp_path)
        seeds = seeds_from_journal(
            out, None, target, exclude_keys={("src/a.c", "f0")},
        )
        assert len(seeds) == MAX_SEEDS_PER_SOURCE
        names = {s.seed.function for s in seeds}
        assert "f0" not in names

    def test_body_fallback_when_no_hypotheses(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        append_entry(out, _entry(hypotheses=[]))
        seeds = seeds_from_journal(out, None, _target(tmp_path))
        assert seeds[0].seed.reasoning == "confirmed OOB write"


class TestCrashSeeds:
    def _crash_run(self, tmp_path, contexts) -> Path:
        run = tmp_path / "fuzz-run"
        (run / "crash_analysis").mkdir(parents=True)
        (run / "crash_analysis" / "crash-contexts.json").write_text(
            json.dumps({"contexts": contexts})
        )
        return run

    def _ctx(self, target, **kw):
        base = {
            "crash_id": "crash-1",
            "signal": "SIGSEGV",
            "crash_type": "heap_overflow",
            "exploitability": "likely",
            "function_name": "f",
            "source_location": str(target / "src" / "a.c") + ":2",
            "analysis": {"reasoning": "OOB write past dst"},
        }
        base.update(kw)
        return base

    def test_crash_context_becomes_seed(self, tmp_path):
        target = _target(tmp_path)
        run = self._crash_run(tmp_path, [self._ctx(target)])
        seeds = seeds_from_crash_contexts([run], target)
        assert len(seeds) == 1
        seed = seeds[0].seed
        assert seed.file == "src/a.c"
        assert seed.cwe == "CWE-122"
        assert seed.provenance == "crash:crash-1"
        assert "heap_overflow" in seed.reasoning
        assert "OOB write past dst" in seed.reasoning

    def test_checklist_resolves_span(self, tmp_path):
        target = _target(tmp_path)
        run = self._crash_run(tmp_path, [self._ctx(target)])
        checklist = {
            "files": [
                {
                    "path": "src/a.c",
                    "functions": [
                        {"name": "f", "line_start": 1, "line_end": 3}
                    ],
                }
            ]
        }
        seeds = seeds_from_crash_contexts(
            [run], target, checklist=checklist,
        )
        assert seeds[0].seed.line_start == 1
        assert seeds[0].seed.line_end == 3

    def test_escaping_location_skipped(self, tmp_path):
        target = _target(tmp_path)
        run = self._crash_run(
            tmp_path,
            [self._ctx(target, source_location="/etc/passwd:1")],
        )
        assert seeds_from_crash_contexts([run], target) == []

    def test_bound_and_dedup(self, tmp_path):
        target = _target(tmp_path)
        contexts = [
            self._ctx(target, crash_id=f"c{i}")
            for i in range(4)
        ] + [
            self._ctx(
                target,
                crash_id="cx",
                source_location=str(target / "src" / "a.c") + ":3",
            )
        ]
        run = self._crash_run(tmp_path, contexts)
        seeds = seeds_from_crash_contexts([run], target, max_seeds=2)
        assert len(seeds) == 2
        # First 4 contexts share one site → dedup collapsed them.
        assert seeds[0].seed.provenance == "crash:c0"
        assert seeds[1].seed.provenance == "crash:cx"

    def test_missing_artifact(self, tmp_path):
        target = _target(tmp_path)
        assert seeds_from_crash_contexts([tmp_path / "none"], target) == []


class TestCvefixSeeds:
    def _corpus(self, tmp_path, entries) -> Path:
        corpus = tmp_path / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)
        for fid, verdict, snippet in entries:
            (corpus / f"{fid}.json").write_text(
                json.dumps(
                    {
                        "finding_id": fid,
                        "producer": "codeql",
                        "rule_id": "cpp/sql-injection",
                        "message": "user data flows into query",
                        "sink": {
                            "file_path": "src/db.c",
                            "line": 12,
                            "column": 1,
                            "snippet": snippet,
                        },
                    }
                )
            )
            (corpus / f"{fid}.label.json").write_text(
                json.dumps({"finding_id": fid, "verdict": verdict})
            )
        return corpus

    def test_tp_becomes_external_seed_with_fixtures(self, tmp_path):
        corpus = self._corpus(
            tmp_path,
            [
                ("cve-1__pre", "true_positive", "exec(q + user)"),
                ("cve-1__post", "false_positive", "exec(sanitize(q))"),
            ],
        )
        seeds = seeds_from_cvefix_corpus(corpus)
        assert len(seeds) == 1
        ext = seeds[0]
        assert ext.seed.provenance == "cvefix:cve-1__pre"
        assert ext.positive_fixture == "exec(q + user)"
        assert ext.negative_fixture == "exec(sanitize(q))"
        assert "cve-1__pre" in ext.seed.reasoning

    def test_tp_without_fp_sibling_has_no_negative(self, tmp_path):
        corpus = self._corpus(
            tmp_path, [("cve-2__pre", "true_positive", "exec(q)")],
        )
        seeds = seeds_from_cvefix_corpus(corpus)
        assert seeds[0].negative_fixture is None

    def test_bound(self, tmp_path):
        entries = []
        for i in range(5):
            entries.append((f"cve-{i}__pre", "true_positive", f"exec(q{i})"))
        corpus = self._corpus(tmp_path, entries)
        # Distinct files so per-file dedup doesn't hide the bound.
        for i, (fid, _, _) in enumerate(entries):
            data = json.loads((corpus / f"{fid}.json").read_text())
            data["sink"]["file_path"] = f"src/db{i}.c"
            (corpus / f"{fid}.json").write_text(json.dumps(data))
        assert len(seeds_from_cvefix_corpus(corpus)) == MAX_SEEDS_PER_SOURCE

    def test_missing_dir(self, tmp_path):
        assert seeds_from_cvefix_corpus(tmp_path / "none") == []


class TestCollect:
    def test_merges_sources_and_survives_failures(self, tmp_path):
        target = _target(tmp_path)
        project = tmp_path / "project"
        out = project / "audit-run"
        out.mkdir(parents=True)
        (out / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(target)})
        )
        append_entry(out, _entry())
        config = SimpleNamespace(out_dir=out, target_path=target)
        seeds = collect_external_seeds(config)
        assert len(seeds) == 1
        assert seeds[0].seed.provenance == "journal:current"

    def test_no_target_returns_empty(self):
        assert collect_external_seeds(SimpleNamespace(target_path=None)) == []


class TestOrchestratorHook:
    def _result(self):
        calls = []

        class _Tracker:
            def record_call(self, phase, **kw):
                calls.append((phase, kw))

        result = SimpleNamespace(
            _lock=threading.Lock(),
            outcomes=[],
            synthesis_amplified=0,
            total_cost_usd=0.0,
            cost_tracker=_Tracker(),
        )
        return result, calls

    def test_hits_join_synthesis_queue_with_provenance(
        self, tmp_path, monkeypatch,
    ):
        from core.audit import orchestrator as orch_mod
        from core.audit.checker_synthesis import SynthesisResult

        result, tracker_calls = self._result()
        shared = SimpleNamespace(
            synthesis_queue=[], checker_library=None,
        )
        config = SimpleNamespace(
            out_dir=tmp_path, target_path=tmp_path,
        )

        seed = SimpleNamespace(
            file="src/db.c", function="", provenance="cvefix:cve-1",
        )
        monkeypatch.setattr(
            orch_mod,
            "_synthesize_external_seeds",
            orch_mod._synthesize_external_seeds,
        )
        import core.audit.synthesis_seeds as seeds_mod

        monkeypatch.setattr(
            seeds_mod,
            "collect_external_seeds",
            lambda cfg, **kw: [ExternalSeed(seed=seed)],
        )
        import core.audit.checker_synthesis as cs_mod

        monkeypatch.setattr(
            cs_mod,
            "synthesize_from_external_seed",
            lambda ext, cfg, **kw: SynthesisResult(
                rule_id="r1",
                tool="semgrep",
                content="rules: []",
                cwe="CWE-89",
                origin_file="src/db.c",
                origin_function="",
                hits=[
                    {
                        "file": "src/x.c",
                        "line": 4,
                        "function": "",
                        "snippet": "exec(q)",
                        "origin_file": "src/db.c",
                        "origin_function": "",
                        "provenance": "cvefix:cve-1",
                    }
                ],
                cost_usd=0.25,
            ),
        )

        queued = orch_mod._synthesize_external_seeds(
            config, result, shared, {"files": []},
        )
        assert queued == 1
        assert shared.synthesis_queue[0]["provenance"] == "cvefix:cve-1"
        assert shared.synthesis_queue[0]["priority_score"] == 0.8
        assert result.synthesis_amplified == 1
        assert result.total_cost_usd == 0.25
        assert tracker_calls == [
            ("checker_synthesis", {"cost_usd": 0.25}),
        ]

    def test_provenance_flows_to_gap(self):
        from core.audit.orchestrator import _synthesis_hits_to_gaps

        checklist = {
            "files": [
                {
                    "path": "src/x.c",
                    "items": [
                        {
                            "name": "g",
                            "kind": "function",
                            "line_start": 1,
                            "line_end": 10,
                        }
                    ],
                }
            ]
        }
        gaps = _synthesis_hits_to_gaps(
            [
                {
                    "file": "src/x.c",
                    "line": 4,
                    "snippet": "exec(q)",
                    "provenance": "cvefix:cve-1",
                }
            ],
            checklist,
        )
        assert gaps[0]["synthesis_provenance"] == "cvefix:cve-1"
        assert gaps[0]["from_synthesis"] is True

    def test_wired_before_second_pass(self):
        import inspect

        from core.audit import orchestrator as orch_mod

        src = inspect.getsource(orch_mod._run_audit_body)
        idx_ext = src.index("_synthesize_external_seeds(")
        idx_drain = src.index("shared.synthesis_queue and not executor_stats")
        assert idx_ext < idx_drain


class TestExternalSeedAdapter:
    def test_cap_respected(self, tmp_path):
        from core.audit.checker_synthesis import (
            synthesize_from_external_seed,
        )

        ext = ExternalSeed(
            seed=SimpleNamespace(file="a.c", function="", provenance="x"),
        )
        config = SimpleNamespace(out_dir=tmp_path, target_path=tmp_path)
        assert (
            synthesize_from_external_seed(
                ext, config, synthesis_count=5, max_per_run=5,
            )
            is None
        )

    def test_ground_truth_fixtures_forwarded(self, tmp_path, monkeypatch):
        import core.audit.checker_synthesis as cs_mod
        from packages.checker_synthesis import SeedBug

        captured = {}

        class _FakeClient:
            total_cost = 0.0
            model_name = "m"

        monkeypatch.setattr(
            cs_mod,
            "_build_llm_callable",
            lambda cfg: (lambda p, s, sp: None, _FakeClient()),
        )

        def fake_synthesise_and_run(seed, **kw):
            captured["fixtures"] = kw.get("ground_truth_fixtures")

            class _R:
                rule = None
                errors: list = []  # noqa: RUF012 — stub result

            return _R()

        import packages.checker_synthesis.synthesise as synth_mod

        monkeypatch.setattr(
            synth_mod, "synthesise_and_run", fake_synthesise_and_run,
        )

        seed = SeedBug(
            file="src/db.c", function="", line_start=1, line_end=1,
            cwe="CWE-89", reasoning="r", snippet="exec(q)",
            provenance="cvefix:cve-1",
        )
        config = SimpleNamespace(
            out_dir=tmp_path, target_path=tmp_path, models=None,
        )
        cs_mod.synthesize_from_external_seed(
            ExternalSeed(
                seed=seed,
                positive_fixture="exec(q + user)",
                negative_fixture="exec(safe(q))",
            ),
            config,
        )
        assert captured["fixtures"] == ("exec(q + user)", "exec(safe(q))")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
