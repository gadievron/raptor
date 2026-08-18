"""Tests for core.audit.orchestrator — autonomous review loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.hypothesis_mapping import (
    hypothesis_to_semgrep_rule as _hypothesis_to_semgrep_rule,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _check_finding_gates,
    _ContentFilterError,
    _hypothesis_to_tool_chain,
    _is_verification_evidence_for_gate,
    _joern_live_query,
    _multi_pass_review,
    _promote_hypothesis_inconsistent,
    _resolve_gate_demoted,
    _run_tool_chain,
    get_reviewed_set,
    run_orchestrator,
)


def _setup_target(tmp_path: Path):
    """Create a minimal target + output dir with a checklist."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "src").mkdir()
    (target / "src" / "auth.c").write_text(
        "int check_pw(char *pw, int len) {\n"
        "  if (len > MAX_PW) return -1;\n"
        "  char buf[256];\n"
        "  memcpy(buf, pw, len);\n"
        "  return strcmp(buf, stored);\n"
        "}\n"
        "\n"
        "int validate(char *input, size_t sz) {\n"
        "  if (sz == 0) return -1;\n"
        "  char tmp[128];\n"
        "  memcpy(tmp, input, sz);\n"
        "  return strlen(tmp) > 0;\n"
        "}\n"
    )

    out = tmp_path / "out"
    out.mkdir()

    checklist = {
        "files": [
            {
                "path": "src/auth.c",
                "items": [
                    {"name": "check_pw", "line_start": 1, "line_end": 6},
                    {"name": "validate", "line_start": 8, "line_end": 13},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))

    context_map = {
        "entry_points": [
            {"file": "src/auth.c", "name": "check_pw"},
            {"file": "src/auth.c", "name": "validate"},
        ],
        "sinks": [],
        "trust_boundaries": [],
        "unchecked_flows": [],
    }
    (out / "context-map.json").write_text(json.dumps(context_map))
    return target, out


class TestGetReviewedSet:
    def test_empty_log(self, tmp_path: Path):
        result = get_reviewed_set(tmp_path)
        assert result == set()

    def test_reads_record_actions(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"record","key":"src/auth.c:check_pw"}\n'
            '{"action":"context","key":"src/auth.c:validate"}\n'
            '{"action":"record","key":"src/util.c:helper"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/util.c:helper" in result
        assert "src/auth.c:validate" not in result

    def test_reads_orchestrator_review_actions(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"orchestrator_review","key":"src/auth.c:check_pw"}\n'
            '{"action":"context","key":"src/auth.c:validate"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/auth.c:validate" not in result

    def test_lined_key_produces_bare_fallback(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"orchestrator_review","key":"sql.go:Scan:3232"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert "sql.go:Scan:3232" in result
        assert "sql.go:Scan" in result

    def test_bare_key_no_spurious_strip(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"orchestrator_review","key":"src/auth.c:check_pw"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/auth.c" not in result

    def test_error_status_excluded(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"orchestrator_review","key":"src/a.c:ok","status":"clean"}\n'
            '{"action":"orchestrator_review","key":"src/b.c:fail","status":"error"}\n'
            '{"action":"record","key":"src/c.c:also_fail","status":"error"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert "src/a.c:ok" in result
        assert "src/b.c:fail" not in result
        assert "src/c.c:also_fail" not in result


@pytest.mark.slow
class TestRunOrchestrator:
    def test_reviews_all_gaps(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="reviewed",
                model="test-model",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 2
        assert result.clean == 2
        assert result.terminated_by == "complete"

    def test_budget_limits_reviews(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, budget=1, resume=False,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 1

    def test_resume_skips_reviewed(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        log = out / ".audit-log.jsonl"
        log.write_text('{"action":"record","key":"src/auth.c:check_pw"}\n')

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=True,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 1
        assert result.skipped == 1

    def test_resume_false_reviews_all(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        log = out / ".audit-log.jsonl"
        log.write_text('{"action":"record","key":"src/auth.c:check_pw"}\n')

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 2
        assert result.skipped == 0

    def test_cost_budget_terminates(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
                cost_usd=1.0,
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            max_cost_usd=0.5,
            resume=False,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed >= 1
        if result.reviewed < 2:
            assert result.terminated_by == "max_cost_usd"

    def test_time_budget_terminates(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            max_seconds=0.001,
            resume=False,
        )

        import time
        def slow_review(ctx, config):
            time.sleep(0.01)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        result = run_orchestrator(config, slow_review)
        assert result.terminated_by in ("max_seconds", "complete")

    def test_review_fn_exception_records_error(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def failing_review(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("review logic failed")
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, failing_review)
        assert result.reviewed == 2
        assert result.errors == 1
        assert result.clean == 1

    def test_finding_counts(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def mixed_review(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="SQL injection via format string",
                    hypothesis="SQL injection via string format",
                    evidence_tool="semgrep:sql-injection",
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="test",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            # hermetic: with Joern installed, the post-resolution channel
            # settles the unverifiable suspicious verdict as "dark" and
            # spends a live LLM call doing so (see TestSuspiciousPromotion).
            joern_overrides={"enabled": False},
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            max_refinements=0,
        )
        result = run_orchestrator(config, mixed_review)
        assert result.findings == 1
        assert result.suspicious == 1

    def test_progress_callback(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        progress_log = []
        def on_progress(idx, total, outcome):
            progress_log.append((idx, total, outcome.function))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            max_refinements=0,
        )
        run_orchestrator(config, review_fn, on_progress=on_progress)
        reviews = [(i, t, fn) for i, t, fn in progress_log if t > 0]
        assert len(reviews) == 2
        assert reviews[0][1] == 2

    def test_no_checklist_returns_early(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
        )
        result = run_orchestrator(config, lambda c, cfg: None)
        assert result.terminated_by == "no_checklist"
        assert result.reviewed == 0

    def test_scope_filters_functions(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "auth.c").write_text("int f() {}\n")
        (target / "lib").mkdir()
        (target / "lib" / "util.c").write_text("int g() {}\n")

        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [
                {"path": "src/auth.c", "items": [
                    {"name": "f", "line_start": 1, "line_end": 1}]},
                {"path": "lib/util.c", "items": [
                    {"name": "g", "line_start": 1, "line_end": 1}]},
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            scope="src/", resume=False,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 1

    def test_writes_audit_log(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
                model="test-m",
                cost_usd=0.01,
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        run_orchestrator(config, review_fn)

        log_path = out / ".audit-log.jsonl"
        assert log_path.exists()
        entries = [json.loads(ln) for ln in log_path.read_text().splitlines()]
        orch_entries = [e for e in entries if e["action"] == "orchestrator_review"]
        assert len(orch_entries) == 2
        assert orch_entries[0]["model"] == "test-m"

    def test_prioritize_with_context_map(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        context_map = {
            "entry_points": [{"file": "src/auth.c", "name": "validate"}],
            "sinks": [{"file": "src/auth.c", "name": "check_pw"}],
        }
        (out / "context-map.json").write_text(json.dumps(context_map))

        reviewed = []
        def review_fn(ctx, config):
            reviewed.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        run_orchestrator(config, review_fn)
        assert len(reviewed) == 2


def _setup_varied_sloc(tmp_path: Path):
    """Create a target with functions of varying sizes."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "src").mkdir()
    (target / "src" / "a.c").write_text(
        "int tiny1() { return 0; }\n"
        "int tiny2() { return 1; }\n"
        "int big(int x) {\n"
        "  if (x > 0) {\n"
        "    return x * 2;\n"
        "  }\n"
        "  int y = x + 1;\n"
        "  int z = y * 3;\n"
        "  return z;\n"
        "}\n"
    )
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "src/a.c",
                "items": [
                    {"name": "tiny1", "line_start": 1, "line_end": 3},
                    {"name": "tiny2", "line_start": 4, "line_end": 6},
                    {"name": "big", "line_start": 7, "line_end": 25},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))

    context_map = {
        "entry_points": [
            {"file": "src/a.c", "name": "tiny1"},
            {"file": "src/a.c", "name": "tiny2"},
            {"file": "src/a.c", "name": "big"},
        ],
        "sinks": [],
        "trust_boundaries": [],
        "unchecked_flows": [],
    }
    (out / "context-map.json").write_text(json.dumps(context_map))
    return target, out


@pytest.mark.slow
class TestBatching:
    def test_trivial_functions_batched(self, tmp_path: Path):
        target, out = _setup_varied_sloc(tmp_path)

        contexts = []
        def review_fn(ctx, config):
            contexts.append(ctx)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=5,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 3
        batch_contexts = [c for c in contexts if "batch_context" in c]
        assert len(batch_contexts) == 2

    def test_batch_disabled(self, tmp_path: Path):
        target, out = _setup_varied_sloc(tmp_path)

        contexts = []
        def review_fn(ctx, config):
            contexts.append(ctx)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 3
        batch_contexts = [c for c in contexts if "batch_context" in c]
        assert len(batch_contexts) == 0

    def test_single_trivial_not_batched(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "a.c").write_text("int f() {}\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [
                {
                    "path": "src/a.c",
                    "items": [
                        {"name": "f", "line_start": 1, "line_end": 1},
                        {"name": "g", "line_start": 2, "line_end": 20},
                    ],
                },
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        contexts = []
        def review_fn(ctx, config):
            contexts.append(ctx)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=5,
        )
        run_orchestrator(config, review_fn)
        batch_contexts = [c for c in contexts if "batch_context" in c]
        assert len(batch_contexts) == 0


@pytest.mark.slow
class TestContentFilter:
    def test_content_filter_records_error(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                raise _ContentFilterError("blocked")
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.errors == 1
        assert result.clean == 1
        error_outcome = next(o for o in result.outcomes if o.status == "error")
        assert "content filter" in error_outcome.body


@pytest.mark.slow
class TestCheckedByLabels:
    def test_checked_by_written_to_journal(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
                model="gpt-test",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
            prefilter=False,
            max_refinements=0,
        )
        run_orchestrator(config, review_fn)

        from core.audit.journal import latest_entries
        entries = latest_entries(out)
        assert len(entries) > 0
        for entry in entries.values():
            assert entry.producer == "audit"
            assert entry.model == "gpt-test"

    def test_error_status_journal_verdict(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            raise RuntimeError("boom")

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        from core.audit.journal import latest_entries
        entries = latest_entries(out)
        error_entries = [e for e in entries.values() if e.verdict == "error"]
        assert len(error_entries) > 0

    def test_journal_entry_for_each_function(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
                model="test-m",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        from core.audit.journal import latest_entries
        entries = latest_entries(out)
        check_pw = next(
            (e for e in entries.values() if e.function == "check_pw"),
            None,
        )
        assert check_pw is not None
        assert check_pw.verdict == "clean"
        assert check_pw.producer == "audit"


@pytest.mark.slow
class TestFuzzCoverage:
    def test_fuzz_data_passed_to_context(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        fuzz = {
            "files": {
                "src/auth.c": {
                    "functions": {
                        "check_pw": {
                            "harness": "fuzz_auth",
                            "iterations": 50000,
                        },
                    },
                },
            },
        }
        (out / "coverage-fuzz.json").write_text(json.dumps(fuzz))

        contexts = []
        def review_fn(ctx, config):
            contexts.append(ctx)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        fuzzed = [c for c in contexts if c.get("fuzz_coverage")]
        assert len(fuzzed) == 1
        assert fuzzed[0]["function"] == "check_pw"
        assert fuzzed[0]["fuzz_coverage"]["harness"] == "fuzz_auth"

    def test_fuzzed_function_still_reviewed(self, tmp_path: Path):
        """Fuzz coverage does NOT exclude functions from review."""
        target, out = _setup_target(tmp_path)

        fuzz = {
            "files": {
                "src/auth.c": {
                    "functions": {
                        "check_pw": {"harness": "fuzz_auth"},
                        "validate": {"harness": "fuzz_validate"},
                    },
                },
            },
        }
        (out / "coverage-fuzz.json").write_text(json.dumps(fuzz))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 2

    def test_no_fuzz_data_no_crash(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            assert "fuzz_coverage" not in ctx
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.reviewed == 2


@pytest.mark.slow
class TestConstraintWiring:
    def test_constraints_extracted_and_saved(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="needs bounds check",
                review_result={
                    "constraints": [
                        {
                            "kind": "parameter",
                            "target": "len",
                            "rule": "len must be <= 1024",
                        },
                    ],
                },
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            propagate_constraints=True,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        constraints_path = out / "constraints.json"
        assert constraints_path.exists()
        with open(constraints_path) as f:
            data = json.load(f)
        assert len(data) >= 1

    def test_constraints_disabled(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="ok",
                review_result={
                    "constraints": [
                        {"kind": "parameter", "target": "x",
                         "rule": "x must be positive"},
                    ],
                },
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            propagate_constraints=False,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)
        assert not (out / "constraints.json").exists()

    def test_no_review_result_no_constraint_extraction(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            propagate_constraints=True,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)
        assert not (out / "constraints.json").exists()


@pytest.mark.slow
class TestPrefilterWiring:
    """Test that the prefilter is wired into the orchestrator loop."""

    def _setup_with_accessor(self, tmp_path: Path):
        """Create a target with one trivial accessor and one function with strcpy."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "util.c").write_text(
            "int get_count(void) {\n"
            "    return 42;\n"
            "}\n"
            "\n"
            "void copy_name(char *dst, const char *src) {\n"
            "    strcpy(dst, src);\n"
            "}\n"
        )

        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [
                {
                    "path": "src/util.c",
                    "items": [
                        {"name": "get_count", "line_start": 1, "line_end": 3,
                         "metadata": {}},
                        {"name": "copy_name", "line_start": 5, "line_end": 7,
                         "metadata": {}},
                    ],
                },
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        return target, out

    def test_trivial_accessor_skipped_by_prefilter(self, tmp_path: Path):
        target, out = self._setup_with_accessor(tmp_path)

        llm_calls = []
        def review_fn(ctx, config):
            llm_calls.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="reviewed by LLM",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            prefilter=True, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)

        assert result.prefilter_skipped == 1
        assert "get_count" not in llm_calls
        assert "copy_name" in llm_calls

    def test_prefilter_disabled(self, tmp_path: Path):
        target, out = self._setup_with_accessor(tmp_path)

        llm_calls = []
        def review_fn(ctx, config):
            llm_calls.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="reviewed by LLM",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            prefilter=False, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)

        assert result.prefilter_skipped == 0
        assert len(llm_calls) == 2

    def test_prefilter_hits_injected_into_context(self, tmp_path: Path):
        target, out = self._setup_with_accessor(tmp_path)

        seen_contexts = []
        def review_fn(ctx, config):
            seen_contexts.append(ctx)
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="reviewed",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            prefilter=True, batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        copy_name_ctx = next(
            (c for c in seen_contexts if c["function"] == "copy_name"),
            None,
        )
        assert copy_name_ctx is not None
        assert "prefilter_results" in copy_name_ctx

    def test_prefilter_hits_counted(self, tmp_path: Path):
        target, out = self._setup_with_accessor(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="reviewed",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            prefilter=True, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.prefilter_hits >= 1


@pytest.mark.slow
class TestSweepValidation:
    """Test post-LLM sweep validation of findings."""

    def test_finding_without_hypothesis_demoted(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="looks dangerous",
                    hypothesis="",
                    evidence_tool="",
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_demoted == 1

    def test_finding_with_tool_evidence_kept(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="SQL injection confirmed by Semgrep",
                    hypothesis="SQL injection via string format",
                    evidence_tool="semgrep:sql-injection",
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_demoted == 0

    def test_sweep_validation_disabled(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="grounded finding",
                hypothesis="buffer overflow via strcpy",
                evidence_tool="semgrep:unbounded-strcpy",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False, batch_sloc_threshold=0,
            prefilter=False, max_refinements=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.findings == 2
        assert result.sweep_demoted == 0


class TestHypothesisToSemgrepRule:
    """Test Semgrep rule generation from LLM hypothesis strings."""

    def test_buffer_overflow_generates_rule(self):
        path = _hypothesis_to_semgrep_rule(
            "buffer overflow via unchecked strcpy", "vuln.c",
        )
        assert path is not None
        content = Path(path).read_text()
        assert "strcpy" in content
        assert "languages: [c]" in content
        Path(path).unlink()

    def test_sql_injection_generates_rule(self):
        path = _hypothesis_to_semgrep_rule(
            "SQL injection through user-controlled query parameter",
            "db.py",
        )
        assert path is not None
        content = Path(path).read_text()
        assert "SELECT" in content
        assert "languages: [python]" in content
        Path(path).unlink()

    def test_use_after_free_generates_rule(self):
        path = _hypothesis_to_semgrep_rule(
            "use after free of request buffer", "handler.c",
        )
        assert path is not None
        content = Path(path).read_text()
        assert "free" in content
        Path(path).unlink()

    def test_unknown_hypothesis_returns_none(self):
        path = _hypothesis_to_semgrep_rule(
            "the function is suspicious", "unknown.c",
        )
        assert path is None

    def test_language_detection_python(self):
        path = _hypothesis_to_semgrep_rule(
            "command injection via os.system", "app.py",
        )
        assert path is not None
        content = Path(path).read_text()
        assert "languages: [python]" in content
        Path(path).unlink()

    def test_language_detection_java(self):
        path = _hypothesis_to_semgrep_rule(
            "sql injection in query builder", "Dao.java",
        )
        assert path is not None
        content = Path(path).read_text()
        assert "languages: [java]" in content
        Path(path).unlink()


class TestHypothesisToSmtVerb:
    """Test _hypothesis_to_smt_verb routing."""

    def test_integer_overflow(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb("integer overflow in size calc") == "check-overflow"

    def test_buffer_overflow(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb("buffer overflow via memcpy") == "check-oob"

    def test_null_pointer_maps_to_null_propagation(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb("null pointer dereference") == "check-null-propagation"

    def test_overflow_to_oob(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb(
            "integer overflow leading to heap OOB",
        ) == "check-overflow-to-oob"

    def test_negative_value_bypass(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb(
            "A negative value for msg_qbytes can bypass the size check",
        ) == "check-negative-bypass"

    def test_negative_bypass_regex(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb(
            "signed to unsigned conversion allows bypass",
        ) == "check-negative-bypass"

    def test_unrelated_hypothesis(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb("SQL injection via string concat") is None


class TestHypothesisToCocciCheck:
    """Test _hypothesis_to_cocci_check routing."""

    def test_no_rules_dir_returns_none(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check("unchecked return value from malloc")
        assert result is None or isinstance(result, str)

    def test_unrelated_hypothesis(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check("XSS via innerHTML")
        assert result is None

    def test_uninitialized_routes_to_rule(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "variable err is not initialized and can be returned"
        )
        if result is not None:
            assert "uninitialized_return" in result

    def test_lock_imbalance_routes_to_rule(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "return with lock held on error path"
        )
        if result is not None:
            assert "lock_imbalance" in result

    def test_bounds_check_routes_to_rule(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "array index sem_num used out of bounds without validation"
        )
        if result is not None:
            assert "missing_bounds_check" in result

    def test_copy_to_user_uninit_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "struct not fully initialized before copy_to_user — info leak"
        )
        if result is not None:
            assert "copy_to_user_uninit" in result

    def test_leak_kernel_memory_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "may leak uninitialized kernel memory to userspace"
        )
        if result is not None:
            assert "copy_to_user_uninit" in result

    def test_toctou_routes_to_double_fetch(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "TOCTOU vulnerability via double copy_from_user"
        )
        if result is not None:
            assert "double_fetch" in result

    def test_list_corruption_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "linked list corruption via list_del during iteration"
        )
        if result is not None:
            assert "unsafe_list_del" in result

    def test_rcu_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "rcu_dereference without rcu_read_lock held"
        )
        if result is not None:
            assert "rcu" in result

    def test_uid_truncation_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "truncating conversion of UID from 32-bit to 16-bit"
        )
        if result is not None:
            assert "uid_truncation" in result

    def test_resource_leak_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "resource leak if creating the root dentry fails"
        )
        if result is not None:
            assert "resource_leak_err" in result

    def test_race_condition_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "race condition leads to use-after-free on shared object"
        )
        if result is not None:
            assert "use_after_unlock" in result

    def test_freed_while_routes(self):
        from core.audit.orchestrator import _hypothesis_to_cocci_check
        result = _hypothesis_to_cocci_check(
            "structure can be freed while still in use by another thread"
        )
        if result is not None:
            assert "use_after_unlock" in result

    def test_underflow_routes_to_smt(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb(
            "integer underflow in use_global_lock"
        ) == "check-overflow"

    def test_double_free_no_smt(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb(
            "double-free vulnerability when called twice"
        ) is None


class TestCheckFindingGates:
    """Fast unit tests for _check_finding_gates G2 gate."""

    def _outcome(self, evidence_tool="", hypothesis="overflow"):
        return ReviewOutcome(
            file="a.c", function="f",
            status="finding", body="bad",
            hypothesis=hypothesis,
            evidence_tool=evidence_tool,
        )

    def test_g2_empty_evidence(self):
        v = _check_finding_gates(self._outcome(evidence_tool=""))
        assert any("G2" in x for x in v)

    def test_g2_llm_evidence(self):
        v = _check_finding_gates(self._outcome(evidence_tool="llm"))
        assert any("G2" in x for x in v)

    def test_g2_llm_review_evidence(self):
        v = _check_finding_gates(self._outcome(evidence_tool="llm review"))
        assert any("G2" in x for x in v)

    def test_g2_manual_review_evidence(self):
        v = _check_finding_gates(self._outcome(evidence_tool="manual code review"))
        assert any("G2" in x for x in v)

    def test_g2_none_evidence(self):
        v = _check_finding_gates(self._outcome(evidence_tool="none"))
        assert any("G2" in x for x in v)

    def test_g2_real_tool_passes(self):
        v = _check_finding_gates(self._outcome(evidence_tool="semgrep:sql-injection"))
        assert not any("G2" in x for x in v)

    def test_g2_prefilter_passes(self):
        v = _check_finding_gates(self._outcome(evidence_tool="prefilter:buffer-overflow"))
        assert not any("G2" in x for x in v)

    def test_g2_joern_passes(self):
        v = _check_finding_gates(self._outcome(evidence_tool="joern"))
        assert not any("G2" in x for x in v)

    def test_g2_review_result_joern_without_stamp_rejected(self):
        """LLM writes 'joern' into review_result but no tool actually ran."""
        o = self._outcome(evidence_tool="")
        o.review_result = {"evidence_tool": "joern"}
        v = _check_finding_gates(o)
        assert any("G2" in x for x in v)

    def test_g2_review_result_with_stamp_passes(self):
        """review_result has raw LLM value but outcome.evidence_tool was stamped."""
        o = self._outcome(evidence_tool="joern")
        o.review_result = {"evidence_tool": "joern"}
        v = _check_finding_gates(o)
        assert not any("G2" in x for x in v)

    def test_g2_llm_claimed_prefix_rejected(self):
        v = _check_finding_gates(self._outcome(evidence_tool="llm-claimed:joern"))
        assert any("G2" in x for x in v)

    def test_g5_memory_cwe_in_python_file(self):
        o = ReviewOutcome(
            file="app/views.py", function="handle",
            status="finding", body="overflow", hypothesis="buffer overflow",
            evidence_tool="semgrep:overflow",
            review_result={"cwe_class": "CWE-120"},
        )
        v = _check_finding_gates(o)
        assert any("G5" in x for x in v)

    def test_g5_memory_cwe_in_c_file_passes(self):
        o = ReviewOutcome(
            file="src/parser.c", function="parse",
            status="finding", body="overflow", hypothesis="buffer overflow",
            evidence_tool="semgrep:overflow",
            review_result={"cwe_class": "CWE-120"},
        )
        v = _check_finding_gates(o)
        assert not any("G5" in x for x in v)

    def test_g5_non_memory_cwe_in_python_passes(self):
        o = ReviewOutcome(
            file="app/views.py", function="query",
            status="finding", body="sqli", hypothesis="sql injection",
            evidence_tool="semgrep:sqli",
            review_result={"cwe_class": "CWE-89"},
        )
        v = _check_finding_gates(o)
        assert not any("G5" in x for x in v)

    def test_g5_memory_cwe_in_java_file(self):
        o = ReviewOutcome(
            file="src/Main.java", function="run",
            status="finding", body="use-after-free", hypothesis="UAF",
            evidence_tool="joern",
            review_result={"cwe_class": "CWE-416"},
        )
        v = _check_finding_gates(o)
        assert any("G5" in x for x in v)


@pytest.mark.slow
class TestGateEnforcement:
    """Test G1/G2 gate enforcement in _commit_outcome."""

    def test_finding_without_hypothesis_demoted_by_gate(self, tmp_path: Path):
        """G1: finding without hypothesis gets demoted to suspicious."""
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="I think this is bad",
                hypothesis="",
                evidence_tool="semgrep:sql-injection",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.findings == 0
        assert result.suspicious == 0

    def test_finding_without_evidence_demoted_by_gate(self, tmp_path: Path):
        """G2: finding without evidence_tool gets demoted to suspicious."""
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="SQL injection here",
                hypothesis="SQL injection via string format",
                evidence_tool="",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.findings == 0
        assert result.suspicious == 0

    def test_finding_with_llm_evidence_demoted_by_gate(
        self, tmp_path: Path, monkeypatch,
    ):
        """G2: finding with evidence_tool='llm' gets demoted to
        suspicious, then mechanically resolved (clean/dark) by
        _resolve_gate_demoted."""
        target, out = _setup_target(tmp_path)

        # Hermetic: on hosts with a live LLM transport, the dark-verify
        # pass builds its own LLMClient, synthesizes a witness for the
        # gate-demoted outcome, and can re-promote it to finding —
        # making the assertions depend on a real model's verdict (and
        # billing real money per test run).
        import core.audit.orchestrator as _orch
        monkeypatch.setattr(
            _orch, "_run_dark_verification", lambda *a, **kw: None,
        )

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="Buffer overflow here",
                hypothesis="Stack overflow via unchecked length",
                evidence_tool="llm",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
            # Hermetic: see TestSuspiciousPromotion — the Joern-gated
            # suspicious demotion must not decide this test's outcome.
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)
        assert result.findings == 0
        assert result.suspicious == 0

    def test_finding_with_both_passes_gate(self, tmp_path: Path):
        """Finding with hypothesis + evidence passes gates."""
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            if call_count[0] == 1:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="SQL injection confirmed",
                    hypothesis="SQL injection via string format",
                    evidence_tool="semgrep:sql-injection",
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            max_refinements=0,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.findings == 1
        assert result.clean == 1

    def test_gate_violation_logged_in_audit_trail(self, tmp_path: Path):
        """Gate violations should appear in the audit log."""
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="no hypothesis no evidence",
                hypothesis="",
                evidence_tool="",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
            # Hermetic: with a live Joern server the suspicious-demotion
            # gate rewrites the G1-demoted verdict to clean, and the
            # log loses both markers this test asserts on.
            joern_overrides={"enabled": False},
        )
        run_orchestrator(config, review_fn)

        log = (out / ".audit-log.jsonl").read_text()
        assert "G1" in log or "suspicious" in log


@pytest.mark.slow
class TestSuspiciousPromotion:
    """Sweep tools should promote suspicious items when they confirm the hypothesis."""

    def test_suspicious_with_prefilter_hit_promoted(self, tmp_path: Path):
        """Suspicious item whose source triggers prefilter gets promoted to finding."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "vuln.c").write_text(
            "void process(char *input) {\n"
            "  char buf[64];\n"
            "  strcpy(buf, input);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [
                {
                    "path": "src/vuln.c",
                    "items": [
                        {"name": "process", "line_start": 1, "line_end": 4, "sloc": 4},
                    ],
                },
            ],
            "metadata": {"total_items": 1, "total_sloc": 4},
        }
        import json
        (out / "checklist.json").write_text(json.dumps(checklist))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="strcpy with unbounded input",
                hypothesis="buffer overflow via strcpy",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
            # Hermetic: with Joern installed, the suspicious-demotion
            # gate (suspicious + no verification evidence -> clean)
            # would flip the stubbed verdict before the sweep promotes
            # it, making the assertions host-dependent.
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_promoted >= 1
        assert result.findings >= 1
        promoted = [o for o in result.outcomes if o.status == "finding"]
        assert len(promoted) >= 1
        assert "prefilter:" in promoted[0].evidence_tool

    def test_suspicious_without_hypothesis_stays_suspicious(self, tmp_path: Path):
        """Suspicious items with no hypothesis are not promoted."""
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="something looks off",
                hypothesis="",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
            # Hermetic: with Joern installed, the post-resolution
            # channel settles the unverifiable suspicious verdicts as
            # "dark" (no tool could confirm or refute) — and spends
            # live LLM calls getting there when the host has a
            # configured provider. The assertions below are about
            # sweep promotion, not host tooling. Same pin as
            # test_suspicious_with_prefilter_hit_promoted.
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_promoted == 0
        assert result.findings == 0
        # Demotion gate may convert suspicious→clean when Joern is available
        assert result.suspicious + result.clean == 2

    def test_promotion_disabled_when_sweep_off(self, tmp_path: Path):
        """No promotion when sweep_validate_findings=False."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "vuln.c").write_text(
            "void process(char *input) {\n"
            "  char buf[64];\n"
            "  strcpy(buf, input);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [
                {
                    "path": "src/vuln.c",
                    "items": [
                        {"name": "process", "line_start": 1, "line_end": 4, "sloc": 4},
                    ],
                },
            ],
            "metadata": {"total_items": 1, "total_sloc": 4},
        }
        import json
        (out / "checklist.json").write_text(json.dumps(checklist))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="strcpy with unbounded input",
                hypothesis="buffer overflow via strcpy",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_promoted == 0
        assert result.findings == 0


    def test_counter_hypothesis_blocks_promotion(self, tmp_path: Path):
        """Suspicious item with a specific counter-hypothesis is NOT promoted."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "vuln.c").write_text(
            "void req_free(struct Request *req) {\n"
            "  if (req->body) {\n"
            "    free(req->body);\n"
            "    req->body = NULL;\n"
            "  }\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        import json
        checklist = {
            "files": [
                {
                    "path": "src/vuln.c",
                    "items": [
                        {"name": "req_free", "line_start": 1, "line_end": 6, "sloc": 6},
                    ],
                },
            ],
            "metadata": {"total_items": 1, "total_sloc": 6},
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="check-then-free pattern",
                hypothesis="double free via TOCTOU race condition",
                review_result={
                    "status": "suspicious",
                    "body": "check-then-free pattern",
                    "hypothesis": "double free via TOCTOU race condition",
                    "hypotheses": [
                        {
                            "mechanism": "double free via TOCTOU race condition",
                            "confidence": "medium",
                            "counter": (
                                "This server is single-threaded — there is no "
                                "concurrent access to the Request structure, so "
                                "the TOCTOU window cannot be hit"
                            ),
                        },
                    ],
                },
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_promoted == 0, (
            "should not promote when LLM has a specific counter-hypothesis"
        )
        assert result.findings == 0
        # The item must never become a finding.  Its resting status is
        # environment-dependent: bare hosts keep it suspicious, while
        # tool-equipped hosts may triage-skip it or apply the
        # Joern-conditional suspicious-demotion gate (both → clean).
        assert result.suspicious + result.clean == 1
        assert all(o.status != "finding" for o in result.outcomes)


class TestResolveGateDemoted:
    """Gate-demoted suspicious → clean when no mechanical tool corroborates."""

    def _make_result(self, *outcomes):
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        return r

    def test_g2_demoted_resolves_to_dark_without_tool_coverage(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "safe.c").write_text(
            "int safe_fn(int x) { return x + 1; }\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "safe.c",
                "items": [{"name": "safe_fn", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="safe.c", function="safe_fn", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(result, config, sarif_cache=None, checklist=checklist)
        assert result.outcomes[0].status == "dark"
        assert result.suspicious == 0

    def test_self_contradiction_resolves_to_dark_without_tool_coverage(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "safe.c").write_text(
            "int safe_fn(int x) { return x + 1; }\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "safe.c",
                "items": [{"name": "safe_fn", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="safe.c", function="safe_fn", status="suspicious",
            body="[self-contradiction: the finding description asserts the code is safe]",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(result, config, sarif_cache=None, checklist=checklist)
        assert result.outcomes[0].status == "dark"
        assert result.suspicious == 0

    def test_stays_suspicious_with_prefilter_hit(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "risky.c").write_text(
            "void process(char *input) {\n"
            "  char buf[64];\n"
            "  strcpy(buf, input);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "risky.c",
                "items": [{"name": "process", "line_start": 1, "line_end": 4}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="risky.c", function="process", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(result, config, sarif_cache=None, checklist=checklist)
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1
        assert result.clean == 0

    def test_non_gate_suspicious_untouched(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="something looks off",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(result, config, sarif_cache=None, checklist={})
        assert result.outcomes[0].status == "suspicious"

    def test_finding_status_untouched(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="finding",
            body="real bug here", line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(result, config, sarif_cache=None, checklist={})
        assert result.outcomes[0].status == "finding"

    def test_semantic_confidence_high_rescues_from_clean(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "auth.c").write_text(
            "int check_uid(int uid) {\n"
            "    if (uid = 0)\n"
            "        return 1;\n"
            "    return 0;\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "auth.c",
                "items": [{"name": "check_uid", "line_start": 1, "line_end": 5}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="auth.c", function="check_uid", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="line 2 uses `=` instead of `==` in a conditional",
            line=1,
        )
        outcome.semantic_confidence = "high"
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"prefilter": True},
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_semantic_confidence_low_still_resolved_to_clean(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="integer overflow in addition",
            line=1,
        )
        # SMT actually RAN for this function and stayed silent —
        # covered==ran semantics require the dispatch record.
        outcome.tools_dispatched = {"smt"}
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"prefilter": True, "smt": True},
        )
        assert result.outcomes[0].status == "clean"

    def test_covered_class_without_dispatch_record_resolves_dark(self, tmp_path: Path):
        """Installed-but-never-ran is NOT coverage: the same outcome
        with no dispatch record routes to dark, not clean."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="integer overflow in addition",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"prefilter": True, "smt": True},
        )
        assert result.outcomes[0].status == "dark"

    def test_errored_channel_routes_to_dark_not_clean(self, tmp_path: Path):
        """A dispatched channel that errored/timed out did not run —
        it must not convert the outcome into a clean verdict."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="integer overflow in addition",
            line=1,
        )
        outcome.tools_dispatched = {"smt"}
        outcome.tools_errored = {"smt"}
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"prefilter": True, "smt": True},
        )
        assert result.outcomes[0].status == "dark"

    def test_plain_suspicious_resolved_when_joern_up(self, tmp_path: Path):
        """Replacement for the in-loop Joern-up demotion: evidence-free
        plain suspicious outcomes resolve here (class/error-aware)."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        # Tool-blind hypothesis, nothing ran → dark (old gate: clean).
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="looks like an auth bypass",
            hypothesis="authorization bypass in role check",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status == "dark"
        assert result.outcomes[0].body.startswith("[suspicious-resolution:")

    def test_plain_suspicious_with_silent_covering_channel_resolves_clean(
        self, tmp_path: Path,
    ):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="possible overflow",
            hypothesis="integer overflow in addition",
            line=1,
        )
        outcome.tools_dispatched = {"smt"}
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"joern": True, "smt": True},
        )
        assert result.outcomes[0].status == "clean"

    def test_plain_suspicious_with_verification_evidence_untouched(
        self, tmp_path: Path,
    ):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="tool-backed", hypothesis="integer overflow",
            evidence_tool="semgrep:rule-1",
            line=1,
        )
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist={},
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status == "suspicious"


    def test_provenance_all_trusted_overrides_corroboration(self, tmp_path: Path):
        """When all inputs are trusted, detection-only corroboration is overridden."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "safe.c").write_text(
            "void process(char *input) {\n"
            "  char buf[64];\n"
            "  strcpy(buf, input);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "safe.c",
                "items": [{"name": "process", "line_start": 1, "line_end": 4}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="safe.c", function="process", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="buffer overflow in strcpy",
            line=1,
        )
        outcome.provenance_all_trusted = True
        outcome.evidence_tool = "joern"
        # A covering channel (codeql for CWE-120) ran and stayed silent.
        outcome.tools_dispatched = {"codeql"}
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"prefilter": True, "codeql": True},
        )
        # Prefilter would normally corroborate (strcpy), but provenance
        # override lets it fall through to covered-and-ran → clean.
        assert result.outcomes[0].status == "clean"

    def test_provenance_smt_evidence_not_overridden(self, tmp_path: Path):
        """SMT evidence is never overridden by provenance."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "risky.c").write_text(
            "void process(char *input) {\n"
            "  char buf[64];\n"
            "  strcpy(buf, input);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "risky.c",
                "items": [{"name": "process", "line_start": 1, "line_end": 4}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="risky.c", function="process", status="suspicious",
            body="[gate violation: G2: finding emitted without tool-grounded evidence]",
            hypothesis="buffer overflow in strcpy",
            line=1,
        )
        outcome.provenance_all_trusted = True
        outcome.evidence_tool = "smt"
        result = self._make_result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
        )
        # SMT evidence is immune to provenance override — stays suspicious
        assert result.outcomes[0].status == "suspicious"


def _gate_outcome(evidence_tool: str = "", review: dict | None = None) -> ReviewOutcome:
    return ReviewOutcome(
        file="src/a.c",
        function="f",
        status="suspicious",
        body="",
        evidence_tool=evidence_tool,
        review_result=review,
    )


class TestReviewFallbackSanitised:
    """LLM evidence_tool sentinels must not defeat the suspicious→clean gate.

    _is_verification_evidence_for_gate falls back to the RAW LLM
    review["evidence_tool"] when the outcome carries no genuine stamp.
    That fallback must go through _sanitize_llm_et — otherwise an
    LLM-emitted sentinel like "none" (which is not a _NON_MECHANICAL
    prefix) passes pipeline._is_verification_evidence and silently blocks
    the Joern-era demotion gate."""

    @pytest.mark.parametrize("sentinel", [
        "none", "n/a", "manual", "None", "N/A", "Manual",
        "manual code review", "manual review", "code review",
        "llm", "llm review", "  none  ",
    ])
    def test_llm_sentinel_is_not_verification_evidence(self, sentinel):
        outcome = _gate_outcome(review={"evidence_tool": sentinel})
        assert _is_verification_evidence_for_gate(outcome) is False

    def test_llm_freeform_tool_claim_is_not_verification_evidence(self):
        # A hallucinated tool name must land under llm-claimed:, which
        # pipeline._is_verification_evidence rejects as non-mechanical.
        outcome = _gate_outcome(review={"evidence_tool": "semgrep"})
        assert _is_verification_evidence_for_gate(outcome) is False

    @pytest.mark.parametrize("joined", [
        "none+manual",
        "manual+none",
        "semgrep+manual",
        "none+n/a+manual",
    ])
    def test_plus_joined_llm_values_sanitised_per_part(self, joined):
        # Sanitizing the joined string whole would prefix only the first
        # part — every part must be sanitised before the "+" split.
        outcome = _gate_outcome(review={"evidence_tool": joined})
        assert _is_verification_evidence_for_gate(outcome) is False

    def test_empty_review_fallback_is_not_verification_evidence(self):
        assert _is_verification_evidence_for_gate(_gate_outcome(review={})) is False
        assert _is_verification_evidence_for_gate(_gate_outcome(review=None)) is False


class TestGenuineOutcomeStampUnchanged:
    def test_genuine_outcome_stamp_still_counts(self):
        # outcome.evidence_tool is pipeline-controlled — genuine stamps
        # keep their gate protection (sanitizing them was a regression).
        outcome = _gate_outcome(evidence_tool="joern:flow")
        assert _is_verification_evidence_for_gate(outcome) is True

    def test_genuine_stamp_wins_over_review_sentinel(self):
        outcome = _gate_outcome(
            evidence_tool="joern:flow",
            review={"evidence_tool": "none"},
        )
        assert _is_verification_evidence_for_gate(outcome) is True

    def test_prefilter_stamp_is_not_verification(self):
        outcome = _gate_outcome(evidence_tool="prefilter:some-rule")
        assert _is_verification_evidence_for_gate(outcome) is False


class TestRejournalFinalStatuses:
    """Journal entries are committed mid-loop, pre-resolution — the
    end-of-run pass appends corrective entries so the journal (and
    everything reading it) reflects final statuses, dark included."""

    def _setup(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def _journal_initial(self, config, status="suspicious"):
        from core.audit.collector import append_journal_for_outcome
        initial = ReviewOutcome(
            file="a.c", function="f", status=status,
            body="initial", hypothesis="auth bypass", line=1,
        )
        append_journal_for_outcome(
            out_dir=config.out_dir,
            target_path=config.target_path,
            run_id="run-1",
            outcome=initial,
            gap={"line_start": 1},
        )

    def test_drifted_status_rejournaled(self, tmp_path: Path):
        from core.audit.journal import latest_entries, make_function_key
        from core.audit.orchestrator import _rejournal_final_statuses

        config = self._setup(tmp_path)
        self._journal_initial(config, status="suspicious")

        final = ReviewOutcome(
            file="a.c", function="f", status="dark",
            body="resolved dark", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        updated = _rejournal_final_statuses(result, config)
        assert updated == 1
        entries = latest_entries(config.out_dir)
        key = make_function_key("a.c", "f")
        assert entries[key].verdict == "dark"

    def test_unchanged_status_not_rejournaled(self, tmp_path: Path):
        from core.audit.orchestrator import _rejournal_final_statuses

        config = self._setup(tmp_path)
        self._journal_initial(config, status="suspicious")

        final = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="still suspicious", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _rejournal_final_statuses(result, config) == 0

    def test_never_journaled_outcome_skipped(self, tmp_path: Path):
        from core.audit.orchestrator import _rejournal_final_statuses

        config = self._setup(tmp_path)
        final = ReviewOutcome(
            file="a.c", function="f", status="dark",
            body="resolved dark", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _rejournal_final_statuses(result, config) == 0


class TestRefutationGateWirePoint:
    """Refutation gates demote findings/suspicious via the orchestrator wire point."""

    @pytest.fixture(autouse=True)
    def _hermetic_tool_layer(self, monkeypatch):
        """These tests pin gate WIRING, not sweep behaviour.

        Left unstubbed, the outcome depends on which external tools
        are installed: a locally-installed semgrep re-confirming the
        planted hypothesis masked a gate regression that only CI
        (where the sweep found nothing) caught, and Joern server
        startup adds minutes per test.  "No tool confirmation" is the
        deterministic baseline the gate assertions are written
        against.
        """
        import core.audit.orchestrator as _orch

        monkeypatch.setattr(_orch, "_run_tool_chain", lambda *a, **k: [])
        monkeypatch.setattr(
            _orch, "_start_joern_server_raw", lambda *a, **k: None,
        )

    def test_race_in_single_threaded_demoted_to_clean(self, tmp_path: Path):
        """Architecture gate demotes a race-condition finding to clean."""
        target = tmp_path / "target"
        target.mkdir()
        src = target / "src"
        src.mkdir()
        (src / "net.c").write_text(
            "void newaddress(void) {\n"
            "  // single-threaded event-driven program\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "src/net.c",
                "items": [
                    {"name": "newaddress", "line_start": 1, "line_end": 3,
                     "sloc": 3},
                ],
            }],
            "metadata": {"total_items": 1, "total_sloc": 3},
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        # Domain model says single-threaded
        dm = {
            "architecture": {"threading_model": "single_threaded"},
            "contracts": [],
        }
        (out / "domain-model.json").write_text(json.dumps(dm))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="race condition on shared state",
                hypothesis="data race in newaddress concurrent modification",
                review_result={"cwe": "CWE-362"},
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        # The refutation gate should demote to clean
        assert result.findings == 0
        outcomes = [o for o in result.outcomes if o.function == "newaddress"]
        assert len(outcomes) == 1
        assert outcomes[0].status == "clean"
        assert "architecture" in outcomes[0].body

    def test_tool_confirmed_finding_not_refuted(self, tmp_path: Path):
        """Finding with tool evidence is not touched by refutation gates.

        The reachability gate (G7) may still demote the finding for
        other reasons (no callers), but the refutation gate must not
        fire — tool evidence protects it.
        """
        target = tmp_path / "target"
        target.mkdir()
        src = target / "src"
        src.mkdir()
        (src / "net.c").write_text(
            "void newaddress(void) {\n"
            "  // has a real race confirmed by a tool\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "src/net.c",
                "items": [
                    {"name": "newaddress", "line_start": 1, "line_end": 3,
                     "sloc": 3},
                ],
            }],
            "metadata": {"total_items": 1, "total_sloc": 3},
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        dm = {
            "architecture": {"threading_model": "single_threaded"},
            "contracts": [],
        }
        (out / "domain-model.json").write_text(json.dumps(dm))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="race condition confirmed by tool",
                hypothesis="data race in newaddress concurrent modification",
                evidence_tool="semgrep:race-detect",
                review_result={"cwe": "CWE-362"},
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        outcomes = [o for o in result.outcomes if o.function == "newaddress"]
        assert len(outcomes) == 1
        # Refutation gate must not have fired — no "[architecture:" in body
        assert "architecture" not in outcomes[0].body
        # Tool evidence still present
        assert outcomes[0].evidence_tool == "semgrep:race-detect"

    def test_hypothesis_promoted_race_refuted_post_loop(self, tmp_path: Path):
        """Race hypothesis promoted by hypothesis-consistency is caught
        by the post-promote refutation gate.

        Flow: LLM returns clean with high-confidence CWE-362 hypothesis
        → hypothesis-consistency promotes to suspicious → refutation gate
        catches the race-in-single-threaded and demotes back to clean.
        """
        target = tmp_path / "target"
        target.mkdir()
        src = target / "src"
        src.mkdir()
        (src / "cache.c").write_text(
            "void cache_update(void) {\n"
            "  // updates cache entries\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "src/cache.c",
                "items": [
                    {"name": "cache_update", "line_start": 1, "line_end": 3,
                     "sloc": 3},
                ],
            }],
            "metadata": {"total_items": 1, "total_sloc": 3},
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        dm = {
            "architecture": {"threading_model": "single_threaded"},
            "contracts": [],
        }
        (out / "domain-model.json").write_text(json.dumps(dm))

        def review_fn(ctx, config):
            # LLM says clean but retains a high-confidence race hypothesis
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="no issues found",
                hypothesis="race condition on cache entries",
                hypotheses=[{
                    "mechanism": "race condition on shared cache: "
                                "concurrent threads modify cache entries "
                                "without synchronisation",
                    "confidence": "high",
                    # No counter — LLM contradicts itself
                }],
                review_result={"cwe": "CWE-362"},
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, review_fn)
        outcomes = [o for o in result.outcomes if o.function == "cache_update"]
        assert len(outcomes) == 1
        # Hypothesis-consistency promoted clean → suspicious,
        # then refutation gate demoted suspicious → clean
        assert outcomes[0].status == "clean"
        assert "architecture" in outcomes[0].body


class TestHasRefutingCounter:
    """Unit tests for _has_refuting_counter."""

    def test_no_hypotheses_returns_false(self):
        from core.audit.orchestrator import _has_refuting_counter
        o = ReviewOutcome(file="f", function="g", status="suspicious", body="x")
        assert not _has_refuting_counter(o)

    def test_dismissive_counter_returns_false(self):
        from core.audit.orchestrator import _has_refuting_counter
        o = ReviewOutcome(
            file="f", function="g", status="suspicious", body="x",
            review_result={
                "hypotheses": [{
                    "mechanism": "overflow",
                    "confidence": "medium",
                    "counter": "no plausible attack vector exists",
                }],
            },
        )
        assert not _has_refuting_counter(o)

    def test_short_counter_returns_false(self):
        from core.audit.orchestrator import _has_refuting_counter
        o = ReviewOutcome(
            file="f", function="g", status="suspicious", body="x",
            review_result={
                "hypotheses": [{
                    "mechanism": "overflow",
                    "confidence": "medium",
                    "counter": "safe",
                }],
            },
        )
        assert not _has_refuting_counter(o)

    def test_specific_counter_returns_true(self):
        from core.audit.orchestrator import _has_refuting_counter
        o = ReviewOutcome(
            file="f", function="g", status="suspicious", body="x",
            review_result={
                "hypotheses": [{
                    "mechanism": "double free via TOCTOU",
                    "confidence": "medium",
                    "counter": (
                        "This server is single-threaded so the race "
                        "condition window cannot be hit in practice"
                    ),
                }],
            },
        )
        assert _has_refuting_counter(o)

    def test_refuted_hypothesis_ignored(self):
        from core.audit.orchestrator import _has_refuting_counter
        o = ReviewOutcome(
            file="f", function="g", status="suspicious", body="x",
            review_result={
                "hypotheses": [{
                    "mechanism": "overflow",
                    "confidence": "refuted",
                    "counter": (
                        "This server is single-threaded so the race "
                        "condition window cannot be hit in practice"
                    ),
                }],
            },
        )
        assert not _has_refuting_counter(o)

    def test_refuted_hypothesis_case_insensitive(self):
        from core.audit.orchestrator import _has_refuting_counter
        for variant in ("Refuted", "REFUTED", "rEfUtEd"):
            o = ReviewOutcome(
                file="f", function="g", status="suspicious", body="x",
                review_result={
                    "hypotheses": [{
                        "mechanism": "overflow",
                        "confidence": variant,
                        "counter": (
                            "This server is single-threaded so the race "
                            "condition window cannot be hit in practice"
                        ),
                    }],
                },
            )
            assert not _has_refuting_counter(o), (
                f"confidence={variant!r} should be treated as refuted"
            )


def _unlink_chain_rules(chain):
    """Remove the on-disk audit_sweep_ rule files a chain carries.

    Production unlinks them in _run_tool_chain's finally; tests that
    only build the chain must clean up themselves or every run strands
    rule files in the system temp dir.
    """
    import os
    for entry in chain:
        rule = entry.get("config", {}).get("rule") or ""
        if isinstance(rule, str) and \
                os.path.basename(rule).startswith("audit_sweep_"):
            Path(rule).unlink(missing_ok=True)


class TestToolChain:
    """Test _hypothesis_to_tool_chain and _run_tool_chain."""

    def test_chain_returns_multiple_tools(self):
        chain = _hypothesis_to_tool_chain(
            "out-of-bounds array index without validation",
            "sem.c",
        )
        types = [e["type"] for e in chain]
        _unlink_chain_rules(chain)
        assert "smt" in types
        assert "coccinelle" in types

    def test_chain_empty_for_unmatched(self):
        chain = _hypothesis_to_tool_chain(
            "the function has unusual formatting and long lines",
            "shm.c",
        )
        assert chain == []

    def test_caller_context_hypotheses_dispatch_boundary_channel(self):
        # Caller-contract shapes are no longer chain-less: the
        # api-boundary channel adjudicates them at the call sites.
        chain = _hypothesis_to_tool_chain(
            "the function trusts its calling context",
            "shm.c",
        )
        assert [e["type"] for e in chain] == ["api_boundary"]

    def test_chain_single_tool(self):
        chain = _hypothesis_to_tool_chain(
            "race condition leads to use-after-free",
            "shm.c",
        )
        types = [e["type"] for e in chain]
        _unlink_chain_rules(chain)
        assert "coccinelle" in types

    def test_chain_preserves_order(self):
        chain = _hypothesis_to_tool_chain(
            "buffer overflow via strcpy call",
            "msg.c",
        )
        types = [e["type"] for e in chain]
        _unlink_chain_rules(chain)
        assert types.index("semgrep") < types.index("smt")

    def test_run_chain_fallback_on_error(self, tmp_path: Path, monkeypatch):
        """When first tool errors, second tool still runs."""
        from core.audit import orchestrator as orch_mod
        from core.audit.sweep import SweepResult

        call_log = []

        def mock_semgrep(**kw):
            call_log.append("semgrep")
            return SweepResult(
                tool="semgrep", file_path=kw["file_path"],
                function_name=kw["function_name"],
                outcome="error", errors=["semgrep not installed"],
            )

        def mock_smt(**kw):
            call_log.append("smt")
            return SweepResult(
                tool="smt", file_path=kw["file_path"],
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_semgrep_sweep", mock_semgrep)
        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)

        chain = [
            {"type": "semgrep", "config": {"rule": "fake.yaml"}},
            {"type": "smt", "config": {"verb": "check-oob"}},
        ]
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="foo", source="int x;",
            hypothesis="out of bounds",
        )
        assert "semgrep" in call_log
        assert "smt" in call_log
        assert confirmed == ["smt:check-oob"]

    def test_run_chain_multi_confirm(self, tmp_path: Path, monkeypatch):
        """When both tools confirm, both appear in result."""
        from core.audit import orchestrator as orch_mod
        from core.audit.sweep import SweepResult

        def mock_smt(**kw):
            return SweepResult(
                tool="smt", file_path=kw["file_path"],
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        def mock_cocci(**kw):
            return SweepResult(
                tool="coccinelle", file_path=kw.get("file_path", "<codebase>"),
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_coccinelle_sweep", mock_cocci)

        chain = [
            {"type": "smt", "config": {"verb": "check-oob"}},
            {"type": "coccinelle", "config": {"rule": "/tmp/fake.cocci"}},
        ]
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="foo", source="int x;",
            hypothesis="out of bounds",
        )
        assert len(confirmed) == 2
        assert "smt:check-oob" in confirmed
        assert "coccinelle:fake" in confirmed

    def test_run_chain_exception_skips_tool(self, tmp_path: Path, monkeypatch):
        """An exception in one tool doesn't abort the chain."""
        from core.audit import orchestrator as orch_mod
        from core.audit.sweep import SweepResult

        def mock_smt(**kw):
            raise RuntimeError("Z3 not installed")

        def mock_cocci(**kw):
            return SweepResult(
                tool="coccinelle", file_path=kw.get("file_path", "<codebase>"),
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_coccinelle_sweep", mock_cocci)

        chain = [
            {"type": "smt", "config": {"verb": "check-oob"}},
            {"type": "coccinelle", "config": {"rule": "/tmp/test.cocci"}},
        ]
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="foo", source="int x;",
            hypothesis="out of bounds",
        )
        assert confirmed == ["coccinelle:test"]

    def test_evidence_label_joined(self, tmp_path: Path, monkeypatch):
        """Multi-tool evidence is joined with '+' in the outcome."""
        from core.audit import orchestrator as orch_mod
        from core.audit.sweep import SweepResult

        def mock_smt(**kw):
            return SweepResult(
                tool="smt", file_path=kw["file_path"],
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        def mock_cocci(**kw):
            return SweepResult(
                tool="coccinelle", file_path=kw.get("file_path", "<codebase>"),
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_coccinelle_sweep", mock_cocci)

        chain = [
            {"type": "smt", "config": {"verb": "check-oob"}},
            {"type": "coccinelle", "config": {"rule": "/tmp/bounds.cocci"}},
        ]
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="foo", source="int x;",
            hypothesis="out of bounds",
        )
        label = "+".join(confirmed)
        assert label == "smt:check-oob+coccinelle:bounds"


class TestJoernLiveQuery:
    """Test _joern_live_query and joern:live wiring in _run_tool_chain."""

    def test_live_query_returns_flows(self):
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        server = MagicMock()
        flow = TaintFlow(
            source_method="parse_header", source_param="buf",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server.run_taint_query.return_value = [flow]

        result = _joern_live_query(server, "parse_header", ["memcpy"])
        assert len(result) == 1
        assert result[0].sink_call == "memcpy"
        server.run_taint_query.assert_called_once_with(
            "parse_header", "memcpy", timeout=30,
        )

    def test_live_query_short_circuits_on_first_hit(self):
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        server = MagicMock()
        flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="strcpy", sink_arg_idx=0,
        )
        server.run_taint_query.return_value = [flow]

        result = _joern_live_query(server, "fn", ["strcpy", "memcpy"])
        assert len(result) == 1
        server.run_taint_query.assert_called_once()

    def test_live_query_empty_when_no_flows(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_query.return_value = []

        result = _joern_live_query(server, "fn", ["memcpy", "strcpy"])
        assert result == []
        assert server.run_taint_query.call_count == 2

    def test_live_query_rejects_invalid_function_name(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        result = _joern_live_query(server, "not valid!", ["memcpy"])
        assert result == []
        server.run_taint_query.assert_not_called()

    def test_live_query_skips_invalid_sink(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_query.return_value = []
        _joern_live_query(server, "fn", ["bad;sink", "memcpy"])
        assert server.run_taint_query.call_count == 1
        call_args = server.run_taint_query.call_args
        assert call_args[0][1] == "memcpy"

    def test_live_query_handles_exception(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_query.side_effect = RuntimeError("timeout")

        result = _joern_live_query(server, "fn", ["memcpy"])
        assert result == []

    def test_tool_chain_joern_live_fallback(self, tmp_path: Path):
        """When pre-sweep has no hit and server is available, fires live query."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        server = MagicMock()
        flow = TaintFlow(
            source_method="fn", source_param="buf",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server.run_taint_query.return_value = [flow]

        chain = [{"type": "joern", "config": {"sinks": ["memcpy"]}}]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="fn", source="int x;",
            hypothesis="buffer overflow via memcpy",
            joern_server=server,
        )
        assert "joern:live" in confirmed

    def test_tool_chain_joern_presweep_hit_skips_live(self, tmp_path: Path):
        """When pre-sweep index has a hit, live query is not fired."""
        from unittest.mock import MagicMock

        from core.evidence import EvidenceRecord

        server = MagicMock()

        rec = EvidenceRecord(
            file="test.c", function="fn",
            joern_flows=[{"source": "fn", "sink": "memcpy"}],
        )

        chain = [{"type": "joern", "config": {"sinks": ["memcpy"]}}]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="fn", source="int x;",
            hypothesis="buffer overflow",
            evidence_index={"test.c:fn": rec},
            joern_server=server,
        )
        assert "joern:pre_sweep" in confirmed
        server.run_taint_query.assert_not_called()

    def test_tool_chain_joern_no_server_skips(self, tmp_path: Path):
        """When no server and no pre-sweep hit, joern is skipped."""
        chain = [{"type": "joern", "config": {"sinks": ["memcpy"]}}]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        confirmed = _run_tool_chain(
            chain, config=config, file_path="test.c",
            function_name="fn", source="int x;",
            hypothesis="buffer overflow",
        )
        assert confirmed == []

    def test_dotted_sink_name_extracted(self):
        """For 'os.system', only 'system' is passed as the sink."""
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_query.return_value = []

        _joern_live_query(server, "fn", ["os.system"])
        call_args = server.run_taint_query.call_args
        assert call_args[0][1] == "system"


@pytest.mark.slow
class TestIterativeReReview:
    """Re-review callers of findings with propagated callee knowledge."""

    def test_caller_re_reviewed_when_callee_found_vulnerable(self, tmp_path: Path):
        """When callee is found vulnerable, its callers are re-reviewed
        with the callee finding injected as context."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "handler.c").write_text(
            "void process(char *input) {\n"
            "  dangerous(input);\n"
            "}\n"
            "\n"
            "void dangerous(char *buf) {\n"
            "  char local[64];\n"
            "  strcpy(local, buf);\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "src/handler.c",
                "items": [
                    {"name": "process", "line_start": 1, "line_end": 3},
                    {"name": "dangerous", "line_start": 5, "line_end": 8},
                ],
            }],
        }
        context_map = {
            "entry_points": [
                {"file": "src/handler.c", "name": "process"},
                {"file": "src/handler.c", "name": "dangerous"},
            ],
            "sinks": [],
            "trust_boundaries": [],
            "unchecked_flows": [],
            "call_edges": [
                {"caller": "process", "caller_file": "src/handler.c",
                 "callee": "dangerous"},
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        (out / "context-map.json").write_text(json.dumps(context_map))

        call_log = []

        def review_fn(ctx, config):
            has_callee_findings = bool(ctx.get("callee_findings"))
            call_log.append({
                "function": ctx["function"],
                "has_callee_findings": has_callee_findings,
            })
            if ctx["function"] == "dangerous":
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="strcpy overflow",
                    hypothesis="buffer overflow via strcpy(local, buf)",
                    evidence_tool="prefilter:unbounded-strcpy",
                    review_result={
                        "status": "finding",
                        "body": "strcpy overflow",
                        "hypothesis": "buffer overflow via strcpy(local, buf)",
                        "evidence_tool": "prefilter:unbounded-strcpy",
                    },
                )
            if has_callee_findings:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="passes unvalidated input to vulnerable dangerous()",
                    hypothesis="process proxies attacker input to strcpy overflow",
                    evidence_tool="prefilter:unbounded-strcpy",
                    review_result={
                        "status": "finding",
                        "body": "passes unvalidated input to vulnerable dangerous()",
                        "hypothesis": "process proxies attacker input",
                        "evidence_tool": "prefilter:unbounded-strcpy",
                    },
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="nothing remarkable",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False, batch_sloc_threshold=0,
            propagate_constraints=True,
            prefilter=False, max_refinements=0,
        )
        result = run_orchestrator(config, review_fn)

        re_reviews = [c for c in call_log if c["has_callee_findings"]]
        assert len(re_reviews) >= 1, f"expected re-review with callee_findings, got {call_log}"
        assert re_reviews[0]["function"] == "process"

        assert result.findings >= 2

    def test_no_re_review_when_no_findings(self, tmp_path: Path):
        """No re-review pass when the initial pass finds nothing."""
        target, out = _setup_target(tmp_path)

        call_count = [0]
        def review_fn(ctx, config):
            call_count[0] += 1
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0, propagate_constraints=True,
        )
        result = run_orchestrator(config, review_fn)
        assert call_count[0] == 2
        assert result.findings == 0

    def test_convergence_no_infinite_loop(self, tmp_path: Path):
        """Re-review converges — re-reviewed callers that stay clean
        don't trigger further iterations."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "chain.c").write_text(
            "void a(char *x) { b(x); }\n"
            "void b(char *y) { c(y); }\n"
            "void c(char *z) { strcpy(buf, z); }\n"
        )
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "src/chain.c",
                "items": [
                    {"name": "a", "line_start": 1, "line_end": 1},
                    {"name": "b", "line_start": 2, "line_end": 2},
                    {"name": "c", "line_start": 3, "line_end": 3},
                ],
            }],
        }
        context_map = {
            "call_edges": [
                {"caller": "a", "caller_file": "src/chain.c", "callee": "b"},
                {"caller": "b", "caller_file": "src/chain.c", "callee": "c"},
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        (out / "context-map.json").write_text(json.dumps(context_map))

        call_count = [0]

        def review_fn(ctx, config):
            call_count[0] += 1
            if ctx["function"] == "c":
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="finding",
                    body="strcpy overflow in c",
                    hypothesis="buffer overflow",
                    evidence_tool="prefilter:unbounded-strcpy",
                    review_result={
                        "status": "finding",
                        "body": "strcpy overflow",
                        "hypothesis": "buffer overflow",
                        "evidence_tool": "prefilter:unbounded-strcpy",
                    },
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
            propagate_constraints=True,
        )
        run_orchestrator(config, review_fn)

        # 3 initial + at most 2 re-reviews (b is caller of c, a is caller of b)
        # but b and a stay clean on re-review, so no further iterations
        assert call_count[0] <= 5, (
            f"expected convergence, got {call_count[0]} calls"
        )


@pytest.mark.slow
class TestSessionObservations:
    """Session context: observations accumulate across reviews."""

    def test_observations_accumulate(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text(
            "void f1() { /* 10 lines */ }\n" * 10
            + "void f2() { /* 10 lines */ }\n" * 10
        )
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "a.c",
                "items": [
                    {"name": "f1", "line_start": 1, "line_end": 10},
                    {"name": "f2", "line_start": 11, "line_end": 20},
                ],
            }],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))

        contexts_seen = []

        def review_fn(ctx, config):
            contexts_seen.append(dict(ctx))
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="clean",
                body="ok",
                review_result={
                    "status": "clean",
                    "body": "ok",
                    "observations": [
                        f"{ctx['function']} owns its buffer",
                    ],
                },
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            budget=10, batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        assert len(contexts_seen) == 2
        assert "session_observations" not in contexts_seen[0]
        assert "session_observations" in contexts_seen[1]
        obs = contexts_seen[1]["session_observations"]
        assert len(obs) == 1
        assert obs[0]["source"] == "a.c:f1"
        assert "owns its buffer" in obs[0]["text"]

    def test_short_observations_filtered(self):
        from core.audit.orchestrator import _accumulate_observations
        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
            review_result={
                "status": "clean", "body": "ok",
                "observations": ["too short", "This is a real observation about ownership"],
            },
        )
        gap = {"file": "a.c", "name": "f"}
        _accumulate_observations(obs_list, outcome, gap)
        assert len(obs_list) == 1
        assert "ownership" in obs_list[0]["text"]

    def test_unbounded_growth(self):
        """Observation list grows without FIFO eviction; sliced at format time."""
        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = [
            {"source": f"x.c:f{i}", "text": f"observation number {i:03d}", "kind": "llm_observation"}
            for i in range(50)
        ]
        outcome = ReviewOutcome(
            file="a.c", function="new", status="clean", body="ok",
            review_result={
                "status": "clean", "body": "ok",
                "observations": ["Brand new observation about lifetimes"],
            },
        )
        _accumulate_observations(obs_list, outcome, {"file": "a.c", "name": "new"})
        assert len(obs_list) == 51
        assert obs_list[-1]["text"] == "Brand new observation about lifetimes"
        assert obs_list[-1]["kind"] == "llm_observation"

    def test_tool_confirmation_injection(self):
        """Sweep confirmation injects tool_confirmation observation."""
        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="vuln", status="finding",
            body="buffer overflow",
            hypothesis="strcpy overflow",
            evidence_tool="semgrep:unbounded-strcpy",
            review_result={"status": "finding", "body": "bof"},
        )
        _accumulate_observations(
            obs_list, outcome, {"file": "a.c", "name": "vuln"},
            sweep_pre_status="finding",
        )
        confirmed = [o for o in obs_list if o.get("kind") == "tool_confirmation"]
        assert len(confirmed) == 1
        assert "semgrep" in confirmed[0]["text"]

    def test_tool_refutation_injection(self):
        """Sweep demotion injects tool_refutation observation."""
        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="vuln", status="suspicious",
            body="maybe bof", hypothesis="strcpy overflow",
            review_result={"status": "suspicious", "body": "maybe bof"},
        )
        _accumulate_observations(
            obs_list, outcome, {"file": "a.c", "name": "vuln"},
            sweep_pre_status="finding",
        )
        refuted = [o for o in obs_list if o.get("kind") == "tool_refutation"]
        assert len(refuted) == 1
        assert "refuted" in refuted[0]["text"].lower()


@pytest.mark.slow
class TestDeepenSuspicious:
    """Deepen step: re-review suspicious verdicts with enriched context."""

    def test_suspicious_gets_deepened(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("void big() {}\n" * 30)
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "a.c",
                "items": [
                    {"name": "big", "line_start": 1, "line_end": 30},
                ],
            }],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        (out / "context-map.json").write_text(json.dumps({
            "entry_points": [{"file": "a.c", "name": "big"}],
            "sinks": [], "trust_boundaries": [], "unchecked_flows": [],
        }))

        call_count = [0]
        contexts_seen = []

        def review_fn(ctx, config):
            call_count[0] += 1
            contexts_seen.append(dict(ctx))
            if call_count[0] == 1:
                return ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="suspicious",
                    body="Possible aliasing issue in scatterlist",
                    hypothesis="scatterlist reuse",
                    review_result={
                        "status": "suspicious",
                        "body": "Possible aliasing issue in scatterlist",
                        "hypothesis": "scatterlist reuse",
                    },
                )
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="finding",
                body="Page cache corruption through alias",
                hypothesis="in-place crypto corrupts page cache",
                evidence_tool="prefilter:alias-check",
                review_result={
                    "status": "finding",
                    "body": "Page cache corruption",
                    "hypothesis": "in-place crypto corrupts page cache",
                    "evidence_tool": "prefilter:alias-check",
                },
            )

        config = OrchestratorConfig(
            # hermetic: findings survive to post-loop — without the pin,
            # config.validate (default True) dispatches the real validation
            # pipeline on hosts with a Claude CLI (live spend, minutes).
            validate=False,
            target_path=target, out_dir=out,
            budget=10, batch_sloc_threshold=0,
            deepen_suspicious=True,
            max_refinements=0,
            sweep_validate_findings=False,
            # Hermetic: the suspicious-demotion gate only runs with a
            # live Joern server and would demote the evidence-less
            # stub verdict to clean, making the assertions
            # host-dependent (deepen dispatch / suspicious tally).
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)

        assert call_count[0] == 2
        assert result.findings == 1
        assert result.suspicious == 0
        assert contexts_seen[1].get("deepen") is True
        assert "prior_verdict" in contexts_seen[1]

    def test_small_suspicious_not_deepened(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("void small() {}\n")
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "a.c",
                "items": [
                    {"name": "small", "line_start": 1, "line_end": 5},
                ],
            }],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        (out / "context-map.json").write_text(json.dumps({
            "entry_points": [{"file": "a.c", "name": "small"}],
            "sinks": [], "trust_boundaries": [], "unchecked_flows": [],
        }))

        call_count = [0]

        def review_fn(ctx, config):
            call_count[0] += 1
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="Maybe something",
                review_result={"status": "suspicious", "body": "Maybe"},
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            budget=10, batch_sloc_threshold=0,
            deepen_suspicious=True,
            max_refinements=0,
            sweep_validate_findings=False,
            # Hermetic: the suspicious-demotion gate only runs with a
            # live Joern server and would demote the evidence-less
            # stub verdict to clean, making the assertions
            # host-dependent (deepen dispatch / suspicious tally).
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)

        assert call_count[0] == 1
        assert result.suspicious == 1

    def test_deepen_disabled(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("void big() {}\n" * 30)
        out = tmp_path / "out"
        out.mkdir()

        checklist = {
            "files": [{
                "path": "a.c",
                "items": [
                    {"name": "big", "line_start": 1, "line_end": 30},
                ],
            }],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        (out / "context-map.json").write_text(json.dumps({
            "entry_points": [{"file": "a.c", "name": "big"}],
            "sinks": [], "trust_boundaries": [], "unchecked_flows": [],
        }))

        call_count = [0]

        def review_fn(ctx, config):
            call_count[0] += 1
            return ReviewOutcome(
                file=ctx["file"],
                function=ctx["function"],
                status="suspicious",
                body="Possible issue",
                review_result={"status": "suspicious", "body": "Possible"},
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            budget=10, batch_sloc_threshold=0,
            deepen_suspicious=False,
            max_refinements=0,
            # Hermetic: see test_suspicious_gets_deepened.
            joern_overrides={"enabled": False},
        )
        result = run_orchestrator(config, review_fn)

        assert call_count[0] == 1
        assert result.suspicious == 1


class TestMultiPassReview:

    def test_single_model_passes_use_substrate_majority_vote(
            self, tmp_path: Path):
        # The former inline best-of-N loop kept a lone "finding" out of
        # 3 samples as the primary (severity-max). The substrate's
        # majority-vote merge downgrades a 1-of-3 lone dissent to
        # "suspicious" — asserting that proves single-model
        # review_passes now go through multi_review.run_self_consistency
        # rather than a third inline self-consistency implementation.
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        call_count = [0]

        def review_fn(ctx, cfg):
            call_count[0] += 1
            status = "finding" if call_count[0] == 1 else "clean"
            return ReviewOutcome(
                file="a.c", function="f", status=status,
                body=f"pass {call_count[0]}", cost_usd=0.01,
            )

        outcome = _multi_pass_review(
            review_fn, {"file": "a.c", "function": "f"}, config, passes=3,
        )
        assert call_count[0] == 3
        assert outcome.status == "suspicious"

    def test_substrate_failure_falls_back_to_single_pass(
            self, tmp_path: Path, monkeypatch):
        import core.audit.multi_review as mr

        def boom(**kwargs):
            raise RuntimeError("substrate down")
        monkeypatch.setattr(mr, "run_self_consistency", boom)

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        calls = [0]

        def review_fn(ctx, cfg):
            calls[0] += 1
            return ReviewOutcome(
                file="a.c", function="f", status="clean", body="ok",
            )

        outcome = _multi_pass_review(
            review_fn, {"file": "a.c", "function": "f"}, config, passes=2,
        )
        assert outcome.status == "clean"
        assert calls[0] == 1  # one plain pass, not an inline N-loop

    def test_merges_hypotheses_across_passes(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        call_count = [0]

        def review_fn(ctx, cfg):
            call_count[0] += 1
            if call_count[0] == 1:
                return ReviewOutcome(
                    file="a.c", function="f", status="suspicious",
                    body="pass 1",
                    hypothesis="aliasing",
                    hypotheses=[
                        {"mechanism": "page-cache aliasing", "confidence": "low"},
                    ],
                    cost_usd=0.01, duration_s=1.0,
                )
            return ReviewOutcome(
                file="a.c", function="f", status="finding",
                body="pass 2",
                hypothesis="overflow",
                hypotheses=[
                    {"mechanism": "integer overflow in outlen", "confidence": "high"},
                    {"mechanism": "page-cache aliasing", "confidence": "medium"},
                ],
                cost_usd=0.02, duration_s=2.0,
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=2)

        assert call_count[0] == 2
        assert outcome.status == "finding"
        assert outcome.cost_usd == 0.03
        # Samples run in parallel through the multi_review substrate:
        # duration is the max across passes (wall-clock), not the sum.
        assert outcome.duration_s == 2.0
        assert outcome.hypotheses is not None
        mechanisms = {h["mechanism"] for h in outcome.hypotheses}
        assert "page-cache aliasing" in mechanisms
        assert "integer overflow in outlen" in mechanisms
        assert len(outcome.hypotheses) == 2

    def test_single_pass_returns_as_is(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status="clean",
                body="ok", cost_usd=0.01, duration_s=1.0,
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=1)
        assert outcome.status == "clean"
        assert outcome.cost_usd == 0.01

    def test_handles_exceptions_gracefully(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        call_count = [0]

        def review_fn(ctx, cfg):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("LLM timeout")
            return ReviewOutcome(
                file="a.c", function="f", status="suspicious",
                body="found something", cost_usd=0.01, duration_s=1.0,
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=2)
        assert outcome.status == "suspicious"
        assert call_count[0] == 2


class TestRefinementConfig:
    """Tests for refinement config fields and result counters."""

    def test_default_max_refinements(self):
        config = OrchestratorConfig(
            target_path=Path("/tmp/x"), out_dir=Path("/tmp/o"),
        )
        assert config.max_refinements == 2

    def test_default_clean_check(self):
        config = OrchestratorConfig(
            target_path=Path("/tmp/x"), out_dir=Path("/tmp/o"),
        )
        assert config.clean_check is True

    def test_result_counters_default_zero(self):
        result = OrchestratorResult()
        assert result.refinement_rounds == 0
        assert result.clean_checks == 0
        assert result.clean_check_rescues == 0

    def test_max_refinements_configurable(self):
        config = OrchestratorConfig(
            target_path=Path("/tmp/x"), out_dir=Path("/tmp/o"),
            max_refinements=3,
        )
        assert config.max_refinements == 3

    def test_clean_check_disableable(self):
        config = OrchestratorConfig(
            target_path=Path("/tmp/x"), out_dir=Path("/tmp/o"),
            clean_check=False,
        )
        assert config.clean_check is False


class TestRunCleanCheckSweep:
    """Tests for _run_clean_check_sweep evidence collection."""

    def test_returns_none_without_evidence(self):
        from core.audit.orchestrator import _run_clean_check_sweep
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="all good",
        )
        result = _run_clean_check_sweep(outcome, None, None)
        assert result is None

    def test_returns_flows_from_evidence_index(self, tmp_path):
        from core.audit.orchestrator import _run_clean_check_sweep
        from core.evidence import EvidenceRecord
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="all good",
        )

        class FakeFlow:
            source_param = "buf"
            sink_call = "memcpy"

        rec = EvidenceRecord(file="a.c", function="f")
        rec.joern_flows = [FakeFlow()]
        index = {"a.c:f": rec}

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        result = _run_clean_check_sweep(outcome, config, index)
        assert result is not None
        assert "buf" in result
        assert "memcpy" in result

    def test_returns_none_for_empty_evidence(self, tmp_path):
        from core.audit.orchestrator import _run_clean_check_sweep
        from core.evidence import EvidenceRecord
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="all good",
        )
        rec = EvidenceRecord(file="a.c", function="f")
        index = {"a.c:f": rec}

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        result = _run_clean_check_sweep(outcome, config, index)
        assert result is None


class TestEnrichSummariesFromJoern:
    def test_merges_cpg_summaries_into_taint_results(self):
        from core.audit.orchestrator import _enrich_summaries_from_joern
        from packages.joern.models import JoernMethodSummary

        class FakeServer:
            def run_summary_batch(self, methods, *, timeout=None):
                return {
                    "parse_input": JoernMethodSummary(
                        method="parse_input",
                        taint_rules=["buf"],
                        preconditions=["assert(buf != NULL)"],
                        returns=["int"],
                    ),
                }

        flows = {
            "src/parser.c": [
                {
                    "source_method": "parse_input",
                    "source_param": "buf",
                    "sink_call": "exec",
                    "sink_arg_idx": 0,
                    "steps": [
                        {"file": "src/parser.c", "function": "parse_input",
                         "line": 10, "code": "buf", "variable": "buf"},
                    ],
                },
            ],
        }
        taint_summary: dict = {}
        _enrich_summaries_from_joern(FakeServer(), flows, taint_summary)

        assert "src/parser.c:parse_input" in taint_summary
        fs = taint_summary["src/parser.c:parse_input"]
        assert fs.source == "joern_cpg"
        assert len(fs.taint_rules) == 1
        assert fs.taint_rules[0].source_param == "buf"
        assert len(fs.preconditions) == 1
        assert len(fs.returns) == 1

    def test_does_not_overwrite_existing_cpg_summary(self):
        from core.analysis.summaries import EvidenceTier, FunctionSummary
        from core.audit.orchestrator import _enrich_summaries_from_joern
        from packages.joern.models import JoernMethodSummary

        class FakeServer:
            def run_summary_batch(self, methods, *, timeout=None):
                return {
                    "f": JoernMethodSummary(
                        method="f", taint_rules=["new"],
                        preconditions=[], returns=[],
                    ),
                }

        existing = FunctionSummary(
            function="f", file="a.c",
            source="joern_cpg",
            evidence_tier=EvidenceTier.XREF_BACKED,
        )
        taint_summary = {"a.c:f": existing}
        _enrich_summaries_from_joern(
            FakeServer(),
            {"a.c": [{"source_method": "f", "source_param": "",
                       "sink_call": "x", "sink_arg_idx": 0, "steps": []}]},
            taint_summary,
        )
        assert taint_summary["a.c:f"] is existing

    def test_empty_flows_is_noop(self):
        from core.audit.orchestrator import _enrich_summaries_from_joern

        class FakeServer:
            def run_summary_batch(self, methods, *, timeout=None):
                raise AssertionError("should not be called")

        taint_summary: dict = {}
        _enrich_summaries_from_joern(FakeServer(), {}, taint_summary)
        assert taint_summary == {}

    def test_server_exception_swallowed(self):
        from core.audit.orchestrator import _enrich_summaries_from_joern

        class FakeServer:
            def run_summary_batch(self, methods, *, timeout=None):
                raise RuntimeError("server died")

        taint_summary: dict = {}
        _enrich_summaries_from_joern(
            FakeServer(),
            {"a.c": [{"source_method": "f", "source_param": "",
                       "sink_call": "x", "sink_arg_idx": 0, "steps": []}]},
            taint_summary,
        )
        assert taint_summary == {}


# ------------------------------------------------------------------
# SAGE audit pathway tests
# ------------------------------------------------------------------

class TestCommitOutcomeJournal:
    """Every ``_commit_outcome`` call must fold the LLM's body +
    review context into ``review-journal.jsonl``. Pre-fix only
    ``Collector.submit`` wrote to the journal — the 8 sites that
    dispatch through ``_commit_outcome`` (prefilter/sweep/refinement/
    dead-code-skip/etc.) silently dropped the LLM reasoning, and the
    ``run_id`` also had to be routed through explicitly because
    ``OrchestratorConfig`` doesn't carry one.
    """

    def test_commit_outcome_writes_journal_entry(self, tmp_path: Path):
        from core.audit.journal import latest_entries
        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="finding", body="Hypothesis + tool evidence.",
            hypothesis="strcpy without bound", model="test-model",
            evidence_tool="semgrep:strcpy",
        )
        gap = {"file": "src/auth.c", "name": "check_pw",
               "line_start": 1, "line_end": 3, "strategies": ["cwe-120"]}
        _commit_outcome(config, outcome, gap)

        entries = latest_entries(out)
        entry = entries.get("src/auth.c:check_pw")
        assert entry is not None
        assert entry.verdict == "finding"
        assert entry.body == "Hypothesis + tool evidence."
        assert entry.model == "test-model"
        assert entry.evidence_tools == ["semgrep:strcpy"]
        assert entry.strategies == ["cwe-120"]
        # run_id derived from run-dir basename, not empty string.
        assert entry.run_id == out.name
        assert entry.run_id != ""


class TestSageHypothesisPathway:
    """Test the SAGE hypothesis verdict store/recall pathway through _commit_outcome."""

    def test_commit_outcome_calls_sage_store(self, tmp_path: Path):
        """_commit_outcome stores hypothesis verdict when source hash present."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="clean", body="no issues",
            hypothesis="strcpy overflow from user input",
            evidence_tool="semgrep:unbounded-strcpy",
        )
        gap = {
            "file": "src/auth.c", "name": "check_pw",
            "line_start": 1, "line_end": 3,
            "_sage_source_hash": "abcdef123456",
        }

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            mock_store.return_value = True
            _commit_outcome(config, outcome, gap)

            mock_store.assert_called_once()
            kw = mock_store.call_args
            assert kw[1]["file_path"] == "src/auth.c"
            assert kw[1]["function"] == "check_pw"
            assert kw[1]["hypothesis"] == "strcpy overflow from user input"
            assert kw[1]["status"] == "clean"
            assert kw[1]["evidence_tool"] == "semgrep:unbounded-strcpy"
            assert kw[1]["source_hash"] == "abcdef123456"

    def test_commit_outcome_skips_without_source_hash(self, tmp_path: Path):
        """_commit_outcome does NOT call sage store when no source hash."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="clean", body="no issues",
            hypothesis="test hyp",
        )
        gap = {"file": "src/auth.c", "name": "check_pw", "line_start": 1}

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            _commit_outcome(config, outcome, gap)
            mock_store.assert_not_called()

    def test_commit_outcome_skips_error_status(self, tmp_path: Path):
        """_commit_outcome does NOT store verdicts for error outcomes."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="error", body="failed to review",
            hypothesis="test hyp",
        )
        gap = {
            "file": "src/auth.c", "name": "check_pw",
            "line_start": 1, "_sage_source_hash": "h123",
        }

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            _commit_outcome(config, outcome, gap)
            mock_store.assert_not_called()

    def test_commit_outcome_skips_empty_hypothesis(self, tmp_path: Path):
        """_commit_outcome does NOT store when hypothesis is empty."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="clean", body="ok", hypothesis="",
        )
        gap = {
            "file": "src/auth.c", "name": "check_pw",
            "line_start": 1, "_sage_source_hash": "h123",
        }

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            _commit_outcome(config, outcome, gap)
            mock_store.assert_not_called()

    def test_commit_outcome_chain_context_tag(self, tmp_path: Path):
        """Chain-injected gaps tag evidence_tool with chain_context."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="finding", body="vuln",
            hypothesis="buffer overflow via chain",
            evidence_tool="semgrep:rule",
        )
        gap = {
            "file": "src/auth.c", "name": "check_pw",
            "line_start": 1, "_sage_source_hash": "h123",
            "force_review": True,
        }

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            mock_store.return_value = True
            _commit_outcome(config, outcome, gap)

            mock_store.assert_called_once()
            kw = mock_store.call_args
            assert kw[1]["evidence_tool"] == "semgrep:rule+chain_context"

    def test_commit_outcome_chain_context_tag_no_prior_tool(self, tmp_path: Path):
        """Chain-injected gaps with no evidence_tool get bare chain_context."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _commit_outcome

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )

        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="finding", body="vuln",
            hypothesis="buffer overflow via chain",
        )
        gap = {
            "file": "src/auth.c", "name": "check_pw",
            "line_start": 1, "_sage_source_hash": "h123",
            "force_review": True,
        }

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock_store:
            mock_store.return_value = True
            _commit_outcome(config, outcome, gap)

            mock_store.assert_called_once()
            kw = mock_store.call_args
            assert kw[1]["evidence_tool"] == "chain_context"

    @pytest.mark.slow
    def test_source_hash_precompute_via_orchestrator(self, tmp_path: Path):
        """run_orchestrator pre-computes _sage_source_hash on gaps with line_start."""
        from unittest.mock import patch as _patch

        hash_calls: list = []

        orig_hash = None

        def track_hash(file_path, line, window=10):
            h = orig_hash(file_path, line, window)
            hash_calls.append({"file": str(file_path), "line": line, "hash": h})
            return h

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok",
                hypothesis="test hypothesis",
                evidence_tool="semgrep:test",
            )

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
        )

        from core.sage.hooks import compute_finding_source_hash
        orig_hash = compute_finding_source_hash

        with _patch("core.sage.hooks.compute_finding_source_hash", side_effect=track_hash):
            run_orchestrator(config, review_fn)

        assert len(hash_calls) >= 1, "Source hash should be computed for functions with line_start"
        assert all(h["hash"] for h in hash_calls), "All hashes should be non-empty"


class TestSageObservationPathway:
    """Test the SAGE observation store pathway through _accumulate_observations."""

    def test_tool_confirmation_stores_to_sage(self):
        """_accumulate_observations stores tool confirmations to SAGE."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="vuln", status="finding",
            body="buffer overflow",
            hypothesis="strcpy overflow via attacker input",
            evidence_tool="semgrep:unbounded-strcpy",
            review_result={"status": "finding", "body": "bof"},
        )
        gap = {"file": "a.c", "name": "vuln"}

        with _patch("core.audit.orchestrator._sage_store_observation") as mock_store:
            _accumulate_observations(
                obs_list, outcome, gap, sweep_pre_status="finding",
            )
            mock_store.assert_called_once()
            args = mock_store.call_args[0]
            assert "[tool-confirmed]" in args[0]
            assert args[1] == "tool_confirmation"
            assert args[2] == "a.c:vuln"

    def test_tool_refutation_stores_to_sage(self):
        """_accumulate_observations stores tool refutations to SAGE."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="vuln", status="suspicious",
            body="maybe bof", hypothesis="strcpy overflow",
            review_result={"status": "suspicious", "body": "maybe"},
        )
        gap = {"file": "a.c", "name": "vuln"}

        with _patch("core.audit.orchestrator._sage_store_observation") as mock_store:
            _accumulate_observations(
                obs_list, outcome, gap, sweep_pre_status="finding",
            )
            mock_store.assert_called_once()
            args = mock_store.call_args[0]
            assert args[1] == "tool_refutation"

    def test_llm_observation_not_stored_to_sage(self):
        """_accumulate_observations does NOT store plain LLM observations to SAGE."""
        from unittest.mock import patch as _patch

        from core.audit.orchestrator import _accumulate_observations

        obs_list: list = []
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
            review_result={
                "status": "clean", "body": "ok",
                "observations": ["This function owns its buffer throughout"],
            },
        )
        gap = {"file": "a.c", "name": "f"}

        with _patch("core.audit.orchestrator._sage_store_observation") as mock_store:
            _accumulate_observations(obs_list, outcome, gap)
            mock_store.assert_not_called()

    def test_sage_store_observation_delegates_to_hook(self):
        """_sage_store_observation calls store_audit_observation with correct args."""
        from unittest.mock import patch as _patch

        import core.audit.orchestrator as _omod
        _omod._active_target_path = Path("/data/kernel")

        with _patch("core.sage.hooks.store_audit_observation") as mock_hook:
            mock_hook.return_value = True
            _omod._sage_store_observation(
                "semgrep confirmed: overflow in memcpy",
                "tool_confirmation",
                "net/tcp.c:tcp_recv",
            )
            mock_hook.assert_called_once_with(
                repo_path="/data/kernel",
                observation="semgrep confirmed: overflow in memcpy",
                kind="tool_confirmation",
                source_function="net/tcp.c:tcp_recv",
            )

        _omod._active_target_path = None

    def test_sage_store_observation_silent_on_import_error(self):
        """_sage_store_observation swallows ImportError when SAGE unavailable."""
        from unittest.mock import patch as _patch

        import core.audit.orchestrator as _omod

        with _patch("core.sage.hooks.store_audit_observation", side_effect=ImportError):
            _omod._sage_store_observation("test text long enough", "tool_confirmation", "f.c:fn")


class TestSageCombinedPathway:
    """Test the full SAGE pathway through the production Collector path.

    The Collector's ``submit()`` method stores hypothesis verdicts to
    SAGE (same logic as ``_commit_outcome``).  These tests run the
    real pipeline with the collector active.
    """

    @pytest.mark.slow
    def test_full_pipeline_stores_verdict(self, tmp_path: Path):
        """run_orchestrator → Collector.submit → SAGE hypothesis store."""
        from unittest.mock import patch as _patch

        stored_calls: list = []

        def capture_store(**kwargs):
            stored_calls.append(kwargs)
            return True

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="no issues found",
                hypothesis="unchecked return from strcmp",
                evidence_tool="semgrep:return-check",
            )

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
        )

        with _patch("core.sage.hooks.store_audit_hypothesis_verdict", side_effect=capture_store):
            run_orchestrator(config, review_fn)

        assert len(stored_calls) >= 1
        call = stored_calls[0]
        assert call["file_path"] in ("src/auth.c",)
        assert call["function"] in ("check_pw", "validate")
        assert call["hypothesis"] == "unchecked return from strcmp"
        assert call["status"] == "clean"
        assert call["source_hash"], "Source hash must be non-empty"

    @pytest.mark.slow
    def test_full_pipeline_finding_and_observation(self, tmp_path: Path):
        """Tool-confirmed finding stores both hypothesis verdict AND observation."""
        from unittest.mock import patch as _patch

        hypothesis_calls: list = []
        observation_calls: list = []

        def capture_hyp(**kwargs):
            hypothesis_calls.append(kwargs)
            return True

        def capture_obs(**kwargs):
            observation_calls.append(kwargs)
            return True

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="finding", body="buffer overflow",
                hypothesis="strcpy overflow via user input",
                evidence_tool="semgrep:unbounded-strcpy",
                review_result={"status": "finding", "body": "bof"},
            )

        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
        )

        with (
            _patch("core.sage.hooks.store_audit_hypothesis_verdict",
                   side_effect=capture_hyp),
            _patch("core.sage.hooks.store_audit_observation",
                   side_effect=capture_obs),
        ):
            run_orchestrator(config, review_fn)

        assert len(hypothesis_calls) >= 1
        # Gate enforcement may demote to suspicious, but hypothesis
        # still gets stored with whatever status the commit path sees.
        assert hypothesis_calls[0]["status"] in ("finding", "suspicious")

        # The pipeline may trigger a mechanical sweep that fires
        # tool_confirmation observations — verify the observation content
        # when it fires.
        tool_obs = [o for o in observation_calls if o.get("kind") == "tool_confirmation"]
        for obs in tool_obs:
            assert "semgrep" in obs["observation"]
            assert obs["kind"] == "tool_confirmation"


class TestDeadCodeReason:
    """Tests for _dead_code_reason helper."""

    def test_lexical_dead(self):
        from core.audit.orchestrator import _dead_code_reason
        gap = {"file": "a.py", "name": "f", "lexical_dead": True}
        r = _dead_code_reason(gap)
        assert r is not None
        assert "lexical_dead" in r

    def test_module_aborts(self):
        from core.audit.orchestrator import _dead_code_reason
        gap = {"file": "a.py", "name": "f", "module_aborts_on_load": True}
        r = _dead_code_reason(gap)
        assert r is not None
        assert "module_aborts" in r

    def test_build_excluded(self):
        from core.audit.orchestrator import _dead_code_reason
        gap = {"file": "a.go", "name": "f", "build_excluded": True}
        r = _dead_code_reason(gap)
        assert r is not None
        assert "build_excluded" in r

    def test_live_returns_none(self):
        from core.audit.orchestrator import _dead_code_reason
        gap = {"file": "a.py", "name": "f"}
        assert _dead_code_reason(gap) is None


class TestJoernTarget:
    """_joern_target narrows CPG builds to the scoped subtree."""

    def _cfg(self, tmp_path, scope=None):
        target = tmp_path / "repo"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out, scope=scope)

    def test_no_scope_returns_target(self, tmp_path):
        from core.audit.orchestrator import _joern_target
        cfg = self._cfg(tmp_path)
        assert _joern_target(cfg) == cfg.target_path

    def test_single_scope_narrows(self, tmp_path):
        from core.audit.orchestrator import _joern_target
        cfg = self._cfg(tmp_path, scope="src/database/sql")
        (cfg.target_path / "src" / "database" / "sql").mkdir(parents=True)
        assert _joern_target(cfg) == cfg.target_path / "src" / "database" / "sql"

    def test_multi_scope_common_prefix(self, tmp_path):
        from core.audit.orchestrator import _joern_target
        cfg = self._cfg(tmp_path, scope=["fs", "kernel/locking"])
        (cfg.target_path / "fs").mkdir()
        (cfg.target_path / "kernel" / "locking").mkdir(parents=True)
        # No common prefix → returns full target
        assert _joern_target(cfg) == cfg.target_path

    def test_multi_scope_shared_prefix(self, tmp_path):
        from core.audit.orchestrator import _joern_target
        cfg = self._cfg(tmp_path, scope=["src/database/sql", "src/database/driver"])
        (cfg.target_path / "src" / "database" / "sql").mkdir(parents=True)
        (cfg.target_path / "src" / "database" / "driver").mkdir(parents=True)
        assert _joern_target(cfg) == cfg.target_path / "src" / "database"

    def test_nonexistent_prefix_falls_back(self, tmp_path):
        from core.audit.orchestrator import _joern_target
        cfg = self._cfg(tmp_path, scope="does/not/exist")
        assert _joern_target(cfg) == cfg.target_path


class TestPromoteHypothesisInconsistent:
    """Tests for _promote_hypothesis_inconsistent."""

    def _result(self, outcomes):
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        r.suspicious = sum(
            1 for o in outcomes if o.status == "suspicious"
        )
        return r

    def _outcome(self, status="clean", body="", hypotheses=None):
        return ReviewOutcome(
            file="f.c",
            function="fn",
            status=status,
            body=body,
            hypothesis="",
            hypotheses=hypotheses or [],
            evidence_tool="",
            cost_usd=0,
            model="test",
            duration_s=0,
        )

    def test_promotes_clean_with_unrefuted_high_hypothesis(self):
        o = self._outcome(
            hypotheses=[{"mechanism": "oob", "confidence": "high"}],
        )
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "suspicious"

    def test_promotes_medium_confidence_hypothesis(self):
        """Medium-confidence hypotheses also trigger promotion."""
        o = self._outcome(
            hypotheses=[{"mechanism": "oob", "confidence": "medium"}],
        )
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "suspicious"

    def test_promotes_high_confidence_with_counter(self):
        """Counter text does not suppress promotion."""
        o = self._outcome(
            hypotheses=[{
                "mechanism": "oob",
                "confidence": "high",
                "counter": "bounds checked by caller",
            }],
        )
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "suspicious"

    def test_skips_gate_demoted_outcome(self):
        o = self._outcome(
            body="[suspicious-demotion: no verification evidence "
                 "with Joern available]\n\noriginal body",
            hypotheses=[{"mechanism": "oob", "confidence": "high"}],
        )
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "clean"

    def test_skips_outcome_without_hypotheses(self):
        o = self._outcome()
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "clean"

    def test_skips_refuted_only_hypotheses(self):
        o = self._outcome(
            hypotheses=[
                {"mechanism": "oob", "confidence": "refuted"},
            ],
        )
        r = self._result([o])
        _promote_hypothesis_inconsistent(r)
        assert r.outcomes[0].status == "clean"



class TestGapIndex:
    """_gap_index must round-trip the real checklist shape, whose file
    records carry "path" (inventory builder) — not "file"."""

    def test_indexes_real_checklist_shape(self):
        from core.audit.orchestrator import _gap_index

        checklist = {
            "files": [
                {
                    "path": "src/auth.c",
                    "language": "c",
                    "items": [
                        {
                            "name": "check_pw",
                            "line_start": 10,
                            "line_end": 42,
                            "source": "int check_pw(...) {}",
                        },
                    ],
                },
            ],
        }
        index = _gap_index(checklist)
        assert "src/auth.c:check_pw" in index
        gap = index["src/auth.c:check_pw"]
        assert gap["file"] == "src/auth.c"
        assert gap["name"] == "check_pw"
        assert gap["line_start"] == 10
        assert gap["line_end"] == 42

    def test_legacy_functions_key(self):
        from core.audit.orchestrator import _gap_index

        checklist = {
            "files": [
                {"path": "a.py", "functions": [{"name": "f"}]},
            ],
        }
        assert "a.py:f" in _gap_index(checklist)


class TestTaintApproxHasFlow:
    """_taint_approx_has_flow must handle both TaintApprox objects and
    the plain dicts the taint-approx cache round-trips through JSON on
    resumed runs (previously dicts always read as no-flow, dropping the
    taint-path priority signal on every resumed run)."""

    def test_cached_dict_with_dangerous_flows(self):
        from core.audit.orchestrator import _taint_approx_has_flow

        assert _taint_approx_has_flow(
            {"dangerous_flows": {"0": [["memcpy", 1]]}, "direct_flows": {}},
        )

    def test_cached_dict_with_direct_flows_only(self):
        from core.audit.orchestrator import _taint_approx_has_flow

        assert _taint_approx_has_flow(
            {"dangerous_flows": {}, "direct_flows": {"1": [["helper", 0]]}},
        )

    def test_cached_dict_without_flows(self):
        from core.audit.orchestrator import _taint_approx_has_flow

        assert not _taint_approx_has_flow(
            {"dangerous_flows": {}, "direct_flows": {}},
        )

    def test_object_shapes(self):
        from core.audit.orchestrator import _taint_approx_has_flow

        class FakeApprox:
            def __init__(self, dangerous, direct):
                self._dangerous = dangerous
                self.direct_flows = direct

            def has_any_dangerous_flow(self):
                return self._dangerous

        assert _taint_approx_has_flow(FakeApprox(True, {}))
        assert _taint_approx_has_flow(FakeApprox(False, {0: [("f", 1)]}))
        assert not _taint_approx_has_flow(FakeApprox(False, {}))

    def test_none(self):
        from core.audit.orchestrator import _taint_approx_has_flow

        assert not _taint_approx_has_flow(None)


class TestHeuristicBypassFindings:
    """Post-loop stored-taint / config-provenance bypass detection.

    The runner is None whenever IRIS refinement did not build a
    compositional analyzer — previously the name was not even bound in
    that (common) case and the pass died with a NameError swallowed by
    a broad except."""

    def test_none_runner_returns_empty(self):
        from core.audit.orchestrator import _heuristic_bypass_findings

        assert _heuristic_bypass_findings([{"file": "a.c"}], None) == []

    def test_runner_findings_are_collected(self, monkeypatch):
        from core.audit.orchestrator import _heuristic_bypass_findings

        class FakeAssumption:
            enforced_by = ("check_auth",)
            bug_class = "stored_taint"
            target = "db_write"

        class FakeBypass:
            assumption = FakeAssumption()
            caller_file = "web.c"
            caller_function = "handler"
            missing_enforcer = "check_auth"

        import core.iris.synthesise as synth_mod
        monkeypatch.setattr(
            synth_mod, "stored_taint_assumptions",
            lambda gaps: [FakeAssumption()],
        )
        monkeypatch.setattr(
            synth_mod, "config_provenance_assumptions", lambda gaps: [],
        )

        findings = _heuristic_bypass_findings(
            [{"file": "web.c"}], lambda assumptions: [FakeBypass()],
        )
        assert len(findings) == 1
        assert findings[0]["check"] == "iris_stored_taint"
        assert findings[0]["file"] == "web.c"
        assert findings[0]["function"] == "handler"

    def test_runner_error_is_contained(self, monkeypatch):
        from core.audit.orchestrator import _heuristic_bypass_findings

        class FakeAssumption:
            enforced_by = ("check_auth",)

        import core.iris.synthesise as synth_mod
        monkeypatch.setattr(
            synth_mod, "stored_taint_assumptions",
            lambda gaps: [FakeAssumption()],
        )
        monkeypatch.setattr(
            synth_mod, "config_provenance_assumptions", lambda gaps: [],
        )

        def broken_runner(assumptions):
            raise RuntimeError("analyzer crashed")

        assert _heuristic_bypass_findings([], broken_runner) == []


class TestDiffNewConcepts:
    """Study-consumer concept diffing: new concepts must be computed
    BEFORE the current model's names are folded into seen_concepts
    (previously the fold ran first, so the diff was always empty and
    the ConceptIndex-scoped broader re-review never triggered)."""

    @staticmethod
    def _dm(*names):
        return {"concepts": [{"name": n} for n in names]}

    def test_study_added_concept_is_new(self):
        from core.audit.orchestrator import _diff_new_concepts

        seen: set = set()
        new = _diff_new_concepts(seen, self._dm("Alloc"), self._dm("Alloc", "Free"))
        assert new == {"free"}
        assert seen == {"alloc", "free"}

    def test_previously_seen_not_returned_again(self):
        from core.audit.orchestrator import _diff_new_concepts

        seen: set = set()
        _diff_new_concepts(seen, self._dm("A"), self._dm("A", "B"))
        new = _diff_new_concepts(seen, self._dm("A", "B"), self._dm("A", "B", "C"))
        assert new == {"c"}

    def test_no_growth_still_updates_seen(self):
        from core.audit.orchestrator import _diff_new_concepts

        seen: set = set()
        new = _diff_new_concepts(seen, self._dm("A"), None)
        assert new == set()
        assert seen == {"a"}


class TestG3ReRecordGate:
    """G3 must match journal entries by their lined key form
    ("file:function:line", the shape _commit_outcome writes)."""

    def _outcome(self, evidence_tool=""):
        return ReviewOutcome(
            file="a.c", function="f",
            status="finding", body="bad",
            hypothesis="overflow",
            evidence_tool=evidence_tool,
        )

    def test_lined_prior_record_triggers_g3(self):
        audit_log = [
            {
                "action": "orchestrator_review",
                "key": "a.c:f:42",
                "status": "finding",
            },
        ]
        v = _check_finding_gates(
            self._outcome(evidence_tool=""), audit_log=audit_log,
        )
        assert any("G3" in x for x in v)

    def test_bare_prior_record_still_triggers_g3(self):
        audit_log = [
            {"action": "record", "key": "a.c:f", "status": "finding"},
        ]
        v = _check_finding_gates(
            self._outcome(evidence_tool=""), audit_log=audit_log,
        )
        assert any("G3" in x for x in v)

    def test_new_tool_evidence_passes_g3(self):
        audit_log = [
            {
                "action": "orchestrator_review",
                "key": "a.c:f:42",
                "status": "finding",
            },
        ]
        v = _check_finding_gates(
            self._outcome(evidence_tool="semgrep:overflow"),
            audit_log=audit_log,
        )
        assert not any("G3" in x for x in v)

    def test_other_function_does_not_trigger_g3(self):
        audit_log = [
            {
                "action": "orchestrator_review",
                "key": "a.c:other:42",
                "status": "finding",
            },
        ]
        v = _check_finding_gates(
            self._outcome(evidence_tool=""), audit_log=audit_log,
        )
        assert not any("G3" in x for x in v)


class TestUpdateRunProgress:
    def test_checkpoint_reports_reviewed_count(self, tmp_path):
        from core.audit.orchestrator import _update_run_progress

        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(json.dumps({"status": "running"}))

        result = OrchestratorResult(reviewed=7)
        _update_run_progress(tmp_path, result)

        meta = json.loads(meta_path.read_text())
        assert meta["extra"]["progress"]["completed"] == 7

    def test_checkpoint_write_is_atomic_and_clean(self, tmp_path):
        """Written via the shared atomic primitive: other fields
        survive, and no tempfile debris is left behind (only the
        flock sidecar every metadata writer shares)."""
        from core.audit.orchestrator import _update_run_progress

        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(json.dumps({
            "status": "running",
            "command": "audit",
            "extra": {"note": "keep-me"},
        }))
        _update_run_progress(tmp_path, OrchestratorResult(reviewed=3))

        meta = json.loads(meta_path.read_text())
        assert meta["status"] == "running"
        assert meta["extra"]["note"] == "keep-me"
        assert meta["extra"]["progress"]["completed"] == 3
        leftovers = [
            q.name for q in tmp_path.iterdir()
            if q.name not in (".raptor-run.json", ".raptor-run.json.lock")
        ]
        assert leftovers == []

    def test_missing_metadata_is_noop(self, tmp_path):
        from core.audit.orchestrator import _update_run_progress

        _update_run_progress(tmp_path, OrchestratorResult(reviewed=1))
        assert not (tmp_path / ".raptor-run.json").exists()

    def test_corrupt_metadata_does_not_raise(self, tmp_path):
        from core.audit.orchestrator import _update_run_progress

        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text("{torn write")
        _update_run_progress(tmp_path, OrchestratorResult(reviewed=1))
        # Untouched: a corrupt file is not silently replaced here
        # (recovery belongs to the lifecycle layer).
        assert meta_path.read_text() == "{torn write"


class TestRunCritiqueConcurrency:
    """_run_critique runs from concurrent review workers: promotions
    must be applied under the result lock and skipped when another
    worker already replaced the outcome."""

    @staticmethod
    def _suspicious(fn="f"):
        return ReviewOutcome(
            file="a.c", function=fn, status="suspicious",
            body="maybe", hypothesis="unbounded memcpy overflow",
        )

    def _patch_chain(self, monkeypatch, run_tool_chain):
        import core.audit.orchestrator as orch_mod

        monkeypatch.setattr(
            orch_mod, "_hypothesis_to_tool_chain",
            lambda hyp, f, cwe="": ["fake-rule"],
        )
        monkeypatch.setattr(
            orch_mod, "_read_raw_source", lambda *a, **kw: "src",
        )
        monkeypatch.setattr(orch_mod, "_run_tool_chain", run_tool_chain)
        monkeypatch.setattr(orch_mod, "_is_detection_only", lambda t: False)
        monkeypatch.setattr(
            orch_mod, "_check_sink_guarded_cached", lambda *a, **kw: None,
        )

    def test_promotes_confirmed_suspicious(self, monkeypatch, tmp_path):
        from core.audit.orchestrator import _run_critique

        result = OrchestratorResult(suspicious=1)
        result.outcomes = [self._suspicious()]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        self._patch_chain(
            monkeypatch, lambda *a, **kw: ["semgrep:unbounded-memcpy"],
        )
        _run_critique(result, config)

        assert result.outcomes[0].status == "finding"
        assert result.findings == 1
        assert result.suspicious == 0
        assert result.sweep_promoted == 1

    def test_skips_outcome_replaced_during_tool_run(
        self, monkeypatch, tmp_path,
    ):
        """Simulates a concurrent worker replacing the outcome while
        the tool chain runs: no ValueError, no double-count."""
        from core.audit.orchestrator import _run_critique

        suspicious = self._suspicious()
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [suspicious]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        replacement = ReviewOutcome(
            file="a.c", function="f", status="finding",
            body="[sweep promoted via critique:other]\n\nmaybe",
            evidence_tool="critique:other",
        )

        def racing_tool_chain(*a, **kw):
            # another worker promotes/replaces the same outcome first
            result.outcomes[0] = replacement
            return ["semgrep:unbounded-memcpy"]

        self._patch_chain(monkeypatch, racing_tool_chain)
        _run_critique(result, config)  # must not raise

        assert result.outcomes[0] is replacement
        assert result.findings == 0  # no double promotion tally
        assert result.suspicious == 1
        assert result.sweep_promoted == 0


class TestRecordExecutorStop:
    """A shutdown-stopped run must not report terminated_by='complete'
    (the old guard compared 'not terminated_by' against the truthy
    default, so it never fired)."""

    def test_shutdown_stop_named(self):
        from core.audit.executor import ExecutorStats
        from core.audit.orchestrator import _record_executor_stop

        result = OrchestratorResult()
        _record_executor_stop(result, ExecutorStats(budget_stopped=True))
        assert result.terminated_by == "shutdown"

    def test_budget_reason_preserved(self):
        from core.audit.executor import ExecutorStats
        from core.audit.orchestrator import _record_executor_stop

        result = OrchestratorResult(terminated_by="llm_budget_exceeded")
        _record_executor_stop(result, ExecutorStats(budget_stopped=True))
        assert result.terminated_by == "llm_budget_exceeded"

    def test_normal_completion_untouched(self):
        from core.audit.executor import ExecutorStats
        from core.audit.orchestrator import _record_executor_stop

        result = OrchestratorResult()
        _record_executor_stop(result, ExecutorStats(budget_stopped=False))
        assert result.terminated_by == "complete"


class TestChecklistLineEndCache:
    """The line_end cache must not leak values across targets that
    share a relative path + function name (corpus runner executes
    multiple targets in one process)."""

    @staticmethod
    def _config(target, line_end):
        return OrchestratorConfig(
            target_path=target,
            out_dir=target,
            inventory={
                "files": [
                    {
                        "path": "src/util.c",
                        "items": [
                            {"name": "init", "line_end": line_end},
                        ],
                    },
                ],
            },
        )

    def test_no_cross_target_leak(self, tmp_path):
        from core.audit.orchestrator import _checklist_line_end

        target_a = tmp_path / "a"
        target_b = tmp_path / "b"

        assert _checklist_line_end(
            self._config(target_a, 42), "src/util.c", "init",
        ) == 42
        assert _checklist_line_end(
            self._config(target_b, 99), "src/util.c", "init",
        ) == 99


class TestMultiPassConsensusFailureVisibility:
    """A runtime failure in cross-model consensus must be visible at
    WARNING (the operator asked for --model A --model B and silently
    got single-model results), while a missing module stays at DEBUG."""

    def test_consensus_runtime_failure_warns(
        self, tmp_path, monkeypatch, caplog,
    ):
        import logging

        import core.audit.multi_review as mr_mod

        def broken_multi_review(*a, **kw):
            raise RuntimeError("provider exploded")

        monkeypatch.setattr(
            mr_mod, "run_audit_multi_review", broken_multi_review,
        )

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
        )

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status="clean", body="ok",
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        with caplog.at_level(logging.DEBUG, logger="core.audit.orchestrator"):
            outcome = _multi_pass_review(review_fn, ctx, config, passes=2)

        assert outcome.status == "clean"  # inline fallback still ran
        warning_msgs = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
            and "multi-model consensus failed" in r.message
        ]
        assert warning_msgs, "consensus failure must be logged at WARNING"


class TestJoernReReviewDuplicateGaps:
    """Two gaps resolving to the same prior clean outcome (duplicate
    function keys in gaps_before_joern) must not crash the post-loop
    phase with ValueError on the second replace."""

    def test_duplicate_gaps_processed_once(self, tmp_path, monkeypatch):
        import time as _time
        from unittest.mock import MagicMock

        import core.audit.orchestrator as orch_mod
        from core.audit.orchestrator import _re_review_joern_enriched

        monkeypatch.setattr(
            orch_mod, "_build_context",
            lambda config, gap, *a, **kw: {
                "file": gap["file"], "function": gap["name"],
                "line_start": gap.get("line_start", 1),
            },
        )
        monkeypatch.setattr(orch_mod, "_commit_outcome", lambda *a, **kw: None)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]

        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        rec = MagicMock()
        rec.all_joern_flows.return_value = ["flow"]
        evidence_index = {"a.c:f": rec}

        review_calls = [0]

        def review_fn(ctx, cfg):
            review_calls[0] += 1
            return ReviewOutcome(
                file="a.c", function="f", status="suspicious",
                body="joern flow reaches sink", hypothesis="taint",
            )

        gaps = [
            {"file": "a.c", "name": "f", "line_start": 1},
            {"file": "a.c", "name": "f", "line_start": 40},  # duplicate
        ]

        _re_review_joern_enriched(
            result, config, review_fn,
            checklist={"files": []},
            context_map=None,
            fuzz_coverage=None,
            evidence_index=evidence_index,
            sarif_cache=None,
            entry_points=set(),
            gaps_before_joern=gaps,
            start_time=_time.monotonic(),
            on_progress=None,
        )

        assert review_calls[0] == 1  # deduped, one re-review
        assert len(result.outcomes) == 1
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1
        assert result.clean == 0
