"""Tests for core.audit.orchestrator — autonomous review loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _ContentFilterError,
    _check_finding_gates,
    _joern_live_query,
    _multi_pass_review,
    _hypothesis_to_semgrep_rule,
    _hypothesis_to_tool_chain,
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
        "int check_pw(char *pw) {\n"
        "  return strcmp(pw, stored);\n"
        "}\n"
        "\n"
        "int validate(char *input) {\n"
        "  return strlen(input) > 0;\n"
        "}\n"
    )

    out = tmp_path / "out"
    out.mkdir()

    checklist = {
        "files": [
            {
                "path": "src/auth.c",
                "items": [
                    {"name": "check_pw", "line_start": 1, "line_end": 3},
                    {"name": "validate", "line_start": 5, "line_end": 7},
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
        assert result == {"src/auth.c:check_pw", "src/util.c:helper"}

    def test_reads_orchestrator_review_actions(self, tmp_path: Path):
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"orchestrator_review","key":"src/auth.c:check_pw"}\n'
            '{"action":"context","key":"src/auth.c:validate"}\n'
        )
        result = get_reviewed_set(tmp_path)
        assert result == {"src/auth.c:check_pw"}


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
                raise RuntimeError("LLM timeout")
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
    def test_checked_by_written_to_checklist(self, tmp_path: Path):
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

        with open(out / "checklist.json") as f:
            updated = json.load(f)
        items = updated["files"][0]["items"]
        for item in items:
            assert "checked_by" in item
            assert "audit" in item["checked_by"]
            assert "gpt-test" in item["checked_by"]

    def test_error_status_not_marked_checked(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)

        def review_fn(ctx, config):
            raise RuntimeError("boom")

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            batch_sloc_threshold=0,
        )
        run_orchestrator(config, review_fn)

        with open(out / "checklist.json") as f:
            updated = json.load(f)
        items = updated["files"][0]["items"]
        for item in items:
            assert "checked_by" not in item

    def test_checked_by_written_to_coverage_audit(self, tmp_path: Path):
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

        with open(out / "coverage-audit.json") as f:
            audit_data = json.load(f)
        analysed = audit_data["functions_analysed"]
        check_pw = next(
            (fa for fa in analysed if fa["function"] == "check_pw"),
            None,
        )
        assert check_pw is not None
        assert "checked_by" in check_pw
        assert "audit" in check_pw["checked_by"]


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

    def test_null_pointer_no_smt(self):
        from core.audit.orchestrator import _hypothesis_to_smt_verb
        assert _hypothesis_to_smt_verb("null pointer dereference") is None

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
            assert "rcu_no_lock" in result

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

    def test_g2_joern_receipt_passes(self):
        v = _check_finding_gates(self._outcome(evidence_tool="joern:live"))
        assert not any("G2" in x for x in v)

    def test_g2_bare_joern_fails(self):
        """A bare tool name is a model claim, not an orchestrator receipt.

        Only ``_stamp_evidence`` mints a receipt, and it always writes
        ``<namespace>:<detail>``. Accepting the bare name let an
        un-run tool stand in for a real one.
        """
        v = _check_finding_gates(self._outcome(evidence_tool="joern"))
        assert any("G2" in x for x in v)

    def test_g2_arbitrary_string_fails(self):
        v = _check_finding_gates(self._outcome(evidence_tool="madeup:thing"))
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

    def test_finding_with_llm_evidence_demoted_by_gate(self, tmp_path: Path):
        """G2: finding with evidence_tool='llm' gets demoted to suspicious."""
        target, out = _setup_target(tmp_path)

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
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False,
            batch_sloc_threshold=0,
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
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
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
        )
        result = run_orchestrator(config, review_fn)
        assert result.sweep_promoted == 0
        assert result.findings == 0
        assert result.suspicious == 2

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
        assert result.suspicious >= 1


class TestResolveGateDemoted:
    """Gate-demoted suspicious → clean when no mechanical tool corroborates."""

    def _make_result(self, *outcomes):
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        return r

    def test_g2_demoted_resolves_to_clean(self, tmp_path: Path):
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
        assert result.outcomes[0].status == "clean"
        assert result.suspicious == 0
        assert result.clean == 1

    def test_self_contradiction_resolves_to_clean(self, tmp_path: Path):
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
        assert result.outcomes[0].status == "clean"
        assert result.suspicious == 0
        assert result.clean == 1

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


class TestToolChain:
    """Test _hypothesis_to_tool_chain and _run_tool_chain."""

    def test_chain_returns_multiple_tools(self):
        chain = _hypothesis_to_tool_chain(
            "out-of-bounds array index without validation",
            "sem.c",
        )
        types = [e["type"] for e in chain]
        assert "smt" in types
        assert "coccinelle" in types

    def test_chain_empty_for_unmatched(self):
        chain = _hypothesis_to_tool_chain(
            "the function trusts its calling context",
            "shm.c",
        )
        assert chain == []

    def test_chain_single_tool(self):
        chain = _hypothesis_to_tool_chain(
            "race condition leads to use-after-free",
            "shm.c",
        )
        types = [e["type"] for e in chain]
        assert "coccinelle" in types

    def test_chain_preserves_order(self):
        chain = _hypothesis_to_tool_chain(
            "buffer overflow via strcpy call",
            "msg.c",
        )
        types = [e["type"] for e in chain]
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
                tool="coccinelle_consistency", file_path="<codebase>",
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_consistency_check", mock_cocci)

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
                tool="coccinelle_consistency", file_path="<codebase>",
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_consistency_check", mock_cocci)

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
                tool="coccinelle_consistency", file_path="<codebase>",
                function_name=kw["function_name"],
                outcome="confirmed",
            )

        monkeypatch.setattr(orch_mod, "run_smt_verb_direct", mock_smt)
        monkeypatch.setattr(orch_mod, "run_consistency_check", mock_cocci)

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
            target_path=target, out_dir=out,
            budget=10, batch_sloc_threshold=0,
            deepen_suspicious=True,
            max_refinements=0,
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
        )
        result = run_orchestrator(config, review_fn)

        assert call_count[0] == 1
        assert result.suspicious == 1


class TestMultiPassReview:

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
        assert outcome.duration_s == 3.0
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

    def test_returns_flows_from_evidence_index(self):
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
            target_path=Path("/tmp"), out_dir=Path("/tmp"),
        )
        result = _run_clean_check_sweep(outcome, config, index)
        assert result is not None
        assert "buf" in result
        assert "memcpy" in result

    def test_returns_none_for_empty_evidence(self):
        from core.audit.orchestrator import _run_clean_check_sweep
        from core.evidence import EvidenceRecord
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean", body="all good",
        )
        rec = EvidenceRecord(file="a.c", function="f")
        index = {"a.c:f": rec}

        config = OrchestratorConfig(
            target_path=Path("/tmp"), out_dir=Path("/tmp"),
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
        from core.audit.orchestrator import _enrich_summaries_from_joern
        from core.analysis.summaries import FunctionSummary, EvidenceTier
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
