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
    """Rows are appended through the legitimate writer
    (``append_audit_log``), which stamps the per-purpose integrity
    token — suppression authority requires it (see the forged/
    tampered cases at the end)."""

    def test_empty_log(self, tmp_path: Path):
        result = get_reviewed_set(tmp_path)
        assert result == set()

    def test_reads_record_actions(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "record",
                                    "key": "src/auth.c:check_pw"})
        append_audit_log(tmp_path, {"action": "context",
                                    "key": "src/auth.c:validate"})
        append_audit_log(tmp_path, {"action": "record",
                                    "key": "src/util.c:helper"})
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/util.c:helper" in result
        assert "src/auth.c:validate" not in result

    def test_reads_orchestrator_review_actions(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "orchestrator_review",
                                    "key": "src/auth.c:check_pw"})
        append_audit_log(tmp_path, {"action": "context",
                                    "key": "src/auth.c:validate"})
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/auth.c:validate" not in result

    def test_lined_key_produces_bare_fallback(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "orchestrator_review",
                                    "key": "sql.go:Scan:3232"})
        result = get_reviewed_set(tmp_path)
        assert "sql.go:Scan:3232" in result
        assert "sql.go:Scan" in result

    def test_bare_key_no_spurious_strip(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "orchestrator_review",
                                    "key": "src/auth.c:check_pw"})
        result = get_reviewed_set(tmp_path)
        assert "src/auth.c:check_pw" in result
        assert "src/auth.c" not in result

    def test_edge_contract_records_never_mark_caller_reviewed(
        self, tmp_path: Path,
    ):
        """A tier-1 edge-contract record reviews one outgoing EDGE, not
        the caller function. Without the edge_callee screen the caller
        was treated as reviewed and its function review silently
        dropped from the workqueue (observed live on pinned targets)."""
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {
            "action": "orchestrator_review", "key": "src/a.c:recv:66",
            "status": "clean", "edge_callee": "src/b.c:pull"})
        append_audit_log(tmp_path, {
            "action": "orchestrator_review", "key": "src/a.c:send:20",
            "status": "clean"})
        result = get_reviewed_set(tmp_path)
        assert "src/a.c:recv" not in result
        assert "src/a.c:recv:66" not in result
        assert "src/a.c:send" in result

    def test_error_status_excluded(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "orchestrator_review",
                                    "key": "src/a.c:ok",
                                    "status": "clean"})
        append_audit_log(tmp_path, {"action": "orchestrator_review",
                                    "key": "src/b.c:fail",
                                    "status": "error"})
        append_audit_log(tmp_path, {"action": "record",
                                    "key": "src/c.c:also_fail",
                                    "status": "error"})
        result = get_reviewed_set(tmp_path)
        assert "src/a.c:ok" in result
        assert "src/b.c:fail" not in result
        assert "src/c.c:also_fail" not in result

    def test_forged_unstamped_row_never_suppresses(self, tmp_path: Path):
        """The log is target-writable mid-run and its rows are
        declared telemetry; a hand-planted clean row (the journal's
        forged-clean-row lever, one file over) must not silently drop
        the function from the workqueue."""
        log = tmp_path / ".audit-log.jsonl"
        log.write_text(
            '{"action":"record","status":"clean","key":"src/x.c:f"}\n'
            '{"action":"orchestrator_review","status":"clean",'
            '"key":"src/y.c:g"}\n'
        )
        assert get_reviewed_set(tmp_path) == set()

    def test_tampered_row_never_suppresses(self, tmp_path: Path):
        from core.audit.record import append_audit_log, load_audit_log
        append_audit_log(tmp_path, {"action": "record",
                                    "key": "src/a.c:real",
                                    "status": "clean"})
        rows = load_audit_log(tmp_path)
        rows[0]["key"] = "src/b.c:forged"      # edit under a valid token
        import json as _json
        (tmp_path / ".audit-log.jsonl").write_text(
            "\n".join(_json.dumps(r) for r in rows) + "\n")
        assert get_reviewed_set(tmp_path) == set()

    def test_cross_run_replay_never_suppresses(self, tmp_path: Path):
        """A row legitimately stamped in run A, copied verbatim into
        run B's log, must NOT suppress in run B: the audit-log lane
        has no source-hash gate or fold to bound a replay, and a
        sibling run's log carries exactly the file:function keys the
        current workqueue would use. The MAC is run-bound."""
        from core.audit.record import append_audit_log
        run_a = tmp_path / "run-a"
        run_b = tmp_path / "run-b"
        run_a.mkdir()
        run_b.mkdir()
        append_audit_log(run_a, {"action": "record",
                                 "key": "src/x.c:f",
                                 "status": "clean"})
        (run_b / ".audit-log.jsonl").write_bytes(
            (run_a / ".audit-log.jsonl").read_bytes())
        assert "src/x.c:f" in get_reviewed_set(run_a)
        assert get_reviewed_set(run_b) == set()

    def test_oversize_log_never_suppresses(self, tmp_path: Path):
        """The log is suppression-authority input from the
        sandbox-writable run dir — an over-budget trail loads as
        nothing (over-review direction), same intake rule as the
        journal's cap."""
        from core.audit.record import append_audit_log
        append_audit_log(tmp_path, {"action": "record",
                                    "key": "src/x.c:f",
                                    "status": "clean"})
        log = tmp_path / ".audit-log.jsonl"
        with log.open("ab") as f:
            f.truncate(65 * 1024 * 1024)
        assert get_reviewed_set(tmp_path) == set()

    def test_collector_flush_rows_suppress(self, tmp_path: Path):
        """The Collector's batched flush is the production writer of
        orchestrator_review rows — its rows must carry the token and
        keep their resume-suppression authority."""
        from core.audit.collector import Collector
        collector = Collector(
            out_dir=tmp_path, target_path=tmp_path, run_id="r1")
        collector._log_entries.append({
            "action": "orchestrator_review",
            "key": "src/a.c:reviewed", "status": "clean"})
        collector._flush_audit_log()
        assert "src/a.c:reviewed" in get_reviewed_set(tmp_path)


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


class TestExtractAndPropagate:
    """The propagation-result consumption seam in _extract_and_propagate."""

    def _outcome_with_constraint(self):
        return ReviewOutcome(
            file="src/auth.c",
            function="check_pw",
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

    def test_depth_limited_status_lands_on_constraint(self):
        """A depth-limited hop must mark the constraint, not fall
        through as an ordinary unresolved result."""
        from core.audit.orchestrator import _extract_and_propagate
        from core.audit.propagation import PropagationConfig

        constraints = _extract_and_propagate(
            self._outcome_with_constraint(),
            [],
            {"files": []},
            set(),
            PropagationConfig(max_depth=0),
        )
        assert len(constraints) == 1
        assert constraints[0].status == "depth_limited"
        assert constraints[0].depth_reached == 0

    def test_unresolved_constraint_stays_open(self):
        """An unresolved hop (no inventory, no resolvers) leaves the
        constraint open — nothing is derived, nothing is demoted."""
        from core.audit.orchestrator import _extract_and_propagate
        from core.audit.propagation import PropagationConfig

        constraints = _extract_and_propagate(
            self._outcome_with_constraint(),
            [],
            {"files": []},
            set(),
            PropagationConfig(max_depth=5),
        )
        assert len(constraints) == 1
        assert constraints[0].status == "open"


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
        """G1: finding without hypothesis gets demoted to suspicious.

        The stub claims a bare tool receipt (``semgrep:...``), so the
        demotion referee keeps the demoted outcomes suspicious at
        end-of-run: a probe-backed suspicious may only be resolved by a
        verification-role refuter, never by silence (see
        test_demotion_referee.py). The gate's own contract — no finding
        survives without a testable hypothesis — still holds.
        """
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
        assert result.suspicious == 2

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

    def test_corrective_entry_carries_prior_strategies_and_span(
        self, tmp_path: Path,
    ):
        # The corrective row re-describes the SAME review — dropping
        # the strategy record (the old minimal gap did) made cross-run
        # verdict reuse refuse the function as strategy_changed on
        # every later run, and the line_end-less span left only a
        # one-line source hash as staleness evidence.
        from core.audit.collector import append_journal_for_outcome
        from core.audit.journal import latest_entries, make_function_key
        from core.audit.orchestrator import _rejournal_final_statuses

        config = self._setup(tmp_path)
        initial = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="initial", hypothesis="auth bypass", line=1,
        )
        append_journal_for_outcome(
            out_dir=config.out_dir,
            target_path=config.target_path,
            run_id="run-1",
            outcome=initial,
            gap={
                "line_start": 1, "line_end": 1,
                "strategies": ["auth", "general"],
            },
        )

        final = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="resolved clean", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _rejournal_final_statuses(result, config) == 1
        entry = latest_entries(config.out_dir)[make_function_key("a.c", "f")]
        assert entry.verdict == "clean"
        assert entry.strategies == ["auth", "general"]
        assert entry.line_start == 1
        assert entry.line_end == 1

    def test_echo_drift_corrective_carries_the_review_not_the_echo(
        self, tmp_path: Path,
    ):
        # A post-loop mechanical echo is routinely the newest journal
        # row for exactly the function being corrected — the echo's
        # verdict IS the drift the corrective row resolves. The
        # corrective row must carry the REVIEW's span and strategy
        # record: adopting the echo's fields stamps the function's
        # final verdict as a mechanical echo, so every
        # is_mechanical_echo consumer drops it — the report's
        # reviewed/clean counts lose the function (a resumed run's
        # report no longer covered its own segment's verdicts) and
        # cross-run reuse refuses it as strategy_changed.
        from core.audit.collector import append_journal_for_outcome
        from core.audit.journal import (
            is_mechanical_echo,
            latest_entries,
            make_function_key,
        )
        from core.audit.orchestrator import _rejournal_final_statuses

        config = self._setup(tmp_path)
        review = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="reviewed clean", hypothesis="auth bypass", line=1,
        )
        append_journal_for_outcome(
            out_dir=config.out_dir, target_path=config.target_path,
            run_id="run-1", outcome=review,
            gap={"line_start": 1, "line_end": 1,
                 "strategies": ["auth", "general"]},
        )
        echo = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="[mechanical] pattern hit", line=0,
        )
        append_journal_for_outcome(
            out_dir=config.out_dir, target_path=config.target_path,
            run_id="run-1", outcome=echo,
            gap={"line_start": 0,
                 "strategies": ["post-loop-mechanical"]},
        )

        final = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="resolved clean", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _rejournal_final_statuses(result, config) == 1
        entry = latest_entries(config.out_dir)[make_function_key("a.c", "f")]
        assert entry.verdict == "clean"
        assert not is_mechanical_echo(entry)
        assert entry.strategies == ["auth", "general"]
        assert entry.line_start == 1
        assert entry.line_end == 1


class TestPostLoopReceiptRescue:
    """Post-loop structural receipts re-drive the anti-self-refutation
    gate for clean outcomes, so a receipt that never reached (or did
    not survive to) the review-time gate still reaches the verdict."""

    def _setup(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "m.py").write_text("def wire_endpoints():\n    pass\n")
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def _clean_outcome(self, *, confidence="refuted"):
        return ReviewOutcome(
            file="m.py", function="wire_endpoints", status="clean",
            body="reviewed clean", line=800,
            hypotheses=[{
                "mechanism": (
                    "the auth mode flag gates registration endpoints "
                    "asymmetrically: some stay wired in every mode"
                ),
                "confidence": confidence,
                "counter": "each view enforces its own permission",
            }],
        )

    def _receipt(self, check_type="auth_mode_registration"):
        return {
            "check_type": check_type,
            "file": "m.py",
            "function": "wire_endpoints",
            "evidence": "calls gated on an auth-mode conditional",
            "cwe": "CWE-306",
        }

    def test_strong_stem_floors_without_call_overlap(
        self, tmp_path: Path,
    ):
        """Reviewer used the receipt's own vocabulary (auth/mode/
        registration) without naming the call site — still floors."""
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "views registered unconditionally regardless of the auth mode; "
            "under external auth modes the endpoints stay reachable"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._call_site_receipt()], config,
        )
        assert flipped == 1
        assert outcome.status == "suspicious"

    def test_matching_receipt_flips_clean_outcome(self, tmp_path: Path):
        from core.audit.orchestrator import _post_loop_receipt_rescue
        from core.audit.record import load_audit_log

        config = self._setup(tmp_path)
        outcome = self._clean_outcome()
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1

        flipped = _post_loop_receipt_rescue(
            result, [self._receipt()], config,
        )
        assert flipped == 1
        assert outcome.status == "suspicious"
        # Tally counters move with the flip — the final summary line
        # prints from them (observed live: "0 suspicious" printed while
        # the journal held three post-loop flips).
        assert result.clean == 0
        assert result.suspicious == 1
        assert "anti_self_refutation" in outcome.body
        rows = [
            e for e in load_audit_log(config.out_dir)
            if e.get("action") == "refutation_gate"
        ]
        assert len(rows) == 1
        assert rows[0]["stage"] == "post-loop"
        assert rows[0]["function"] == "wire_endpoints"

    def test_source_reaches_gate_for_mechanical_acceptance(
        self, tmp_path: Path,
    ):
        """The post-loop backstop threads the raw source span to the
        gate: without it the mechanical acceptance probes (safe
        teardown / race protection) cannot run and this pass RE-FLOORED
        the very self-refutations the mid-loop gate had accepted."""
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        src_file = config.target_path / "t.c"
        src_file.write_text(
            "static int release_ctx(struct ctx *c)\n"
            "{\n"
            "\thrtimer_cancel(&c->tmr);\n"
            "\tkfree_rcu(c, rcu);\n"
            "\treturn 0;\n"
            "}\n",
        )
        outcome = ReviewOutcome(
            file="t.c", function="release_ctx", status="clean",
            body="reviewed clean", line=1,
            hypotheses=[{
                "mechanism": (
                    "CWE-416 use after free: kfree_rcu frees the ctx "
                    "while a callback may still walk it"
                ),
                "confidence": "refuted",
                "counter": "hrtimer_cancel waits; kfree_rcu defers",
            }],
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        detectors = {
            "t.c:release_ctx": [{
                "file": "t.c", "function": "release_ctx",
                "detector": "typestate", "line": 4,
                "description": "free of tracked pointer",
            }],
        }
        gaps = [{
            "file": "t.c", "name": "release_ctx",
            "line_start": 1, "line_end": 6,
        }]
        flipped = _post_loop_receipt_rescue(
            result, [], config,
            mechanical_findings=detectors, gaps=gaps,
        )
        # The waiting-teardown witness discharges the lifetime
        # self-refutation — no re-floor.
        assert flipped == 0
        assert outcome.status == "clean"

    def test_same_named_methods_use_their_own_span(self, tmp_path: Path):
        """A file with several same-named functions (Go methods named
        after their interface) must hand each outcome ITS OWN span:
        the old (file, name) keying gave every outcome the first gap's
        body, so the gate's mechanical probes ran on the wrong
        function and re-floored discharges the mid-loop gate had
        accepted with the right source."""
        pytest.importorskip("tree_sitter_go")
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        # The goconc discharge only runs under the operator's
        # repo-trust assertion (synthetic fixture — asserted here).
        config.repo_trusted = True
        src_file = config.target_path / "store.go"
        src_file.write_text(
            "package store\n\n"                            # 1-2
            "type Rows struct{ done chan struct{} }\n\n"   # 3-4
            "func (rs *Rows) awaitDone() {\n"              # 5
            "\t<-rs.done\n"
            "}\n\n"
            "func (rs *Rows) init() {\n"                   # 9
            "\tgo rs.awaitDone()\n"
            "}\n\n"
            "func (rs *Rows) Scan(v string) error {\n"     # 13
            "\treturn nil\n"
            "}\n\n"
            "type Null struct{ Valid bool }\n\n"           # 17-18
            "func (n *Null) Scan(v string) error {\n"      # 19
            "\tn.Valid = true\n"
            "\treturn nil\n"
            "}\n",
        )
        outcome = ReviewOutcome(
            file="store.go", function="Scan", status="clean",
            body="reviewed clean", line=19,
            hypotheses=[{
                "mechanism": (
                    "CWE-362 data race: a package-internal goroutine "
                    "could write n.Valid concurrently with Scan"
                ),
                "confidence": "refuted",
                "counter": (
                    "no internal goroutine in the package touches "
                    "scan receivers"
                ),
            }],
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        detectors = {
            "store.go:Scan": [{
                "file": "store.go", "function": "Scan",
                "detector": "typestate", "line": 20,
                "description": "unsynchronised field write",
            }],
        }
        gaps = [
            {"file": "store.go", "name": "Scan",
             "line_start": 13, "line_end": 15},
            {"file": "store.go", "name": "Scan",
             "line_start": 19, "line_end": 22},
        ]
        flipped = _post_loop_receipt_rescue(
            result, [], config,
            mechanical_findings=detectors, gaps=gaps,
        )
        # With ITS OWN span the goconc witness discharges the Null
        # receiver's dismissal; with the first gap's span (a *Rows
        # method — the package spawns a Rows-receiver goroutine) it
        # would refuse and this pass would re-floor.
        assert flipped == 0
        assert outcome.status == "clean"

    def test_non_structural_receipt_ignored(self, tmp_path: Path):
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome()
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._receipt(check_type="resource_exhaustion")],
            config,
        )
        assert flipped == 0
        assert outcome.status == "clean"

    def test_unrefuted_hypothesis_not_rescued(self, tmp_path: Path):
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._receipt()], config,
        )
        assert flipped == 0
        assert outcome.status == "clean"

    def test_non_clean_outcomes_untouched(self, tmp_path: Path):
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome()
        outcome.status = "suspicious"
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._receipt()], config,
        )
        assert flipped == 0

    def _call_site_receipt(self):
        return {
            "check_type": "auth_mode_registration",
            "file": "m.py",
            "function": "wire_endpoints",
            "evidence": (
                "2 add_view_no_menu() call(s) are gated on an "
                "auth-mode conditional, but the add_view_no_menu() "
                "call(s) at line(s) 17, 18 run REGARDLESS of the mode"
            ),
            "cwe": "CWE-306",
        }

    def test_low_confidence_dismissal_floored_on_call_site_overlap(
        self, tmp_path: Path,
    ):
        """Reviewer raised the receipt's exact shape (same call site)
        at low confidence and ruled clean — receipt outranks the
        dismissal."""
        from core.audit.orchestrator import _post_loop_receipt_rescue
        from core.audit.record import load_audit_log

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "views registered via add_view_no_menu regardless of the "
            "auth mode, exposing mode-gated registration capability"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._call_site_receipt()], config,
        )
        assert flipped == 1
        assert outcome.status == "suspicious"
        rows = [
            e for e in load_audit_log(config.out_dir)
            if e.get("action") == "refutation_gate"
        ]
        assert rows[0]["gate"] == "receipt_corroborated_hypothesis"

    def test_low_confidence_unrelated_hypothesis_untouched(
        self, tmp_path: Path,
    ):
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "session cookie flags are permissive on the login response"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._call_site_receipt()], config,
        )
        assert flipped == 0
        assert outcome.status == "clean"

    def test_family_bridge_floors_race_dismissal(self, tmp_path: Path):
        """Natural race phrasing carries none of the check-type token
        stems — the family bridge plus call-site overlap must carry."""
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "two Write calls on the output field without a lock; a "
            "concurrent caller can insert bytes between them"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        receipt = {
            "check_type": "shared_writer_race",
            "file": "m.py",
            "function": "wire_endpoints",
            "evidence": (
                "wire_endpoints() performs 2 separate Write() calls on "
                "the writer field per invocation, holds no lock"
            ),
        }
        flipped = _post_loop_receipt_rescue(result, [receipt], config)
        assert flipped == 1
        assert outcome.status == "suspicious"

    def test_family_bridge_ignores_unrelated_write_mention(
        self, tmp_path: Path,
    ):
        """A hypothesis that mentions the call name for a different
        reason (ignored error) has no family keyword — no floor."""
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="refuted")
        outcome.hypotheses[0]["mechanism"] = (
            "error from the second Write is returned but the first "
            "Write's failure may be swallowed"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        receipt = {
            "check_type": "shared_writer_race",
            "file": "m.py",
            "function": "wire_endpoints",
            "evidence": (
                "wire_endpoints() performs 2 separate Write() calls on "
                "the writer field per invocation, holds no lock"
            ),
        }
        flipped = _post_loop_receipt_rescue(result, [receipt], config)
        assert flipped == 0

    def test_detector_findings_refloor_clobbered_verdict(
        self, tmp_path: Path,
    ):
        """A later re-review can clobber a mid-loop detector floor
        (its synthetic context lacks the injection); the post-loop
        pass re-applies the deterministic receipt."""
        from core.audit.orchestrator import _post_loop_receipt_rescue
        from core.audit.record import load_audit_log

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "uninitialized ret: the switch has no default case so ret "
            "is left unset on unexpected values"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [], config,
            mechanical_findings={
                "m.py:wire_endpoints": [
                    {"detector": "cocci:uninitialized_return"},
                ],
            },
        )
        assert flipped == 1
        assert outcome.status == "suspicious"
        rows = [
            e for e in load_audit_log(config.out_dir)
            if e.get("action") == "refutation_gate"
        ]
        assert rows[0]["gate"] == "anti_self_refutation"
        assert rows[0]["stage"] == "post-loop"

    def test_pre_evidence_refloors_clobbered_verdict(
        self, tmp_path: Path,
    ):
        """The pre-loop screen receipt lives on the gap; a re-review
        from a synthetic gap loses it — the post-loop pass re-applies
        it to the current verdict."""
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "huge parsed values overflow int32 storage downstream"
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [], config,
            gaps=[{
                "file": "m.py", "name": "wire_endpoints",
                "_smt_pre_evidence": "smt:check-parsed-int-contract",
            }],
        )
        assert flipped == 1
        assert outcome.status == "suspicious"

    def test_tool_evidence_blocks_corroboration_floor(
        self, tmp_path: Path,
    ):
        from core.audit.orchestrator import _post_loop_receipt_rescue

        config = self._setup(tmp_path)
        outcome = self._clean_outcome(confidence="low")
        outcome.hypotheses[0]["mechanism"] = (
            "views registered via add_view_no_menu regardless of the "
            "auth mode, exposing mode-gated registration capability"
        )
        outcome.evidence_tool = "joern:flow"
        result = OrchestratorResult()
        result.outcomes = [outcome]

        flipped = _post_loop_receipt_rescue(
            result, [self._call_site_receipt()], config,
        )
        assert flipped == 0


class TestQualifiedIdentityCarry:
    """Status-flipping clone helpers must carry function_qualified —
    a promotion logged without it never reaches a receiver-qualified
    label key, so the flip is invisible to last-row-wins scoring."""

    def _outcome(self):
        o = ReviewOutcome(
            file="pkg/a.go", function="SetVal", status="clean",
            body="b", line=10,
            hypotheses=[{
                "mechanism": "unchecked arithmetic on parsed exponent",
                "confidence": "medium",
                "counter": "",
            }],
        )
        o.function_qualified = "Recv.SetVal"
        return o

    def test_promote_outcome_carries_qualified(self):
        from core.audit.orchestrator import _promote_outcome
        p = _promote_outcome(self._outcome(), "smt:check")
        assert p.function_qualified == "Recv.SetVal"

    def test_demote_outcome_carries_qualified(self):
        from core.audit.orchestrator import _demote_outcome
        d = _demote_outcome(self._outcome(), "[gate]")
        assert d.function_qualified == "Recv.SetVal"

    def test_hypothesis_inconsistent_promotion_carries_qualified(self):
        from core.audit.orchestrator import (
            _promote_hypothesis_inconsistent,
        )
        result = OrchestratorResult()
        o = self._outcome()
        result.outcomes = [o]
        result.clean = 1
        _promote_hypothesis_inconsistent(result)
        assert result.outcomes[0].status == "suspicious"
        assert result.outcomes[0].function_qualified == "Recv.SetVal"


class TestVerdictFinalizationLatch:
    """After the corrective passes, a straggler commit (abandoned
    study re-review finishing late) must not append — it would land
    after the corrective rows and win last-row-wins with a verdict the
    export never saw."""

    def test_late_commit_suppressed(self, tmp_path: Path):
        from core.audit.journal import latest_entries
        from core.audit.orchestrator import _commit_outcome

        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)

        early = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="b", line=1,
        )
        _commit_outcome(config, early, {"line_start": 1})
        config._verdicts_finalized = True
        late = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="late re-review", line=1,
        )
        _commit_outcome(config, late, {"line_start": 1})

        entries = latest_entries(out)
        assert len(entries) == 1
        (entry,) = entries.values()
        assert entry.verdict == "suspicious"


class TestRelogFinalStatuses:
    """Audit-log twin of the re-journal pass: ``orchestrator_review``
    rows are written mid-loop, pre-resolution — the end-of-run pass
    appends corrective rows so last-row-per-key consumers (corpus
    scoring, resume dedup) read final statuses, not retracted ones."""

    def _setup(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def _log_initial(self, config, status="suspicious"):
        from core.audit.record import append_audit_log
        append_audit_log(config.out_dir, {
            "action": "orchestrator_review",
            "key": "a.c:f:1",
            "status": status,
            "strategies": ["memory"],
            "cost_usd": 0.25,
        })

    def test_drifted_status_relogged_last(self, tmp_path: Path):
        from core.audit.orchestrator import _relog_final_statuses
        from core.audit.record import load_audit_log

        config = self._setup(tmp_path)
        self._log_initial(config, status="suspicious")

        final = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="[counter-escalation resolution: ...]",
            hypothesis="auth bypass", line=1, cost_usd=0.25,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _relog_final_statuses(result, config) == 1
        rows = [
            e for e in load_audit_log(config.out_dir)
            if e.get("action") == "orchestrator_review"
        ]
        assert rows[-1]["status"] == "clean"
        assert rows[-1]["prior_status"] == "suspicious"
        assert rows[-1]["final_status_correction"] is True
        # strategy_stats must not double-count this function: the
        # corrective row never carries ``strategies``.
        assert "strategies" not in rows[-1]
        # Per-label cost attribution survives last-row-wins scoring.
        assert rows[-1]["cost_usd"] == 0.25

    def test_unchanged_status_not_relogged(self, tmp_path: Path):
        from core.audit.orchestrator import _relog_final_statuses

        config = self._setup(tmp_path)
        self._log_initial(config, status="suspicious")

        final = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="still suspicious", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _relog_final_statuses(result, config) == 0

    def test_never_logged_outcome_skipped(self, tmp_path: Path):
        from core.audit.orchestrator import _relog_final_statuses

        config = self._setup(tmp_path)
        final = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="resolved", hypothesis="auth bypass", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _relog_final_statuses(result, config) == 0

    def test_error_outcome_skipped(self, tmp_path: Path):
        from core.audit.orchestrator import _relog_final_statuses

        config = self._setup(tmp_path)
        self._log_initial(config, status="suspicious")
        final = ReviewOutcome(
            file="a.c", function="f", status="error",
            body="", hypothesis="", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]

        assert _relog_final_statuses(result, config) == 0


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
        # Same boundary, prep side: the sandboxed mechanical-detector
        # prep is ~5s of real detector runs per test on fixtures whose
        # findings these gate-wiring assertions never read. Full
        # variadic signature + the real (dict, set) contract, so the
        # stub executes rather than dying into the phase's blanket
        # except.
        monkeypatch.setattr(
            _orch, "_run_mechanical_detectors",
            lambda *args, **kwargs: ({}, set()),
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
        server.run_taint_queries_batch.return_value = [flow]

        result = _joern_live_query(server, "parse_header", ["memcpy"])
        assert len(result) == 1
        assert result[0].sink_call == "memcpy"
        server.run_taint_queries_batch.assert_called_once()
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[0][0] == [("parse_header", "memcpy")]
        assert call_args[1]["timeout"] == 30

    def test_live_query_batches_all_sinks_in_one_submission(self):
        """One batched call covers every sink; the budget scales
        sublinearly with batch width (base x ceil(sqrt(N)))."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        server = MagicMock()
        flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="strcpy", sink_arg_idx=0,
        )
        server.run_taint_queries_batch.return_value = [flow]

        result = _joern_live_query(server, "fn", ["strcpy", "memcpy"])
        assert len(result) == 1
        server.run_taint_queries_batch.assert_called_once()
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[0][0] == [("fn", "strcpy"), ("fn", "memcpy")]
        assert call_args[1]["timeout"] == 60  # 30 x ceil(sqrt(2))

    def test_live_query_budget_sublinear_on_wide_menus(self):
        """11 sinks (the widest dispatch menu) gets 4x the base, not
        11x (per-sink loop) and not 1x (flat batch)."""
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.return_value = []
        sinks = [f"sink_{i}" for i in range(11)]
        _joern_live_query(server, "fn", sinks)
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[1]["timeout"] == 120  # 30 x ceil(sqrt(11))

    def test_live_query_single_sink_keeps_base_budget(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.return_value = []
        _joern_live_query(server, "fn", ["memcpy"])
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[1]["timeout"] == 30

    def test_live_query_multi_sink_returns_all_flows_sorted(self):
        """The batch returns every sink's flows (the per-sink loop's
        first-hit-wins returned only the first) in deterministic
        order — strictly more evidence, same truthiness."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        strcpy_flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="strcpy", sink_arg_idx=0,
        )
        memcpy_flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server = MagicMock()
        server.run_taint_queries_batch.return_value = [
            strcpy_flow, memcpy_flow,
        ]

        result = _joern_live_query(server, "fn", ["strcpy", "memcpy"])
        assert [f.sink_call for f in result] == ["memcpy", "strcpy"]

    def test_live_query_empty_when_no_flows(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.return_value = []

        result = _joern_live_query(server, "fn", ["memcpy", "strcpy"])
        assert result == []
        server.run_taint_queries_batch.assert_called_once()

    def test_live_query_rejects_invalid_function_name(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        result = _joern_live_query(server, "not valid!", ["memcpy"])
        assert result == []
        server.run_taint_queries_batch.assert_not_called()

    def test_live_query_skips_invalid_sink(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.return_value = []
        _joern_live_query(server, "fn", ["bad;sink", "memcpy"])
        server.run_taint_queries_batch.assert_called_once()
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[0][0] == [("fn", "memcpy")]

    def test_live_query_all_sinks_invalid_never_queries(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        result = _joern_live_query(server, "fn", ["bad;sink"])
        assert result == []
        server.run_taint_queries_batch.assert_not_called()

    def test_live_query_handles_exception(self):
        """Batch-level failure falls back to a one-shot per-sink pass;
        the loop's own error accounting is what reaches errors_out."""
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.side_effect = RuntimeError("timeout")
        server.run_taint_query.side_effect = RuntimeError("still down")

        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy"], errors_out=errors,
        )
        assert result == []
        assert errors and "RuntimeError" in errors[0]

    def test_live_query_batch_failure_recovers_via_per_sink_pass(self):
        """A slow-CPG batch timeout must not cost every joern:live
        confirmation — the fallback loop still answers per sink."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server = MagicMock()
        server.run_taint_queries_batch.side_effect = RuntimeError("timeout")
        server.run_taint_query.return_value = [flow]

        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy", "strcpy"], errors_out=errors,
        )
        assert len(result) == 1
        # First-hit-wins loop semantics in the fallback.
        server.run_taint_query.assert_called_once()
        # The loop answered — the batch's failure must not read as
        # "unanswered" next to a real verdict.
        assert errors == []

    def test_live_query_batch_errors_fall_back_then_account(self):
        """A degraded batch is 'unanswered', never a refutation: the
        per-sink recovery pass runs, and when IT also degrades its
        per-sink accounting is what reaches errors_out."""
        from unittest.mock import MagicMock

        server = MagicMock()

        def fake_batch(pairs, *, timeout=None, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("timeout (async poll)")
            return []

        def fake_single(fn, sink, *, timeout=None, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("server is restarting")
            return []

        server.run_taint_queries_batch.side_effect = fake_batch
        server.run_taint_query.side_effect = fake_single

        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy", "strcpy"], errors_out=errors,
        )
        assert result == []
        assert errors == [
            "fn->memcpy: server is restarting",
            "fn->strcpy: server is restarting",
        ]

    def test_live_query_partial_batch_keeps_flows_and_reports_errors(self):
        """Flows AND errors in one batch: the flows are returned (no
        fallback pass) and the partial degradation stays visible to
        the error tier through errors_out."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server = MagicMock()

        def fake_batch(pairs, *, timeout=None, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("truncated response")
            return [flow]

        server.run_taint_queries_batch.side_effect = fake_batch

        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy", "strcpy"], errors_out=errors,
        )
        assert len(result) == 1
        server.run_taint_query.assert_not_called()
        assert errors == ["fn->[memcpy,strcpy]: truncated response"]

    def test_live_query_batch_error_then_clean_loop_is_a_refutation(self):
        """When the recovery pass completes cleanly with no flows, the
        result is a genuine negative — the batch's earlier degradation
        must not linger in errors_out and mislabel it 'unanswered'."""
        from unittest.mock import MagicMock

        server = MagicMock()

        def fake_batch(pairs, *, timeout=None, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("timeout (async poll)")
            return []

        server.run_taint_queries_batch.side_effect = fake_batch
        server.run_taint_query.return_value = []

        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy", "strcpy"], errors_out=errors,
        )
        assert result == []
        assert errors == []
        assert server.run_taint_query.call_count == 2

    def test_live_query_without_batch_api_falls_back_to_loop(self):
        """Duck-typed servers without run_taint_queries_batch keep the
        historical per-sink first-hit-wins loop."""
        from packages.joern.models import TaintFlow

        calls: list[tuple[str, str]] = []
        flow = TaintFlow(
            source_method="fn", source_param="x",
            sink_call="strcpy", sink_arg_idx=0,
        )

        class _LoopOnlyServer:
            def run_taint_query(self, source, sink, **kwargs):
                calls.append((source, sink))
                return [flow] if sink == "strcpy" else []

        result = _joern_live_query(
            _LoopOnlyServer(), "fn", ["strcpy", "memcpy"],
        )
        assert len(result) == 1
        assert calls == [("fn", "strcpy")]

    def test_tool_chain_joern_live_fallback(self, tmp_path: Path):
        """When pre-sweep has no hit and server is available, fires live query."""
        from unittest.mock import MagicMock

        from packages.joern.models import TaintFlow

        server = MagicMock()
        flow = TaintFlow(
            source_method="fn", source_param="buf",
            sink_call="memcpy", sink_arg_idx=0,
        )
        server.run_taint_queries_batch.return_value = [flow]

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
        server.run_taint_queries_batch.assert_not_called()

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
        server.run_taint_queries_batch.return_value = []

        _joern_live_query(server, "fn", ["os.system"])
        call_args = server.run_taint_queries_batch.call_args
        assert call_args[0][0] == [("fn", "system")]


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
            # The assertions below encode strict review ORDER (f1's
            # observation visible to f2's context) — auto worker
            # derivation can go parallel and race the accumulation.
            max_workers=1,
            # Observation accumulation is the subject, not the taint
            # channel: a joern-equipped host must not boot a real JVM
            # whose pre-sweep timing varies with machine load.
            joern_overrides={"enabled": False},
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


class TestMultiPassBudgetPropagation:
    """Budget-exceeded RuntimeErrors must escape _multi_pass_review —
    swallowing them journaled 'error' verdicts (or bought more spend
    via the fallback passes) after the cap was already blown."""

    @staticmethod
    def _budget_review(ctx, cfg):
        raise RuntimeError("LLM budget exceeded ($5.00 cap reached)")

    def test_single_pass_reraises_budget(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        with pytest.raises(RuntimeError, match="budget exceeded"):
            _multi_pass_review(
                self._budget_review,
                {"file": "a.c", "function": "f"}, config, passes=1,
            )

    def test_self_consistency_reraises_budget(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        with pytest.raises(RuntimeError, match="budget exceeded"):
            _multi_pass_review(
                self._budget_review,
                {"file": "a.c", "function": "f"}, config, passes=3,
            )

    def test_non_budget_error_still_journals(self, tmp_path: Path):
        target, out = _setup_target(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)

        def broken(ctx, cfg):
            raise RuntimeError("segfault in helper")

        outcome = _multi_pass_review(
            broken, {"file": "a.c", "function": "f"}, config, passes=1,
        )
        assert outcome.status == "error"


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

        def track_hash(file_path, line, window=10, line_end=None):
            h = orig_hash(file_path, line, window, line_end=line_end)
            hash_calls.append({
                "file": str(file_path), "line": line,
                "line_end": line_end, "hash": h,
            })
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


class TestSageRecallGate:
    """The pre-LLM SAGE recall gate in review_one_function.

    A prior clean/dormant hypothesis verdict with a matching source
    hash skips the LLM review entirely; findings/suspicious always
    re-test; ``config.sage_recall`` and the force bypasses gate it.
    Hermetic: the hook function is stubbed at its module seam, so no
    SAGE client is ever contacted.
    """

    def _run(self, tmp_path: Path, recall, *, config_kw=None):
        from unittest.mock import patch as _patch

        target, out = _setup_target(tmp_path)
        calls: list[str] = []

        def review_fn(ctx, config):
            calls.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="looked fine",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False, batch_sloc_threshold=0,
            joern_overrides={"enabled": False},
            **(config_kw or {}),
        )
        with _patch(
            "core.sage.hooks.recall_audit_hypothesis_verdict",
            side_effect=recall,
        ) as mock_recall:
            result = run_orchestrator(config, review_fn)
        return result, calls, mock_recall

    def test_prior_clean_verdict_skips_llm(self, tmp_path: Path):
        from core.audit.journal import latest_entries

        result, calls, mock_recall = self._run(
            tmp_path,
            lambda **kw: {
                "status": "clean",
                "tool": "semgrep:x",
                "source_hash": kw["source_hash"],
            },
        )

        assert calls == []  # LLM never invoked
        assert result.prefilter_skipped == 2
        assert mock_recall.call_count == 2
        kw = mock_recall.call_args[1]
        assert kw["file_path"] == "src/auth.c"
        assert kw["function"] in ("check_pw", "validate")
        assert kw["source_hash"]  # real hash from the real source

        # The skip is journaled as a real outcome with the recall
        # provenance stamp — coverage and reports see it.
        entries = latest_entries(tmp_path / "out")
        entry = entries.get("src/auth.c:check_pw")
        assert entry is not None
        assert entry.verdict == "clean"
        assert entry.evidence_tools == ["sage:recall:semgrep:x"]

    def test_prior_dormant_verdict_skips_as_dormant(self, tmp_path: Path):
        result, calls, _ = self._run(
            tmp_path,
            lambda **kw: {"status": "dormant", "tool": ""},
        )
        assert calls == []
        assert all(o.status == "dormant" for o in result.outcomes)

    def test_prior_finding_status_never_skips(self, tmp_path: Path):
        """Findings and suspicious verdicts always re-test — even if a
        hook ever returned one, the gate must not skip on it."""
        _, calls, _ = self._run(
            tmp_path,
            lambda **kw: {"status": "finding", "tool": "semgrep:x"},
        )
        assert sorted(calls) == ["check_pw", "validate"]

    def test_no_prior_verdict_reviews_normally(self, tmp_path: Path):
        _, calls, mock_recall = self._run(tmp_path, lambda **kw: None)
        assert sorted(calls) == ["check_pw", "validate"]
        assert mock_recall.call_count == 2

    def test_sage_recall_flag_disables_gate(self, tmp_path: Path):
        _, calls, mock_recall = self._run(
            tmp_path,
            lambda **kw: {"status": "clean", "tool": ""},
            config_kw={"sage_recall": False},
        )
        assert sorted(calls) == ["check_pw", "validate"]
        mock_recall.assert_not_called()

    def test_force_bypasses_recall(self, tmp_path: Path):
        _, calls, mock_recall = self._run(
            tmp_path,
            lambda **kw: {"status": "clean", "tool": ""},
            config_kw={"force": True},
        )
        assert sorted(calls) == ["check_pw", "validate"]
        mock_recall.assert_not_called()

    def test_recall_failure_never_blocks_review(self, tmp_path: Path):
        def _boom(**kw):
            raise RuntimeError("sage unavailable")

        _, calls, _ = self._run(tmp_path, _boom)
        assert sorted(calls) == ["check_pw", "validate"]

    def test_validate_confirmed_floor_blocks_recall_skip(
        self, tmp_path: Path,
    ):
        """Never-skip-validate-confirmed floor: a /validate-CONFIRMED
        function must get a real review even when a prior clean
        verdict with a matching source hash is recalled — a stored
        pre-validate clean is exactly what a confirmed detection-
        evasion defect looks like from the recall's side."""
        from unittest.mock import patch as _patch

        def _floor(evidence_index, gap_key):
            return gap_key == "src/auth.c:check_pw"

        with _patch(
            "core.audit.orchestrator._validate_confirmed_gap",
            side_effect=_floor,
        ):
            _, calls, _ = self._run(
                tmp_path,
                lambda **kw: {"status": "clean", "tool": "semgrep:x"},
            )
        # The confirmed gap reaches the LLM; the sibling still skips.
        assert calls == ["check_pw"]


class TestSageFpPrimer:
    """Prior finding-verdict FP primers in review_one_function.

    A prior false_positive / not_exploitable adjudication for a
    finding in the function (source window unchanged) is injected as
    HINT-TIER review context — the review always runs and the verdict
    is the reviewer's own. Never a skip, never a committed verdict:
    a finding-scoped adjudication says nothing about bug classes it
    never examined. Hermetic: both SAGE hooks stubbed at their seams.
    """

    @staticmethod
    def _hash_for(target: Path, line: int) -> str:
        from core.sage.hooks import compute_finding_source_hash
        return compute_finding_source_hash(target / "src" / "auth.c", line)

    def _run(self, tmp_path: Path, rows_fn, *, config_kw=None):
        from unittest.mock import patch as _patch

        target, out = _setup_target(tmp_path)
        seen_ctx: dict[str, dict] = {}

        def review_fn(ctx, config):
            seen_ctx[ctx["function"]] = ctx
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="looked fine",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=False, batch_sloc_threshold=0,
            joern_overrides={"enabled": False},
            **(config_kw or {}),
        )
        with (
            _patch(
                "core.sage.hooks.recall_audit_hypothesis_verdict",
                return_value=None,
            ),
            _patch(
                "core.sage.hooks.recall_prior_fp_verdicts",
                side_effect=lambda **kw: rows_fn(target, **kw),
            ) as mock_fp,
        ):
            result = run_orchestrator(config, review_fn)
        return result, seen_ctx, mock_fp, out

    def test_matching_prior_injects_hint_and_never_skips(
        self, tmp_path: Path,
    ):
        def rows(target, **kw):
            if kw["function"] != "check_pw":
                return []
            # Store-side shape: window hash around the FINDING line.
            return [{
                "verdict": "false_positive",
                "rule": "semgrep.strcpy",
                "source_hash": self._hash_for(target, 4),
                "confidence": 0.95,
            }]

        result, seen_ctx, _, out = self._run(tmp_path, rows)

        # BOTH functions were fully reviewed — the primer never skips.
        assert sorted(seen_ctx) == ["check_pw", "validate"]
        assert result.prefilter_skipped == 0
        # The hint reached the primed function's context only.
        priors = seen_ctx["check_pw"].get("sage_fp_priors")
        assert priors == [
            {"verdict": "false_positive", "rule": "semgrep.strcpy"},
        ]
        assert "sage_fp_priors" not in seen_ctx["validate"]
        # The committed verdict is the REVIEWER's, with no recall stamp.
        for o in result.outcomes:
            assert not (o.evidence_tool or "").startswith("sage:fp")

        # Hint-tier provenance trail: recorded, and dropped=False —
        # nothing was suppressed.
        recs = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        fp_recs = [
            r for r in recs if r.get("verdict") == "sage_false_positive"
        ]
        assert fp_recs and fp_recs[0]["function"] == "check_pw"
        assert fp_recs[0]["dropped"] is False
        assert fp_recs[0]["injected"] is True

    def test_stale_source_hash_injects_nothing(self, tmp_path: Path):
        """A recalled verdict whose window hash no longer matches any
        line of the function is dropped — no hint, plain review."""
        def rows(target, **kw):
            return [{
                "verdict": "false_positive",
                "rule": "semgrep.strcpy",
                "source_hash": "feedfacecafe",
            }]

        _, seen_ctx, _, out = self._run(tmp_path, rows)
        assert sorted(seen_ctx) == ["check_pw", "validate"]
        assert all(
            "sage_fp_priors" not in ctx for ctx in seen_ctx.values()
        )
        assert not (out / "suppressions.jsonl").exists()

    def test_blind_first_pass_withholds_hint(self, tmp_path: Path):
        def rows(target, **kw):
            if kw["function"] != "check_pw":
                return []
            return [{
                "verdict": "false_positive",
                "rule": "semgrep.strcpy",
                "source_hash": self._hash_for(target, 4),
            }]

        _, seen_ctx, _, out = self._run(
            tmp_path, rows, config_kw={"blind_first_pass": True},
        )
        assert sorted(seen_ctx) == ["check_pw", "validate"]
        assert "sage_fp_priors" not in seen_ctx["check_pw"]
        # The provenance record states what happened: matched but
        # withheld — it must not claim an injection blind mode never
        # performed.
        recs = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        fp_recs = [
            r for r in recs if r.get("verdict") == "sage_false_positive"
        ]
        assert fp_recs and fp_recs[0]["injected"] is False
        assert "matched" in fp_recs[0]["reason"]

    def test_sage_recall_flag_disables_primer(self, tmp_path: Path):
        def rows(target, **kw):
            raise AssertionError("hook must not be consulted")

        _, seen_ctx, mock_fp, _ = self._run(
            tmp_path, rows, config_kw={"sage_recall": False},
        )
        assert sorted(seen_ctx) == ["check_pw", "validate"]
        mock_fp.assert_not_called()

    def test_prompt_renders_hints_not_verdicts(self):
        from core.audit.context import format_context_for_prompt

        ctx = {
            "file": "src/auth.c",
            "function": "check_pw",
            "line_start": 1,
            "source": "int check_pw(void) { return 0; }",
            "sage_fp_priors": [
                {"verdict": "false_positive", "rule": "semgrep.strcpy"},
                {"verdict": "not_exploitable", "rule": "codeql.of\nlow"},
            ],
        }
        prompt = format_context_for_prompt(ctx)
        assert "hints, not verdicts" in prompt
        assert "never inherit a verdict" in prompt
        assert "semgrep.strcpy" in prompt
        # not_exploitable is dormant-leaning — a REAL defect, never
        # a clean steer.
        assert "not_exploitable" in prompt
        assert "dormant-leaning" in prompt
        assert "never clean" in prompt
        # Rule ids are single-line clamped before joining the prompt.
        assert "codeql.of low" in prompt

    def test_match_helper_requires_span(self):
        from core.audit.orchestrator import _match_fp_verdict_to_source

        rows = [{"verdict": "false_positive", "source_hash": "abc"}]
        assert _match_fp_verdict_to_source(
            rows, Path("/nonexistent"), {"file": "a.c", "name": "f"},
        ) == []

    def test_scan_bound_binds_both_directions(self, tmp_path, monkeypatch):
        """_FP_RECALL_MAX_SCAN_LINES is load-bearing: a finding line
        within the cap matches; one beyond it does not (and raising
        the cap would flip the second assertion — two-direction pin)."""
        import core.audit.orchestrator as orch_mod
        from core.audit.orchestrator import _match_fp_verdict_to_source
        from core.sage.hooks import compute_finding_source_hash

        target = tmp_path / "t"
        (target / "src").mkdir(parents=True)
        (target / "src" / "big.c").write_text(
            "\n".join(f"int l{i};" for i in range(1, 40)) + "\n",
        )
        monkeypatch.setattr(orch_mod, "_FP_RECALL_MAX_SCAN_LINES", 10)
        gap = {"file": "src/big.c", "name": "f",
               "line_start": 1, "line_end": 39}

        within = compute_finding_source_hash(target / "src" / "big.c", 5)
        beyond = compute_finding_source_hash(target / "src" / "big.c", 20)
        row_within = [{"verdict": "false_positive", "source_hash": within}]
        row_beyond = [{"verdict": "false_positive", "source_hash": beyond}]

        assert _match_fp_verdict_to_source(row_within, target, gap)
        assert _match_fp_verdict_to_source(row_beyond, target, gap) == []


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


class TestChecklistItemIndex:
    """One walking authority for checklist["files"][*] items: the
    hand-rolled per-pass walkers had drifted on the path/file and
    items/functions key fallbacks, and the per-outcome lookup walked
    the whole checklist every call."""

    @staticmethod
    def _checklist():
        return {
            "files": [
                {"path": "a.c", "items": [
                    {"name": "f", "line_start": 10, "line_end": 20},
                ]},
            ],
        }

    def test_find_gap_resolves_legacy_file_key(self):
        # The pre-index walker matched the strict "path" key only —
        # a "file"-keyed record (older artifacts) silently returned
        # None while _gap_index resolved it. One walker, one fallback.
        from core.audit.orchestrator import _find_gap_in_checklist

        checklist = {
            "files": [
                {"file": "a.c", "items": [
                    {"name": "f", "line_start": 3, "line_end": 9},
                ]},
            ],
        }
        gap = _find_gap_in_checklist(checklist, "a.c", "f")
        assert gap == {
            "file": "a.c", "name": "f", "line_start": 3, "line_end": 9,
        }

    def test_find_gap_contract_unchanged(self):
        from core.audit.orchestrator import _find_gap_in_checklist

        gap = _find_gap_in_checklist(self._checklist(), "a.c", "f")
        assert gap == {
            "file": "a.c", "name": "f", "line_start": 10, "line_end": 20,
        }
        assert _find_gap_in_checklist(self._checklist(), "a.c", "x") is None
        # Absent line_end stays None (not 0) — consumers distinguish.
        gap2 = _find_gap_in_checklist(
            {"files": [{"path": "b.c", "items": [{"name": "g"}]}]},
            "b.c", "g",
        )
        assert gap2["line_start"] == 0
        assert gap2["line_end"] is None

    def test_first_match_wins_on_duplicates(self):
        from core.audit.orchestrator import _find_gap_in_checklist

        checklist = {
            "files": [
                {"path": "a.c", "items": [{"name": "f", "line_start": 1}]},
                {"path": "a.c", "items": [{"name": "f", "line_start": 99}]},
            ],
        }
        assert _find_gap_in_checklist(
            checklist, "a.c", "f",
        )["line_start"] == 1

    def test_index_memoised_per_checklist_identity(self):
        from core.audit.orchestrator import _checklist_item_index

        checklist = self._checklist()
        first = _checklist_item_index(checklist)
        assert _checklist_item_index(checklist) is first
        # In-place growth invalidates (fingerprint guard).
        checklist["files"].append(
            {"path": "b.c", "items": [{"name": "g"}]},
        )
        second = _checklist_item_index(checklist)
        assert second is not first
        assert ("b.c", "g") in second
        # A different checklist object never reads another's index.
        other = self._checklist()
        other["files"][0]["items"][0]["line_start"] = 77
        assert (
            _checklist_item_index(other)[("a.c", "f")][1]["line_start"]
            == 77
        )

    def test_item_append_with_stable_file_count_invalidates(self):
        # The fingerprint covers TOTAL item count, not just the files
        # count — an in-place item append inside an existing file
        # record must not serve a stale index.
        from core.audit.orchestrator import (
            _checklist_item_index,
            _find_gap_in_checklist,
        )

        checklist = self._checklist()
        _checklist_item_index(checklist)
        checklist["files"][0]["items"].append(
            {"name": "late", "line_start": 44, "line_end": 50},
        )
        gap = _find_gap_in_checklist(checklist, "a.c", "late")
        assert gap is not None
        assert gap["line_start"] == 44

    def test_colon_bearing_path_never_aliases(self):
        # Tuple keys, not a "file:name" join: with a joined key,
        # file "a" + function "b.c:f" and file "a:b.c" + function "f"
        # collapse to the same spelling and serve each other's items.
        from core.audit.orchestrator import _find_gap_in_checklist

        checklist = {
            "files": [
                {"path": "a", "items": [
                    {"name": "b.c:f", "line_start": 1, "line_end": 2},
                ]},
                {"path": "a:b.c", "items": [
                    {"name": "f", "line_start": 30, "line_end": 40},
                ]},
            ],
        }
        gap = _find_gap_in_checklist(checklist, "a:b.c", "f")
        assert gap is not None
        assert gap["line_start"] == 30
        gap2 = _find_gap_in_checklist(checklist, "a", "b.c:f")
        assert gap2 is not None
        assert gap2["line_start"] == 1

    def test_function_line_resolves_legacy_file_key(self):
        from core.audit.orchestrator import _checklist_function_line

        checklist = {
            "files": [
                {"file": "a.c", "functions": [
                    {"name": "f", "line_start": 12},
                ]},
            ],
        }
        assert _checklist_function_line(checklist, "a.c", "f") == 12


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


class TestGuardVetoFailClosed:
    """Transient guard degradation must fail closed at promotion
    vetoes and never be cached (the joern trap-flap fix: the
    confirming joern:live receipt needs a healthy server while the
    guard veto silently evaporated on a sick one)."""

    def _fresh_cache(self):
        from core.audit import orchestrator as orch
        orch._sink_guard_cache.clear()
        return orch

    def test_unavailable_not_cached(self):
        from unittest.mock import MagicMock
        orch = self._fresh_cache()

        server = MagicMock()
        server.is_alive.return_value = False   # degraded now...
        assert orch._check_sink_guarded_cached("fn_a", server) == \
            orch.GUARD_UNAVAILABLE
        assert "fn_a" not in orch._sink_guard_cache

        # ...recovered later: the next consultation must re-query.
        server.is_alive.return_value = True
        result = MagicMock()
        result.errors = []
        result.raw_output = "JOERN_GUARD_SUMMARY:0/2"
        server.query.return_value = result
        assert orch._check_sink_guarded_cached("fn_a", server) == "guarded"
        assert orch._sink_guard_cache["fn_a"] == "guarded"
        orch._sink_guard_cache.clear()

    def test_definitive_verdicts_still_cached(self):
        from unittest.mock import MagicMock
        orch = self._fresh_cache()

        server = MagicMock()
        server.is_alive.return_value = True
        result = MagicMock()
        result.errors = []
        result.raw_output = "JOERN_GUARD_SUMMARY:1/2"
        server.query.return_value = result
        assert orch._check_sink_guarded_cached("fn_b", server) == "unguarded"
        assert orch._sink_guard_cache["fn_b"] == "unguarded"
        # Cached: no second query.
        server.query.reset_mock()
        assert orch._check_sink_guarded_cached("fn_b", server) == "unguarded"
        server.query.assert_not_called()
        orch._sink_guard_cache.clear()

    def test_guard_blocks_promotion_on_guarded(self):
        from unittest.mock import MagicMock
        orch = self._fresh_cache()

        server = MagicMock()
        server.is_alive.return_value = True
        result = MagicMock()
        result.errors = []
        result.raw_output = "JOERN_GUARD_SUMMARY:0/2"
        server.query.return_value = result
        assert orch._guard_blocks_promotion("fn_c", server) == "guarded"
        orch._sink_guard_cache.clear()

    def test_guard_blocks_promotion_on_unavailable(self):
        """The flap shape: veto channel down -> promotion must BLOCK,
        not proceed, and the tier counter must record the degradation
        so the run is diagnosable."""
        from unittest.mock import MagicMock
        orch = self._fresh_cache()

        server = MagicMock()
        server.is_alive.return_value = False
        counters = {"joern_guard": orch.TierCounters()}
        assert orch._guard_blocks_promotion(
            "fn_d", server, counters) == "guard-unavailable"
        assert counters["joern_guard"].errors == 1
        orch._sink_guard_cache.clear()

    def test_guard_allows_promotion_without_joern_lane(self):
        """Runs with no Joern server keep the pre-fix behavior —
        the veto is a non-answer, promotion proceeds."""
        orch = self._fresh_cache()
        assert orch._guard_blocks_promotion("fn_e", None) is None
        orch._sink_guard_cache.clear()

    def test_guard_allows_promotion_on_no_tested_sinks(self):
        from unittest.mock import MagicMock
        orch = self._fresh_cache()

        server = MagicMock()
        server.is_alive.return_value = True
        result = MagicMock()
        result.errors = []
        result.raw_output = "JOERN_GUARD_SUMMARY:0/0"
        server.query.return_value = result
        assert orch._guard_blocks_promotion("fn_f", server) is None
        orch._sink_guard_cache.clear()


class TestJoernLiveErrorAccounting:
    """A degraded live query is an unanswered question, never a
    refutation — and its flows must come back in deterministic order."""

    def test_errors_out_on_exception(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.side_effect = RuntimeError("timeout")
        # The recovery pass is equally down — its per-sink accounting
        # is what lands in errors_out.
        server.run_taint_query.side_effect = RuntimeError("timeout")
        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy"], errors_out=errors)
        assert result == []
        assert len(errors) == 1
        assert "RuntimeError" in errors[0]

    def test_errors_out_on_server_reported_errors(self):
        from unittest.mock import MagicMock

        server = MagicMock()

        def _batch(pairs, timeout=30, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("server is restarting")
            return []

        def _single(fn, sink, timeout=30, errors_out=None, **kw):
            if errors_out is not None:
                errors_out.append("server is restarting")
            return []

        server.run_taint_queries_batch.side_effect = _batch
        server.run_taint_query.side_effect = _single
        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy"], errors_out=errors)
        assert result == []
        assert errors and "restarting" in errors[0]

    def test_clean_no_flow_reports_no_errors(self):
        from unittest.mock import MagicMock

        server = MagicMock()
        server.run_taint_queries_batch.return_value = []
        errors: list = []
        result = _joern_live_query(
            server, "fn", ["memcpy"], errors_out=errors)
        assert result == []
        assert errors == []

    def test_flows_returned_in_deterministic_order(self):
        from unittest.mock import MagicMock

        from packages.joern.models import FlowStep, TaintFlow

        def _flow(file, line, sink="memcpy"):
            return TaintFlow(
                source_method="fn", source_param="p",
                sink_call=sink, sink_arg_idx=0,
                steps=[FlowStep(
                    file=file, function="fn", line=line,
                    code="x", variable="p",
                )],
            )

        a = _flow("a.c", 10)
        b = _flow("b.c", 5)
        c = _flow("a.c", 2)

        server = MagicMock()
        server.run_taint_queries_batch.return_value = [b, a, c]
        first = _joern_live_query(server, "fn", ["memcpy"])
        server.run_taint_queries_batch.return_value = [a, c, b]
        second = _joern_live_query(server, "fn", ["memcpy"])
        assert first == second
        assert [f.steps[0].file for f in first] == ["a.c", "a.c", "b.c"]
        assert [f.steps[0].line for f in first] == [2, 10, 5]


class TestJoernReachabilityDetectionRole:
    """Bare joern reachability receipts corroborate; they never
    convict alone.  reachableByFlows returns flows for a correctly
    clamped memcpy wrapper — guards on the path are invisible — so a
    joern:live confirm must not single-handedly promote a hypothesis
    the reviewer itself refuted (the trap-flap shape)."""

    def test_joern_live_is_detection_only(self):
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only("joern:live") is True

    def test_joern_pre_sweep_is_detection_only(self):
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only("joern:pre_sweep") is True

    def test_hypothesis_bound_joern_channels_keep_verification_role(self):
        """joern:flow / joern:guard-dominance match the hypothesis's
        own endpoints (joern_verify) — they stay promote-grade."""
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only("joern:flow") is False
        assert _is_detection_only("joern:guard-dominance") is False


class TestGapSloc:
    """The sarif-clean gate's SLOC fallback must tolerate present-but-
    None span fields (inventory rows without a span) — the subtraction
    crashed the run pre-review."""

    def test_none_line_end_is_zero_span(self):
        from core.audit.orchestrator import _gap_sloc

        gap = {"file": "a.c", "name": "f", "line_start": 10, "line_end": None}
        assert _gap_sloc(gap) == 0

    def test_none_line_start_is_zero_floor(self):
        from core.audit.orchestrator import _gap_sloc

        gap = {"file": "a.c", "name": "f", "line_start": None, "line_end": 12}
        assert _gap_sloc(gap) == 12

    def test_span_fallback_when_no_sloc(self):
        from core.audit.orchestrator import _gap_sloc

        gap = {"line_start": 10, "line_end": 25}
        assert _gap_sloc(gap) == 15

    def test_inventory_sloc_wins(self):
        from core.audit.orchestrator import _gap_sloc

        gap = {"sloc": 7, "line_start": 10, "line_end": 25}
        assert _gap_sloc(gap) == 7


class TestFileLinesCacheClear:
    """Clearing the lines cache must reset the byte counter with it —
    a stale counter permanently shrinks the byte bound for every later
    in-process run."""

    def test_clear_resets_byte_counter(self, tmp_path):
        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            _clear_file_lines_cache,
            _read_raw_source,
        )

        (tmp_path / "a.c").write_text("int f(void) { return 0; }\n" * 10)
        _clear_file_lines_cache()
        src = _read_raw_source(tmp_path, "a.c", 1, 5)
        assert src
        assert _orch._file_lines_cache_bytes > 0
        assert _orch._file_lines_cache

        _clear_file_lines_cache()
        assert _orch._file_lines_cache_bytes == 0
        assert not _orch._file_lines_cache


class TestPostPassWiring:
    """Source-level wiring checks for fixes inside _run_audit_body
    (the heavy scaffolding is exercised in integration tests,
    mirroring TestPrefilterSkipKnobWiring)."""

    @staticmethod
    def _body_src():
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def _run_audit_body")
        assert idx != -1
        end = src.find("\ndef ", idx)
        return src[idx:end if end != -1 else len(src)]

    def test_findings_re_persisted_after_status_mutating_passes(self):
        # findings.json must be rewritten AFTER phase 2 / pre-export
        # hooks and BEFORE the journal correction pass reads final
        # statuses — else late-minted findings are missing and
        # retracted ones ship.
        window = self._body_src()
        phase2 = window.find("_run_phase2(result, config)")
        hooks = window.find("config.pre_export_hooks")
        # Match the call head only: the persists thread the prep-time
        # vendor verdicts (tree-class stamp) as an extra argument.
        final_persist = window.rfind("_persist_findings(")
        rejournal = window.find("_rejournal_final_statuses(result, config)")
        assert -1 not in (phase2, hooks, final_persist, rejournal)
        assert phase2 < hooks < final_persist < rejournal

    def test_live_sink_harvest_precedes_budget_break(self):
        # A completed future's outcome is paid work: it must be
        # harvested BEFORE the budget-check break, like the batched
        # review loop's tally-before-stop.
        window = self._body_src()
        block = window.find("live-sink re-queue")
        assert block != -1
        sub = window[block:block + 8000]
        harvest = sub.find("ls_raw.append(fut.result())")
        cancel = sub.find("f.cancel()")
        assert harvest != -1 and cancel != -1
        assert harvest < cancel


class TestContainedSourceText:
    """The shared confined whole-file reader behind the prep loops,
    post-loop verifiers and prompt-context builders: file fields come
    from LLM-writable artifacts, so escaping paths must read as
    no-source, never as out-of-root content."""

    def test_normal_read(self, tmp_path: Path):
        from core.audit.orchestrator import _contained_source_text

        (tmp_path / "a.c").write_text("int x;\n")
        assert _contained_source_text(tmp_path, "a.c") == "int x;\n"

    def test_traversal_refused(self, tmp_path: Path):
        from core.audit.orchestrator import _contained_source_text

        target = tmp_path / "target"
        target.mkdir()
        (tmp_path / "outside.c").write_text("secret\n")
        assert _contained_source_text(target, "../outside.c") is None

    def test_absolute_refused(self, tmp_path: Path):
        from core.audit.orchestrator import _contained_source_text

        target = tmp_path / "target"
        target.mkdir()
        outside = tmp_path / "outside.c"
        outside.write_text("secret\n")
        assert _contained_source_text(target, str(outside)) is None

    def test_missing_and_empty_name(self, tmp_path: Path):
        from core.audit.orchestrator import _contained_source_text

        assert _contained_source_text(tmp_path, "absent.c") is None
        assert _contained_source_text(tmp_path, "") is None


class TestFpVerdictHashProbeContainment:
    """The FP-primer staleness probe hashes the gap's file: an
    escaping gap path must never reach the hash helper (it would fold
    arbitrary host files into the staleness match)."""

    def test_escaping_gap_path_never_hashed(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.sage.hooks as hooks_mod

        from core.audit.orchestrator import _match_fp_verdict_to_source

        target = tmp_path / "target"
        target.mkdir()
        (tmp_path / "outside.c").write_text("int f(void) { return 0; }\n")
        probed: list = []

        def spy(path, line_start, line_end):
            probed.append(str(path))
            return set()

        monkeypatch.setattr(hooks_mod, "finding_source_hashes", spy)
        rows = [{"source_hash": "deadbeef", "verdict": "false_positive"}]
        gap = {"file": "../outside.c", "line_start": 1, "line_end": 1}
        assert _match_fp_verdict_to_source(rows, target, gap) == []
        assert probed == []

    def test_contained_gap_path_still_probed(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.sage.hooks as hooks_mod

        from core.audit.orchestrator import _match_fp_verdict_to_source

        (tmp_path / "a.c").write_text("int f(void) { return 0; }\n")
        probed: list = []

        def spy(path, line_start, line_end):
            probed.append(str(path))
            return {"deadbeef"}

        monkeypatch.setattr(hooks_mod, "finding_source_hashes", spy)
        rows = [{"source_hash": "deadbeef", "verdict": "false_positive"}]
        gap = {"file": "a.c", "line_start": 1, "line_end": 1}
        matched = _match_fp_verdict_to_source(rows, tmp_path, gap)
        assert len(matched) == 1
        assert probed and probed[0].endswith("a.c")


class TestBlockContextContainment:
    """_try_block_level_context derives priority-0 prompt text from
    the gap's file: an escaping path must never feed out-of-root
    content into the CFG builder / prompt path."""

    def test_outside_content_never_reaches_the_builder(
        self, tmp_path: Path, monkeypatch,
    ):
        from types import SimpleNamespace

        import core.audit.block_review as br_mod

        from core.audit.orchestrator import _try_block_level_context

        target = tmp_path / "target"
        target.mkdir()
        (tmp_path / "outside.c").write_text("int f(void) { return 0; }\n")
        seen: dict = {}

        def spy(file_path, function_name, target_path, source=""):
            seen["source"] = source
            return None

        monkeypatch.setattr(br_mod, "try_build_cfg", spy)
        gap = {"file": "../outside.c", "name": "f",
               "line_start": 1, "line_end": 1}
        config = SimpleNamespace(target_path=target, out_dir=tmp_path)
        assert _try_block_level_context(gap, {}, config, None) is None
        assert seen["source"] == "", (
            "out-of-root file content reached the block-review builder"
        )


class TestValidateConfirmedPrefilterFloor:
    """Review-time twin of the triage floor: the prefilter skip lane
    must never journal a mechanical clean over a /validate-CONFIRMED
    function (the helper reads the validate-bridge history off the
    evidence record — the same source validate_confirmed_keys uses)."""

    def test_confirmed_history_blocks_skip(self):
        from types import SimpleNamespace

        from core.audit.orchestrator import _validate_confirmed_gap

        rec = SimpleNamespace(validate_history={
            "confirmed": [{"fresh": True, "line": 12}],
            "ruled_out": [],
        })
        assert _validate_confirmed_gap({"a.c:fn": rec}, "a.c:fn")

    def test_no_history_allows_skip(self):
        from types import SimpleNamespace

        from core.audit.orchestrator import _validate_confirmed_gap

        assert not _validate_confirmed_gap(None, "a.c:fn")
        assert not _validate_confirmed_gap({}, "a.c:fn")
        assert not _validate_confirmed_gap(
            {"a.c:fn": SimpleNamespace(validate_history=None)}, "a.c:fn",
        )
        # Ruled-out-only history is not a confirmation.
        rec = SimpleNamespace(validate_history={
            "confirmed": [], "ruled_out": [{"fresh": True}],
        })
        assert not _validate_confirmed_gap({"a.c:fn": rec}, "a.c:fn")


class TestDiscardPresweepFuture:
    """Empty-gaps runs discard the server-start pre-sweep future."""

    def test_unstarted_future_is_cancelled(self):
        from concurrent.futures import Future

        from core.audit.orchestrator import _discard_presweep_future

        fut: Future = Future()
        _discard_presweep_future(fut)
        assert fut.cancelled()

    def test_discard_sets_the_abort_event(self):
        """cancel() essentially never lands (the 1-worker executor
        starts the task at submit) — the abort event is the real
        interrupt, and it must be set for running AND unstarted
        futures alike."""
        import threading
        from concurrent.futures import Future

        from core.audit.orchestrator import _discard_presweep_future

        for started in (False, True):
            fut: Future = Future()
            if started:
                fut.set_running_or_notify_cancel()
            ev = threading.Event()
            _discard_presweep_future(fut, abort_event=ev)
            assert ev.is_set()

    def test_running_future_interrupts_and_logs_its_failure(self, caplog):
        """Real interrupt path: a running build stops when the abort
        event is set, and the attached done-callback logs a failing
        discarded future instead of letting it vanish unobserved."""
        import logging as _logging
        import threading
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

        from core.audit.orchestrator import _discard_presweep_future

        ev = threading.Event()
        started = threading.Event()

        def fake_build():
            # Step-boundary polling stand-in: waits for the abort,
            # then fails — exercising both the interrupt and the
            # logging callback.
            started.set()
            assert ev.wait(timeout=10)
            raise RuntimeError("pre-sweep died")

        pool = ThreadPoolExecutor(max_workers=1)
        try:
            fut = pool.submit(fake_build)
            # Structural running-ness: a fixed pre-discard sleep let a
            # starved pool worker start the task late, cancel() landed,
            # and the not-cancelled assert false-failed.
            assert started.wait(timeout=10)  # running: cancel() cannot land
            with caplog.at_level(
                _logging.DEBUG, logger="core.audit.orchestrator",
            ):
                _discard_presweep_future(fut, abort_event=ev)
                assert not fut.cancelled()
                with pytest.raises(RuntimeError):
                    fut.result(timeout=10)
                deadline = _time.monotonic() + 5
                while _time.monotonic() < deadline:
                    if "discarded joern pre-sweep failed" in caplog.text:
                        break
                    _time.sleep(0.02)
            assert "discarded joern pre-sweep failed" in caplog.text
        finally:
            pool.shutdown(wait=True)

    def test_none_is_a_noop(self):
        from core.audit.orchestrator import _discard_presweep_future

        _discard_presweep_future(None)


def _presweep_target(tmp_path: Path, n_functions: int = 1):
    """Tiny C target + checklist for run-level pre-sweep wiring tests."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    items = []
    src_lines: list[str] = []
    line = 1
    for i in range(n_functions):
        body = (
            f"int handler_{i}(char *input, int len) {{\n"
            "  char buf[64];\n"
            "  memcpy(buf, input, len);\n"
            "  return buf[0];\n"
            "}"
        )
        n = body.count("\n") + 1
        items.append({
            "name": f"handler_{i}",
            "line_start": line, "line_end": line + n - 1,
        })
        src_lines.append(body)
        line += n
    (target / "src" / "app.c").write_text("\n".join(src_lines) + "\n")
    out = tmp_path / "out"
    out.mkdir()
    checklist = {"files": [{"path": "src/app.c", "items": items}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _presweep_config(target: Path, out: Path, **kw):
    defaults: dict = {
        "target_path": target,
        "out_dir": out,
        "resume": False,
        "force": True,
        "max_workers": 1,
        "batch_sloc_threshold": 0,
        "prefilter": False,
        "validate": False,
        # The wiring under test is the future hand-off, not a live
        # server; a joern-equipped host must not start a real JVM.
        "joern_overrides": {"enabled": False},
    }
    defaults.update(kw)
    return OrchestratorConfig(**defaults)


def _clean_review_fn(ctx, config):
    return ReviewOutcome(
        file=ctx["file"], function=ctx["function"],
        status="clean", body="ok",
    )


@pytest.mark.slow
class TestPresweepSubmittedAtServerStart:
    """The pre-sweep future is submitted before prep runs (ordering
    probe) and adopted by prep — never resubmitted; an empty-gaps run
    discards it."""

    def test_submission_precedes_prep_and_is_adopted(
        self, tmp_path: Path, monkeypatch,
    ):
        from concurrent.futures import Future

        import core.audit.orchestrator as orch_mod

        target, out = _presweep_target(tmp_path)
        events: list[str] = []
        fut: Future = Future()
        fut.set_result(None)  # completed: the drain path is a no-op

        def fake_resolve(*args, **kwargs):
            events.append("presweep_submit")
            return (None, fut)

        real_prep = orch_mod._compute_audit_prep
        received: dict = {}

        def probed_prep(config, **kwargs):
            events.append("prep")
            received.update(kwargs)
            return real_prep(config, **kwargs)

        monkeypatch.setattr(
            orch_mod, "_resolve_joern_evidence_raw", fake_resolve,
        )
        monkeypatch.setattr(orch_mod, "_compute_audit_prep", probed_prep)

        result = orch_mod.run_orchestrator(
            _presweep_config(target, out), _clean_review_fn,
        )

        assert result.reviewed >= 1
        assert events[0] == "presweep_submit"
        assert "prep" in events
        # Prep adopted the server-start future instead of resubmitting.
        assert events.count("presweep_submit") == 1
        assert received.get("presweep_future") is fut
        assert received.get("presweep_activity") is not None

    def test_empty_gaps_run_interrupts_the_running_build(
        self, tmp_path: Path, monkeypatch,
    ):
        """Real interrupt path: the pre-sweep task is already RUNNING
        when the empty-gaps discard fires (the 1-worker executor
        starts it at submit, so cancel() cannot land) — the discard
        must set the abort event the build polls, and the build must
        finish promptly instead of paying a full pre-sweep."""
        import threading
        from concurrent.futures import ThreadPoolExecutor

        import core.audit.orchestrator as orch_mod

        target, out = _presweep_target(tmp_path, n_functions=1)
        # Empty checklist → zero gaps → nothing consumes the future.
        (out / "checklist.json").write_text(json.dumps({"files": []}))

        pool = ThreadPoolExecutor(max_workers=1)
        state: dict = {}

        def fake_resolve(*args, abort_event=None, **kwargs):
            assert abort_event is not None
            state["abort_event"] = abort_event
            build_started = threading.Event()

            def fake_build():
                # Mirrors build_joern_evidence's step-boundary poll.
                build_started.set()
                state["interrupted"] = abort_event.wait(timeout=30)
                return None

            fut = pool.submit(fake_build)
            # Structural running-ness (like production, where the
            # build is in flight before prep): a fixed sleep let a
            # starved pool worker start late, the discard's cancel()
            # landed, and the not-cancelled assert false-failed.
            assert build_started.wait(timeout=10)
            state["future"] = fut
            return (None, fut)

        monkeypatch.setattr(
            orch_mod, "_resolve_joern_evidence_raw", fake_resolve,
        )
        try:
            orch_mod.run_orchestrator(
                _presweep_config(target, out), _clean_review_fn,
            )
        finally:
            pool.shutdown(wait=True)

        assert isinstance(state.get("abort_event"), threading.Event)
        assert state["abort_event"].is_set()
        assert state["interrupted"] is True
        assert state["future"].done()
        assert not state["future"].cancelled()


@pytest.mark.slow
class TestPerPassWallClockPhases:
    """Prep sub-passes and post-loop passes book wall time into the
    run ledger (cost-breakdown.json's phases block)."""

    def test_prep_and_postloop_phases_booked(
        self, tmp_path: Path, monkeypatch,
    ):
        import itertools
        from types import SimpleNamespace

        import core.audit.cost_tracker as ct_mod
        from core.audit.orchestrator import run_orchestrator

        # Deterministic step clock for the ledger: every read
        # advances 1ms, so each start_phase/end marker pair books a
        # positive pass wall by construction. The sum assert below
        # then pins that the markers were laid down AND closed
        # (structural), instead of deriving "prep did work" from the
        # real clock — which under a loaded runner measured the
        # scheduler, not the booking.
        ticks = itertools.count(1)
        monkeypatch.setattr(
            ct_mod, "time",
            SimpleNamespace(monotonic=lambda: next(ticks) * 0.001),
        )

        target, out = _presweep_target(tmp_path)
        result = run_orchestrator(
            _presweep_config(target, out), _clean_review_fn,
        )

        phases = result.cost_tracker.phases
        expected = (
            "prep_macro_recovery",
            "prep_context_map",
            "prep_taint_passes",
            "prep_evidence_index",
            "prep_gap_compute",
            "prep_triage",
            "prep_mechanical_detectors",
            "prep_finalize",
            "iterative_re_review",
            "confidence_propagation",
            "resolve_gate_demoted",
            "auto_synthesize_rules",
            "flow_trace_review",
            "post_loop_checks",
        )
        for name in expected:
            assert name in phases, f"missing phase: {name}"
        # Every prep marker was opened and closed — under the step
        # clock each pair books a positive pass wall, so a zero sum
        # can only mean the markers stopped being laid down. Pass
        # wall stays out of the per-call wall_time_s accounting.
        assert sum(
            phases[n].pass_wall_time_s
            for n in expected if n.startswith("prep_")
        ) > 0.0
        # No dangling open phase at run end.
        assert result.cost_tracker._active_phase is None
        # The phases serialize into the cost-breakdown shape.
        d = result.cost_tracker.to_dict()
        assert "prep_triage" in d["phases"]

    def test_cpg_build_time_lands_on_the_joern_tier(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.audit.orchestrator as orch_mod

        target, out = _presweep_target(tmp_path)

        def fake_start(path, overrides, jt, exclude_dirs=(),
                       timings_out=None):
            if timings_out is not None:
                timings_out["cpg_build_s"] = 7.5
            return None

        monkeypatch.setattr(
            orch_mod, "_start_joern_server_raw", fake_start,
        )
        result = orch_mod.run_orchestrator(
            _presweep_config(target, out), _clean_review_fn,
        )
        assert result.tier_counters["joern"].cpg_build_s == 7.5


class TestPhase2bChainCommit:
    """Phase-2b chain outcomes vs the tool-gated promotion firewall.

    Chain composition is an LLM judgement, so a chain outcome may
    claim ``finding`` only when both constituent bugs carry real tool
    receipts (the joined stamp passes ``is_tool_evidence``); anything
    less commits as ``suspicious``. The pre-fix unconditional
    ``finding`` with the unregistered ``chain_detector`` stamp fired
    the CRITICAL promotion alarm on every legitimate chain and was
    silently demoted at export while already counted."""

    @staticmethod
    def _run(monkeypatch, tmp_path: Path, constituents, chain):
        import core.audit.chain_detector as chain_mod
        import core.audit.orchestrator as orch_mod
        import core.audit.security_classifier as sc_mod

        result = OrchestratorResult()
        result.outcomes = list(constituents)
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        monkeypatch.setattr(orch_mod, "_run_llm_client", lambda cfg: None)
        monkeypatch.setattr(
            orch_mod, "_make_dispatch_gate",
            lambda cfg, stop_check=None: (lambda: False),
        )
        monkeypatch.setattr(
            sc_mod, "classify_security_impact",
            lambda *a, **k: {},
        )
        monkeypatch.setattr(
            chain_mod, "find_chain_candidates",
            lambda outcomes, out_dir, cls: [
                (constituents[0], constituents[1]),
            ],
        )
        monkeypatch.setattr(
            chain_mod, "evaluate_chains",
            lambda cands, client, **kw: [chain],
        )
        orch_mod._run_phase2(result, config)
        return result

    @staticmethod
    def _constituents(tool_a: str, tool_b: str):
        return [
            ReviewOutcome(
                file="a.c", function="f", status="finding",
                body="b", hypothesis="h", evidence_tool=tool_a,
            ),
            ReviewOutcome(
                file="b.c", function="g", status="finding",
                body="b", hypothesis="h", evidence_tool=tool_b,
            ),
        ]

    _CHAIN = {
        "bug_a": "a.c:f", "bug_b": "b.c:g",
        "chain_description": "A leaks a pointer B dereferences",
        "primitive": "read", "confidence": "high",
    }

    def test_receipt_backed_chain_commits_as_finding(
        self, monkeypatch, tmp_path: Path,
    ):
        from core.audit.evidence_grade import is_tool_evidence

        result = self._run(
            monkeypatch, tmp_path,
            self._constituents("semgrep", "joern:flow"), dict(self._CHAIN),
        )
        chain_out = result.outcomes[-1]
        assert chain_out.review_result["chain"] is True
        assert chain_out.status == "finding"
        assert chain_out.evidence_tool == "semgrep+joern:flow"
        assert is_tool_evidence(chain_out.evidence_tool)
        assert result.findings == 1

    def test_unreceipted_chain_commits_as_suspicious_not_counted(
        self, monkeypatch, tmp_path: Path,
    ):
        result = self._run(
            monkeypatch, tmp_path,
            self._constituents("", "llm-claimed:manual"), dict(self._CHAIN),
        )
        chain_out = result.outcomes[-1]
        assert chain_out.review_result["chain"] is True
        assert chain_out.status == "suspicious"
        assert chain_out.evidence_tool == "chain_detector"
        assert result.findings == 0

    def test_half_receipted_chain_commits_as_suspicious(
        self, monkeypatch, tmp_path: Path,
    ):
        # One receipt-backed constituent must not lend its receipt to
        # the composition claim.
        result = self._run(
            monkeypatch, tmp_path,
            self._constituents("semgrep", ""), dict(self._CHAIN),
        )
        assert result.outcomes[-1].status == "suspicious"
        assert result.outcomes[-1].evidence_tool == "chain_detector"
        assert result.findings == 0

    def test_committed_chains_never_alarm_or_demote(
        self, monkeypatch, tmp_path: Path,
    ):
        # The alarm channel is documented EMPTY on legitimate runs;
        # both chain lanes must survive the enforcing export sweep
        # untouched.
        from core.audit.promotion_alarm import ALARM_FILENAME, check_outcomes

        for tools, status in (
            (("semgrep", "joern:flow"), "finding"),
            (("", ""), "suspicious"),
        ):
            out_dir = tmp_path / f"run-{status}"
            out_dir.mkdir()
            result = self._run(
                monkeypatch, out_dir,
                self._constituents(*tools), dict(self._CHAIN),
            )
            chain_out = result.outcomes[-1]
            check_outcomes(
                out_dir, [chain_out], stage="findings-export",
                enforce=True,
            )
            assert chain_out.status == status
            assert not (out_dir / ALARM_FILENAME).exists()


class TestReReviewCostBooking:
    """Every post-loop re-review pass books its LLM spend: the phase
    ledger gets a re_review record for each call, and a call whose
    verdict is KEPT (no tally) still lands in result.total_cost_usd —
    otherwise the --max-cost rail under-enforces by the untracked
    spend and cost-breakdown.json shows the money only as end-of-run
    unattributed residual."""

    COST = 0.25

    def _patch_ctx(self, monkeypatch):
        import core.audit.orchestrator as orch_mod

        monkeypatch.setattr(
            orch_mod, "_build_context",
            lambda config, gap, *a, **kw: {
                "file": gap["file"], "function": gap["name"],
                "line_start": gap.get("line_start", 1),
            },
        )
        monkeypatch.setattr(
            orch_mod, "_commit_outcome", lambda *a, **kw: None,
        )
        return orch_mod

    def _review_fn(self, status: str):
        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status=status,
                body="re-review", hypothesis="h", cost_usd=self.COST,
            )
        return review_fn

    def _assert_booked(self, result):
        assert result.cost_tracker.phases["re_review"].cost_usd == (
            pytest.approx(self.COST)
        )
        assert result.total_cost_usd == pytest.approx(self.COST)

    def test_joern_enriched_kept_verdict_books_spend(
        self, tmp_path, monkeypatch,
    ):
        import time as _time
        from unittest.mock import MagicMock

        orch_mod = self._patch_ctx(monkeypatch)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        rec = MagicMock()
        rec.all_joern_flows.return_value = ["flow"]

        orch_mod._re_review_joern_enriched(
            result, config, self._review_fn("clean"),
            checklist={"files": []},
            context_map=None,
            fuzz_coverage=None,
            evidence_index={"a.c:f": rec},
            sarif_cache=None,
            entry_points=set(),
            gaps_before_joern=[
                {"file": "a.c", "name": "f", "line_start": 1},
            ],
            start_time=_time.monotonic(),
            on_progress=None,
        )
        # Verdict kept clean: no tally ran, the spend must still land.
        assert result.outcomes[0] is prior
        self._assert_booked(result)

    def test_joern_enriched_changed_verdict_books_phase(
        self, tmp_path, monkeypatch,
    ):
        import time as _time
        from unittest.mock import MagicMock

        orch_mod = self._patch_ctx(monkeypatch)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        rec = MagicMock()
        rec.all_joern_flows.return_value = ["flow"]

        orch_mod._re_review_joern_enriched(
            result, config, self._review_fn("suspicious"),
            checklist={"files": []},
            context_map=None,
            fuzz_coverage=None,
            evidence_index={"a.c:f": rec},
            sarif_cache=None,
            entry_points=set(),
            gaps_before_joern=[
                {"file": "a.c", "name": "f", "line_start": 1},
            ],
            start_time=_time.monotonic(),
            on_progress=None,
        )
        assert result.outcomes[0].status == "suspicious"
        self._assert_booked(result)

    def test_callee_contract_kept_verdict_books_spend(
        self, tmp_path, monkeypatch,
    ):
        import time as _time

        orch_mod = self._patch_ctx(monkeypatch)

        caller = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
            review_result={
                "relies_on": [
                    {"callee": "g", "assumption": "validates input"},
                ],
            },
        )
        callee = ReviewOutcome(
            file="a.c", function="g", status="finding",
            body="bad", evidence_tool="semgrep",
        )
        result = OrchestratorResult(clean=1, findings=1)
        result.outcomes = [caller, callee]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        re_reviewed = orch_mod._callee_contract_requeue(
            result, config, self._review_fn("clean"),
            checklist={"files": []},
            context_map=None,
            fuzz_coverage=None,
            evidence_index={},
            start_time=_time.monotonic(),
        )
        assert re_reviewed == 0  # verdict kept
        self._assert_booked(result)

    def test_study_enriched_kept_verdict_books_spend(
        self, tmp_path, monkeypatch,
    ):
        import time as _time

        orch_mod = self._patch_ctx(monkeypatch)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        orch_mod._re_review_study_enriched(
            result, config, self._review_fn("clean"),
            checklist={"files": []},
            context_map=None,
            evidence_index={},
            sarif_cache=None,
            entry_points=set(),
            reading_list_functions={"a.c:f"},
            start_time=_time.monotonic(),
            on_progress=None,
        )
        assert result.outcomes[0] is prior
        self._assert_booked(result)

    def test_disagreement_kept_verdict_books_spend(
        self, tmp_path, monkeypatch,
    ):
        import time as _time
        from types import SimpleNamespace

        orch_mod = self._patch_ctx(monkeypatch)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        orch_mod._re_review_disagreements(
            [SimpleNamespace(
                file="a.c", function="f", resolution="needs_re_review",
                mechanical_claim=None,
            )],
            result, config, self._review_fn("clean"),
            checklist={
                "files": [{
                    "path": "a.c",
                    "items": [{"name": "f", "line_start": 1}],
                }],
            },
            context_map=None,
            evidence_index={},
            start_time=_time.monotonic(),
            _on_progress=None,
        )
        # Verdict kept clean: no tally ran, the spend must still land.
        assert result.outcomes[0] is prior
        self._assert_booked(result)

    def test_disagreement_changed_verdict_books_phase(
        self, tmp_path, monkeypatch,
    ):
        import time as _time
        from types import SimpleNamespace

        orch_mod = self._patch_ctx(monkeypatch)

        prior = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = OrchestratorResult(clean=1)
        result.outcomes = [prior]
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

        orch_mod._re_review_disagreements(
            [SimpleNamespace(
                file="a.c", function="f", resolution="needs_re_review",
                mechanical_claim=None,
            )],
            result, config, self._review_fn("suspicious"),
            checklist={
                "files": [{
                    "path": "a.c",
                    "items": [{"name": "f", "line_start": 1}],
                }],
            },
            context_map=None,
            evidence_index={},
            start_time=_time.monotonic(),
            _on_progress=None,
        )
        assert result.outcomes[0].status == "suspicious"
        self._assert_booked(result)
