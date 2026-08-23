"""/agentic --gap-audit post-pass: command construction and phase handling.

The post-pass runs ``raptor-audit run`` over the coverage residual as a
lifecycle-managed sibling run. These tests pin the subprocess argv
contract (unified validation, priority schedule, prior-journal handoff,
budget reserve, model/adversarial and binary passthrough, single-DB
CodeQL discovery) and the phase-dict outcomes for success, failure, and
interruption.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from core.json import save_json
from raptor_agentic import (
    _audit_run_status,
    _build_audit_postpass_cmd,
    _discover_codeql_dbs,
    run_audit_postpass,
)


def _args(**kw) -> argparse.Namespace:
    base = {
        "gap_audit": True,
        "gap_audit_budget": None,
        "gap_audit_strategy": None,
        "gap_audit_scope": None,
        "gap_audit_share": 0.35,
        "gap_audit_no_adversarial": False,
        "gap_audit_reserved_cost": None,
        "max_cost_usd": None,
        "model": [],
        "binary": None,
        "binary_auto": False,
        "no_binary_oracle": False,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def _flag_value(cmd: list, flag: str) -> str | None:
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


class TestBuildCmd:
    def test_baseline_contract(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(), tmp_path / "target", tmp_path / "audit", tmp_path / "out",
        )
        assert cmd[0].endswith("raptor-audit")
        assert cmd[1] == "run"
        assert cmd[2] == str(tmp_path / "target")
        assert "--no-validate" in cmd
        assert _flag_value(cmd, "--schedule") == "priority"
        priors = [cmd[i + 1] for i, a in enumerate(cmd)
                  if a == "--prior-journal"]
        assert priors == [
            str(tmp_path / "out"),
            str(tmp_path / "out" / "autonomous"),
        ]
        assert _flag_value(cmd, "--out") == str(tmp_path / "audit")
        assert "--max-cost" not in cmd
        assert "--adversarial" not in cmd

    def test_reserved_cost_wins_over_max_cost(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(gap_audit_reserved_cost=17.5, max_cost_usd=32.5),
            tmp_path, tmp_path, tmp_path,
        )
        assert _flag_value(cmd, "--max-cost") == "17.5"

    def test_max_cost_passthrough_without_reserve(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(max_cost_usd=40.0), tmp_path, tmp_path, tmp_path,
        )
        assert _flag_value(cmd, "--max-cost") == "40.0"

    def test_audit_flags_passthrough(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(gap_audit_budget=50, gap_audit_strategy="memory",
                  gap_audit_scope=["ipc/", "net/"]),
            tmp_path, tmp_path, tmp_path,
        )
        assert _flag_value(cmd, "--budget") == "50"
        assert _flag_value(cmd, "--strategy") == "memory"
        assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--scope"] == [
            "ipc/", "net/",
        ]

    def test_two_models_enable_adversarial(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(model=["model-a", "model-b"]), tmp_path, tmp_path, tmp_path,
        )
        assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--model"] == [
            "model-a", "model-b",
        ]
        assert "--adversarial" in cmd

    def test_single_model_no_adversarial(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(model=["model-a"]), tmp_path, tmp_path, tmp_path,
        )
        assert "--adversarial" not in cmd

    def test_adversarial_opt_out(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(model=["model-a", "model-b"],
                  gap_audit_no_adversarial=True),
            tmp_path, tmp_path, tmp_path,
        )
        assert "--adversarial" not in cmd

    def test_binary_passthrough(self, tmp_path):
        cmd = _build_audit_postpass_cmd(
            _args(binary=["/b/lib.so"], no_binary_oracle=True,
                  binary_auto=True),
            tmp_path, tmp_path, tmp_path,
        )
        assert _flag_value(cmd, "--binary") == "/b/lib.so"
        assert "--binary-auto" in cmd
        assert "--no-binary-oracle" in cmd


class TestDiscoverCodeqlDbs:
    def _report(self, out_dir: Path, dbs: dict) -> None:
        (out_dir / "codeql").mkdir(parents=True, exist_ok=True)
        save_json(out_dir / "codeql" / "codeql_report.json",
                  {"databases_created": dbs})

    def test_single_database(self, tmp_path):
        db = tmp_path / "db-python"
        db.mkdir()
        self._report(tmp_path, {
            "python": {"success": True, "database_path": str(db)},
        })
        assert _discover_codeql_dbs(tmp_path) == [str(db)]

    def test_multiple_databases_all_returned(self, tmp_path):
        db1 = tmp_path / "db-python"
        db2 = tmp_path / "db-cpp"
        db1.mkdir()
        db2.mkdir()
        self._report(tmp_path, {
            "python": {"success": True, "database_path": str(db1)},
            "cpp": {"success": True, "database_path": str(db2)},
        })
        assert set(_discover_codeql_dbs(tmp_path)) == {str(db1), str(db2)}

    def test_failed_or_missing_databases_ignored(self, tmp_path):
        db = tmp_path / "db-python"
        db.mkdir()
        self._report(tmp_path, {
            "python": {"success": True, "database_path": str(db)},
            "cpp": {"success": False,
                    "database_path": str(tmp_path / "nope")},
            "go": {"success": True,
                   "database_path": str(tmp_path / "gone")},
        })
        assert _discover_codeql_dbs(tmp_path) == [str(db)]

    def test_no_report_yields_empty(self, tmp_path):
        assert _discover_codeql_dbs(tmp_path) == []


class TestRunStatus:
    def test_reads_lifecycle_status(self, tmp_path):
        save_json(tmp_path / ".raptor-run.json", {"status": "running"})
        assert _audit_run_status(tmp_path) == "running"

    def test_missing_metadata_is_none(self, tmp_path):
        assert _audit_run_status(tmp_path) is None


@pytest.fixture
def _postpass_env(tmp_path, monkeypatch):
    """Fake lifecycle + subprocess so run_audit_postpass is hermetic."""
    import raptor_agentic
    from core.orchestration import skill_dispatch

    audit_dir = tmp_path / "audit_run"
    audit_dir.mkdir()
    monkeypatch.setattr(
        skill_dispatch, "start_lifecycle", lambda cmd, target: audit_dir,
    )
    fails: list = []
    monkeypatch.setattr(
        skill_dispatch, "fail_lifecycle",
        lambda d, msg: fails.append((d, msg)),
    )
    calls: dict = {"rc": 0}

    def fake_stream(cmd, description, timeout=1800):
        calls["cmd"] = cmd
        calls["timeout"] = timeout
        return calls["rc"], "", "boom"

    monkeypatch.setattr(raptor_agentic, "run_command_streaming", fake_stream)
    return audit_dir, calls, fails


class TestRunAuditPostpass:
    def test_success_reads_report_stats(self, tmp_path, _postpass_env):
        audit_dir, calls, _fails = _postpass_env
        save_json(audit_dir / "audit-report.json", {
            "stats": {"reviewed": 12, "finding": 2, "suspicious": 1,
                      "clean": 9, "dormant": 0, "error": 0},
            "findings_count": 2,
            "gaps_remaining": 88,
        })
        out_dir = tmp_path / "agentic_out"
        out_dir.mkdir()
        (out_dir / "checklist.json").write_text("{}", encoding="utf-8")

        phase = run_audit_postpass(_args(), tmp_path / "target", out_dir)

        assert phase["completed"] is True
        assert phase["reviewed"] == 12
        assert phase["findings_count"] == 2
        assert phase["gaps_remaining"] == 88
        assert phase["audit_dir"] == str(audit_dir)
        # No wall timeout: the audit self-bounds via cost/time budgets.
        assert calls["timeout"] == 0
        # The agentic checklist is provisioned for reuse.
        assert (audit_dir / "checklist.json").is_file()
        # The adversarial decision is recorded even when off.
        assert phase["adversarial"] is False
        # Deferred-tail marker staged for a potential later resume.
        tail = json.loads(
            (audit_dir / "pipeline-tail.json").read_text())
        assert tail["deferred"] == ["validate", "feedback"]
        assert tail["parent_run"] == str(out_dir)

    def test_failure_backstops_lifecycle(self, tmp_path, _postpass_env):
        audit_dir, calls, fails = _postpass_env
        calls["rc"] = 2
        save_json(audit_dir / ".raptor-run.json", {"status": "running"})
        out_dir = tmp_path / "agentic_out"
        out_dir.mkdir()

        phase = run_audit_postpass(_args(), tmp_path / "target", out_dir)

        assert phase["completed"] is False
        assert "exited 2" in phase["skipped_reason"]
        assert fails and fails[0][0] == audit_dir

    def test_failure_after_own_lifecycle_handling_no_double_fail(
        self, tmp_path, _postpass_env,
    ):
        audit_dir, calls, fails = _postpass_env
        calls["rc"] = 1
        save_json(audit_dir / ".raptor-run.json", {"status": "failed"})
        out_dir = tmp_path / "agentic_out"
        out_dir.mkdir()

        phase = run_audit_postpass(_args(), tmp_path / "target", out_dir)

        assert phase["completed"] is False
        assert not fails

    def test_interrupt_reports_resume_hint(self, tmp_path, _postpass_env):
        audit_dir, calls, fails = _postpass_env
        calls["rc"] = 130
        out_dir = tmp_path / "agentic_out"
        out_dir.mkdir()

        phase = run_audit_postpass(_args(), tmp_path / "target", out_dir)

        assert phase["completed"] is False
        assert "resume" in phase["skipped_reason"]
        assert not fails

    def test_lifecycle_start_failure_skips(self, tmp_path, monkeypatch):
        from core.orchestration import skill_dispatch
        monkeypatch.setattr(
            skill_dispatch, "start_lifecycle", lambda cmd, target: None,
        )
        phase = run_audit_postpass(_args(), tmp_path, tmp_path)
        assert phase["completed"] is False
        assert phase["skipped_reason"] == "lifecycle start failed"


class TestReportSection:
    def test_completed_phase_renders_counts(self):
        from raptor_agentic import _build_audit_report_section
        section = _build_audit_report_section({
            "enabled": True, "completed": True, "reviewed": 10,
            "findings_count": 2, "suspicious": 1, "clean": 7,
            "dormant": 0, "gaps_remaining": 5, "audit_dir": "/x/audit",
        })
        assert section.title == "Gap Audit Post-Pass"
        assert "**10**" in section.content
        assert "`/x/audit`" in section.content

    def test_skipped_phase_names_reason(self):
        from raptor_agentic import _build_audit_report_section
        section = _build_audit_report_section({
            "enabled": True, "completed": False,
            "skipped_reason": "lifecycle start failed",
        })
        assert "Skipped" in section.content
        assert "lifecycle start failed" in section.content


class TestResidualEstimate:
    def test_counts_unjournaled_functions(self, tmp_path):
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        from raptor_agentic import _estimate_review_residual
        save_json(tmp_path / "checklist.json", {"files": [{
            "path": "a.c",
            "items": [
                {"name": "f", "kind": "function", "line_start": 1},
                {"name": "g", "kind": "function", "line_start": 5},
                {"name": "MACRO", "kind": "macro", "line_start": 9},
            ],
        }]})
        autonomous = tmp_path / "autonomous"
        autonomous.mkdir()
        append_entry(autonomous, ReviewJournalEntry(
            ts=now_iso(), run_id="agentic_1", file="a.c", function="f",
            verdict="clean", source_hash="", producer="agentic",
        ))
        # macro kind is outside the quick estimate; f journaled → 1 of 2
        assert _estimate_review_residual(tmp_path) == (1, 2)

    def test_no_checklist_returns_none(self, tmp_path):
        from raptor_agentic import _estimate_review_residual
        assert _estimate_review_residual(tmp_path) is None


class TestJsonRoundTrip:
    def test_phase_dict_is_json_serialisable(self, tmp_path, _postpass_env):
        audit_dir, _calls, _fails = _postpass_env
        out_dir = tmp_path / "agentic_out"
        out_dir.mkdir()
        phase = run_audit_postpass(_args(), tmp_path / "target", out_dir)
        json.dumps(phase)


class TestGapAuditGate:
    """LLM-availability gate for the post-pass, including the
    claudecode-transport fallback."""

    def _llm_env(self, external=False, cc=False):
        return argparse.Namespace(external_llm=external, claude_code=cc)

    def test_external_llm_runs(self):
        from raptor_agentic import _gap_audit_skip_reason
        assert _gap_audit_skip_reason(
            _args(model=[]), self._llm_env(external=True),
            block_cc_dispatch=True,
        ) is None

    def test_explicit_model_runs_even_without_detection(self):
        from raptor_agentic import _gap_audit_skip_reason
        assert _gap_audit_skip_reason(
            _args(model=["m"]), self._llm_env(),
            block_cc_dispatch=True,
        ) is None

    def test_cc_only_runs_on_trusted_repo(self):
        from raptor_agentic import _gap_audit_skip_reason
        assert _gap_audit_skip_reason(
            _args(model=[]), self._llm_env(cc=True),
            block_cc_dispatch=False,
        ) is None

    def test_cc_only_blocked_repo_skips(self):
        from raptor_agentic import _gap_audit_skip_reason
        reason = _gap_audit_skip_reason(
            _args(model=[]), self._llm_env(cc=True),
            block_cc_dispatch=True,
        )
        assert reason and "trust check" in reason

    def test_no_llm_at_all_skips(self):
        from raptor_agentic import _gap_audit_skip_reason
        reason = _gap_audit_skip_reason(
            _args(model=[]), self._llm_env(),
            block_cc_dispatch=False,
        )
        assert reason and "no LLM available" in reason


class TestReportFindingsTable:
    """The gap-audit section inlines the sibling run's findings so the
    main report tells the whole story, not counts + a pointer."""

    def _phase(self, audit_dir):
        return {
            "enabled": True, "completed": True, "reviewed": 5,
            "findings_count": 2, "suspicious": 0, "clean": 3,
            "dormant": 0, "gaps_remaining": 1,
            "audit_dir": str(audit_dir),
        }

    def _audit_report(self, audit_dir, findings):
        save_json(audit_dir / "audit-report.json", {
            "stats": {"reviewed": 5}, "findings": findings,
        })

    def _finding(self, n=1, **kw):
        base = {
            "id": f"AUDIT-{n:03d}",
            "file": "src/a.c",
            "function": "f",
            "title": "unchecked length before memcpy",
            "severity": "high",
            "cwe": "CWE-120",
            "tool_evidence": [{"tool": "smt"}],
        }
        base.update(kw)
        return base

    def test_findings_rows_and_severity_rollup(self, tmp_path):
        from raptor_agentic import _build_audit_report_section
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._audit_report(audit_dir, [
            self._finding(1), self._finding(2, severity="medium"),
        ])
        section = _build_audit_report_section(self._phase(audit_dir))
        assert "unchecked length before memcpy" in section.content
        assert "`src/a.c:f`" in section.content
        assert "1 high, 1 medium" in section.content
        assert "smt" in section.content

    def test_validate_outcomes_joined(self, tmp_path):
        from raptor_agentic import _build_audit_report_section
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        validate_dir = tmp_path / "validate"
        validate_dir.mkdir()
        self._audit_report(audit_dir, [self._finding(1)])
        save_json(validate_dir / "findings.json", {"findings": [
            {"id": "AUDIT-001", "final_status": "confirmed"},
        ]})
        section = _build_audit_report_section(
            self._phase(audit_dir), validate_dir=validate_dir,
        )
        assert "Validation |" in section.content
        assert "Confirmed" in section.content

    def test_truncation_names_the_full_list(self, tmp_path):
        from raptor_agentic import _build_audit_report_section
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._audit_report(
            audit_dir, [self._finding(i) for i in range(1, 14)])
        section = _build_audit_report_section(self._phase(audit_dir))
        assert "3 more in" in section.content
        assert "findings.json" in section.content

    def test_missing_report_degrades_to_counts(self, tmp_path):
        from raptor_agentic import _build_audit_report_section
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        section = _build_audit_report_section(self._phase(audit_dir))
        assert "Functions reviewed: **5**" in section.content
        assert "| Finding |" not in section.content
