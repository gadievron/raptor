"""Digest honesty for audit runs: run-scope coverage + residue.

The end-of-run digest rendered two dishonest lines for gap-audit /
residual-queue runs:

* ``Coverage: 0.0% of reviewable units`` — the coverage store view is
  built with ``store_path=<run>/coverage.json``, so its project-dir
  derivation lands on the RUN dir (the project journal index is never
  found), and the store is line-interval based, so line-less (binary)
  checklist items can never earn credit. A run that reviewed 4 of its
  6 queued functions rendered 0.0% over the full checklist.
* ``No verified or exploitable-unverified findings.`` — implied
  all-clear while suspicious journal rows and low-confidence graded
  items sat unmentioned in the run artifacts.

These tests pin the honest replacements.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.run.digest import read_run_digest, render_run_digest


def _meta(run: Path, **over: Any) -> None:
    meta: dict[str, Any] = {
        "command": "audit",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "status": "completed",
    }
    meta.update(over)
    (run / ".raptor-run.json").write_text(json.dumps(meta),
                                          encoding="utf-8")


def _append(out_dir: Path, **kw: Any) -> None:
    from core.coverage.journal import ReviewJournalEntry, append_entry
    base: dict[str, Any] = {
        "run_id": "t", "file": "binary:lib.so", "source_hash": "",
    }
    base.update(kw)
    append_entry(out_dir, ReviewJournalEntry(**base))


def _seed_gap_audit_run(run: Path) -> None:
    """6-item residual queue; 4 completed reviews, 2 errored —
    modeled on a live gap-audit run's shapes (line-less binary
    items)."""
    _meta(run)
    (run / "gaps.json").write_text(json.dumps({
        "count": 6,
        "gaps": [
            {"file": "binary:lib.so", "name": f"FUN_{i}"}
            for i in range(6)
        ],
    }))
    verdicts = ["clean", "clean", "suspicious", "suspicious"]
    for i, verdict in enumerate(verdicts):
        _append(run, ts=f"2026-01-01T00:00:0{i}+00:00",
                function=f"FUN_{i}", verdict=verdict)
    for i in (4, 5):
        _append(run, ts=f"2026-01-01T00:00:0{i}+00:00",
                function=f"FUN_{i}", verdict="error",
                error_class="task_exception")


class TestRunScopeCoverage:
    def test_gap_audit_run_reports_run_scope(self, tmp_path: Path) -> None:
        _seed_gap_audit_run(tmp_path)

        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 4
        assert d.coverage_total == 6
        assert d.coverage_percent is not None
        assert abs(d.coverage_percent - 100.0 * 4 / 6) < 0.01

        out = render_run_digest(d)
        assert "4 of 6" in out
        assert "0.0%" not in out

    def test_errored_reviews_do_not_earn_run_coverage(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 2,
            "gaps": [
                {"file": "binary:lib.so", "name": "FUN_0"},
                {"file": "binary:lib.so", "name": "FUN_1"},
            ],
        }))
        for i in (0, 1):
            _append(tmp_path, ts=f"2026-01-01T00:00:0{i}+00:00",
                    function=f"FUN_{i}", verdict="error",
                    error_class="task_exception")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 0
        assert d.coverage_total == 2

    def test_mechanical_echoes_do_not_earn_run_coverage(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 1,
            "gaps": [{"file": "binary:lib.so", "name": "FUN_0"}],
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="suspicious",
                strategies=["post-loop-mechanical"],
                body="[mechanical] sweep rule hit")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope == "run"
        assert d.coverage_reviewed == 0

    def test_run_without_queue_keeps_prior_behaviour(
        self, tmp_path: Path,
    ) -> None:
        _meta(tmp_path, command="agentic")
        d = read_run_digest(tmp_path)
        assert d.coverage_scope != "run"
        assert d.coverage_percent is None  # store layer absent → absent

    # ── hostile gaps.json shapes ─────────────────────────────────
    # run_scope_coverage's contract is None / fall-back, never
    # raise. gaps.json is a run artifact a hostile target's build
    # tooling can influence; each shape below crashed the accessor
    # on direct call before the guard (str count reached the legacy
    # subtraction raw; truthy non-list / mixed rows reached the
    # per-row ``.get``).

    def test_str_count_without_gap_list_falls_back_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({"count": "6"}))
        for i in range(2):
            _append(tmp_path, ts=f"2026-01-01T00:00:0{i}+00:00",
                    function=f"FUN_{i}", verdict="clean")
        assert run_scope_coverage(tmp_path) == (2, 6)

    def test_str_gaps_field_falls_back_to_count_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 3, "gaps": "corrupted-by-truncation",
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="clean")
        assert run_scope_coverage(tmp_path) == (1, 3)

    def test_dict_gaps_field_falls_back_to_count_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 2, "gaps": {"file": "binary:lib.so"},
        }))
        assert run_scope_coverage(tmp_path) == (0, 2)

    def test_mixed_non_dict_gap_rows_are_ignored_not_raises(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.report import run_scope_coverage
        _meta(tmp_path)
        (tmp_path / "gaps.json").write_text(json.dumps({
            "count": 4,
            "gaps": [
                {"file": "binary:lib.so", "name": "FUN_0"},
                "junk-row", 42,
                {"file": "binary:lib.so", "name": "FUN_1"},
            ],
        }))
        _append(tmp_path, ts="2026-01-01T00:00:01+00:00",
                function="FUN_0", verdict="clean")
        # Denominator and set-difference both see dict rows only.
        assert run_scope_coverage(tmp_path) == (1, 2)
