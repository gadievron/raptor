"""Cross-run token-enforcement drift in /project correlate.

Minimal by design (comparison helper + report field, no new pipeline
stage): pinned here is the fold — consecutive map-bearing runs are
compared in run-time order, drift records carry the run pair, and the
report/summary keys exist even when empty (consumers can rely on the
shape).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from core.project.correlate import _empty_result, _find_token_drift


def _write_map(run_dir: Path, statuses: dict[str, str],
               mtime: float) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "1",
        "artifact": "token-enforcement-map",
        "check_functions": [{"name": "om_verify_request_stamp"}],
        "entries": [
            {"entry": f, "file": f, "status": s}
            for f, s in statuses.items()
        ],
        "census": {},
    }
    (run_dir / "token-map.json").write_text(json.dumps(payload))
    os.utime(run_dir, (mtime, mtime))


class TestFindTokenDrift:
    def test_lost_enforcement_between_consecutive_runs(self, tmp_path):
        now = time.time()
        _write_map(tmp_path / "audit_1",
                   {"web/a.php": "enforced", "web/b.php": "not_enforced"},
                   now - 200)
        _write_map(tmp_path / "audit_2",
                   {"web/a.php": "not_enforced", "web/b.php": "not_enforced"},
                   now - 100)
        records = _find_token_drift(
            [tmp_path / "audit_2", tmp_path / "audit_1"],  # unordered input
        )
        (rec,) = records
        assert rec["change"] == "lost_enforcement"
        assert rec["file"] == "web/a.php"
        assert rec["prior_run"] == "audit_1"
        assert rec["current_run"] == "audit_2"

    def test_runs_without_maps_are_skipped_not_compared(self, tmp_path):
        now = time.time()
        _write_map(tmp_path / "r1", {"web/a.php": "enforced"}, now - 300)
        (tmp_path / "r2").mkdir()  # no map — a scan run, say
        os.utime(tmp_path / "r2", (now - 200, now - 200))
        _write_map(tmp_path / "r3", {"web/a.php": "not_enforced"},
                   now - 100)
        records = _find_token_drift(
            [tmp_path / "r1", tmp_path / "r2", tmp_path / "r3"],
        )
        (rec,) = records
        assert (rec["prior_run"], rec["current_run"]) == ("r1", "r3")

    def test_no_maps_no_records(self, tmp_path):
        (tmp_path / "r1").mkdir()
        assert _find_token_drift([tmp_path / "r1"]) == []

    def test_stable_maps_no_records(self, tmp_path):
        now = time.time()
        _write_map(tmp_path / "r1", {"web/a.php": "enforced"}, now - 200)
        _write_map(tmp_path / "r2", {"web/a.php": "enforced"}, now - 100)
        assert _find_token_drift([tmp_path / "r1", tmp_path / "r2"]) == []


class TestReportShape:
    def test_empty_result_carries_the_keys(self):
        result = _empty_result()
        assert result["token_enforcement_drift"] == []
        assert result["summary"]["token_enforcement_drift"] == 0

    def test_correlate_project_folds_the_drift(self, tmp_path):
        now = time.time()
        _write_map(tmp_path / "audit_1", {"web/a.php": "enforced"},
                   now - 200)
        _write_map(tmp_path / "audit_2", {"web/a.php": "not_enforced"},
                   now - 100)

        class _Project:
            name = "p"

            def get_run_dirs(self, sweep=False):
                return [tmp_path / "audit_1", tmp_path / "audit_2"]

        from core.project.correlate import correlate_project
        result = correlate_project(_Project())
        assert result["summary"]["token_enforcement_drift"] == 1
        (rec,) = result["token_enforcement_drift"]
        assert rec["change"] == "lost_enforcement"
