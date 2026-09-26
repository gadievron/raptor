"""raptor-audit run --forecast wiring — $0 pin and run-start band.

Hermetic: the CLI is loaded in-process through its real argument
parser; the lifecycle stub subprocesses are stubbed; the pipeline
entry point is replaced with a tripwire that fails the test if any
path would have spent money.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]


def _load_cli():
    cli_path = str(_RAPTOR_DIR / "libexec" / "raptor-audit")
    loader = SourceFileLoader("raptor_audit_forecast_cli_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_forecast_cli_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    """Target + out dir with a pre-built two-function checklist, the
    lifecycle stub faked, and the pipeline tripwired."""
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.php").write_text("<?php function f1() {}\n")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    checklist = {
        "target_path": str(target),
        "total_files": 1,
        "total_functions": 2,
        "files": [{
            "path": "a.php",
            "language": "php",
            "sloc": 60,
            "items": [
                {"name": "f1", "kind": "function", "line_start": 1,
                 "line_end": 30, "checked_by": [], "metadata": {}},
                {"name": "f2", "kind": "function", "line_start": 32,
                 "line_end": 60, "checked_by": [], "metadata": {}},
            ],
        }],
    }
    (out_dir / "checklist.json").write_text(json.dumps(checklist))

    lifecycle_calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        cmd_strs = [str(c) for c in cmd]
        if any("raptor-run-lifecycle" in c for c in cmd_strs):
            lifecycle_calls.append(cmd_strs)
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={out_dir}\n", stderr="")
        raise AssertionError(
            f"unexpected subprocess in forecast path: {cmd_strs}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # $0 tripwire: any route into the paying pipeline fails the test.
    import core.audit.pipeline as pipeline

    def _no_spend(*a, **k):
        raise AssertionError("run_audit_pipeline called in --forecast mode")

    monkeypatch.setattr(pipeline, "run_audit_pipeline", _no_spend)

    def run_cli(argv: list[str]) -> int:
        # Through the real parser: every run-flag default is present,
        # exactly as a live invocation would see them.
        import core.project.trust as trust
        monkeypatch.setattr(
            trust, "apply_project_sandbox_floor", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", ["raptor-audit", *argv])
        return mod.main()

    return SimpleNamespace(
        mod=mod, target=target, out_dir=out_dir,
        lifecycle_calls=lifecycle_calls, run_cli=run_cli,
    )


def test_forecast_exits_zero_spend(cli_env, capsys):
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--forecast",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Cost forecast: $" in out
    assert "not a cap" in out
    assert "AUDIT FORECAST COMPLETE" in out
    assert "$0 LLM spend" in out
    # The run never reached the review loop, and no telemetry exists.
    assert not (cli_env.out_dir / "llm-telemetry.jsonl").exists()

    doc = json.loads((cli_env.out_dir / "forecast.json").read_text())
    assert doc["outcome"] == "forecast_only"
    assert doc["queue_n"] == 2
    assert doc["usd_low"] <= doc["usd_central"] <= doc["usd_high"]

    # Lifecycle: started, then completed (a forecast is a clean exit,
    # not a failure).
    verbs = [c[1] for c in cli_env.lifecycle_calls]
    assert verbs[0] == "start"
    assert "complete" in verbs
    assert "fail" not in verbs


def test_uncapped_run_prints_band_then_commits(cli_env, capsys):
    # No --max-cost: the band prints informationally, then the run
    # proceeds into the pipeline (the tripwire proves the order).
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
    ])
    out = capsys.readouterr()
    assert rc == 1                      # tripwire error path
    assert "Cost forecast: $" in out.out
    assert "run_audit_pipeline called" in out.err
    # The pre-run forecast persisted for the completion tail.
    doc = json.loads((cli_env.out_dir / "forecast.json").read_text())
    assert doc["outcome"] == "pre_run"


def test_capped_run_skips_band(cli_env, capsys):
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--max-cost", "5",
    ])
    out = capsys.readouterr()
    assert rc == 1                      # tripwire error path
    assert "Cost forecast" not in out.out
    assert not (cli_env.out_dir / "forecast.json").exists()


def test_forecast_without_inventory_fails_loudly(cli_env, capsys):
    (cli_env.out_dir / "checklist.json").write_text("{}")
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--forecast",
    ])
    err = capsys.readouterr().err
    assert rc == 1
    assert "forecast unavailable" in err
    verbs = [c[1] for c in cli_env.lifecycle_calls]
    assert "fail" in verbs


def test_finalize_run_records_forecast_vs_actual(tmp_path, monkeypatch,
                                                 capsys):
    """Completion tail: a run that started with a forecast pairs it
    with the ledger — report block, calibration record, console line."""
    mod = _load_cli()
    out_dir = tmp_path / "run-1"
    out_dir.mkdir()

    from core.audit.forecast import (
        forecast_audit_cost,
        predicted_suspicious_density,
        save_forecast,
    )
    fc = forecast_audit_cost(
        slocs=[50, 50],
        density=predicted_suspicious_density([], None),
        seed_mass=0,
    )
    save_forecast(out_dir, fc)
    (out_dir / "cost-breakdown.json").write_text(json.dumps({
        "phases": {
            "review": {"cost_usd": 4.0, "calls": 2},
            "re_review": {"cost_usd": 2.0, "calls": 3},
            "refinement": {"cost_usd": 1.0, "calls": 1},
        },
        "totals": {"cost_usd": 7.0, "total_spend_usd": 7.0, "calls": 6},
    }))

    written: dict = {}
    import core.audit.report as report_mod
    monkeypatch.setattr(
        report_mod, "generate_report",
        lambda out, final_status=None: {"findings": []})

    def fake_write(report, out):
        written.update(report)
        return out / "audit-report.json"

    monkeypatch.setattr(report_mod, "write_report", fake_write)
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))

    result = SimpleNamespace(
        terminated_by="complete", total_duration_s=10.0, reviewed=2,
        findings=0, suspicious=1, clean=1, errors=0,
        total_cost_usd=7.0, failed_attempts_cost_usd=0.0,
        llm_spend_usd=7.0, cost_tracker=None,
    )
    rc = mod._finalize_run(out_dir, result, "")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Forecast vs actual:" in out
    assert "forecast_vs_actual" in written
    block = written["forecast_vs_actual"]
    assert block["actual"]["deepen_usd"] == 3.0
    assert block["actual"]["total_spend_usd"] == 7.0
    lines = (out_dir / "forecast-calibration.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["run_id"] == "run-1"


def test_forecast_uses_journal_priors(cli_env, capsys, tmp_path):
    # A project-level journal index marks a.php's functions
    # suspicious: the forecast must source its density from priors
    # and land higher than the cold shape of the same queue.
    from core.coverage.journal import INDEX_FILENAME
    index = {
        "schema_version": 1,
        "updated_at": "2026-01-01T00:00:00Z",
        "entries": {
            f"a.php:f{i}:m:h:audit": {
                "ts": "2026-01-01T00:00:00Z", "run_id": "r0",
                "file": "a.php", "function": f"f{i}",
                "verdict": "suspicious", "source_hash": "00",
            }
            for i in (1, 2)
        },
    }
    (cli_env.out_dir.parent / INDEX_FILENAME).write_text(json.dumps(index))
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--forecast",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "(priors)" in out
    doc = json.loads((cli_env.out_dir / "forecast.json").read_text())
    assert doc["density_source"] == "priors"


def _finalize_env(tmp_path, monkeypatch):
    """Shared _finalize_run harness: stubbed report module + lifecycle."""
    mod = _load_cli()
    out_dir = tmp_path / "run-1"
    out_dir.mkdir()
    (out_dir / "cost-breakdown.json").write_text(json.dumps({
        "phases": {"review": {"cost_usd": 4.0, "calls": 2}},
        "totals": {"cost_usd": 4.0, "total_spend_usd": 4.0, "calls": 2},
    }))
    import core.audit.report as report_mod
    monkeypatch.setattr(
        report_mod, "generate_report",
        lambda out, final_status=None: {"findings": []})
    monkeypatch.setattr(
        report_mod, "write_report",
        lambda report, out: out / "audit-report.json")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    result = SimpleNamespace(
        terminated_by="complete", total_duration_s=10.0, reviewed=2,
        findings=0, suspicious=1, clean=1, errors=0,
        total_cost_usd=4.0, failed_attempts_cost_usd=0.0,
        llm_spend_usd=4.0, cost_tracker=None,
    )
    return mod, out_dir, result


def test_finalize_run_tolerates_partial_forecast(tmp_path, monkeypatch,
                                                 capsys):
    """A parseable-but-partial forecast.json (valid dict, no usd keys)
    must not fail a fully-paid run at the calibration print seam — the
    line degrades to visible $? markers and the run completes."""
    mod, out_dir, result = _finalize_env(tmp_path, monkeypatch)
    (out_dir / "forecast.json").write_text(json.dumps(
        {"outcome": "pre_run"}))
    rc = mod._finalize_run(out_dir, result, "")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Forecast vs actual:" in out
    assert "$?" in out
    assert "Report:" in out


def test_finalize_run_contains_calibration_line_crash(tmp_path, monkeypatch,
                                                      capsys):
    """Belt behind the tolerant formatter: even a formatter exception
    must not escape the completion tail after the report is written."""
    mod, out_dir, result = _finalize_env(tmp_path, monkeypatch)
    from core.audit.forecast import forecast_audit_cost, save_forecast
    fc = forecast_audit_cost(
        slocs=[50, 50],
        density={"central": 0.35, "low": 0.15, "high": 0.55,
                 "source": "cold", "prior_coverage": 0.0},
        seed_mass=0,
    )
    save_forecast(out_dir, fc)
    import core.audit.forecast as forecast_mod

    def _boom(entry):
        raise RuntimeError("formatter sabotage")

    monkeypatch.setattr(forecast_mod, "format_calibration_line", _boom)
    rc = mod._finalize_run(out_dir, result, "")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Forecast vs actual:" not in out
    assert "Report:" in out


def test_forecast_only_save_failure_still_completes(cli_env, capsys,
                                                    monkeypatch):
    """--forecast with forecast.json unpersistable (ENOSPC-alike): the
    printed band is the product — warn loudly, complete the lifecycle,
    exit 0. Never a traceback with the run stuck at start."""
    import core.audit.forecast as forecast_mod

    def _enospc(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(forecast_mod, "save_forecast", _enospc)
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--forecast",
    ])
    captured = capsys.readouterr()
    assert rc == 0
    assert "Cost forecast: $" in captured.out
    assert "AUDIT FORECAST COMPLETE" in captured.out
    assert "could not persist" in captured.err
    assert "forecast.json" in captured.err
    assert not (cli_env.out_dir / "forecast.json").exists()
    verbs = [c[1] for c in cli_env.lifecycle_calls]
    assert "start" in verbs and "complete" in verbs
    assert "fail" not in verbs


def test_uncapped_save_failure_warns_and_proceeds(cli_env, capsys,
                                                  monkeypatch):
    """Sibling seam, same containment: an uncapped run whose pre-run
    forecast.json cannot persist still prints the band, warns that
    calibration will be skipped, and proceeds into the pipeline."""
    import core.audit.forecast as forecast_mod

    def _enospc(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(forecast_mod, "save_forecast", _enospc)
    rc = cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
    ])
    captured = capsys.readouterr()
    assert rc == 1                      # tripwire error path
    assert "run_audit_pipeline called" in captured.err
    assert "Cost forecast: $" in captured.out
    assert "could not persist" in captured.err
    assert "calibration will be skipped" in captured.err
