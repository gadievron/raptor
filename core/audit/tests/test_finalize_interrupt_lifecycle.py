"""SIGTERM finalisation surfaces a failed lifecycle transition.

The complete path already checks the lifecycle child's exit code and
prints its captured stderr; the interrupt path must do the same — a
swallowed failed transition leaves the run stamped 'running' (so the
advertised resume refuses it) while the console claims a clean
interrupt.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_finalize", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_finalize", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture()
def finalize_env(tmp_path, monkeypatch):
    out_dir = tmp_path / "run"
    out_dir.mkdir()

    import core.audit.cost_tracker as cost_tracker
    import core.audit.report as report_mod
    monkeypatch.setattr(
        report_mod, "generate_report",
        lambda out, final_status=None: {},
    )
    monkeypatch.setattr(
        report_mod, "write_report",
        lambda report, out: out / "audit-report.json",
    )
    monkeypatch.setattr(
        cost_tracker, "format_cost_summary", lambda result: "",
    )

    result = SimpleNamespace(
        terminated_by="sigterm",
        total_duration_s=5.0,
        reviewed=0, findings=0, suspicious=0, clean=0, errors=0,
    )
    return out_dir, result


def _fake_lifecycle(calls, returncode: int, stderr: str = ""):
    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        return SimpleNamespace(returncode=returncode, stdout="",
                               stderr=stderr)
    return fake_run


def test_failed_interrupt_transition_is_surfaced(
        finalize_env, monkeypatch, capsys):
    mod = _load_cli()
    out_dir, result = finalize_env
    calls: list[list[str]] = []
    import subprocess
    monkeypatch.setattr(
        subprocess, "run",
        _fake_lifecycle(calls, returncode=1, stderr="run not owned"),
    )
    rc = mod._finalize_run(out_dir, result, "model-x")
    captured = capsys.readouterr()
    assert rc == 130
    assert any("interrupt" in c for c in calls[0])
    assert "lifecycle interrupt failed (exit 1)" in captured.err
    assert "run not owned" in captured.err


def test_clean_interrupt_transition_stays_quiet(
        finalize_env, monkeypatch, capsys):
    mod = _load_cli()
    out_dir, result = finalize_env
    calls: list[list[str]] = []
    import subprocess
    monkeypatch.setattr(
        subprocess, "run", _fake_lifecycle(calls, returncode=0),
    )
    rc = mod._finalize_run(out_dir, result, "model-x")
    captured = capsys.readouterr()
    assert rc == 130
    assert "lifecycle interrupt failed" not in captured.err
    assert "Interrupted by SIGTERM" in captured.out
