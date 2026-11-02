"""raptor-run-lifecycle children are bounded and expiry is surfaced.

The stub takes cross-process locks; without a timeout a wedged
lock-holder hung the audit CLI forever. Expiry is treated like a
nonzero exit: start aborts, interrupt/complete report the failed
transition instead of claiming a clean one, and the _lifecycle_fail
helper keeps swallowing (it already runs on a reported error path).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_lctimeout", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_lctimeout", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


def _timeout_run(recorded):
    def fake_run(cmd, **kwargs):
        recorded.append((list(map(str, cmd)), kwargs))
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout") or 0)
    return fake_run


def test_run_lifecycle_start_timeout_aborts(tmp_path, monkeypatch, capsys):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("def f():\n    return 1\n")

    recorded: list = []
    monkeypatch.setattr(subprocess, "run", _timeout_run(recorded))
    rc = mod.cmd_run(SimpleNamespace(target=str(target), out=None))
    captured = capsys.readouterr()
    assert rc == 1
    assert "lifecycle start timed out" in captured.err
    # The child was invoked with an actual bound.
    assert recorded and recorded[0][1].get("timeout")


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
    return out_dir


def _result(terminated_by: str):
    return SimpleNamespace(
        terminated_by=terminated_by,
        total_duration_s=5.0,
        reviewed=0, findings=0, suspicious=0, clean=0, errors=0,
    )


def test_interrupt_timeout_surfaced(finalize_env, monkeypatch, capsys):
    mod = _load_cli()
    recorded: list = []
    monkeypatch.setattr(subprocess, "run", _timeout_run(recorded))
    rc = mod._finalize_run(finalize_env, _result("sigterm"), "model-x")
    captured = capsys.readouterr()
    assert rc == 130
    assert "lifecycle interrupt failed (timed out" in captured.err
    assert "Interrupted by SIGTERM" in captured.out


def test_complete_timeout_surfaced(finalize_env, monkeypatch, capsys):
    mod = _load_cli()
    recorded: list = []
    monkeypatch.setattr(subprocess, "run", _timeout_run(recorded))
    rc = mod._finalize_run(finalize_env, _result("complete"), "model-x")
    captured = capsys.readouterr()
    assert rc == 0
    assert "lifecycle complete failed (timed out" in captured.err


def test_lifecycle_fail_swallows_timeout(tmp_path, monkeypatch):
    mod = _load_cli()
    recorded: list = []
    monkeypatch.setattr(subprocess, "run", _timeout_run(recorded))
    # Must not raise.
    mod._lifecycle_fail(tmp_path, "boom")
    assert recorded and recorded[0][1].get("timeout")
