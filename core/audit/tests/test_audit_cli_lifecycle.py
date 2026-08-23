"""cmd_run lifecycle-start wiring — explicit --out runs get run metadata.

Pre-fix the --out branch only mkdir'd the directory: no .raptor-run.json
was ever written, the end-of-run lifecycle complete failed, and the
supervisor-advertised `raptor-audit resume <dir>` refused the directory.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace


def _load_cli():
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_cli_test", cli_path)
    spec = importlib.util.spec_from_loader("raptor_audit_cli_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_explicit_out_goes_through_lifecycle_start(tmp_path, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    out_dir = tmp_path / "out"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={out_dir}\n", stderr="")
        # First downstream step (checklist build) fails fast so the
        # test never reaches the orchestrator.
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)

    args = SimpleNamespace(target=str(target), out=str(out_dir))
    rc = mod.cmd_run(args)
    assert rc == 1                       # stopped at the stubbed step

    start = calls[0]
    assert start[0].endswith("raptor-run-lifecycle")
    assert start[1:3] == ["start", "audit"]
    assert "--target" in start and str(target) in start
    assert "--out" in start
    assert str(out_dir) in start


def test_no_out_still_resolves_via_lifecycle(tmp_path, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={resolved}\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)

    rc = mod.cmd_run(SimpleNamespace(target=str(target), out=None))
    assert rc == 1
    assert "--out" not in calls[0]
