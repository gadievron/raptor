"""End-to-end regression pin: ``--project -`` beats the active project.

The pin contract (core/run/pin.py): children receive ``--project`` by
explicit argv threading, never ambiently. When ``cmd_run`` spawned
``raptor-run-lifecycle start`` without the flag, the child resolved
the pin itself (session binding / ``.active`` symlink): an EXPLICITLY
projectless run (``--project -``) under an active project was pinned
to that project anyway — its run dir landed inside the project's
output dir and every pin-keyed store write (IRIS specs, coverage,
journal merges) contaminated the project the operator had
deliberately unpinned.

The argv-threading unit pins live in test_audit_cli_lifecycle.py;
this file pins the OUTCOME with the real lifecycle child against a
real (isolated) project registry: standalone run dir, authoritative
null pin, active project's IRIS spec store untouched.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]


def _load_cli():
    cli_path = str(_RAPTOR_DIR / "libexec" / "raptor-audit")
    loader = SourceFileLoader("raptor_audit_cli_pin_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_pin_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.mark.skipif(os.name != "posix", reason="posix subprocess env")
def test_projectless_run_lands_standalone_under_active_project(
        tmp_path, monkeypatch, capsys):
    """With a project ACTIVE (``.active`` symlink), ``raptor-audit run
    <target> --project -`` must resolve a STANDALONE run dir with an
    authoritative null pin — never a run dir inside the active
    project's output dir, whose pin would route the IRIS spec store
    (and every other pin-keyed store write) into the project the
    operator deliberately unpinned.

    Isolated HOME + RAPTOR_OUT_DIR: the real project registry and out/
    are never touched. The lifecycle child runs for real; the first
    downstream step (checklist build) is stubbed so the orchestrator
    never starts.
    """
    home = tmp_path / "home"
    home.mkdir()
    out_root = tmp_path / "outroot"
    out_root.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n",
                                   encoding="utf-8")

    env = dict(os.environ,
               HOME=str(home),
               RAPTOR_OUT_DIR=str(out_root),
               CLAUDECODE="1",
               _RAPTOR_TRUSTED="1")
    pm = str(_RAPTOR_DIR / "libexec" / "raptor-project-manager")
    for cmd in (
        [sys.executable, pm, "create", "tmpproj",
         "--target", str(target), "-d", "pin regression"],
        [sys.executable, pm, "use", "tmpproj"],
    ):
        cp = subprocess.run(cmd, env=env, capture_output=True, text=True,
                            check=False, timeout=120)
        assert cp.returncode == 0, cp.stderr
    proj_out = out_root / "projects" / "tmpproj"
    assert proj_out.is_dir()

    mod = _load_cli()
    real_run = subprocess.run

    def selective_run(cmd, **kwargs):
        if "raptor-run-lifecycle" in str(cmd[0]):
            return real_run(cmd, **kwargs)
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    # The in-process cmd_run spawns the REAL lifecycle child, which
    # reads HOME / RAPTOR_OUT_DIR from the (patched) process env.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RAPTOR_OUT_DIR", str(out_root))
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(subprocess, "run", selective_run)

    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=None, project="-"))
    assert rc == 1                       # stopped at the stubbed step

    out_line = [ln for ln in capsys.readouterr().out.splitlines()
                if ln.startswith("OUTPUT_DIR=")]
    assert out_line, "lifecycle start printed no OUTPUT_DIR"
    run_dir = Path(out_line[-1].split("=", 1)[1])

    # Standalone by pin: never inside the active project's output dir.
    assert not run_dir.resolve().is_relative_to(proj_out.resolve())
    marker = json.loads(
        (run_dir / ".raptor-run.json").read_text(encoding="utf-8"))
    assert marker["project"] is None
    assert marker["project_source"] == "argv"

    # The contamination vector stays shut: the active project gained
    # no run dir and no IRIS spec store from the projectless run.
    assert not list(proj_out.glob("audit*"))
    assert not (proj_out / "iris-specs").exists()
