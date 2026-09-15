"""Hardening tests for crash_trace.py (run by path — the .claude tree
is excluded from root pytest collection; skill kits own their tests):

    python3 -m pytest .claude/skills/crash-analysis/rr-debugger/scripts/test_crash_trace.py
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parent / "crash_trace.py"
_spec = importlib.util.spec_from_file_location("crash_trace", _MOD_PATH)
crash_trace = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_spec and crash_trace)


class _Result:
    returncode = 0
    stdout = b""
    stderr = b""


def _run_capture(monkeypatch, **kwargs):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured.update(kw)
        return _Result()

    monkeypatch.setattr(subprocess, "run", fake_run)
    crash_trace.extract_trace("/tmp/some-trace", steps=1, **kwargs)
    return captured


def test_gdb_hardening_flags_on_command_line(monkeypatch):
    # Startup-time auto-load (init files, objfile scripts, inlined
    # .debug_gdb_scripts Python) happens before the first stdin
    # command runs — suppression must ride the command line.
    cap = _run_capture(monkeypatch)
    cmd = cap["cmd"]
    assert "--" in cmd
    gdb_args = cmd[cmd.index("--") + 1:]
    assert "-nx" in gdb_args
    joined = " ".join(gdb_args)
    assert "set auto-load off" in joined
    assert "set auto-load python-scripts off" in joined
    assert "set auto-load safe-path /dev/null" in joined
    # The trusts-everything spelling must never come back.
    assert "safe-path /" + " " not in joined + " "


def test_env_is_neutral(monkeypatch):
    monkeypatch.setenv("LD_PRELOAD", "/evil/lib.so")
    monkeypatch.setenv("PYTHONPATH", "/evil")
    cap = _run_capture(monkeypatch)
    env = cap["env"]
    assert "LD_PRELOAD" not in env
    assert "PYTHONPATH" not in env
    # HOME points at a fresh neutral dir, not the operator's home.
    home = env["HOME"]
    assert home != os.path.expanduser("~")
    assert Path(home).is_dir()
    assert not any(Path(home).iterdir())


def test_cwd_is_neutral_and_matches_home(monkeypatch):
    cap = _run_capture(monkeypatch)
    assert cap["cwd"] == cap["env"]["HOME"]


def test_trace_lookup_preserved_via_rr_trace_dir(monkeypatch):
    monkeypatch.delenv("_RR_TRACE_DIR", raising=False)
    cap = _run_capture(monkeypatch)
    env = cap["env"]
    expected = os.path.join(
        os.path.expanduser("~"), ".local", "share", "rr",
    )
    assert env.get("_RR_TRACE_DIR") == expected


def test_stdin_backstop_still_present(monkeypatch):
    cap = _run_capture(monkeypatch)
    batch = cap["input"].decode()
    assert batch.startswith("set auto-load no\n")


if __name__ == "__main__":
    sys.exit(subprocess.call(
        [sys.executable, "-m", "pytest", __file__, "-q"],
    ))
