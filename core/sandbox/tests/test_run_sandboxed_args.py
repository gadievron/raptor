"""Output-dir resolution and program-path handling in
libexec/raptor-run-sandboxed.

The output dir resolves flag > OUTPUT_DIR env > this session's live
run (session run ledger) — dispatched agent shells don't persist
exports and must not env-prefix commands, so the flag is the
supported route. A relative program path containing a slash is
resolved against the caller's cwd before sandbox assembly; a missing
file refuses up-front with the real reason instead of surfacing a
bind-tree/exec failure from inside the sandbox.

Hermetic: the script is exec'd in-process with a stubbed core.sandbox
module, so no namespaces, Landlock, or real children are involved.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import json
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-run-sandboxed"


def _exec_script(monkeypatch, argv, seen, env=None):
    """Execute the script with a recording sandbox stub.

    ``seen`` is filled with the sandbox() kwargs and the run() cmd;
    the script always ends in SystemExit, so the capture dict is
    caller-owned.
    """
    fake = types.ModuleType("core.sandbox")

    class SandboxSetupError(Exception):
        pass

    @contextlib.contextmanager
    def sandbox(**kwargs):
        seen["sandbox_kwargs"] = kwargs

        def run_fn(cmd, **_kwargs):
            seen["cmd"] = list(cmd)
            return SimpleNamespace(
                returncode=0, stdout="", stderr="", sandbox_info={})

        yield run_fn

    fake.SandboxSetupError = SandboxSetupError
    fake.SANDBOX_ENGAGE_EXIT_CODE = 3
    fake.sandbox = sandbox
    monkeypatch.setitem(sys.modules, "core.sandbox", fake)

    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(sys, "argv", ["raptor-run-sandboxed", *argv])

    loader = importlib.machinery.SourceFileLoader(
        "raptor_run_sandboxed_args_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)


def _run(monkeypatch, argv, env=None):
    """Run the script, returning (exit_code, seen)."""
    seen: dict = {}
    with pytest.raises(SystemExit) as exc:
        _exec_script(monkeypatch, argv, seen, env=env)
    return exc.value.code, seen


def _stub_ledger(monkeypatch, records, alive_pids=()):
    fake_sessions = types.ModuleType("core.project.sessions")

    def ledger_runs(status=None):
        assert status == "running"
        return records

    fake_sessions.ledger_runs = ledger_runs
    monkeypatch.setitem(sys.modules, "core.project.sessions",
                        fake_sessions)

    # The wrapper consults core.run.metadata._session_alive_for_meta
    # to reject crashed runs (status=running, dead owner); stub it on
    # the recorded session_pid so the tests need no real processes.
    fake_metadata = types.ModuleType("core.run.metadata")

    def _session_alive_for_meta(meta):
        return meta.get("session_pid") in alive_pids

    fake_metadata._session_alive_for_meta = _session_alive_for_meta
    monkeypatch.setitem(sys.modules, "core.run.metadata", fake_metadata)


def _write_run_meta(run_dir: Path, session_pid: int) -> None:
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "running", "session_pid": session_pid}))


def _record(run_dir: Path, epoch: int) -> dict:
    return {"status": "running", "epoch": epoch,
            "run_id": f"r{epoch}", "run_dir": str(run_dir)}


def test_output_dir_flag_without_env(monkeypatch, tmp_path):
    out = tmp_path / "out"
    code, seen = _run(monkeypatch,
                      ["--output-dir", str(out), "/bin/true"])
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(out))
    assert seen["cmd"] == ["/bin/true"]


def test_flag_beats_env(monkeypatch, tmp_path):
    flag_dir = tmp_path / "flag-out"
    env_dir = tmp_path / "env-out"
    code, seen = _run(
        monkeypatch,
        ["--output-dir", str(flag_dir), "/bin/true"],
        env={"OUTPUT_DIR": str(env_dir)},
    )
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(flag_dir))


def test_env_still_works(monkeypatch, tmp_path):
    env_dir = tmp_path / "env-out"
    code, seen = _run(monkeypatch, ["/bin/true"],
                      env={"OUTPUT_DIR": str(env_dir)})
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(env_dir))


def test_equals_form_accepted(monkeypatch, tmp_path):
    out = tmp_path / "out"
    code, seen = _run(monkeypatch,
                      [f"--output-dir={out}", "/bin/true"])
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(out))


def test_child_args_never_consumed(monkeypatch, tmp_path):
    # Only LEADING options belong to the wrapper: a child command
    # carrying its own --output-dir keeps it verbatim.
    out = tmp_path / "out"
    code, seen = _run(
        monkeypatch,
        ["--output-dir", str(out),
         "/bin/echo", "--output-dir", "/child/path"],
    )
    assert code == 0
    assert seen["cmd"] == ["/bin/echo", "--output-dir", "/child/path"]


def test_ledger_fallback_resolves_live_run(monkeypatch, tmp_path, capsys):
    run_dir = tmp_path / "run"
    _write_run_meta(run_dir, session_pid=1001)
    _stub_ledger(monkeypatch, [_record(run_dir, 1)], alive_pids=(1001,))

    code, seen = _run(monkeypatch, ["/bin/true"])
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(run_dir))
    assert ("output dir from this session's live run"
            in capsys.readouterr().err)


def test_ledger_fallback_rejects_stale_record(monkeypatch, tmp_path,
                                              capsys):
    # A ledger line still saying running while the run metadata says
    # completed must not steer the write grant.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "completed", "session_pid": 1001}))
    _stub_ledger(monkeypatch, [_record(run_dir, 1)], alive_pids=(1001,))

    code, _seen = _run(monkeypatch, ["/bin/true"])
    assert code == 1
    assert "--output-dir" in capsys.readouterr().err


def test_crashed_newer_run_skipped_live_older_resolves(
        monkeypatch, tmp_path):
    # A hard-killed run's metadata says running forever (ledger
    # eviction only removes finished records) — without the owner
    # liveness check the crashed newer run shadows the live older one
    # and output lands in the wrong run dir.
    crashed = tmp_path / "crashed-run"
    live = tmp_path / "live-run"
    _write_run_meta(crashed, session_pid=2002)
    _write_run_meta(live, session_pid=1001)
    _stub_ledger(monkeypatch,
                 [_record(crashed, 9), _record(live, 5)],
                 alive_pids=(1001,))

    code, seen = _run(monkeypatch, ["/bin/true"])
    assert code == 0
    assert seen["sandbox_kwargs"]["output"] == os.path.realpath(str(live))


def test_all_crashed_runs_refuse_with_flag_message(monkeypatch, tmp_path,
                                                   capsys):
    crashed = tmp_path / "crashed-run"
    _write_run_meta(crashed, session_pid=2002)
    _stub_ledger(monkeypatch, [_record(crashed, 9)], alive_pids=())

    code, _seen = _run(monkeypatch, ["/bin/true"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--output-dir" in err
    assert "OUTPUT_DIR" in err


def test_empty_flag_value_refuses(monkeypatch, tmp_path, capsys):
    # An explicit empty value is a mistake (unexpanded shell var), not
    # an absence — it must not silently fall through to env/ledger.
    code, seen = _run(monkeypatch, ["--output-dir=", "/bin/true"],
                      env={"OUTPUT_DIR": str(tmp_path / "env-out")})
    assert code == 1
    assert "sandbox_kwargs" not in seen
    assert "non-empty" in capsys.readouterr().err


def test_empty_env_value_refuses(monkeypatch, tmp_path, capsys):
    _stub_ledger(monkeypatch, [])
    code, seen = _run(monkeypatch, ["/bin/true"],
                      env={"OUTPUT_DIR": ""})
    assert code == 1
    assert "sandbox_kwargs" not in seen
    assert "set but empty" in capsys.readouterr().err


def test_flag_sourced_validation_error_names_the_flag(
        monkeypatch, tmp_path, capsys):
    # Provenance-accurate messages: a bad value that came from the
    # flag must not be reported as an OUTPUT_DIR env problem.
    code, _seen = _run(monkeypatch,
                       ["--output-dir", "relative/dir", "/bin/true"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--output-dir" in err
    assert "OUTPUT_DIR env var" not in err


def test_no_output_dir_error_names_the_flag(monkeypatch, tmp_path,
                                            capsys):
    _stub_ledger(monkeypatch, [])
    code, _seen = _run(monkeypatch, ["/bin/true"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--output-dir" in err
    assert "OUTPUT_DIR" in err


def test_relative_program_path_absolutized(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    poc = workdir / "poc"
    poc.write_text("#!/bin/sh\n")
    monkeypatch.chdir(workdir)
    out = tmp_path / "out"
    code, seen = _run(monkeypatch,
                      ["--output-dir", str(out), "./poc", "arg1"])
    assert code == 0
    assert seen["cmd"] == [str(poc), "arg1"]


def test_relative_program_path_missing_fails_fast(monkeypatch, tmp_path,
                                                  capsys):
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    out = tmp_path / "out"
    code, seen = _run(monkeypatch,
                      ["--output-dir", str(out), "./poc"])
    assert code == 1
    err = capsys.readouterr().err
    assert "'./poc'" in err
    assert "caller's cwd" in err
    # The sandbox never engaged — the message is the wrapper's, not a
    # bind-tree failure surfaced from inside the sandbox.
    assert "sandbox_kwargs" not in seen
    assert "bind tree" not in err


def test_bare_program_name_keeps_path_lookup(monkeypatch, tmp_path):
    out = tmp_path / "out"
    code, seen = _run(monkeypatch,
                      ["--output-dir", str(out), "gcc", "-o", "x"])
    assert code == 0
    assert seen["cmd"] == ["gcc", "-o", "x"]


def test_help_exits_zero(monkeypatch, tmp_path, capsys):
    code, _seen = _run(monkeypatch, ["--help"])
    assert code == 0
    assert "--output-dir" in capsys.readouterr().err


def test_no_args_usage_exits_one(monkeypatch, tmp_path):
    code, _seen = _run(monkeypatch, [])
    assert code == 1
