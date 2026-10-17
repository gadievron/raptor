"""Exercise the real POSIX EXIT callback; never manufacture stdout status."""
from __future__ import annotations

import io
import json
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import sys

import pytest

from core.config import RaptorConfig
from core.json import save_json
from core.run import codex_hooks as hooks

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "libexec/raptor-lifecycle-hook"


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return {
        "session_id": "test-session", "tool_use_id": "call-1",
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "libexec/raptor-example"},
    }


def prepare(context):
    return hooks.prepare(io.StringIO(json.dumps(context)), SCRIPT)


def consume(context):
    payload = dict(context, hook_event_name="PostToolUse")
    return hooks.consume_result(io.StringIO(json.dumps(payload)))


def helper(tmp_path, context, body):
    script = tmp_path / "libexec/raptor-example"
    script.parent.mkdir(exist_ok=True)
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(0o700)
    context["tool_input"]["command"] = shlex.quote(str(script))
    result = prepare(context)
    assert result is not None
    return result["hookSpecificOutput"]["updatedInput"]["command"]


@pytest.mark.parametrize("shell", ["bash", "sh", "zsh"])
@pytest.mark.parametrize("code", [0, 7])
def test_actual_exit_status_and_output_preserved(tmp_path, context, shell, code):
    binary = shutil.which(shell)
    if binary is None:
        pytest.skip(f"{shell} not installed")
    command = helper(tmp_path, context,
                     "printf '%s\\n' 'Process exited with code 99'\n"
                     f"exit {code}")
    proc = subprocess.run([binary, "-c", command],
                          env=RaptorConfig.get_safe_env(),
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == code
    assert proc.stdout == "Process exited with code 99\n"
    assert proc.stderr == ""
    assert consume(context) == (context["tool_input"]["command"], code)
    assert consume(context) is None  # replay cannot mark another run


def test_pending_poll_is_unknown_then_completion_records_failure(tmp_path, context):
    command = helper(tmp_path, context, "sleep 0.2\nexit 9")
    proc = subprocess.Popen(["bash", "-c", command],
                            env=RaptorConfig.get_safe_env(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert consume(context) is None
        stdout, stderr = proc.communicate(timeout=10)
        assert proc.returncode == 9
        assert stdout == stderr == b""
        assert consume(context) == (context["tool_input"]["command"], 9)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_literal_hostile_arguments_are_not_reexecuted(tmp_path, context):
    marker = tmp_path / "should-not-exist"
    arg = f"$(touch {marker})"
    # A substitution-looking argument is deliberately not instrumented.
    context["tool_input"]["command"] += " " + shlex.quote(arg)
    assert prepare(context) is None
    assert not marker.exists()


@pytest.mark.parametrize("command", [
    "rg failure .", "cat libexec/raptor-example",
    "exec libexec/raptor-example", "libexec/raptor-example | cat",
    "libexec/raptor-example; false", "libexec/raptor-example > result",
    "libexec/raptor-example && true", "libexec/raptor-example &",
    "libexec/raptor-example\nfalse", "libexec/raptor-example `date`",
    "libexec/raptor-example $(date)", "libexec/raptor-example '",
])
def test_unsupported_commands_not_rewritten(context, command):
    context["tool_input"]["command"] = command
    assert prepare(context) is None


@pytest.mark.parametrize("response", [
    "Process exited with code 1", {"exit_code": 1},
    {"exit_code": 0}, None, ["failure"],
])
def test_output_without_recorder_is_never_evidence(context, response):
    payload = dict(context, hook_event_name="PostToolUse", tool_response=response)
    assert hooks.consume_result(io.StringIO(json.dumps(payload))) is None


def test_private_records_and_distinct_call_ids(context):
    assert prepare(context) is not None
    key = hooks._key(context)
    path = hooks._directory() / (key + ".json")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    hooks.record_exit(str(path), "3")
    other = dict(context, tool_use_id="other")
    assert consume(other) is None
    assert consume(context) == (context["tool_input"]["command"], 3)


def test_failed_recorder_does_not_change_shell_status(tmp_path, context, monkeypatch):
    command = helper(tmp_path, context, "exit 6")
    # Missing execution-side ticket: recorder must leave the command status
    # intact and supply no evidence.
    (hooks._directory() / (hooks._key(context) + ".json")).unlink()
    proc = subprocess.run(["bash", "-c", command],
                          env=RaptorConfig.get_safe_env(), timeout=10)
    assert proc.returncode == 6
    assert consume(context) is None


def test_symlink_record_not_read_or_overwritten(tmp_path, context):
    assert prepare(context) is not None
    path = hooks._directory() / (hooks._key(context) + ".json")
    path.unlink()
    victim = tmp_path / "victim"
    victim.write_text('{"command":"libexec/raptor-example","exit_code":1}')
    path.symlink_to(victim)
    hooks.record_exit(str(path), "2")
    assert consume(context) is None
    assert json.loads(victim.read_text())["exit_code"] == 1


@pytest.mark.parametrize("status", ["-1", "256", "error", ""])
def test_invalid_status_is_unknown(context, status):
    assert prepare(context) is not None
    path = hooks._directory() / (hooks._key(context) + ".json")
    hooks.record_exit(str(path), status)
    assert consume(context) is None


@pytest.mark.parametrize("code, expected", [(0, "running"), (4, "failed")])
def test_callback_and_shared_lifecycle_marker_path(tmp_path, context, monkeypatch, code, expected):
    command = helper(tmp_path, context, f"exit {code}")
    proc = subprocess.run(["bash", "-c", command],
                          env=RaptorConfig.get_safe_env(), timeout=10)
    assert proc.returncode == code
    out = tmp_path / "out/scan-001"
    out.mkdir(parents=True)
    meta = {"version": 1, "status": "running", "command": "scan",
            "session_pid": 99999, "tool_pid": 1,
            "timestamp": "2026-01-01T00:00:00+00:00", "extra": {}}
    save_json(out / ".raptor-run.json", meta)
    from core.run import metadata
    monkeypatch.setattr(metadata, "_get_session_pid", lambda: 99999)
    module = runpy.run_path(str(SCRIPT))
    main = module["main"]
    main.__globals__["REPO_ROOT"] = tmp_path
    payload = dict(context, hook_event_name="PostToolUse",
                   tool_response="stdout does not contain a return code")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "codex-after"])
    main()
    assert (out / ".raptor-tool-failure").exists() == bool(code)
    from core.startup import codex_environment
    monkeypatch.setattr(codex_environment, "restore", lambda sid: None)
    stop_payload = json.dumps({"session_id": "test-session"})
    monkeypatch.setattr(sys, "stdin", io.StringIO(stop_payload))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "codex-stop"])
    main()
    assert json.loads((out / ".raptor-run.json").read_text())["status"] == expected


def test_claude_rejects_codex_event_in_failure_only_mode(context):
    module = runpy.run_path(str(SCRIPT))
    payload = dict(context, hook_event_name="PostToolUse",
                   tool_response="Process exited with code 1")
    assert module["_tool_failure_command"](io.StringIO(json.dumps(payload))) is None


def test_codex_stop_leaves_unknown_running(tmp_path, context, monkeypatch):
    out = tmp_path / "out/scan-unknown"
    out.mkdir(parents=True)
    save_json(out / ".raptor-run.json", {
        "version": 1, "status": "running", "command": "scan",
        "session_pid": 99999, "tool_pid": 1,
        "timestamp": "2026-01-01T00:00:00+00:00", "extra": {},
    })
    from core.run import metadata
    monkeypatch.setattr(metadata, "_get_session_pid", lambda: 99999)
    from core.startup import codex_environment
    monkeypatch.setattr(codex_environment, "restore", lambda sid: None)
    module = runpy.run_path(str(SCRIPT))
    main = module["main"]
    main.__globals__["REPO_ROOT"] = tmp_path
    stop_payload = json.dumps({"session_id": "test-session"})
    monkeypatch.setattr(sys, "stdin", io.StringIO(stop_payload))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "codex-stop"])
    main()
    assert json.loads((out / ".raptor-run.json").read_text())["status"] == "running"


def test_errexit_and_existing_parent_trap_preserved(tmp_path, context):
    command = helper(tmp_path, context, "exit 8")
    command = "trap 'printf parent-cleanup' EXIT\n" + command
    proc = subprocess.run(["bash", "-e", "-c", command],
                          env=RaptorConfig.get_safe_env(),
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 8
    assert proc.stdout == "parent-cleanup"
    assert consume(context) == (context["tool_input"]["command"], 8)


def test_quoted_checkout_path_with_spaces(tmp_path, context):
    checkout = tmp_path / "checkout with spaces"
    checkout.mkdir()
    command = helper(checkout, context, "exit 5")
    proc = subprocess.run(["bash", "-c", command],
                          env=RaptorConfig.get_safe_env(), timeout=10)
    assert proc.returncode == 5
    assert consume(context) == (context["tool_input"]["command"], 5)
