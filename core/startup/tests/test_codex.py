"""Tests for Codex CLI readiness and delegated login setup."""

from __future__ import annotations

import os
import subprocess

from core.startup import codex


def _fake_codex(tmp_path, body: str):
    exe = tmp_path / "codex"
    exe.write_text("#!/usr/bin/env sh\n" + body)
    exe.chmod(0o755)
    return exe


def test_find_codex_executable_uses_path(tmp_path, monkeypatch):
    exe = _fake_codex(tmp_path, "exit 0\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert codex.find_codex_executable() == str(exe)


def test_check_codex_auth_reports_missing(monkeypatch):
    monkeypatch.setattr(codex.shutil, "which", lambda _: None)
    status = codex.check_codex_auth()
    assert not status.available
    assert not status.authenticated
    assert "not found" in status.detail


def test_check_codex_auth_success_with_fake_cli(tmp_path):
    exe = _fake_codex(
        tmp_path,
        'test "$1 $2" = "login status" || exit 9\n'
        'printf "Logged in\\n"\n'
        "exit 0\n",
    )
    status = codex.check_codex_auth(executable=str(exe))
    assert status.available
    assert status.authenticated
    assert "Logged in" in status.detail


def test_check_codex_auth_nonzero_is_setup_needed(tmp_path):
    exe = _fake_codex(
        tmp_path,
        'test "$1 $2" = "login status" || exit 9\n'
        'printf "Not logged in\\n" >&2\n'
        "exit 1\n",
    )
    status = codex.check_codex_auth(executable=str(exe))
    assert status.available
    assert not status.authenticated
    assert "Not logged in" in status.detail


def test_check_codex_auth_timeout(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["codex", "login", "status"], 10)

    monkeypatch.setattr(codex.subprocess, "run", fake_run)
    status = codex.check_codex_auth(executable="/tmp/codex", timeout=10)
    assert status.available
    assert not status.authenticated
    assert "timed out" in status.detail


def test_check_codex_auth_sanitizes_diagnostics(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "\x1b[31mnope\x1b[0m"

    monkeypatch.setattr(codex.subprocess, "run", lambda *_a, **_kw: Result())
    status = codex.check_codex_auth(executable="/tmp/codex")
    assert "\x1b" not in status.detail
    assert "\\x1b[31mnope" in status.detail


def test_run_codex_login_delegates_browser_login(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(codex.subprocess, "run", fake_run)
    rc = codex.run_codex_login(executable="/opt/bin/codex")
    assert rc == 0
    assert seen["cmd"] == ["/opt/bin/codex", "login"]
    assert "PATH" in seen["env"]
    assert "OPENAI_API_KEY" not in seen["env"]


def test_run_codex_login_delegates_device_auth(monkeypatch):
    seen = {}

    def fake_run(cmd, **_kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(codex.subprocess, "run", fake_run)
    rc = codex.run_codex_login(executable="/opt/bin/codex", device_auth=True)
    assert rc == 0
    assert seen["cmd"] == ["/opt/bin/codex", "login", "--device-auth"]


def test_run_codex_login_does_not_read_codex_home(tmp_path, monkeypatch):
    """The setup boundary must stay CLI-owned, not credential-store-owned."""

    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    (codex_home / "auth.json").write_text("do not read me")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(
        codex.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0),
    )

    rc = codex.run_codex_login(executable="/opt/bin/codex")
    assert rc == 0
    assert (codex_home / "auth.json").read_text() == "do not read me"


def test_no_api_key_in_safe_env_for_login(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw["env"]
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(codex.subprocess, "run", fake_run)
    codex.run_codex_login(executable="/opt/bin/codex")
    assert "OPENAI_API_KEY" not in seen["env"]
    assert os.environ["OPENAI_API_KEY"] == "sk-test"
