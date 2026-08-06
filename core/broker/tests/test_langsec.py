"""Tests for LangSec hardening — shell quoting, input validation, safe deserialization."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.broker.transport import CommandResult, TransportError


class TestADBShellQuoting:
    """Verify ADB transport quotes paths and validates env keys."""

    def test_path_with_spaces_quoted_in_path_exists(self):
        from core.broker.adb import ADBTransport, _sh_quote
        from core.broker.transport import RemoteSystemEntry, TransportKind

        t = ADBTransport(RemoteSystemEntry(
            alias="pixel", host="localhost", port=0, user="",
            transport=TransportKind.ADB,
        ))
        t._connected = True
        t._serial = "emulator-5554"

        calls = []
        import subprocess
        orig_run = subprocess.run

        def capture_run(cmd, **kw):
            calls.append(cmd)
            return MagicMock(returncode=0, stdout="yes\n", stderr="")

        import unittest.mock
        with unittest.mock.patch("subprocess.run", capture_run):
            t.path_exists("/data/local/tmp/my file.apk")

        shell_arg = calls[0][-1]
        assert "'/data/local/tmp/my file.apk'" in shell_arg

    def test_path_with_semicolon_quoted_in_mkdir(self):
        from core.broker.adb import ADBTransport, _sh_quote
        from core.broker.transport import RemoteSystemEntry, TransportKind

        t = ADBTransport(RemoteSystemEntry(
            alias="pixel", host="localhost", port=0, user="",
            transport=TransportKind.ADB,
        ))
        t._connected = True
        t._serial = "emulator-5554"

        calls = []
        import subprocess
        import unittest.mock

        def capture_run(cmd, **kw):
            calls.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        with unittest.mock.patch("subprocess.run", capture_run):
            t.mkdir("/tmp/evil;rm -rf /")

        shell_arg = calls[0][-1]
        assert "mkdir -p '/tmp/evil;rm -rf /'" in shell_arg

    def test_env_key_injection_rejected(self):
        from core.broker.adb import _validated_env_key

        with pytest.raises(TransportError, match="invalid environment"):
            _validated_env_key("KEY=$(whoami)")

    def test_env_key_with_spaces_rejected(self):
        from core.broker.adb import _validated_env_key

        with pytest.raises(TransportError, match="invalid environment"):
            _validated_env_key("MY KEY")

    def test_valid_env_key_passes(self):
        from core.broker.adb import _validated_env_key

        assert _validated_env_key("RAPTOR_DIR") == "RAPTOR_DIR"
        assert _validated_env_key("_private") == "_private"
        assert _validated_env_key("x") == "x"

    def test_sh_quote_handles_single_quotes(self):
        from core.broker.adb import _sh_quote

        assert _sh_quote("it's") == "'it'\"'\"'s'"

    def test_sh_quote_handles_empty(self):
        from core.broker.adb import _sh_quote

        assert _sh_quote("") == "''"


class TestSSHEnvKeyValidation:
    def test_rejects_shell_injection_in_key(self):
        from core.broker.ssh import _validated_env_key

        with pytest.raises(TransportError):
            _validated_env_key("$(id)")

    def test_rejects_backtick_in_key(self):
        from core.broker.ssh import _validated_env_key

        with pytest.raises(TransportError):
            _validated_env_key("`whoami`")


class TestWinRMEnvKeyValidation:
    def test_rejects_powershell_injection(self):
        from core.broker.winrm import _validated_env_key

        with pytest.raises(TransportError):
            _validated_env_key("$(calc.exe)")


class TestSessionsPIDValidation:
    def test_valid_pid(self):
        from core.broker.sessions import _validated_pid

        assert _validated_pid("12345\n") == "12345"
        assert _validated_pid("1") == "1"

    def test_rejects_command_injection_in_pid(self):
        from core.broker.sessions import _validated_pid

        assert _validated_pid("12345; rm -rf /") is None

    def test_rejects_empty(self):
        from core.broker.sessions import _validated_pid

        assert _validated_pid("") is None
        assert _validated_pid("  \n") is None

    def test_rejects_negative(self):
        from core.broker.sessions import _validated_pid

        assert _validated_pid("-1") is None

    def test_rejects_non_numeric(self):
        from core.broker.sessions import _validated_pid

        assert _validated_pid("abc") is None
        assert _validated_pid("12.34") is None


class TestSessionsPathQuoting:
    def test_unix_cleanup_quotes_workspace(self):
        from core.broker.sessions import cleanup_workspace

        t = MagicMock()
        t.run.return_value = CommandResult(0, "", "")
        cleanup_workspace(t, "/tmp/path with spaces")
        cmd = t.run.call_args[0][0]
        assert "rm -rf '/tmp/path with spaces'" in cmd

    def test_tail_quotes_path(self):
        from core.broker.sessions import _tail_unix

        t = MagicMock()
        t.run.return_value = CommandResult(0, "line\n", "")
        _tail_unix(t, "/tmp/ws/std out.log", 20)
        cmd = t.run.call_args[0][0]
        assert "'/tmp/ws/std out.log'" in cmd


class TestCredsAskpassEscaping:
    def test_password_with_backticks_safe(self, monkeypatch):
        monkeypatch.setattr("core.broker.creds._sshpass_available", lambda: False)

        from core.broker.creds import ResolvedCredential, AuthMethod, ssh_askpass_env

        cred = ResolvedCredential(
            method=AuthMethod.PASSWORD_ENV,
            password="pass`whoami`word",
        )
        env = ssh_askpass_env(cred)
        assert "SSH_ASKPASS" in env

        script_path = env["SSH_ASKPASS"]
        content = Path(script_path).read_text()
        assert "printf" in content
        assert "pass`whoami`word" not in content or "'" in content

        import os
        os.unlink(script_path)

    def test_password_with_dollar_safe(self, monkeypatch):
        monkeypatch.setattr("core.broker.creds._sshpass_available", lambda: False)

        from core.broker.creds import ResolvedCredential, AuthMethod, ssh_askpass_env

        cred = ResolvedCredential(
            method=AuthMethod.PASSWORD_ENV,
            password="pa$$word",
        )
        env = ssh_askpass_env(cred)
        script_path = env["SSH_ASKPASS"]
        content = Path(script_path).read_text()
        assert "printf '%s\\n'" in content

        import os
        os.unlink(script_path)


class TestEngagementDeserializationHardening:
    def test_corrupt_json_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        (tmp_path / "active.json").write_text("not json at all")

        from core.broker.engage import load_engagement
        assert load_engagement() is None

    def test_wrong_type_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        (tmp_path / "active.json").write_text('"just a string"')

        from core.broker.engage import load_engagement
        assert load_engagement() is None

    def test_missing_keys_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        (tmp_path / "active.json").write_text('{"modes": []}')

        from core.broker.engage import load_engagement
        assert load_engagement() is None

    def test_modes_not_list_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.engage._ENGAGE_DIR", tmp_path)
        data = {
            "target_description": "x",
            "modes": "scan",
            "mode_assignments": [],
        }
        (tmp_path / "active.json").write_text(json.dumps(data))

        from core.broker.engage import load_engagement
        assert load_engagement() is None


class TestTaskHandleDeserializationHardening:
    def test_corrupt_json_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.tasks._TASK_STATE_DIR", tmp_path)
        (tmp_path / "bad123.json").write_text("{{{invalid")

        from core.broker.tasks import _load_task_handle
        assert _load_task_handle("bad123") is None

    def test_missing_keys_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.broker.tasks._TASK_STATE_DIR", tmp_path)
        (tmp_path / "bad456.json").write_text('{"task_id": "x"}')

        from core.broker.tasks import _load_task_handle
        assert _load_task_handle("bad456") is None


class TestInventoryDeserializationHardening:
    def test_malformed_system_entry_skipped(self, tmp_path):
        from core.broker.inventory import Inventory

        data = {
            "systems": [
                {"alias": "good", "host": "10.0.0.1", "port": 22,
                 "user": "root", "transport": "ssh"},
                {"broken": True},
            ],
            "capabilities": {},
        }
        path = tmp_path / "inv.json"
        path.write_text(json.dumps(data))

        inv = Inventory(path=path)
        assert inv.get("good") is not None
        assert len(inv.list_all()) == 1

    def test_malformed_capabilities_skipped(self, tmp_path):
        from core.broker.inventory import Inventory

        data = {
            "systems": [
                {"alias": "box", "host": "10.0.0.1", "port": 22,
                 "user": "root", "transport": "ssh"},
            ],
            "capabilities": {
                "box": {"os": "not_a_real_os", "arch": "x86_64"},
            },
        }
        path = tmp_path / "inv.json"
        path.write_text(json.dumps(data))

        inv = Inventory(path=path)
        assert inv.get("box") is not None
        assert inv.get_capabilities("box") is None


class TestWinRMPathTraversalBlocked:
    def test_dotdot_path_skipped(self):
        from core.broker.winrm import WinRMTransport
        from core.broker.transport import RemoteSystemEntry, TransportKind

        t = WinRMTransport(RemoteSystemEntry(
            alias="win", host="10.0.0.1", port=5985, user="admin",
            transport=TransportKind.WINRM,
        ))

        listing_json = json.dumps([
            {"FullName": "C:\\temp\\safe\\file.txt", "PSIsContainer": False},
            {"FullName": "C:\\..\\Windows\\System32\\cmd.exe", "PSIsContainer": False},
        ])

        download_calls = []

        def mock_run(cmd, **kw):
            if "Get-ChildItem" in cmd:
                return CommandResult(0, listing_json, "")
            return CommandResult(0, "", "")

        def mock_download_file(remote, local):
            download_calls.append(remote)

        t.run = mock_run
        t._download_file = mock_download_file

        import tempfile
        with tempfile.TemporaryDirectory() as local_dir:
            t._download_dir("C:\\temp\\safe", local_dir)

        traversal_paths = [p for p in download_calls if ".." in p]
        assert len(traversal_paths) == 0
        safe_paths = [p for p in download_calls if "file.txt" in p]
        assert len(safe_paths) == 1
