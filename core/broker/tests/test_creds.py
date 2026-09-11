"""Tests for the credential resolution system."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from core.broker.creds import (
    AuthMethod,
    ResolvedCredential,
    _env_key,
    _env_password,
    _env_key_passphrase,
    resolve_ssh_credential,
    sshpass_prefix,
    sshpass_env,
)


class TestEnvKeyNormalisation:
    def test_simple_alias(self):
        assert _env_key("linux") == "LINUX"

    def test_hyphenated_alias(self):
        assert _env_key("ci-linux") == "CI_LINUX"

    def test_spaced_alias(self):
        assert _env_key("my box") == "MY_BOX"

    def test_mixed(self):
        assert _env_key("ci-linux-arm64") == "CI_LINUX_ARM64"


class TestEnvPassword:
    def test_specific_env_var(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_PASS_CI_LINUX", "secret123")
        assert _env_password("ci-linux") == "secret123"

    def test_generic_env_var(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_PASS", "fallback")
        assert _env_password("ci-linux") == "fallback"

    def test_specific_wins_over_generic(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_PASS_CI_LINUX", "specific")
        monkeypatch.setenv("RAPTOR_BROKER_PASS", "generic")
        assert _env_password("ci-linux") == "specific"

    def test_no_env_var(self):
        os.environ.pop("RAPTOR_BROKER_PASS_GHOST", None)
        os.environ.pop("RAPTOR_BROKER_PASS", None)
        assert _env_password("ghost") is None


class TestEnvKeyPassphrase:
    def test_specific(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_KEYPASS_CI_LINUX", "keypass")
        assert _env_key_passphrase("ci-linux") == "keypass"

    def test_generic(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_KEYPASS", "generic-keypass")
        assert _env_key_passphrase("ci-linux") == "generic-keypass"


class TestResolveSSHCredential:
    @patch("core.broker.creds._ssh_agent_available", return_value=True)
    def test_prefers_agent(self, mock_agent):
        cred = resolve_ssh_credential("test")
        assert cred.method == AuthMethod.SSH_AGENT

    @patch("core.broker.creds._ssh_agent_available", return_value=False)
    def test_falls_back_to_env_password(self, mock_agent, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_PASS_TEST", "pw123")
        cred = resolve_ssh_credential("test")
        assert cred.method == AuthMethod.PASSWORD_ENV
        assert cred.password == "pw123"

    @patch("core.broker.creds._ssh_agent_available", return_value=False)
    @patch("core.broker.creds._keyring_password", return_value="keyring-pw")
    def test_falls_back_to_keyring(self, mock_kr, mock_agent):
        os.environ.pop("RAPTOR_BROKER_PASS_TEST", None)
        os.environ.pop("RAPTOR_BROKER_PASS", None)
        cred = resolve_ssh_credential("test")
        assert cred.method == AuthMethod.PASSWORD_KEYRING
        assert cred.password == "keyring-pw"

    @patch("core.broker.creds._ssh_agent_available", return_value=True)
    def test_key_passphrase_skipped_with_agent(self, mock_agent):
        cred = resolve_ssh_credential("test", has_key_file=True)
        assert cred.key_passphrase is None

    @patch("core.broker.creds._ssh_agent_available", return_value=False)
    def test_key_passphrase_from_env(self, mock_agent, monkeypatch):
        monkeypatch.setenv("RAPTOR_BROKER_PASS_TEST", "pw")
        monkeypatch.setenv("RAPTOR_BROKER_KEYPASS_TEST", "kp123")
        cred = resolve_ssh_credential("test", has_key_file=True)
        assert cred.key_passphrase == "kp123"


class TestSshpassHelpers:
    def test_prefix_with_password_and_sshpass(self):
        cred = ResolvedCredential(method=AuthMethod.PASSWORD_ENV, password="pw")
        with patch("core.broker.creds._sshpass_available", return_value=True):
            assert sshpass_prefix(cred) == ["sshpass", "-e"]

    def test_prefix_without_sshpass(self):
        cred = ResolvedCredential(method=AuthMethod.PASSWORD_ENV, password="pw")
        with patch("core.broker.creds._sshpass_available", return_value=False):
            assert sshpass_prefix(cred) == []

    def test_prefix_without_password(self):
        cred = ResolvedCredential(method=AuthMethod.SSH_AGENT)
        assert sshpass_prefix(cred) == []

    def test_env_with_password_and_sshpass(self):
        cred = ResolvedCredential(method=AuthMethod.PASSWORD_ENV, password="secret")
        with patch("core.broker.creds._sshpass_available", return_value=True):
            env = sshpass_env(cred)
            assert env == {"SSHPASS": "secret"}

    def test_env_without_sshpass(self):
        cred = ResolvedCredential(method=AuthMethod.PASSWORD_ENV, password="secret")
        with patch("core.broker.creds._sshpass_available", return_value=False):
            env = sshpass_env(cred)
            assert env == {}
