"""Tests for packages.codeql.is_available and version."""

from __future__ import annotations

from packages import codeql


class TestIsAvailable:
    def test_returns_bool(self):
        result = codeql.is_available()
        assert isinstance(result, bool)

    def test_false_when_not_on_path(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        monkeypatch.delenv("CODEQL_CLI", raising=False)
        assert codeql.is_available() is False

    def test_true_via_env(self, monkeypatch, tmp_path):
        fake = tmp_path / "codeql"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        monkeypatch.setenv("CODEQL_CLI", str(fake))
        assert codeql.is_available() is True


class TestVersion:
    def test_returns_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        monkeypatch.delenv("CODEQL_CLI", raising=False)
        assert codeql.version() is None
