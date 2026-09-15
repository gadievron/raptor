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


class TestQueryRunnerCliResolution:
    """QueryRunner must resolve the CLI through the same ladder as
    is_available / DatabaseManager (explicit arg > CODEQL_CLI env >
    PATH). It used to skip the env var: on hosts where codeql is
    reachable only via CODEQL_CLI, the availability probe said True
    and construction then raised — CodeQLAgent died after database
    creation succeeded, and gate-then-construct callers silently
    degraded to a disabled lane."""

    def test_constructs_from_env_only(self, monkeypatch, tmp_path):
        from packages.codeql.query_runner import QueryRunner

        fake = tmp_path / "codeql"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        monkeypatch.setenv("CODEQL_CLI", str(fake))
        monkeypatch.setattr("shutil.which", lambda _x: None)
        runner = QueryRunner()
        assert runner.codeql_cli == str(fake.resolve())

    def test_explicit_arg_beats_env(self, monkeypatch, tmp_path):
        from packages.codeql.query_runner import QueryRunner

        explicit = tmp_path / "explicit-codeql"
        explicit.write_text("#!/bin/sh\n", encoding="utf-8")
        explicit.chmod(0o755)
        monkeypatch.setenv("CODEQL_CLI", str(tmp_path / "other"))
        runner = QueryRunner(codeql_cli=str(explicit))
        assert runner.codeql_cli == str(explicit.resolve())

    def test_raises_with_actionable_message_when_absent(
        self, monkeypatch,
    ):
        import pytest

        from packages.codeql.query_runner import QueryRunner

        monkeypatch.delenv("CODEQL_CLI", raising=False)
        monkeypatch.setattr("shutil.which", lambda _x: None)
        with pytest.raises(RuntimeError, match="CODEQL_CLI"):
            QueryRunner()

    def test_agreement_with_availability_probe(self, monkeypatch, tmp_path):
        """The construction gate and the availability probe must share
        one verdict: probe True implies construction succeeds."""
        from packages import codeql as pkg
        from packages.codeql.query_runner import QueryRunner

        fake = tmp_path / "codeql"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        monkeypatch.setenv("CODEQL_CLI", str(fake))
        monkeypatch.setattr("shutil.which", lambda _x: None)
        assert pkg.is_available() is True
        QueryRunner()  # must not raise
