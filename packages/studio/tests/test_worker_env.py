"""Tests for the worker's job-subprocess environment sanitisation."""

from __future__ import annotations

from packages.studio.services.worker import _PRESERVED_HOST_ENV, _job_env


def test_dangerous_host_vars_do_not_reach_jobs(monkeypatch):
    for name, value in (
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp/evil"),
        ("BASH_ENV", "/tmp/evil.sh"),
        ("PAGER", "sh -c id"),
        ("EDITOR", "sh -c id"),
        ("IFS", ";"),
        ("PYTHONSTARTUP", "/tmp/evil.py"),
        ("NODE_OPTIONS", "--require /tmp/evil.js"),
    ):
        monkeypatch.setenv(name, value)
    env = _job_env()
    for name in (
        "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "PAGER",
        "EDITOR", "IFS", "PYTHONSTARTUP", "NODE_OPTIONS",
    ):
        assert name not in env, name


def test_provider_config_preserved_deliberately(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-a")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/creds.json")
    monkeypatch.setenv("RAPTOR_MAX_COST", "5.0")
    env = _job_env()
    assert env["ANTHROPIC_API_KEY"] == "test-key-a"
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == "/tmp/creds.json"
    assert env["RAPTOR_MAX_COST"] == "5.0"


def test_unset_preserved_vars_stay_unset(monkeypatch):
    for name in _PRESERVED_HOST_ENV:
        monkeypatch.delenv(name, raising=False)
    env = _job_env()
    for name in _PRESERVED_HOST_ENV:
        assert name not in env, name


def test_raptor_path_config_preserved(monkeypatch):
    monkeypatch.setenv("RAPTOR_PROJECTS_DIR", "/tmp/projects")
    monkeypatch.setenv("RAPTOR_MODELS_CONFIG", "/tmp/models.json")
    env = _job_env()
    assert env["RAPTOR_PROJECTS_DIR"] == "/tmp/projects"
    assert env["RAPTOR_MODELS_CONFIG"] == "/tmp/models.json"


def test_python_unbuffered_always_set(monkeypatch):
    monkeypatch.delenv("PYTHONUNBUFFERED", raising=False)
    assert _job_env()["PYTHONUNBUFFERED"] == "1"


def test_path_and_home_survive():
    # Sanity: the baseline still carries what subprocesses need to run.
    env = _job_env()
    assert "PATH" in env
    assert "HOME" in env


def test_proxy_config_preserved_for_top_level_invocations(monkeypatch):
    # A studio job is the equivalent of an operator shell launch; egress
    # proxy config must survive or provider traffic breaks on proxied hosts.
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    env = _job_env()
    assert env["HTTPS_PROXY"] == "http://proxy.example:3128"
    assert env["NO_PROXY"] == "localhost,127.0.0.1"


def test_loader_and_credential_helper_vars_stripped(monkeypatch):
    # Gaps of the blocklist-era get_safe_env: PYTHONPATH injects into the
    # job's own python process; askpass/ssh hooks are exec'd by git/ssh.
    for name in (
        "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE",
        "GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND",
    ):
        monkeypatch.setenv(name, "/tmp/evil")
    env = _job_env()
    for name in (
        "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE",
        "GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND",
    ):
        assert name not in env, name


def test_codeql_and_sage_config_preserved(monkeypatch):
    monkeypatch.setenv("CODEQL_CLI", "/opt/codeql/codeql")
    monkeypatch.setenv("CODEQL_QUERIES", "/opt/codeql-queries")
    monkeypatch.setenv("SAGE_URL", "http://localhost:8090")
    monkeypatch.setenv("SAGE_ENABLED", "true")
    env = _job_env()
    assert env["CODEQL_CLI"] == "/opt/codeql/codeql"
    assert env["CODEQL_QUERIES"] == "/opt/codeql-queries"
    assert env["SAGE_URL"] == "http://localhost:8090"
    assert env["SAGE_ENABLED"] == "true"
