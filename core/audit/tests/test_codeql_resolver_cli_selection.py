"""Resolver discovery uses the selected CLI without invoking a real tool."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.codeql_query_resolver as resolver
from core.config import RaptorConfig


@pytest.mark.parametrize("override,expected", [
    ("/owned/selected codeql", "/owned/selected codeql"),
    (None, "codeql"), ("", "codeql"),
])
def test_resolver_pack_discovery_uses_selected_cli(override, expected, monkeypatch):
    if override is None:
        monkeypatch.delenv("CODEQL_CLI", raising=False)
    else:
        monkeypatch.setenv("CODEQL_CLI", override)
    calls = []

    def owned_run(argv, **options):
        calls.append((argv, options))
        return SimpleNamespace(stdout='{"codeql/cpp-queries": ["/owned/pack"]}')

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=owned_run))
    monkeypatch.setattr(RaptorConfig, "get_safe_env", staticmethod(lambda: {}))
    assert resolver._cli_qlpack_roots("codeql/cpp-queries") == [Path("/owned/pack")]
    assert calls[0][0] == [expected, "resolve", "qlpacks", "--format=json"]
    assert calls[0][1] == {
        "capture_output": True, "text": True,
        "timeout": resolver._RESOLVE_QLPACKS_TIMEOUT_S, "env": {}, "cwd": "/",
    }


def test_resolver_cli_discovery_failure_preserves_empty_result(monkeypatch):
    monkeypatch.setenv("CODEQL_CLI", "/owned/selected-codeql")

    def owned_failure(*args, **kwargs):
        raise OSError("owned callback refusal")

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=owned_failure))
    monkeypatch.setattr(RaptorConfig, "get_safe_env", staticmethod(lambda: {}))
    assert resolver._cli_qlpack_roots("codeql/cpp-queries") == []
