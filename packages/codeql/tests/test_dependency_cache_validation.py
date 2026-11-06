"""Skipping dependency installation requires complete, matching cached metadata."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from core.config import RaptorConfig
from packages.codeql import query_runner


@pytest.fixture
def cached(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cache = home / ".codeql" / "packages"
    cache.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    pack = tmp_path / "queries"
    pack.mkdir()
    (pack / "query.ql").write_text("select 1\n")
    (pack / "qlpack.yml").write_text("name: raptor/test-queries\nversion: 0.0.1\n")
    lock = pack / "codeql-pack.lock.yml"
    lock.write_text("dependencies:\n  codeql/python-all:\n    version: 7.1.0\n")
    installed = cache / "codeql" / "python-all" / "7.1.0"
    installed.mkdir(parents=True)
    (installed / "qlpack.yml").write_text("name: codeql/python-all\nversion: 7.1.0\n")
    return pack, lock, installed


@pytest.mark.parametrize("legacy", [False, True])
def test_matching_cache_is_warm_and_missing_transitive_dependency_is_not(cached, legacy):
    pack, lock, installed = cached
    if legacy:
        (installed / "qlpack.yml").rename(installed / "codeql-pack.yml")
    assert query_runner._iris_pack_deps_already_resolved(pack)
    lock.write_text(lock.read_text() + "  codeql/util:\n    version: 2.0.0\n")
    assert not query_runner._iris_pack_deps_already_resolved(pack)


@pytest.mark.parametrize("content", [
    "- not-a-mapping\n", "true\n", "", "dependencies: []\n", "dependencies: text\n",
    "dependencies:\n  codeql/python-all: []\n",
    "dependencies:\n  codeql/python-all: true\n",
    "dependencies:\n  codeql/python-all: null\n",
    "dependencies:\n  codeql/python-all:\n    version: [7, 1, 0]\n",
    "dependencies:\n  codeql/python-all:\n    version: true\n",
    "dependencies:\n  codeql/python-all:\n    version: null\n",
    "dependencies: [unterminated\n",
])
def test_malformed_lock_returns_cold_instead_of_raising(cached, content):
    pack, lock, _ = cached
    lock.write_text(content)
    assert not query_runner._iris_pack_deps_already_resolved(pack)


@pytest.mark.parametrize("content", [
    None, "- not-a-mapping\n", "name: codeql/other\nversion: 7.1.0\n",
    "name: codeql/python-all\nversion: 7.0.0\n", "name: codeql/python-all\n",
    "name: codeql/python-all\nversion: [7, 1, 0]\n",
])
def test_empty_or_mismatched_cache_is_not_warm(cached, content):
    pack, _, installed = cached
    manifest = installed / "qlpack.yml"
    if content is None:
        manifest.unlink()
    else:
        manifest.write_text(content)
    assert not query_runner._iris_pack_deps_already_resolved(pack)


@pytest.mark.parametrize("field,value", [
    ("name", "../python-all"), ("name", "/codeql/python-all"),
    ("name", "codeql/../python-all"), ("name", "codeql\\python-all"),
    ("version", ".."), ("version", "../7.1.0"), ("version", "/tmp"),
])
def test_path_shaped_dependency_values_never_count_as_warm(cached, field, value):
    pack, lock, _ = cached
    name = value if field == "name" else "codeql/python-all"
    version = value if field == "version" else "7.1.0"
    lock.write_text(yaml.safe_dump({"dependencies": {name: {"version": version}}}))
    assert not query_runner._iris_pack_deps_already_resolved(pack)


@pytest.mark.parametrize("which", ["lock", "manifest"])
def test_oversized_or_undecodable_metadata_is_cold(cached, which):
    pack, lock, installed = cached
    path = lock if which == "lock" else installed / "qlpack.yml"
    original = path.read_bytes()
    path.write_bytes(original + b"#" * (1024 * 1024))
    assert not query_runner._iris_pack_deps_already_resolved(pack)
    path.write_bytes(b"\xff")
    assert not query_runner._iris_pack_deps_already_resolved(pack)


def test_cache_escape_via_symlink_is_not_a_warm_dependency(cached, tmp_path):
    pack, _, installed = cached
    outside = tmp_path / "outside"
    installed.rename(outside)
    installed.symlink_to(outside, target_is_directory=True)
    assert not query_runner._iris_pack_deps_already_resolved(pack)


@pytest.mark.parametrize("condition", ["warm", "empty", "malformed"])
def test_local_analysis_installs_only_when_cache_validation_fails(cached, tmp_path, monkeypatch, condition):
    pack, lock, installed = cached
    if condition == "empty":
        (installed / "qlpack.yml").unlink()
    elif condition == "malformed":
        lock.write_text("- invalid lock shape\n")
    runner = query_runner.QueryRunner(codeql_cli="/usr/bin/true")
    monkeypatch.setattr(runner, "_local_dependency_roots", lambda *args: [])
    monkeypatch.setattr(query_runner, "temporary_command", lambda command, **kwargs: command)
    monkeypatch.setattr("packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql", lambda *args: ["ghcr.io"])
    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", False)
    out = tmp_path / "out"
    out.mkdir()
    database = tmp_path / "database"
    database.mkdir()
    calls = []

    def dispatch(command, **kwargs):
        calls.append(command)
        for arg in command:
            if arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(json.dumps({"runs": [{"results": []}]}))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("core.sandbox.run", dispatch)
    result = runner.run_local_pack("python", database, pack, out,
                                   suite_name="test", sarif_name="out.sarif", label="test")
    assert result.success
    assert sum("install" in command for command in calls) == (condition != "warm")
    assert sum("analyze" in command for command in calls) == 1


def test_operator_relocated_cache_root_remains_warm(cached, tmp_path):
    pack, _, installed = cached
    cache = installed.parents[2]
    relocated = tmp_path / "relocated-cache"
    cache.rename(relocated)
    cache.symlink_to(relocated, target_is_directory=True)
    assert query_runner._iris_pack_deps_already_resolved(pack)
