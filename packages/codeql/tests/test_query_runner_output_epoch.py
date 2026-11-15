"""Current analysis attempts cannot inherit an earlier output artifact."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.sandbox
from packages.codeql.query_runner import QueryRunner


PRIOR = json.dumps({"runs": [{"results": [{"ruleId": "owned-prior"}]}]})
CURRENT = json.dumps({"runs": [{"results": []}]})


@pytest.fixture
def owned(tmp_path, monkeypatch):
    cli = tmp_path / "owned-cli"
    cli.write_text("Owned inert path; never executed.\n")
    runner = QueryRunner(codeql_cli=str(cli))
    monkeypatch.delenv("CODEQL_QUERIES", raising=False)
    monkeypatch.setenv("RAPTOR_CODEQL_OFFLINE", "1")
    # Execution is an owned callback; no host grants or cache writes needed.
    monkeypatch.setattr(runner, "_analysis_scope", lambda *args: {})
    calls = []

    def invoke(route, execute):
        monkeypatch.setattr(core.sandbox, "run", execute)
        if route == "suite":
            return runner.run_suite(tmp_path / "db", "python", tmp_path)
        if route == "custom":
            return runner._run_compatible_custom_queries(
                tmp_path / "db", tmp_path / "queries", tmp_path, "python", query_args=["owned-query"])
        return runner._run_selected_local_pack(
            "python", tmp_path / "db", tmp_path / "pack", tmp_path,
            suite_name="owned", sarif_name="codeql_python_local.sarif", label="owned",
            skip_install=True, query_args=["owned-query"])

    return SimpleNamespace(root=tmp_path, runner=runner, invoke=invoke, calls=calls)


def output_for(owned, route):
    suffix = {"suite": "", "custom": "_custom", "local": "_local"}[route]
    return owned.root / f"codeql_python{suffix}.sarif"


def output_argument(command):
    return Path(next(str(arg).split("=", 1)[1] for arg in command if str(arg).startswith("--output=")))


@pytest.mark.parametrize("route", ["suite", "custom", "local"])
@pytest.mark.parametrize("mode", ["missing", "malformed", "current"])
def test_current_attempt_cannot_inherit_previous_sarif(owned, route, mode):
    final = output_for(owned, route)
    final.write_text(PRIOR)

    def execute(command, **kwargs):
        owned.calls.append(command)
        output = output_argument(command)
        assert output == final and not output.exists()
        if mode != "missing":
            output.write_text(CURRENT if mode == "current" else "{owned malformed")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = owned.invoke(route, execute)
    assert result.success is (mode == "current")
    assert result.findings_count == 0
    assert result.sarif_path == (final if mode == "current" else None)
    archives = list(owned.root.glob(".codeql-previous-*/*.sarif"))
    assert len(archives) == 1 and archives[0].read_text() == PRIOR
    assert len(owned.calls) == 1
    if mode == "missing":
        assert not final.exists()
    else:
        assert final.read_text() == (CURRENT if mode == "current" else "{owned malformed")


def test_archive_refusal_fails_before_execution(owned, monkeypatch):
    final = output_for(owned, "local")
    final.write_text(PRIOR)
    original = Path.replace

    def refuse(source, destination):
        if source == final:
            raise PermissionError("owned archive refusal")
        return original(source, destination)

    monkeypatch.setattr(Path, "replace", refuse)

    def forbidden(*args, **kwargs):
        pytest.fail("archive refusal must stop before execution")

    result = owned.invoke("local", forbidden)
    assert not result.success and result.sarif_path is None
    assert any("owned archive refusal" in error for error in result.errors)
    assert final.read_text() == PRIOR
    assert not list(owned.root.glob(".codeql-previous-*"))


def test_directory_output_is_not_relocated(owned):
    final = output_for(owned, "local")
    final.mkdir()
    (final / "owned.txt").write_text("preserve")

    def forbidden(*args, **kwargs):
        pytest.fail("directory output must refuse before execution")

    result = owned.invoke("local", forbidden)
    assert not result.success and (final / "owned.txt").read_text() == "preserve"
    assert not list(owned.root.glob(".codeql-previous-*"))


def test_failed_attempt_keeps_current_partial_diagnostics(owned):
    final = output_for(owned, "local")
    final.write_text(PRIOR)

    def execute(command, **kwargs):
        output_argument(command).write_text("owned partial diagnostic")
        return subprocess.CompletedProcess(command, 2, "", "owned failed analysis")

    result = owned.invoke("local", execute)
    assert not result.success and result.sarif_path is None
    assert final.read_text() == "owned partial diagnostic"
    assert next(owned.root.glob(".codeql-previous-*/*.sarif")).read_text() == PRIOR


def test_analysis_retry_cannot_inherit_failed_attempt_output(owned, monkeypatch):
    import packages.codeql.codeql_proxy_hosts as hosts

    monkeypatch.setenv("RAPTOR_CODEQL_OFFLINE", "0")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: owned.root / "owned-home"))
    monkeypatch.setattr(hosts, "proxy_hosts_for_codeql", lambda *args: [])
    monkeypatch.setattr(owned.runner, "_filesystem_scope", lambda *args, **kwargs: {})
    final = output_for(owned, "suite")
    final.write_text(PRIOR)
    analyses, downloads = [], []

    def execute(command, **kwargs):
        if "download" in command:
            downloads.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")
        analyses.append(command)
        assert not output_argument(command).exists()
        if len(analyses) == 1:
            output_argument(command).write_text(CURRENT)
            return subprocess.CompletedProcess(command, 2, "", "Query pack codeql/python-queries cannot be found")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = owned.invoke("suite", execute)
    assert not result.success and result.sarif_path is None
    assert len(analyses) == 2 and len(downloads) == 1
    assert not final.exists()
    assert sorted(path.read_text() for path in owned.root.glob(".codeql-previous-*/*.sarif")) == sorted([PRIOR, CURRENT])


def test_sandbox_setup_failure_still_propagates(owned):
    def execute(*args, **kwargs):
        raise core.sandbox.SandboxSetupError("owned setup refusal")

    with pytest.raises(core.sandbox.SandboxSetupError, match="owned setup refusal"):
        owned.invoke("local", execute)
