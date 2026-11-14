"""Explicit launchers own their availability and scope-capability answers."""

import json
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from packages.semgrep import runner


@pytest.fixture(autouse=True)
def inert_diagnostics(monkeypatch):
    # Compatibility notices must not turn a capture-runner test into a probe.
    monkeypatch.setattr(runner, "version", lambda: None)
    monkeypatch.setattr(runner, "_scope_upgrade_warned", False)


def test_override_dispatch_does_not_require_default_launcher(tmp_path, monkeypatch):
    selected = tmp_path / "selected-semgrep"
    selected.write_text("inert launcher marker\n")
    selected.chmod(0o755)
    target = tmp_path / "owned.py"
    target.write_text("# inert source\n")
    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: (
        str(selected) if name == str(selected) else None))
    checked = []
    monkeypatch.setattr(runner, "scope_isolation_available", lambda binary=None: (
        checked.append(binary) or False))
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "version": "2.1.0", "runs": []}), stderr="")

    results = runner.run_rules(
        target, [("owned", "p/owned")], semgrep_bin=str(selected),
        subprocess_runner=capture, env={},
    )
    assert len(results) == 1 and results[0].returncode == 0
    assert checked == [str(selected)]
    assert commands[0][0] == str(selected)
    assert "--x-ignore-semgrepignore-files" not in commands[0]


def test_scope_cache_and_probe_follow_explicit_launcher(tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for path in (first, second):
        path.write_text("inert marker\n")
        path.chmod(0o755)
    monkeypatch.setattr(runner.shutil, "which", lambda name: str(name))
    probes = []

    def answer(binary=None):
        probes.append(binary)
        return SimpleNamespace(path=binary, returncode=0,
                               stdout="1.79.0" if binary == str(first) else "2.1.0",
                               stderr="")

    monkeypatch.setattr(runner, "_version_probe", answer)
    runner._reset_scope_probe_cache()
    try:
        assert not runner.scope_isolation_available(str(first))
        assert not runner.scope_isolation_available(str(first))
        assert runner.scope_isolation_available(str(second))
        assert probes == [str(first), str(second)]
    finally:
        runner._reset_scope_probe_cache()


def test_version_probe_routes_online_and_offline_to_override(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    selected.write_text("inert marker\n")
    selected.chmod(0o755)
    seen = []
    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", False)
    monkeypatch.setattr(runner, "probe", lambda name, **kwargs: seen.append(name))
    runner._version_probe(str(selected))
    assert seen == [str(selected)]

    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", True)
    monkeypatch.setattr(runner.shutil, "which", lambda name: (
        str(selected) if name == str(selected) else None))
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="2.1.0", stderr="")

    monkeypatch.setattr(runner, "_default_sandbox_runner", lambda *a: capture)
    answer = runner._version_probe(str(selected))
    assert answer.path == str(selected)
    assert commands[0][0] == str(selected)


def test_empty_override_keeps_default_launcher(tmp_path, monkeypatch):
    default = tmp_path / "default-semgrep"
    default.write_text("inert marker\n")
    default.chmod(0o755)
    target = tmp_path / "owned.py"
    target.write_text("# inert source\n")
    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: (
        str(default) if name == "semgrep" else None))
    checked = []
    monkeypatch.setattr(runner, "scope_isolation_available", lambda binary=None: (
        checked.append(binary) or False))
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='{"runs": []}', stderr="")

    result = runner.run_rule(target, "p/owned", semgrep_bin="",
                             subprocess_runner=capture, env={})
    assert result.returncode == 0
    assert checked == [None]
    assert commands[0][0] == str(default)
