"""Version/availability probes run with a sanitised environment.

Trusted-tool probes carry no target input, but a bare subprocess.run
inherits the operator shell's LD_PRELOAD / PYTHONPATH / NODE_OPTIONS /
JVM agent vars — the consistency idiom the codeql version probe
documents (database_manager). These tests pin the sca resolver
probes; the ghidra / radare2 / frida probe twins are pinned in their
own packages' suites.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace


def _capture_env(monkeypatch):
    seen: dict = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        return SimpleNamespace(returncode=0, stdout="1.22.19\n",
                               stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("LD_PRELOAD", "/evil/lib.so")
    monkeypatch.setenv("PYTHONPATH", "/evil")
    monkeypatch.setenv("NODE_OPTIONS", "--require /evil/agent.js")
    return seen


def test_check_tool_uses_sanitised_env(monkeypatch):
    import packages.sca.resolvers as resolvers

    seen = _capture_env(monkeypatch)
    monkeypatch.setattr(resolvers, "_CHECK_TOOL_CACHE", {})
    assert resolvers._check_tool(["sometool", "--version"]) is True
    env = seen["env"]
    assert env is not None, "probe ran with inherited environment"
    for hostile in ("LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS"):
        assert hostile not in env


def test_yarn_version_probe_uses_sanitised_env(monkeypatch):
    from packages.sca.resolvers import yarn

    seen = _capture_env(monkeypatch)
    assert yarn._detect_major_version() == 1
    env = seen["env"]
    assert env is not None, "probe ran with inherited environment"
    for hostile in ("LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS"):
        assert hostile not in env
