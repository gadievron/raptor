"""The Ghidra availability probe runs with a sanitised environment
(the codeql version-probe idiom): analyzeHeadless is a JVM launcher
and honours JAVA_TOOL_OPTIONS / _JAVA_OPTIONS from the shell, which
can attach a Java agent at startup."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace


def test_version_probe_uses_sanitised_env(monkeypatch):
    from packages.ghidra import detect

    seen: dict = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        return SimpleNamespace(returncode=0, stdout="",
                               stderr="Ghidra 11.1.2 banner\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        detect.shutil, "which", lambda _n: "/opt/ghidra/analyzeHeadless",
    )
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:/evil/a.jar")
    monkeypatch.setenv("LD_PRELOAD", "/evil/lib.so")

    detect.get_ghidra_version()

    env = seen["env"]
    assert env is not None, "probe ran with inherited environment"
    assert "JAVA_TOOL_OPTIONS" not in env
    assert "LD_PRELOAD" not in env
