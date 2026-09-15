"""The radare2 capability probe runs with a sanitised environment
(the codeql version-probe idiom): r2 honours R2_* / LD_* env from the
operator shell."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace


def test_r2ghidra_probe_uses_sanitised_env(monkeypatch):
    from packages.binary_analysis import radare2_understand as r2u

    seen: dict = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        return SimpleNamespace(returncode=0, stdout="ghidra\n",
                               stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(r2u.shutil, "which", lambda _n: "/usr/bin/r2")
    monkeypatch.setenv("LD_PRELOAD", "/evil/lib.so")

    caps = r2u.probe_capability()

    if seen.get("env") is None and not caps.get("has_r2pipe"):
        # r2pipe absent on this host: the probe never ran — nothing
        # to assert (hermetic skip shape).
        import pytest
        pytest.skip("r2pipe not installed; probe not reached")
    env = seen["env"]
    assert env is not None, "probe ran with inherited environment"
    assert "LD_PRELOAD" not in env
