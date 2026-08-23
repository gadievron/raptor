"""Contract tests for ``core.build.toolchain.has_libasan``.

Hermetic — the gcc probe is stubbed, so these pass on hosts and CI
images without a compiler.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import core.build.toolchain as toolchain


def test_no_gcc_means_false(monkeypatch):
    monkeypatch.setattr(toolchain.shutil, "which", lambda cmd: None)
    assert toolchain.has_libasan() is False


def test_probe_success_means_true(monkeypatch):
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda cmd: "/usr/bin/gcc",
    )
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(toolchain.subprocess, "run", fake_run)
    assert toolchain.has_libasan() is True
    assert "-fsanitize=address" in seen["argv"]


def test_probe_failure_means_false(monkeypatch):
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda cmd: "/usr/bin/gcc",
    )
    monkeypatch.setattr(
        toolchain.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1),
    )
    assert toolchain.has_libasan() is False


def test_probe_timeout_fails_closed(monkeypatch):
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda cmd: "/usr/bin/gcc",
    )

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gcc", timeout=10)

    monkeypatch.setattr(toolchain.subprocess, "run", fake_run)
    assert toolchain.has_libasan() is False
