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
        seen["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(returncode=0)

    import core.sandbox
    monkeypatch.setattr(core.sandbox, "run_trusted", fake_run)
    assert toolchain.has_libasan() is True
    assert "-fsanitize=address" in seen["argv"]
    # Trusted-probe doctrine: neutral cwd, never the caller's (which
    # may sit inside a scanned repo).
    import os as _os
    assert seen["cwd"] == _os.sep


def test_probe_failure_means_false(monkeypatch):
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda cmd: "/usr/bin/gcc",
    )
    import core.sandbox
    monkeypatch.setattr(
        core.sandbox, "run_trusted",
        lambda *a, **k: SimpleNamespace(returncode=1),
    )
    assert toolchain.has_libasan() is False


def test_probe_timeout_fails_closed(monkeypatch):
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda cmd: "/usr/bin/gcc",
    )

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gcc", timeout=10)

    import core.sandbox
    monkeypatch.setattr(core.sandbox, "run_trusted", fake_run)
    assert toolchain.has_libasan() is False
