"""Shared fixtures for packages.semgrep tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path,
                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare runs of this package write into the developer's real home.

    The live scope tests run real semgrep (``unsandboxed=True``),
    which unconditionally appends to ``~/.semgrep/semgrep.log`` and
    reads/writes ``~/.semgrep/settings.yml`` — keyed off HOME
    directly. The sandboxed-runner tests additionally cache
    calibration profiles under ``~/.cache/raptor/sandbox-profiles/``
    (``core.sandbox.calibrate``, ``Path.home()``-keyed). Point HOME
    at a per-test tmp dir so bare runs never touch real user state.
    """
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
