"""Shared fixtures for core/run tests.

The estimator reads the scorecard sidecar, whose integrity layer
(``core.llm.scorecard.integrity``) keys off
``$XDG_DATA_HOME/raptor/scorecard-mac.key``. Point XDG_DATA_HOME at a
per-test tmp dir so fixture stamping never touches the developer's
real key.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_scorecard_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
