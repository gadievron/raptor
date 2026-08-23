"""Shared fixtures for the scorecard test suite.

The integrity layer (``core.llm.scorecard.integrity``) mints its
HMAC key under ``$XDG_DATA_HOME/raptor/scorecard-mac.key``. Point
XDG_DATA_HOME at a per-test tmp dir so the suite never touches (or
depends on) the developer's real key, and every test starts from a
fresh-key state.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_scorecard_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
