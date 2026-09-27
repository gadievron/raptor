"""Shared fixtures for core/inventory tests.

The checklist writer chokepoint stamps every saved frame, whose
integrity layer (``core.inventory.checklist_frame_mac``) keys off
``$XDG_DATA_HOME/raptor/checklist-frame-mac.key``. Point XDG_DATA_HOME
at a per-test tmp dir so save/read round-trips never mint or touch the
developer's real key.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_frame_key(tmp_path: Path,
                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
