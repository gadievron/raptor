"""Shared fixtures for core/engagement tests.

The engagement writers stamp checklist frames
(``core.inventory.checklist_frame_mac``), keyed off
``$XDG_DATA_HOME/raptor/checklist-frame-mac.key``. Point XDG_DATA_HOME
at a per-test tmp dir so ledger-slot and chain-stage round-trips never
mint or touch the developer's real key (the same discipline as
``core/inventory/tests/conftest.py``), and reset the frame module's
warn-once registries so demotion-warning assertions cannot bleed
between tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory import checklist_frame_mac as _frame_mac


@pytest.fixture(autouse=True)
def _isolated_frame_key(tmp_path: Path,
                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    for name in ("_warned_unstamped", "_warned_relocated",
                 "_warned_key_paths", "_warned_absent_key"):
        monkeypatch.setattr(_frame_mac, name, set())
