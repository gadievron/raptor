"""Shared fixtures for core/inventory tests.

The checklist writer chokepoint stamps every saved frame, whose
integrity layer (``core.inventory.checklist_frame_mac``) keys off
``$XDG_DATA_HOME/raptor/checklist-frame-mac.key``. Point XDG_DATA_HOME
at a per-test tmp dir so save/read round-trips never mint or touch the
developer's real key.

XDG_CACHE_HOME is pinned for the same reason on a different store:
every ``build_inventory`` call persists a reachability index via
``core.analysis._reach_cache.save_index``, and one bare run of this
suite otherwise mints enough entries in the developer's real
``~/.cache/raptor/reachability/`` to evict live operator cache
entries (the store keeps only ``_MAX_CACHE_ENTRIES``, oldest evicted
first). The pin is effective because ``_reach_cache._cache_dir()``
re-reads the env at call time.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home_stores(tmp_path: Path,
                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
