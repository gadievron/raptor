"""Shared fixtures for core/orchestration tests.

Suites here save and read checklists through the gated accessors
(``core.inventory`` ``save_checklist``/``read_checklist``, plus the
``build_inventory`` calls inside workdir-style fixtures), whose
integrity layer (``core.inventory.checklist_frame_mac``) keys off
``$XDG_DATA_HOME/raptor/checklist-frame-mac.key``; sibling integrity
layers (e.g. the IRIS store MAC) keep their keys in the same
directory. Point XDG_DATA_HOME at a per-test tmp dir so stamp/read
round-trips never mint or touch the developer's real key files, and
every test starts from a fresh-key state. Same pattern as
``core/inventory/tests/conftest.py``. Tests that need a specific key
location set XDG_DATA_HOME themselves (in the test body or an inner
fixture), which runs after this autouse fixture and wins.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_mac_keys(tmp_path: Path,
                       monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))


@pytest.fixture(autouse=True)
def _owned_orchestration_keepalive():
    """Own ticker resources and fail if a orchestration owner forgets its pin."""
    import threading
    from core.run import scratch

    with pytest.MonkeyPatch.context() as owner_patch:
        stop = threading.Event()
        paths = set()
        owner_patch.setattr(scratch, "_keepalive_paths", paths)
        owner_patch.setattr(scratch, "_keepalive_thread", None)
        owner_patch.setattr(scratch, "_keepalive_loop", lambda: stop.wait())
        try:
            yield paths
        finally:
            stop.set()
            thread = scratch._keepalive_thread
            if thread is not None:
                thread.join(timeout=5)
                assert not thread.is_alive(), "owned orchestration keepalive did not stop"
            leaked = [path for path in paths if Path(path).name.startswith("raptor-orchestration-inventory-")]
            assert not leaked, f"Orchestration owner left workspace keepalives registered: {leaked}"
