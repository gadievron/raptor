"""Own scratch state without clearing inherited live registrations."""

import pytest

from core.run import tmp_reaper
from core.testing.module_state import isolated_module_state
from core.testing.scratch_state import isolated_scratch_keepalive


@pytest.fixture(autouse=True)
def _owned_scan_scratch(monkeypatch):
    from packages.semgrep import runner

    lock = runner._SCRATCH_LOCK
    with isolated_module_state(tmp_reaper, {
        "_RUNTIME_DIR_PREFIXES": set(tmp_reaper._RUNTIME_DIR_PREFIXES),
    }), isolated_scratch_keepalive(), isolated_module_state(runner, {
        "_SCRATCH_LOCK": lock,
        "_scratch_parent": None,
        "_scratch_owner_pid": None,
    }, lock=lock):
        try:
            yield
        finally:
            # Unwind body faults before releasing this fixture's scanner parent.
            monkeypatch.undo()
            runner._reset_sandbox_scratch()
