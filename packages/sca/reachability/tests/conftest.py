"""Own scratch ticker resources used by reachability inventory tests."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _owned_reachability_keepalive():
    """Own ticker resources and fail if a reachability owner forgets its pin."""
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
                assert not thread.is_alive(), "owned reachability keepalive did not stop"
            leaked = [path for path in paths if Path(path).name.startswith("raptor-sca-")]
            assert not leaked, f"Reachability owner left workspace keepalives registered: {leaked}"
