"""Worker retirement for the in-memory server single-flight test."""

import pytest

from ._binary_server_ownership import exercise


@pytest.mark.parametrize("phase", ["normal", "before-error", "before-interrupt", "after-error", "after-interrupt"])
def test_server_workers_retire_before_bindings_restore(phase, tmp_path):
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    with exercise(phase, tmp_path) as (invoke, threads, gates, bc, callbacks):
        if phase == "normal":
            invoke()
        else:
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 4
        assert not any(thread.is_alive() for thread in threads)
        assert gates[0].is_set()
        assert not bc._SERVER_CACHE
        assert not bc._SERVER_BOOT_LOCKS
        assert len(callbacks) == (0 if phase.startswith("before-") else 1)
        assert all(thread.joins for thread in threads if thread.ident is not None)
        assert not any(thread.joins for thread in threads if thread.ident is None)
