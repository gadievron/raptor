"""calibrated_hosts fail-soft totality + stampede-sentinel liveness.

The module's contract is documented fail-soft ADVISORY measurement:
every proxy-hosts ladder consumer treats None as "use the static
fallback". Two ways the contract was refutable:

* ``SandboxSetupError`` subclasses BaseException (deliberately, so
  enforcement callers cannot swallow it) — the probe's sandboxed run
  raises it on degraded hosts, and it escaped the advisory layer's
  catch tuple, failing exactly the runs the static-hosts fallback
  exists to carry.
* The stampede sentinel was planted OUTSIDE the try whose finally
  sets it: an owner dying between plant and probe (async
  BaseException in that window) parked every later caller for that
  key in ``waiter.wait()`` forever.
"""

from __future__ import annotations

import threading

import pytest

from core.sandbox import calibrated_hosts as mod
from core.sandbox.errors import SandboxSetupError


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(mod, "_CACHE", {})


def test_sandbox_setup_error_is_absorbed_as_advisory_none(monkeypatch):
    import core.sandbox.calibrate as calibrate

    def refuse(*args, **kwargs):
        raise SandboxSetupError("Landlock is unavailable", "remedy")

    monkeypatch.setattr(calibrate, "load_or_calibrate", refuse)
    assert mod.calibrated_profile("/bin/true", (), tag="t") is None
    # Memoised (sentinel released): the second call must return
    # immediately from the memo, not re-enter calibration.
    monkeypatch.setattr(
        calibrate, "load_or_calibrate",
        lambda *a, **k: pytest.fail("memo miss — sentinel not released"),
    )
    assert mod.calibrated_profile("/bin/true", (), tag="t") is None


class _ExplodingLockOnce:
    """Lock proxy whose FIRST release raises — a deterministic stand-in
    for an async BaseException landing in the plant-to-try window."""

    def __init__(self) -> None:
        self._real = threading.Lock()
        self._fired = False

    def __enter__(self):
        return self._real.__enter__()

    def __exit__(self, *exc):
        out = self._real.__exit__(*exc)
        if not self._fired and exc == (None, None, None):
            self._fired = True
            raise KeyboardInterrupt(
                "simulated async interrupt right after the sentinel "
                "plant")
        return out


def test_owner_death_at_plant_window_does_not_wedge_waiters(monkeypatch):
    monkeypatch.setattr(mod, "_CACHE_LOCK", _ExplodingLockOnce())

    with pytest.raises(KeyboardInterrupt):
        mod.calibrated_profile("/bin/true", (), tag="t")

    # A later caller for the same key must not park forever on a
    # sentinel the dead owner can never set.
    done: list[object] = []
    t = threading.Thread(
        target=lambda: done.append(
            mod.calibrated_profile("/bin/true", (), tag="t")),
        daemon=True,
    )
    t.start()
    t.join(5.0)
    assert not t.is_alive(), (
        "second caller wedged in waiter.wait() — the dead owner's "
        "sentinel was never set"
    )
    assert done == [None]
