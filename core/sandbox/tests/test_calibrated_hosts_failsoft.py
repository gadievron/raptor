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


@pytest.mark.parametrize("kind", ["failed", "refused", "pending"])
@pytest.mark.parametrize("shape", ["ordinary", "controls", "oversized"])
def test_calibration_diagnostics_are_bounded_and_inert(
        monkeypatch, caplog, kind, shape):
    import logging
    from core.sandbox import calibrate

    payload = {
        "ordinary": "plain",
        "controls": "line\n\r\x1b[0m\x00\u2028\ud800",
        "oversized": "x" * 10000,
    }[shape]
    tag, binary, error_text = "caller:" + payload, "/tool/" + payload, "probe:" + payload
    identity = ("stable",)
    monkeypatch.setattr(mod, "_memo_identity", lambda *args: identity)
    calls = []

    def fail(path, **kwargs):
        calls.append((path, kwargs))
        raise (SandboxSetupError(error_text) if kind == "refused"
               else RuntimeError(error_text))

    monkeypatch.setattr(calibrate, "load_or_calibrate", fail)
    key = (binary, (), ("--version",))
    if kind == "pending":
        pending = mod._CacheEntry(identity)
        mod._CACHE[key] = pending
    with caplog.at_level(logging.DEBUG, logger=mod.__name__):
        assert mod.calibrated_profile(binary, (), timeout=0, tag=tag) is None
    entry = mod._CACHE[key]
    if kind == "pending":
        assert entry is pending and not entry.ready.is_set()
        assert calls == []
    else:
        assert entry.ready.is_set() and entry.result is None
        assert calls == [(binary, {"probe_args": ("--version",), "env_keys": (), "timeout": 0})]
        # A logging-only fix must retain the same memoized fallback.
        assert mod.calibrated_profile(binary, (), timeout=0, tag=tag) is None
        assert len(calls) == 1
    records = [record for record in caplog.records if record.name == mod.__name__]
    assert len(records) == 1
    record = records[0]
    message = record.getMessage()
    assert message.isprintable()
    assert len(message) < 1000
    assert record.exc_info is None
    assert all(str(arg).isprintable() and len(str(arg)) < 320 for arg in record.args)
    if shape == "oversized":
        assert "...[+" in message and "chars]" in message
    if shape == "ordinary":
        expected = {
            "failed": "caller:plain: calibration of /tool/plain failed (probe:plain); falling back to static policy",
            "refused": "caller:plain: calibration of /tool/plain refused by the sandbox (probe:plain); falling back to static policy",
            "pending": "caller:plain: calibration of /tool/plain still pending; using static policy",
        }
        assert message == expected[kind]
