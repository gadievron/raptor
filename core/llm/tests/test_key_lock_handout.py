"""Per-key dedupe-lock registry: hand-out refcounting vs eviction.

Between ``_key_lock`` returning and the caller entering ``with``, the
lock is held by nobody — an ``acquire(blocking=False)`` eviction probe
reads that gap as uncontended. Evicting there hands the next caller
for the same key a FRESH lock object, so two provider calls run
concurrently for one cache key. Hand-outs are refcounted; a key with
a live hand-out is never evicted, and the count drops after release
so cold keys stay evictable.
"""

from __future__ import annotations

import threading
from collections import OrderedDict

from core.llm.client import LLMClient


def _mini_client(cap: int = 2) -> LLMClient:
    client = LLMClient.__new__(LLMClient)
    client._key_locks = OrderedDict()
    client._key_locks_guard = threading.Lock()
    client._key_locks_cap = cap
    return client


def test_handed_out_lock_survives_eviction_pressure() -> None:
    """A handed-out-but-not-yet-acquired lock must not be evicted:
    a second caller for the same key gets the SAME lock object."""
    client = _mini_client(cap=2)
    handle_1 = client._key_lock("k1")  # hand-out; not yet acquired
    client._key_lock("k2")
    client._key_lock("k3")  # exceeds the cap → eviction pass runs
    handle_2 = client._key_lock("k1")
    assert handle_2.lock is handle_1.lock


def test_released_lock_is_evictable_again() -> None:
    """After release the refcount clears and eviction pressure drops
    the cold key — the cap keeps working."""
    client = _mini_client(cap=2)
    with client._key_lock("k1"):
        pass
    assert client._key_lock_refs.get("k1", 0) == 0
    client._key_lock("k2")
    client._key_lock("k3")  # eviction pass: k1 is cold now
    assert "k1" not in client._key_locks


def test_handle_acquires_and_releases_underlying_lock() -> None:
    client = _mini_client()
    handle = client._key_lock("k")
    with handle:
        assert handle.lock.locked()
    assert not handle.lock.locked()
    # Refcount table cleaned up after the last release.
    assert client._key_lock_refs == {}


def test_concurrent_handles_serialise_on_one_lock() -> None:
    """Two hand-outs for the same key share one lock: the second
    ``with`` blocks until the first releases."""
    client = _mini_client()
    order: list[str] = []
    first_acquired = threading.Event()
    release_first = threading.Event()

    def holder() -> None:
        with client._key_lock("k"):
            order.append("first")
            first_acquired.set()
            release_first.wait(timeout=5)

    def waiter() -> None:
        first_acquired.wait(timeout=5)
        with client._key_lock("k"):
            order.append("second")

    t1 = threading.Thread(target=holder)
    t2 = threading.Thread(target=waiter)
    t1.start()
    t2.start()
    first_acquired.wait(timeout=5)
    release_first.set()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert order == ["first", "second"]
