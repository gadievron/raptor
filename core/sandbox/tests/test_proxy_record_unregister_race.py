"""_record vs unregister_sandbox: the final audit event must never be
dropped.

unregister_sandbox pops the sandbox's buffer and copies it under
_buffer_lock. The pre-fix _record appended through a LOCK-FREE read of
_sandbox_buffers_snapshot — a recorder holding the pre-pop snapshot
could append AFTER the pop+copy, landing the event (e.g. the sandbox's
final denied CONNECT, racing context exit) on the orphaned list, where
it silently vanished from the persisted evidence.

The test makes the race deterministic: the sandbox's buffer is swapped
for a list whose append blocks on an event, a recorder thread is
parked inside that append, and unregister_sandbox runs while it is
parked. With _record serialised on _buffer_lock, unregister must wait
for the append and the returned events include it; pre-fix, unregister
completed immediately and returned an empty list.
"""

from __future__ import annotations

import threading
import time

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


class TestRecordUnregisterRace:

    def test_final_event_survives_concurrent_unregister(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            token = proxy.register_sandbox(caller_label="race")

            append_entered = threading.Event()
            release_append = threading.Event()

            class _GatedList(list):
                """append() parks until the test releases it —
                simulates the recorder being descheduled between its
                snapshot read and the append landing."""

                def append(self, item):
                    append_entered.set()
                    assert release_append.wait(timeout=10)
                    super().append(item)

            gated = _GatedList()
            with proxy._buffer_lock:
                proxy._sandbox_buffers[token] = gated
                proxy._sandbox_buffers_snapshot = tuple(
                    (buf, proxy._sandbox_lane_subs[tok])
                    for tok, buf in proxy._sandbox_buffers.items()
                )

            event = {
                "t": time.monotonic(), "host": "final.test", "port": 443,
                "result": "denied_host", "reason": "host not in allowlist",
                "resolved_ip": None, "lane": "main", "lane_id": None,
                "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
            }
            recorder = threading.Thread(
                target=proxy._record, args=(event,), daemon=True)
            recorder.start()
            assert append_entered.wait(timeout=5), \
                "recorder never reached the buffer append"

            result: dict = {}
            unregisterer = threading.Thread(
                target=lambda: result.update(
                    events=proxy.unregister_sandbox(token)),
                daemon=True)
            unregisterer.start()
            # Give unregister every chance to complete while the
            # recorder is still parked mid-append. Pre-fix it did
            # (the recorder held no lock) and the append landed on
            # the orphaned, already-copied list.
            time.sleep(0.3)
            release_append.set()
            recorder.join(timeout=5)
            unregisterer.join(timeout=5)
            assert not recorder.is_alive()
            assert not unregisterer.is_alive()

            events = result["events"]
            hosts = [e.get("host") for e in events]
            assert "final.test" in hosts, (
                f"final audit event dropped by concurrent unregister — "
                f"returned events: {events}"
            )
            # The registration label must still be stamped on it.
            final = [e for e in events if e.get("host") == "final.test"][0]
            assert final.get("caller") == "race"
        finally:
            proxy.stop()

    def test_record_after_unregister_is_a_clean_no_op(self, reset_proxy):
        """The other side of the serialisation: once unregister has
        completed, a late _record must simply not deliver anywhere —
        no exception, no resurrecting the popped buffer."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            token = proxy.register_sandbox(caller_label="gone")
            assert proxy.unregister_sandbox(token) == []
            proxy._record({
                "t": time.monotonic(), "host": "late.test", "port": 443,
                "result": "denied_host", "reason": "r", "resolved_ip": None,
                "lane": "main", "lane_id": None,
                "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
            })
            assert proxy._sandbox_buffers == {}
            assert proxy.unregister_sandbox(token) == []
        finally:
            proxy.stop()
