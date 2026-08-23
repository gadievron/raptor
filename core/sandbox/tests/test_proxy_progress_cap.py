"""Tests for the progress-aware absolute tunnel cap.

The historical ``total_timeout`` severed EVERY CONNECT tunnel at the
absolute cap regardless of activity — pooled LLM connections (healthy,
tens of MB relayed) died mid-request hourly during long audit runs.
The supervisor keeps the cap as a DoS bound but makes it
progress-aware: sever only when the cap has elapsed AND the tunnel
made no relay progress within the last idle window.

Hermetic: loopback sockets and sub-second timeouts only.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from core.sandbox import proxy as proxy_mod


def _supervisor_only_proxy(total: float, idle: float):
    """An ``EgressProxy`` shell carrying just the state
    ``_supervise_relay`` touches — no listener thread, no event loop
    of its own, so the unit tests below control time precisely."""
    p = object.__new__(proxy_mod.EgressProxy)
    p._total_timeout = total
    p._idle_timeout = idle
    p._idle_timeout_lock = threading.Lock()
    return p


# ---------- unit level: the supervisor itself ----------


def test_no_progress_tunnel_dies_at_hard_ceiling():
    """A tunnel whose relay pair never finishes and never moves the
    byte counters (the drain-stuck hostile shape the cap exists for)
    is severed at the hard ceiling — total_timeout — not extended."""
    p = _supervisor_only_proxy(total=0.2, idle=0.05)

    async def scenario():
        relay = asyncio.get_running_loop().create_future()
        counters = {"c2u": 0, "u2c": 0}
        t0 = asyncio.get_running_loop().time()
        reason = await p._supervise_relay(relay, counters)
        elapsed = asyncio.get_running_loop().time() - t0
        return reason, elapsed, relay.cancelled()

    reason, elapsed, cancelled = asyncio.run(scenario())
    assert reason is not None and "total_timeout" in reason
    assert cancelled, "relay pair must be cancelled on sever"
    assert elapsed >= 0.2, "must not sever before the ceiling"
    assert elapsed < 5.0, "no-progress tunnel must die promptly at the cap"


def test_steady_progress_extends_past_cap_then_stall_severs():
    """Progress past the cap earns extensions; once progress stops the
    tunnel dies within ~two idle windows of its last progress."""
    p = _supervisor_only_proxy(total=0.2, idle=0.1)

    async def scenario():
        loop = asyncio.get_running_loop()
        relay = loop.create_future()
        counters = {"c2u": 0, "u2c": 0}
        stall_at = loop.time() + 0.45   # progress until well past the cap

        async def pump():
            while loop.time() < stall_at:
                counters["c2u"] += 1
                await asyncio.sleep(0.02)

        pump_task = asyncio.ensure_future(pump())
        t0 = loop.time()
        reason = await p._supervise_relay(relay, counters)
        elapsed = loop.time() - t0
        pump_task.cancel()
        return reason, elapsed, relay.cancelled()

    reason, elapsed, cancelled = asyncio.run(scenario())
    assert reason is not None and "no relay progress" in reason
    assert cancelled
    assert elapsed > 0.4, (
        "an actively-transferring tunnel must survive past the old "
        f"absolute cap (severed at {elapsed:.3f}s, cap 0.2s)"
    )
    assert elapsed < 5.0, "post-stall sever must land within idle-window order"


def test_natural_finish_returns_none_and_skips_the_cap():
    """A relay pair that ends on its own (EOF/idle/reset) reports no
    sever reason — the caller records a normal close."""
    p = _supervisor_only_proxy(total=30.0, idle=0.05)

    async def scenario():
        loop = asyncio.get_running_loop()
        relay = loop.create_future()
        loop.call_later(0.05, relay.set_result, [None, None])
        t0 = loop.time()
        reason = await p._supervise_relay(relay, {"c2u": 0, "u2c": 0})
        return reason, loop.time() - t0

    reason, elapsed = asyncio.run(scenario())
    assert reason is None
    assert elapsed < 5.0


def test_relay_exception_propagates_and_relay_is_reaped():
    """An exception out of the relay pair reaches the caller (which
    books it as a normal relay-ended close) — the supervisor must not
    swallow it into a timeout verdict."""
    p = _supervisor_only_proxy(total=30.0, idle=0.05)

    async def scenario():
        loop = asyncio.get_running_loop()
        relay = loop.create_future()
        loop.call_later(0.02, relay.set_exception, OSError("peer reset"))
        with pytest.raises(OSError, match="peer reset"):
            await p._supervise_relay(relay, {"c2u": 0, "u2c": 0})

    asyncio.run(scenario())


def test_torn_down_supervisor_retrieves_cancelled_relay_outcome():
    """Cancelling the supervisor (proxy stop / loop shutdown cancels
    the CONNECT handler task) must not abandon the relay gather with
    an unretrieved exception: a cancel-requested _GatheringFuture
    finishes with CancelledError set as its *exception* (not the
    cancelled state), and an unretrieved one makes the event-loop
    finalizer log '_GatheringFuture exception was never retrieved'
    after the loop — under pytest, after capture is closed ('I/O
    operation on closed file' teardown noise)."""
    p = _supervisor_only_proxy(total=30.0, idle=0.05)

    async def scenario():
        relay = asyncio.gather(asyncio.sleep(30), asyncio.sleep(30))
        sup = asyncio.ensure_future(
            p._supervise_relay(relay, {"c2u": 0, "u2c": 0})
        )
        await asyncio.sleep(0.02)   # supervisor parked awaiting the relay
        sup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await sup
        # Give the gather's children ticks to process their
        # cancellation and the retrieval callback a tick to run.
        for _ in range(50):
            if relay.done():
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0)
        return relay

    relay = asyncio.run(scenario())
    assert relay.done(), "relay pair must be torn down with the supervisor"
    # _log_traceback is the exact flag Future.__del__ keys on to decide
    # whether to hand the finalizer an 'exception was never retrieved'
    # report — False means the outcome was retrieved. Private but
    # stable across CPython (both the C and pure-Python futures expose
    # it; asyncio's own test suite asserts through it).
    assert relay._log_traceback is False, (
        "torn-down supervisor abandoned the relay gather's outcome"
    )


def test_mid_tunnel_idle_widening_applies():
    """update_idle_timeout's max-semantics widening must reach tunnels
    already in flight: with the cap elapsed and progress stopped, a
    widened idle window keeps the tunnel alive for the widened span."""
    p = _supervisor_only_proxy(total=0.05, idle=0.05)

    async def scenario():
        loop = asyncio.get_running_loop()
        relay = loop.create_future()
        counters = {"c2u": 1, "u2c": 0}  # baseline progress at t0

        def widen():
            with p._idle_timeout_lock:
                p._idle_timeout = 0.5

        loop.call_soon(widen)
        t0 = loop.time()
        reason = await p._supervise_relay(relay, counters)
        return reason, loop.time() - t0

    reason, elapsed = asyncio.run(scenario())
    assert reason is not None
    assert elapsed >= 0.4, "widened idle window must govern the sever point"


# ---------- socket level: real tunnels through a real proxy ----------


def _echo_upstream():
    """One-connection loopback echo server. Returns (sock, port, thread)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                try:
                    conn.sendall(data)
                except OSError:
                    return

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, port, t


def _connect_through(proxy, up_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5.0)
    s.sendall(
        f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{up_port}\r\n\r\n".encode("latin-1")
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    assert b" 200 " in buf.split(b"\r\n", 1)[0]
    return s


def test_tunnel_with_steady_progress_survives_past_old_cap(monkeypatch):
    """End-to-end: a tunnel echoing bytes every 0.1s stays open well
    past total_timeout. Under the pre-fix wait_for it was severed at
    the cap regardless of the healthy transfer."""
    # Gate 2 blocks loopback IPs by design; the captive upstream in
    # this test lives on loopback, so stand the gate down for it.
    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", lambda ip: False)
    srv, up_port, thread = _echo_upstream()
    proxy = proxy_mod.EgressProxy(
        allowed_hosts={"127.0.0.1"}, idle_timeout=0.4, total_timeout=0.6,
    )
    try:
        s = _connect_through(proxy, up_port)
        s.settimeout(5.0)
        try:
            deadline = time.monotonic() + 1.5   # 2.5x the absolute cap
            while time.monotonic() < deadline:
                s.sendall(b"x")
                echoed = s.recv(16)
                assert echoed, (
                    "tunnel severed mid-transfer — the absolute cap "
                    "fired on a tunnel with steady progress"
                )
                time.sleep(0.1)
        finally:
            s.close()
    finally:
        proxy.stop()
        srv.close()
        thread.join(timeout=5.0)


def test_stalled_tunnel_still_dies_at_idle(monkeypatch):
    """End-to-end: a tunnel that goes silent is reaped by the idle
    timeout long before the absolute cap."""
    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", lambda ip: False)
    srv, up_port, thread = _echo_upstream()
    proxy = proxy_mod.EgressProxy(
        allowed_hosts={"127.0.0.1"}, idle_timeout=0.3, total_timeout=60.0,
    )
    try:
        s = _connect_through(proxy, up_port)
        s.settimeout(10.0)
        try:
            t0 = time.monotonic()
            # No bytes in either direction: both relay directions hit
            # the idle read timeout and the tunnel closes (client sees
            # EOF). Far before total_timeout=60.
            got = s.recv(16)
            elapsed = time.monotonic() - t0
            assert got == b"", "expected EOF from idle-close"
            assert elapsed < 8.0, f"idle close took {elapsed:.1f}s"
        finally:
            s.close()
    finally:
        proxy.stop()
        srv.close()
        thread.join(timeout=5.0)
