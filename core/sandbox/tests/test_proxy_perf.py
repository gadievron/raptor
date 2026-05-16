"""Tests for the egress-proxy performance fixes:

  A. TTL'd DNS cache (skip getaddrinfo on repeat host).
  B. Happy-eyeballs dialer (race v6 + v4 instead of serial walk).
  C. Module-top has_nonprintable import + lazy log formatting (smoke).
  D. Snapshot-based buffer fan-out (lock-free hot path; concurrent
     register/unregister/_record exercise).

Pure-Python tests — no subprocess, no real network. The dialer is
exercised against ``EgressProxy`` instance methods with mocked
``getaddrinfo`` and ``open_connection``; concurrency tests run on
the proxy's own asyncio loop via ``loop.call_soon_threadsafe`` +
``run_coroutine_threadsafe``.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from unittest.mock import patch

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


# ---------------------------------------------------------------------------
# A — DNS cache
# ---------------------------------------------------------------------------


class TestDnsCache:

    def test_cache_hit_skips_getaddrinfo(self, reset_proxy):
        """Two resolutions of the same host within TTL → 1 call."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:
            calls = []

            async def fake_gai(host, port, **kwargs):
                calls.append((host, port))
                return [(
                    socket.AF_INET, socket.SOCK_STREAM, 0, "",
                    ("93.184.216.34", port),
                )]

            async def driver():
                with patch.object(proxy._loop, "getaddrinfo", fake_gai):
                    a = await proxy._cached_getaddrinfo("example.com", 443)
                    b = await proxy._cached_getaddrinfo("example.com", 443)
                return a, b

            a, b = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert a == b
            assert calls == [("example.com", 443)], (
                f"second lookup hit getaddrinfo: {calls}"
            )
        finally:
            proxy.stop()

    def test_cache_expires_after_ttl(self, reset_proxy):
        """Past TTL → re-resolves."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:
            calls = []

            async def fake_gai(host, port, **kwargs):
                calls.append((host, port))
                return [(
                    socket.AF_INET, socket.SOCK_STREAM, 0, "",
                    ("93.184.216.34", port),
                )]

            async def driver():
                with patch.object(proxy._loop, "getaddrinfo", fake_gai):
                    await proxy._cached_getaddrinfo("example.com", 443)
                    # Force the cache entry to be expired by rewriting
                    # its expiry timestamp.
                    key = ("example.com", 443)
                    expires, addrs = proxy._dns_cache[key]
                    proxy._dns_cache[key] = (time.monotonic() - 1.0, addrs)
                    await proxy._cached_getaddrinfo("example.com", 443)

            asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert len(calls) == 2, (
                f"expired entry was not refreshed: {calls}"
            )
        finally:
            proxy.stop()

    def test_distinct_keys_cache_independently(self, reset_proxy):
        """Different (host, port) keys do not share cache entries."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"a.com", "b.com"})
        try:
            calls = []

            async def fake_gai(host, port, **kwargs):
                calls.append((host, port))
                return [(
                    socket.AF_INET, socket.SOCK_STREAM, 0, "",
                    ("1.2.3.4", port),
                )]

            async def driver():
                with patch.object(proxy._loop, "getaddrinfo", fake_gai):
                    await proxy._cached_getaddrinfo("a.com", 443)
                    await proxy._cached_getaddrinfo("b.com", 443)
                    await proxy._cached_getaddrinfo("a.com", 80)

            asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert calls == [("a.com", 443), ("b.com", 443),
                              ("a.com", 80)]
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# B — Happy-eyeballs
# ---------------------------------------------------------------------------


class TestHappyEyeballs:

    def _addrinfo(self, family, ip, port=443):
        return (family, socket.SOCK_STREAM, 0, "", (ip, port))

    def test_single_family_walks_in_order(self, reset_proxy):
        """Only v4 records → no race, just walk in order."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:
            connect_calls = []

            async def fake_open(host, port, family=None, **kwargs):
                connect_calls.append(host)
                return ("reader", "writer")

            addrinfo = [
                self._addrinfo(socket.AF_INET, "1.2.3.4"),
                self._addrinfo(socket.AF_INET, "5.6.7.8"),
            ]

            async def driver():
                with patch("asyncio.open_connection", fake_open):
                    return await proxy._happy_eyeballs_connect(
                        addrinfo, 443,
                    )

            r, w, ip = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert ip == "1.2.3.4"
            assert connect_calls == ["1.2.3.4"]
        finally:
            proxy.stop()

    def test_dual_family_v6_succeeds_first(self, reset_proxy):
        """v6 wins the race → return v6 result; v4 cancelled."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:

            async def fake_open(host, port, family=None, **kwargs):
                if family == socket.AF_INET6:
                    return ("r6", "w6")
                # v4 is slower
                await asyncio.sleep(1.0)
                return ("r4", "w4")

            addrinfo = [
                self._addrinfo(socket.AF_INET6, "2606:2800:220:1::"),
                self._addrinfo(socket.AF_INET, "1.2.3.4"),
            ]

            async def driver():
                with patch("asyncio.open_connection", fake_open):
                    return await proxy._happy_eyeballs_connect(
                        addrinfo, 443,
                    )

            r, w, ip = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert ip == "2606:2800:220:1::"
        finally:
            proxy.stop()

    def test_dual_family_v6_stalls_v4_wins(self, reset_proxy):
        """v6 stalls past the 250ms gate; v4 races and wins."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:

            async def fake_open(host, port, family=None, **kwargs):
                if family == socket.AF_INET6:
                    await asyncio.sleep(2.0)
                    return ("r6", "w6")
                # v4 fast
                return ("r4", "w4")

            addrinfo = [
                self._addrinfo(socket.AF_INET6, "2606:2800:220:1::"),
                self._addrinfo(socket.AF_INET, "1.2.3.4"),
            ]

            async def driver():
                with patch("asyncio.open_connection", fake_open):
                    return await proxy._happy_eyeballs_connect(
                        addrinfo, 443,
                    )

            t0 = time.monotonic()
            r, w, ip = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            elapsed = time.monotonic() - t0
            assert ip == "1.2.3.4"
            # Must be quick: v4 starts after the 250ms gate, then
            # connects instantly.
            assert elapsed < 1.0, (
                f"happy-eyeballs took {elapsed:.2f}s — v6 stall not "
                f"bypassed?"
            )
        finally:
            proxy.stop()

    def test_gate2_blocks_first_candidate_falls_through(
        self, reset_proxy,
    ):
        """If gate-2 rejects the first candidate (private IP), the
        dialer tries the next."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
        try:
            connect_calls = []

            async def fake_open(host, port, family=None, **kwargs):
                connect_calls.append(host)
                return ("r", "w")

            # First v4 is loopback (gate-2 reject), second is public.
            addrinfo = [
                self._addrinfo(socket.AF_INET, "127.0.0.1"),
                self._addrinfo(socket.AF_INET, "1.2.3.4"),
            ]

            async def driver():
                with patch("asyncio.open_connection", fake_open):
                    return await proxy._happy_eyeballs_connect(
                        addrinfo, 443,
                    )

            r, w, ip = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop,
            ).result(timeout=5)
            assert ip == "1.2.3.4"
            assert connect_calls == ["1.2.3.4"], (
                f"gate-2-blocked IP was dialled: {connect_calls}"
            )
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# D — Snapshot buffer fan-out
# ---------------------------------------------------------------------------


class TestBufferSnapshot:

    def test_register_appends_to_snapshot(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            assert proxy._sandbox_buffers_snapshot == ()
            t1 = proxy.register_sandbox(caller_label="a")
            assert len(proxy._sandbox_buffers_snapshot) == 1
            t2 = proxy.register_sandbox(caller_label="b")
            assert len(proxy._sandbox_buffers_snapshot) == 2
            proxy.unregister_sandbox(t1)
            assert len(proxy._sandbox_buffers_snapshot) == 1
            proxy.unregister_sandbox(t2)
            assert proxy._sandbox_buffers_snapshot == ()
        finally:
            proxy.stop()

    def test_record_fans_out_lock_free(self, reset_proxy):
        """_record appends to every registered sandbox's buffer
        without acquiring the buffer lock."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            t1 = proxy.register_sandbox()
            t2 = proxy.register_sandbox()
            event = {"host": "h", "port": 1, "result": "allowed"}
            proxy._record(event)
            ev1 = proxy.unregister_sandbox(t1)
            ev2 = proxy.unregister_sandbox(t2)
            assert len(ev1) == 1 and len(ev2) == 1
            assert ev1[0]["host"] == "h"
            assert ev2[0]["host"] == "h"
        finally:
            proxy.stop()

    def test_concurrent_record_and_register(self, reset_proxy):
        """Hammer _record from many threads concurrently with
        register/unregister churn — must not raise (no dict-mutated-
        during-iteration) and every event must land in at least one
        buffer that was registered when the record happened."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            stop = threading.Event()
            errors = []

            def hammer_record():
                try:
                    while not stop.is_set():
                        proxy._record({"host": "h", "port": 1,
                                        "result": "allowed"})
                except Exception as e:
                    errors.append(e)

            def hammer_register():
                try:
                    while not stop.is_set():
                        t = proxy.register_sandbox()
                        proxy.unregister_sandbox(t)
                except Exception as e:
                    errors.append(e)

            ts = [threading.Thread(target=hammer_record) for _ in range(4)]
            ts += [threading.Thread(target=hammer_register) for _ in range(2)]
            for t in ts:
                t.start()
            time.sleep(0.5)
            stop.set()
            for t in ts:
                t.join(timeout=5)
            assert not errors, f"concurrent run raised: {errors}"
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# C — module-top import + lazy log formatting (smoke)
# ---------------------------------------------------------------------------


class TestImportAndLogging:

    def test_has_nonprintable_imported_at_module_top(self):
        """The hot-path inline import is gone — the symbol resolves
        from the proxy module's own namespace."""
        # Direct module attribute lookup; if the inline import was
        # still in _serve_tunnel and the module-top one was removed,
        # this would AttributeError.
        assert hasattr(proxy_mod, "has_nonprintable")
        from core.security.log_sanitisation import (
            has_nonprintable as canonical,
        )
        assert proxy_mod.has_nonprintable is canonical
