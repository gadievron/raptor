"""Observability counters, snapshot(), and the teardown summary on
the egress proxy.

Historically the proxy had no aggregate self-reporting: an operator
asking "did anything get denied?", "did the netlink latch trip?", or
"how contended are the scan permits?" had only per-event JSONL and
DEBUG lines to grep. These tests pin the observability layer:

  * connection verdict counters fold at the existing ``_record`` /
    close seams — accepted/denied/failed headline numbers match a
    churn of real loopback connections exactly (no lost, no double
    counts);
  * peer-uid resolution outcomes are classified per lookup (netlink
    hit / forced-miss scan hit / unresolvable fail-closed /
    latch-active fallback);
  * scan-permit contention is measured without perturbing it —
    parked scans saturate the permits and the counters report peak ==
    bound and the exact queued count, and a cross-thread hammer pins
    the race-freedom design by THREAD IDENTITY: every ``_stats``
    increment must execute on the proxy's own event-loop thread.
    Count conservation alone is NOT a race net on a GIL interpreter
    (unprotected cross-thread ``dict[k] += 1`` loses nothing there),
    so the conservation asserts are sanity checks only;
  * the record-time result strings partition exactly into the
    headline groups (denied / failed / documented-neither), so a new
    result cannot silently drop out of every headline number;
  * the tunnel gauge carries a high-water mark;
  * ``snapshot()`` reports the netlink transient-failure latch
    prominently (the hotpath series' documented silent-degradation
    residual);
  * ``stop()`` emits exactly one summary line per proxy lifetime —
    after the drain and thread join, so tunnels completing during the
    drain window are already folded into it — and the heartbeat line
    is change-gated so idle proxies stay silent.

Hermetic: loopback sockets + threads only; uid-lookup primitives are
monkeypatched at the same module seams the sock_diag tests use, so no
test depends on real NETLINK_SOCK_DIAG availability.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import ipaddress
import logging
import os
import socket
import threading
import time
from typing import Callable

import pytest

from core.sandbox import proxy as proxy_mod

# Far above a loopback round-trip, far below any proxy timeout —
# same bound rationale as test_proxy_teardown.py.
_DEADLINE = 5.0


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


@pytest.fixture
def loopback_permitted(monkeypatch):
    """Permit loopback upstreams through gate 2 for this test only."""
    orig = proxy_mod._ip_is_blocked

    def permit_loopback(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if ip.is_loopback:
            return False
        return orig(ip_str)

    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", permit_loopback)


def _wait_until(cond: Callable[[], bool], msg: str,
                timeout: float = _DEADLINE) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.01)
    pytest.fail(msg)


def _serve_echo_forever() -> "tuple[int, Callable[[], None]]":
    """Multi-connection echo backend; returns (port, close_fn)."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(64)
    port = lsock.getsockname()[1]

    def echo(conn: socket.socket) -> None:
        conn.settimeout(_DEADLINE * 2)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(conn,),
                             daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return port, lsock.close


def _open_tunnel(proxy_port: int, backend_port: int,
                 expect: bytes = b" 200 ") -> socket.socket:
    """CONNECT through the proxy; assert the response status."""
    s = socket.create_connection(("127.0.0.1", proxy_port),
                                 timeout=_DEADLINE)
    s.settimeout(_DEADLINE)
    s.sendall(
        f"CONNECT 127.0.0.1:{backend_port} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{backend_port}\r\n\r\n".encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        assert chunk, f"proxy closed during CONNECT handshake: {buf!r}"
        buf += chunk
    status = buf.split(b"\r\n", 1)[0]
    assert expect in status, f"unexpected CONNECT status: {status!r}"
    return s


def _send_raw(proxy_port: int, payload: bytes) -> bytes:
    """Send raw bytes to the proxy, return the first response line's
    buffer (b"" when the proxy dropped the connection)."""
    s = socket.create_connection(("127.0.0.1", proxy_port),
                                 timeout=_DEADLINE)
    try:
        s.sendall(payload)
        buf = b""
        with contextlib.suppress(OSError):
            while b"\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return buf
    finally:
        s.close()


def _connect_denied(proxy_port: int) -> None:
    buf = _send_raw(
        proxy_port,
        b"CONNECT denied-host.invalid:443 HTTP/1.1\r\n"
        b"Host: denied-host.invalid:443\r\n\r\n")
    assert b" 403 " in buf.split(b"\r\n", 1)[0], buf


class TestConnectionChurnCounters:

    def test_accepted_denied_failed_counts_match_real_churn(
            self, reset_proxy, loopback_permitted):
        """5 allowed tunnels, 3 gate-1 denials, 2 non-CONNECT
        requests — the headline numbers and the per-result map must
        match exactly (a lost update under-counts; a double-fold
        over-counts)."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            for _ in range(5):
                s = _open_tunnel(proxy.port, backend_port)
                s.sendall(b"ping")
                assert s.recv(4) == b"ping"
                s.close()
            for _ in range(3):
                _connect_denied(proxy.port)
            for _ in range(2):
                buf = _send_raw(proxy.port,
                                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                assert b" 400 " in buf.split(b"\r\n", 1)[0], buf

            # Tunnel close (and its byte fold) trails the client-side
            # close — bounded wait, then assert the exact totals.
            _wait_until(
                lambda: proxy.snapshot()["counters"]["tunnels_closed"]
                == 5,
                "5 tunnels never reached their close-time fold")
            snap = proxy.snapshot()
            assert snap["connections_accepted"] == 5
            assert snap["connections_denied"] == 3
            assert snap["connections_failed"] == 2   # the two 400s
            assert snap["events"]["allowed"] == 5
            assert snap["events"]["denied_host"] == 3
            assert snap["events"]["bad_request"] == 2
            c = snap["counters"]
            assert c["requests_connect"] == 8    # 5 allowed + 3 denied
            assert c["requests_non_connect"] == 2
            # Echo protocol: 4 bytes each way per allowed tunnel.
            assert c["bytes_c2u"] == 20
            assert c["bytes_u2c"] == 20
            assert c["tunnels_timed_out"] == 0
        finally:
            proxy.stop()
            close_backend()

    def test_eof_propagation_and_reset_teardown_counted(
            self, reset_proxy, loopback_permitted):
        """The relay termination contract is now measured: a client
        half-close increments the EOF-propagation counter; a client
        RST increments the pair-teardown counter."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            assert s.recv(4) == b"ping"
            s.shutdown(socket.SHUT_WR)   # half-close → write_eof path
            with contextlib.suppress(OSError):
                while s.recv(4096):
                    pass
            s.close()
            _wait_until(
                lambda: proxy.snapshot()["counters"][
                    "relay_eof_propagated"] >= 1,
                "client half-close never counted as EOF propagation")

            import struct
            s2 = _open_tunnel(proxy.port, backend_port)
            s2.sendall(b"x")
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack("ii", 1, 0))
            s2.close()                    # RST → pair-teardown path
            _wait_until(
                lambda: proxy.snapshot()["counters"][
                    "relay_pair_teardowns"] >= 1,
                "client RST never counted as a pair teardown")
        finally:
            proxy.stop()
            close_backend()


class TestTunnelGauge:

    def test_peak_tracks_concurrency_and_survives_drain(
            self, reset_proxy, loopback_permitted):
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            socks = [_open_tunnel(proxy.port, backend_port)
                     for _ in range(3)]
            snap = proxy.snapshot()
            assert snap["tunnels_active"] == 3
            assert snap["tunnels_peak"] == 3
            for s in socks:
                s.close()
            _wait_until(
                lambda: proxy.snapshot()["tunnels_active"] == 0,
                "tunnel gauge did not return to 0 after close")
            # The high-water mark survives the drain.
            assert proxy.snapshot()["tunnels_peak"] == 3
        finally:
            proxy.stop()
            close_backend()


class TestUidResolutionOutcomes:

    def test_netlink_hit_counted(self, reset_proxy, monkeypatch):
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        monkeypatch.setattr(proxy_mod, "_loopback_peer_uid",
                            lambda peer, sockname: os.geteuid())
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            _connect_denied(proxy.port)
            c = proxy.snapshot()["counters"]
            assert c["uid_netlink_hit"] == 1
            assert c["uid_scan_hit"] == 0
            assert c["uid_latch_fallback"] == 0
        finally:
            proxy.stop()

    def test_forced_netlink_miss_counts_scan_hits(
            self, reset_proxy, monkeypatch):
        """Connect-then-reset churn shape: netlink misses every
        lookup, the executor scan owns the verdict — each CONNECT
        must count exactly one scan hit and zero netlink hits."""
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            lambda peer, sockname: os.geteuid())
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            for _ in range(3):
                _connect_denied(proxy.port)
            c = proxy.snapshot()["counters"]
            assert c["uid_scan_hit"] == 3
            assert c["uid_netlink_hit"] == 0
            assert c["uid_scan_miss"] == 0
            assert c["uid_latch_fallback"] == 0, (
                "a per-peer miss must not be booked as the latch route")
        finally:
            proxy.stop()

    def test_unresolvable_failclosed_counted(self, reset_proxy,
                                             monkeypatch):
        """Netlink misses AND the scan cannot resolve: the retry-once
        policy makes exactly two scan misses, and the refusal books
        one fail-closed count."""
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        monkeypatch.setattr(proxy_mod, "_PEER_UID_TABLE_AVAILABLE",
                            True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _send_raw(
                proxy.port,
                b"CONNECT denied-host.invalid:443 HTTP/1.1\r\n"
                b"Host: denied-host.invalid:443\r\n\r\n")
            assert buf == b"", "unverifiable peer must be dropped"
            c = proxy.snapshot()["counters"]
            assert c["uid_unresolvable_failclosed"] == 1
            assert c["uid_scan_miss"] == 2
            assert c["uid_scan_hit"] == 0
        finally:
            proxy.stop()

    def test_latch_fallback_counted(self, reset_proxy, monkeypatch):
        """Netlink latched off: every lookup books the latch route
        (plus its scan outcome)."""
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", False)
        monkeypatch.setattr(proxy_mod, "_loopback_peer_uid",
                            lambda peer, sockname: os.geteuid())
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            for _ in range(2):
                _connect_denied(proxy.port)
            c = proxy.snapshot()["counters"]
            assert c["uid_latch_fallback"] == 2
            assert c["uid_scan_hit"] == 2
            assert c["uid_netlink_hit"] == 0
        finally:
            proxy.stop()


class TestLatchVisibility:

    def test_latch_state_prominent_in_snapshot(self, reset_proxy,
                                               monkeypatch):
        """The hotpath series' documented residual — the un-retried
        process-lifetime latch — must be visible at the snapshot's
        top level, and only as a DEGRADATION: hosts without netlink
        at all report False (that is their permanent shape)."""
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", False)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            assert proxy.snapshot()["peer_uid_netlink_latched"] == (
                hasattr(socket, "AF_NETLINK"))
        finally:
            proxy.stop()

    def test_no_latch_flag_while_netlink_usable(self, reset_proxy,
                                                monkeypatch):
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            assert proxy.snapshot()[
                "peer_uid_netlink_latched"] is False
        finally:
            proxy.stop()


class TestHeadlinePartition:

    def test_event_results_partition_into_headline_groups(self):
        """Every record-time result string lands in exactly one
        headline bucket: denied, failed, or the documented-neither
        set (allowed / would_deny_host / timed_out / buffer_overflow /
        parser_jail_degraded — each excluded from the headlines for a
        reason stated at the grouping constants). A result string added to
        _PROXY_EVENT_RESULTS without a grouping decision fails here
        instead of silently dropping out of every headline number
        while remaining visible only in the per-result census."""
        neither = {"allowed", "would_deny_host", "timed_out",
                   "buffer_overflow", "parser_jail_degraded"}
        denied = proxy_mod._STATS_DENIED_RESULTS
        failed = proxy_mod._STATS_FAILED_RESULTS
        assert (denied | failed | neither
                == proxy_mod._PROXY_EVENT_RESULTS), (
            "headline groups no longer cover the record-time result "
            "strings — classify the new result(s) as denied, failed, "
            "or documented-neither")
        assert not denied & failed
        assert not (denied | failed) & neither


class TestScanPermitContention:

    def test_parked_scans_report_peak_and_deferrals_exactly(
            self, reset_proxy, monkeypatch):
        """12 forced-miss lookups against parked scans: the first
        `bound` acquire immediately, the rest arrive at a locked
        semaphore. Deterministic because every lookup coroutine runs
        on the proxy's single loop from creation to its executor
        await in one scheduling slice."""
        bound = proxy_mod._PEER_SCAN_MAX_CONCURRENCY
        release = threading.Event()

        def parked_scan(peer, sockname):
            release.wait(10.0)   # driver-released; bounded backstop
            return 4242

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            parked_scan)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            async def driver() -> list:
                tasks = [
                    asyncio.ensure_future(proxy._lookup_peer_uid(
                        ("127.0.0.1", 1000 + i), ("127.0.0.1", 2)))
                    for i in range(12)
                ]
                # Let every lookup reach its acquire-or-queue point,
                # then observe the saturated state before release.
                deadline = asyncio.get_running_loop().time() + _DEADLINE
                while (proxy._stats["scan_concurrency_cur"] < bound
                       and asyncio.get_running_loop().time() < deadline):
                    await asyncio.sleep(0.01)
                release.set()
                return await asyncio.gather(*tasks)

            results = asyncio.run_coroutine_threadsafe(
                driver(), proxy._loop).result(timeout=30)
            assert results == [4242] * 12, "a lookup lost its verdict"
            c = proxy.snapshot()["counters"]
            assert c["scan_concurrency_peak"] == bound
            assert c["scan_permits_deferred"] == 12 - bound
            assert c["scan_concurrency_cur"] == 0
            assert c["uid_scan_hit"] == 12
        finally:
            release.set()
            proxy.stop()

    def test_cross_thread_hammer_increments_stay_on_loop_thread(
            self, reset_proxy, monkeypatch):
        """Race-freedom regression net, pinned by THREAD IDENTITY.

        Count conservation alone cannot catch an off-loop increment:
        on a GIL interpreter, 8 threads x 200k unprotected
        ``dict[k] += 1`` lose zero updates (measured — the GIL never
        yields inside the read-modify-write for these dict ops), so
        "the totals conserve" is satisfied even by a mutant that
        moves the increment into the executor worker thread. What the
        design actually guarantees is WHERE each write runs: every
        ``_stats`` scalar increment executes on the proxy's event-loop
        thread (the executor scan's RESULT is consumed after the
        await). This pin swaps the stats dict for a subclass that
        stamps ``threading.get_ident()`` on every ``__setitem__``
        while 8 threads submit 200 forced-miss lookups, then asserts
        loop-thread identity for every recorded write — an increment
        relocated into the executor goes red deterministically, on
        GIL and free-threaded builds alike. The conservation asserts
        below remain as sanity checks only."""
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)

        def slow_scan(peer, sockname):
            time.sleep(0.002)
            return 4242

        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            slow_scan)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})

        write_stamps: list[tuple[str, int]] = []

        class _ThreadStampingStats(dict):
            """Same fixed-key mapping, but every write records the
            writing thread. list.append is atomic enough for the
            stamp log even if a buggy mutant writes off-loop."""

            def __setitem__(self, key: str, value: int) -> None:
                write_stamps.append((key, threading.get_ident()))
                super().__setitem__(key, value)

        proxy._stats = _ThreadStampingStats(proxy._stats)

        async def _ident() -> int:
            return threading.get_ident()

        loop_ident = asyncio.run_coroutine_threadsafe(
            _ident(), proxy._loop).result(timeout=_DEADLINE)
        n_threads, per_thread = 8, 25
        errors: list = []
        try:
            def worker(base: int) -> None:
                try:
                    for i in range(per_thread):
                        fut = asyncio.run_coroutine_threadsafe(
                            proxy._lookup_peer_uid(
                                ("127.0.0.1", base + i),
                                ("127.0.0.1", 2)),
                            proxy._loop)
                        assert fut.result(timeout=30) == 4242
                except Exception as e:  # noqa: BLE001 — hammer thread: collect for the assertion
                    errors.append(e)

            ts = [threading.Thread(target=worker, args=(i * 1000,))
                  for i in range(n_threads)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(timeout=60)
            assert not errors, f"hammer raised: {errors[:3]}"
            # The race net: every stats write ran on the loop thread.
            off_loop = sorted({
                (key, ident) for key, ident in write_stamps
                if ident != loop_ident})
            assert not off_loop, (
                f"stats increments executed off the event-loop "
                f"thread: {off_loop}")
            # The instrumentation itself saw the seam under test —
            # a refactor that stops routing scan verdicts through
            # _stats must not turn this pin vacuous.
            stamped_keys = {key for key, _ in write_stamps}
            assert "uid_scan_hit" in stamped_keys
            assert "scan_concurrency_cur" in stamped_keys
            # Sanity only (NOT a race net — see the docstring).
            c = proxy.snapshot()["counters"]
            total = n_threads * per_thread
            assert c["uid_scan_hit"] == total, (
                f"lost updates: {c['uid_scan_hit']} != {total}")
            assert c["uid_scan_miss"] == 0
            assert c["uid_netlink_hit"] == 0
            assert c["scan_concurrency_cur"] == 0, (
                "concurrency gauge did not conserve to 0")
            assert 1 <= c["scan_concurrency_peak"] <= (
                proxy_mod._PEER_SCAN_MAX_CONCURRENCY)
        finally:
            proxy.stop()


class TestSummaryAndHeartbeat:

    def test_teardown_summary_emitted_exactly_once(self, reset_proxy,
                                                   caplog):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        with caplog.at_level(logging.INFO, logger="core.sandbox.proxy"):
            proxy.stop()
            proxy.stop()   # idempotent stop: no second summary
        summaries = [r for r in caplog.records
                     if "egress proxy summary:" in r.getMessage()]
        assert len(summaries) == 1, (
            f"expected exactly one summary line, got "
            f"{[r.getMessage() for r in summaries]}")

    def test_summary_carries_the_run_facts(self, reset_proxy,
                                           loopback_permitted, caplog):
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            assert s.recv(4) == b"ping"
            s.close()
            _connect_denied(proxy.port)
            _wait_until(
                lambda: proxy.snapshot()["counters"]["tunnels_closed"]
                == 1,
                "tunnel never reached its close-time fold")
        finally:
            with caplog.at_level(logging.INFO,
                                 logger="core.sandbox.proxy"):
                proxy.stop()
            close_backend()
        summaries = [r.getMessage() for r in caplog.records
                     if "egress proxy summary:" in r.getMessage()]
        assert len(summaries) == 1
        line = summaries[0]
        assert "accepted=1" in line
        assert "denied=1" in line
        assert "bytes[c2u=4 u2c=4]" in line

    def test_summary_includes_drain_window_completions(
            self, reset_proxy, loopback_permitted, caplog):
        """A tunnel that finishes during stop()'s drain window must be
        in the summary line: the summary is emitted after the drain
        and thread join, so the close-time fold has already landed.
        (A pre-drain summary reported such a tunnel as still active
        with zero bytes.) The closer thread races stop() only between
        "before the drain" and "during the drain" — the fold precedes
        the summary on both arms, so the assertion is deterministic."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        s = None
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            assert s.recv(4) == b"ping"
            # Tunnel still OPEN here. Close it from a side thread a
            # beat after stop() begins, so the close-time fold lands
            # inside the drain window.
            closer = threading.Timer(0.2, s.close)
            closer.start()
            with caplog.at_level(logging.INFO,
                                 logger="core.sandbox.proxy"):
                proxy.stop()
            closer.join()
        finally:
            with contextlib.suppress(OSError):
                if s is not None:
                    s.close()
            proxy.stop()
            close_backend()
        summaries = [r.getMessage() for r in caplog.records
                     if "egress proxy summary:" in r.getMessage()]
        assert len(summaries) == 1
        line = summaries[0]
        assert "accepted=1" in line
        assert "bytes[c2u=4 u2c=4]" in line, (
            f"drain-window completion missing from the summary: {line}")
        assert "tunnels=0 active" in line

    def test_heartbeat_line_is_change_gated(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            # Idle proxy: nothing happened since construction — the
            # (0, 0) baseline suppresses the beat.
            assert proxy._log_stats_line("heartbeat") is False
            proxy._record({"host": "h", "port": 1, "result": "allowed"})
            assert proxy._log_stats_line("heartbeat") is True
            # No further activity — suppressed again.
            assert proxy._log_stats_line("heartbeat") is False
        finally:
            proxy.stop()

    def test_heartbeat_task_runs_and_is_retired_at_stop(
            self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        stopped = False
        try:
            _wait_until(lambda: proxy._heartbeat_task is not None,
                        "heartbeat task never created")
            assert not proxy._heartbeat_task.done()
            proxy.stop()
            stopped = True
            assert proxy._heartbeat_task.done(), (
                "heartbeat task must be retired by proxy teardown")
        finally:
            if not stopped:
                proxy.stop()

    def test_degraded_marker_rides_the_summary_when_latched(
            self, reset_proxy, monkeypatch, caplog):
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", False)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        with caplog.at_level(logging.INFO, logger="core.sandbox.proxy"):
            proxy.stop()
        summaries = [r.getMessage() for r in caplog.records
                     if "egress proxy summary:" in r.getMessage()]
        assert len(summaries) == 1
        if hasattr(socket, "AF_NETLINK"):
            assert "DEGRADED" in summaries[0], (
                "latch-active must be loud in the summary")
        else:
            assert "DEGRADED" not in summaries[0], (
                "no-netlink platforms are not degraded")


class TestStatsLineClosedStreamGuard:
    """stop()'s teardown summary and the heartbeat can fire during
    interpreter/harness teardown, AFTER a logging handler's underlying
    stream (captured stderr, a closed log file) is gone. The resulting
    ValueError raises inside Handler.emit, where logging swallows it
    and prints a "--- Logging error ---" traceback to stderr — the
    call sites' contextlib.suppress never sees it and the noise lands
    in test/CI output anyway. _log_stats_line therefore skips the emit
    entirely when a handler that would SERVICE the record (parent
    chain up to propagate=False, handler level <= INFO; filters are
    not consulted) sits on an already-closed stream, and the guard
    itself treats any hostile stream/.closed exception as closed."""

    def test_emit_skipped_when_a_servicing_handler_stream_is_closed(
            self, reset_proxy, caplog):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        # Attach to a PARENT logger: the guard must walk the hierarchy
        # exactly as Logger.callHandlers would reach this handler.
        parent_log = logging.getLogger("core.sandbox")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        parent_log.addHandler(handler)
        try:
            with caplog.at_level(logging.INFO,
                                 logger="core.sandbox.proxy"):
                # Open stream: the forced line emits and lands.
                assert proxy._log_stats_line("beat", force=True) is True
                assert "egress proxy beat:" in stream.getvalue()
                # Closed stream (the teardown shape): the emit is
                # SKIPPED — not attempted-and-half-swallowed.
                stream.close()
                assert proxy._log_stats_line("beat",
                                             force=True) is False
        finally:
            parent_log.removeHandler(handler)
            proxy.stop()

    def test_closed_handler_above_record_level_does_not_suppress(
            self, reset_proxy, caplog):
        # A stale CRITICAL-only handler on a closed stream would never
        # service the INFO stats record — callHandlers checks
        # record.levelno against handler.level — so it must not
        # silence the stats trail (the guard is level-aware).
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        parent_log = logging.getLogger("core.sandbox")
        stream = io.StringIO()
        stream.close()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.CRITICAL)
        parent_log.addHandler(handler)
        try:
            with caplog.at_level(logging.INFO,
                                 logger="core.sandbox.proxy"):
                assert proxy._log_stats_line("beat", force=True) is True
        finally:
            parent_log.removeHandler(handler)
            proxy.stop()

    def test_hostile_closed_property_fails_toward_skip(self):
        # Real shape of the class: a TextIOWrapper whose buffer was
        # detached raises ValueError on .closed. getattr shields only
        # AttributeError, so the guard needs its own containment —
        # any exception during the walk counts as closed (skip),
        # never propagates to stop()'s caller.
        class _HostileStream:
            @property
            def closed(self):
                raise RuntimeError("hostile .closed")

            def write(self, *_a):
                return 0

            def flush(self):
                return None

        log = logging.getLogger("jailfix_hostile_closed_test")
        handler = logging.StreamHandler(_HostileStream())
        log.addHandler(handler)
        try:
            assert proxy_mod._stats_emit_would_hit_closed_stream(
                log) is True
        finally:
            log.removeHandler(handler)

    def test_guard_walk_honours_propagate_false(self):
        parent = logging.getLogger("jailfix_guard_walk_test")
        child = logging.getLogger("jailfix_guard_walk_test.child")
        stream = io.StringIO()
        stream.close()
        handler = logging.StreamHandler(stream)
        parent.addHandler(handler)
        try:
            child.propagate = True
            assert proxy_mod._stats_emit_would_hit_closed_stream(
                child) is True
            # propagate=False: records never reach the parent's
            # handler, so its closed stream is not this logger's
            # problem — the walk must stop where callHandlers stops.
            child.propagate = False
            assert proxy_mod._stats_emit_would_hit_closed_stream(
                child) is False
        finally:
            parent.removeHandler(handler)
            child.propagate = True
