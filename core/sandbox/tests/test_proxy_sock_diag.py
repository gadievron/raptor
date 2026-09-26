"""NETLINK_SOCK_DIAG peer-uid lookup and its /proc-scan fallback.

The loopback peer-uid gate historically did a linear /proc/net/tcp{,6}
scan per CONNECT on the event-loop thread — O(host-sockets) of setup
latency that also serialised concurrent CONNECTs. The lookup is now an
exact-match NETLINK_SOCK_DIAG query (O(1) kernel hash lookup of the
same struct-sock owner field), with the scan kept as the structural
fallback and as the second opinion on a netlink miss, so the
dispatcher resolves a strict superset of the peers the scan alone
resolved. EVERY scan execution — latched-off fallback AND miss-path
second opinion — runs in the bounded executor, never on the event
loop: a peer doing connect-then-reset churn can force the miss on
every CONNECT, so the miss path is hostile-triggerable, not rare.

These tests pin:
  * the netlink primitive returns the true owner for real v4/v6
    loopback pairs and a clean miss (None) for absent 4-tuples;
  * netlink and the scan agree on the same live socket;
  * the dispatcher's fallback + latch behaviour on structural failure;
  * the executor path still honours the ``_loopback_peer_uid``
    monkeypatch seam the gate's verdict-policy tests rely on;
  * the miss-path scan never executes on the event-loop thread, and
    miss-path + latch-path scans share one permit bound;
  * verdicts under forced-miss churn are unchanged (same-uid served,
    unresolvable fails closed, the miss never latches netlink off);
  * the end-to-end gate still refuses a wrong-uid peer with the new
    primary path live (load-bearing refusal — see
    test_proxy_peer_uid.py for the full verdict-policy matrix).

Hermetic: loopback sockets only. Netlink-dependent tests probe the
primitive first and skip (with the failure reason) on kernels,
sandboxes, or seccomp profiles that refuse NETLINK_SOCK_DIAG — CI
containers sometimes do; the fallback tests still run there.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import proxy as proxy_mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="NETLINK_SOCK_DIAG and /proc/net/tcp are Linux-only; "
           "elsewhere the gate is advisory (every lookup is None)",
)


@pytest.fixture
def loopback_pair():
    """A connected v4 loopback pair; yields the SERVER-side socket
    (whose peername/sockname identify the client's socket — the
    direction the proxy queries)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli = None
    conn = None
    try:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.create_connection(srv.getsockname(), timeout=5.0)
        conn, _ = srv.accept()
        yield conn
    finally:
        for s in (conn, cli, srv):
            if s is not None:
                s.close()


def _sock_diag_skip_reason() -> "str | None":
    """Probe whether NETLINK_SOCK_DIAG works here; reason if not."""
    try:
        proxy_mod._sock_diag_peer_uid(("127.0.0.1", 1), ("127.0.0.1", 2))
    except proxy_mod._SockDiagUnavailableError as exc:
        return f"NETLINK_SOCK_DIAG unusable in this environment: {exc}"
    return None


class TestSockDiagPrimitive:

    def test_v4_pair_reports_own_uid(self, loopback_pair):
        reason = _sock_diag_skip_reason()
        if reason:
            pytest.skip(reason)
        uid = proxy_mod._sock_diag_peer_uid(
            loopback_pair.getpeername(), loopback_pair.getsockname())
        assert uid == os.geteuid()

    def test_v6_pair_reports_own_uid(self):
        reason = _sock_diag_skip_reason()
        if reason:
            pytest.skip(reason)
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        cli = None
        conn = None
        try:
            srv.bind(("::1", 0))
            srv.listen(1)
            cli = socket.create_connection(
                ("::1", srv.getsockname()[1]), timeout=5.0)
            conn, _ = srv.accept()
            uid = proxy_mod._sock_diag_peer_uid(
                conn.getpeername()[:2], conn.getsockname()[:2])
            assert uid == os.geteuid()
        except OSError as exc:
            pytest.skip(f"IPv6 loopback unavailable: {exc}")
        finally:
            for s in (conn, cli, srv):
                if s is not None:
                    s.close()

    def test_unknown_tuple_is_a_clean_miss(self):
        reason = _sock_diag_skip_reason()
        if reason:
            pytest.skip(reason)
        assert proxy_mod._sock_diag_peer_uid(
            ("127.0.0.1", 1), ("127.0.0.1", 2)) is None

    def test_malformed_tuples_return_none(self):
        # Must not need netlink at all — malformed input short-circuits
        # before any socket is opened (matches the scan's contract).
        assert proxy_mod._sock_diag_peer_uid(None, None) is None
        assert proxy_mod._sock_diag_peer_uid((), ()) is None
        assert proxy_mod._sock_diag_peer_uid(
            ("not-an-ip", 1), ("127.0.0.1", 2)) is None

    def test_agrees_with_proc_scan_on_live_socket(self, loopback_pair):
        """Both primitives read the same kernel owner field — on a
        live socket they must give the same answer."""
        reason = _sock_diag_skip_reason()
        if reason:
            pytest.skip(reason)
        peer = loopback_pair.getpeername()
        sockname = loopback_pair.getsockname()
        assert (proxy_mod._sock_diag_peer_uid(peer, sockname)
                == proxy_mod._peer_uid_via_proc_scan(peer, sockname))


class TestDispatcher:

    def test_structural_failure_latches_and_falls_back(
            self, loopback_pair, monkeypatch):
        """A _SockDiagUnavailableError must (a) still resolve the peer
        via the scan and (b) latch netlink off so later calls skip it."""
        calls: list = []

        def broken(peer, sockname):
            calls.append(peer)
            raise proxy_mod._SockDiagUnavailableError("simulated")

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid", broken)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        peer = loopback_pair.getpeername()
        sockname = loopback_pair.getsockname()
        assert proxy_mod._loopback_peer_uid(peer, sockname) == os.geteuid()
        assert proxy_mod._SOCK_DIAG_USABLE is False, (
            "structural failure must latch netlink off")
        assert proxy_mod._loopback_peer_uid(peer, sockname) == os.geteuid()
        assert len(calls) == 1, (
            "latched-off netlink was attempted again")

    def test_netlink_miss_gets_scan_second_opinion(
            self, loopback_pair, monkeypatch):
        """Semantic-superset property: a netlink miss (e.g. a
        device-bound peer socket the idiag_if=0 lookup cannot see)
        must not refuse a peer the historical scan identified."""
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        assert proxy_mod._loopback_peer_uid(
            loopback_pair.getpeername(), loopback_pair.getsockname(),
        ) == os.geteuid()
        assert proxy_mod._SOCK_DIAG_USABLE is True, (
            "a per-peer miss must not latch the primitive off")

    def test_scan_only_when_netlink_off(self, loopback_pair,
                                        monkeypatch):
        def must_not_run(peer, sockname):
            pytest.fail("netlink attempted while latched off")

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            must_not_run)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", False)
        assert proxy_mod._loopback_peer_uid(
            loopback_pair.getpeername(), loopback_pair.getsockname(),
        ) == os.geteuid()


class TestLookupPeerUidHotPath:
    """EgressProxy._lookup_peer_uid — the event-loop-side wrapper."""

    @staticmethod
    def _run(coro):
        return asyncio.run(coro)

    def test_inline_path_uses_module_seam(self, monkeypatch):
        """With netlink usable the lookup runs inline AND through the
        module-global _loopback_peer_uid name — the seam the verdict-
        policy tests (and the perf probes) monkeypatch."""
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        monkeypatch.setattr(proxy_mod, "_loopback_peer_uid",
                            lambda peer, sockname: 4242)
        me = SimpleNamespace(_peer_scan_sem=None)

        async def driver():
            return await proxy_mod.EgressProxy._lookup_peer_uid(
                me, ("127.0.0.1", 1), ("127.0.0.1", 2))

        assert self._run(driver()) == 4242

    def test_executor_path_uses_module_seam(self, monkeypatch):
        """Scan-only hosts (netlink latched off): the lookup must go
        through the executor and STILL resolve the monkeypatched
        module global — same verdicts, off the loop thread."""
        import threading
        seen: dict = {}

        def fake_lookup(peer, sockname):
            seen["thread"] = threading.current_thread()
            return 4242

        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", False)
        monkeypatch.setattr(proxy_mod, "_loopback_peer_uid", fake_lookup)
        me = SimpleNamespace(_peer_scan_sem=None)

        async def driver():
            return await proxy_mod.EgressProxy._lookup_peer_uid(
                me, ("127.0.0.1", 1), ("127.0.0.1", 2))

        assert self._run(driver()) == 4242
        assert seen["thread"] is not threading.main_thread(), (
            "scan-only lookup ran on the event-loop thread")
        assert isinstance(me._peer_scan_sem, asyncio.Semaphore), (
            "executor path must be bounded by the scan semaphore")

    def test_netlink_miss_scan_runs_off_loop(self, monkeypatch):
        """The hostile-triggerable shape: connect-then-reset churn
        forces a netlink miss (ENOENT) on every lookup, so the scan
        second opinion owes the verdict each time. That scan must run
        in the bounded executor, never on the event-loop thread —
        asyncio.run puts the loop on the MAIN thread here, so a
        main-thread scan execution is a loop-blocking regression."""
        import threading
        seen: dict = {}

        def fake_scan(peer, sockname):
            seen["thread"] = threading.current_thread()
            return 4242

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            fake_scan)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        me = SimpleNamespace(_peer_scan_sem=None)

        async def driver():
            return await proxy_mod.EgressProxy._lookup_peer_uid(
                me, ("127.0.0.1", 1), ("127.0.0.1", 2))

        assert self._run(driver()) == 4242, (
            "the scan's verdict must still be delivered on a miss")
        assert seen["thread"] is not threading.main_thread(), (
            "miss-path scan ran on the event-loop thread")
        assert isinstance(me._peer_scan_sem, asyncio.Semaphore), (
            "miss-path scan must be bounded by the scan semaphore")
        assert proxy_mod._SOCK_DIAG_USABLE is True, (
            "a per-peer miss must not latch netlink off")

    def test_seam_fake_none_is_final_no_executor_rerun(
            self, monkeypatch):
        """Seam contract: a monkeypatched _loopback_peer_uid fake's
        None is a VERDICT (exactly one call per lookup — the retry
        policy in _handle_client counts on it), never a cue to re-run
        the lookup in the executor."""
        calls: list = []

        def fake(peer, sockname):
            calls.append(peer)
            return None

        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        monkeypatch.setattr(proxy_mod, "_loopback_peer_uid", fake)
        me = SimpleNamespace(_peer_scan_sem=None)

        async def driver():
            return await proxy_mod.EgressProxy._lookup_peer_uid(
                me, ("127.0.0.1", 1), ("127.0.0.1", 2))

        assert self._run(driver()) is None
        assert len(calls) == 1, (
            "a seam fake's None verdict was second-guessed")
        assert me._peer_scan_sem is None, (
            "a seam fake's None verdict must not engage the executor")

    def test_permit_bound_shared_by_miss_and_latch_scans(
            self, monkeypatch):
        """Miss-path scans (netlink usable, per-peer ENOENT) and
        latch-path scans (netlink off) must contend for the SAME
        _PEER_SCAN_MAX_CONCURRENCY permits: the bound is per proxy,
        not per route. Scans park until the driver releases them, so
        wave 2 (latch route) provably queues behind wave 1's held
        permits; every verdict still resolves and no scan executes on
        the loop thread."""
        import threading
        bound = proxy_mod._PEER_SCAN_MAX_CONCURRENCY
        lock = threading.Lock()
        state = {"cur": 0, "max": 0, "started": 0, "on_loop": 0}
        release = threading.Event()

        def parked_scan(peer, sockname):
            with lock:
                state["cur"] += 1
                state["started"] += 1
                state["max"] = max(state["max"], state["cur"])
                if threading.current_thread() is threading.main_thread():
                    state["on_loop"] += 1
            release.wait(10.0)  # driver-released; bounded backstop
            with lock:
                state["cur"] -= 1
            return 4242

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            parked_scan)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        me = SimpleNamespace(_peer_scan_sem=None)

        def lookup(i: int):
            return proxy_mod.EgressProxy._lookup_peer_uid(
                me, ("127.0.0.1", 1000 + i), ("127.0.0.1", 2))

        async def wait_for(cond, what: str) -> None:
            deadline = asyncio.get_running_loop().time() + 5.0
            while not cond():
                if asyncio.get_running_loop().time() > deadline:
                    pytest.fail(f"timed out waiting for {what}")
                await asyncio.sleep(0.01)

        async def driver():
            wave1 = [asyncio.ensure_future(lookup(i))
                     for i in range(12)]
            # Wave 1 rides the miss route. Its parked scans must
            # saturate the permits before wave 2 exists, so wave 2
            # demonstrably contends with wave 1 for the same bound.
            await wait_for(lambda: state["started"] >= bound,
                           "wave-1 scans to saturate the permits")
            proxy_mod._SOCK_DIAG_USABLE = False  # wave 2: latch route
            wave2 = [asyncio.ensure_future(lookup(12 + i))
                     for i in range(12)]
            # Let wave 2 reach the semaphore while wave 1's parked
            # scans still hold every permit, then release the scans.
            await asyncio.sleep(0)
            release.set()
            return await asyncio.gather(*wave1, *wave2)

        results = asyncio.run(driver())
        assert results == [4242] * 24, "a lookup lost its verdict"
        assert state["started"] == 24, "a lookup skipped its scan"
        assert state["max"] == bound, (
            f"permit bound not honoured across routes: peak "
            f"{state['max']} vs bound {bound}")
        assert state["on_loop"] == 0, (
            "a scan executed on the event-loop thread")


def _connect_raw(port: int, timeout: float = 5.0) -> bytes:
    """Open a TCP connection to the proxy, send a CONNECT, return the
    raw response bytes (b"" when the proxy dropped the connection)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(b"CONNECT denied-host.invalid:443 HTTP/1.1\r\n"
                  b"Host: denied-host.invalid:443\r\n\r\n")
        buf = b""
        try:
            while b"\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        except OSError:
            pass
        return buf
    finally:
        s.close()


class TestForcedMissChurnVerdicts:
    """Verdict byte-identity under the forced-miss shape: routing the
    miss-path scan through the executor must change WHERE the scan
    runs, never what the gate decides."""

    @pytest.fixture
    def reset_proxy(self):
        proxy_mod._reset_for_tests()
        yield
        proxy_mod._reset_for_tests()

    def test_same_uid_peer_served_under_forced_miss(
            self, reset_proxy, monkeypatch):
        # Netlink misses every lookup; the REAL /proc scan (now in
        # the executor) still identifies the same-uid peer, so the
        # CONNECT reaches the policy gates (403 = served, not
        # dropped) and the miss never latches netlink off.
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _connect_raw(proxy.port)
            assert b"403" in buf.split(b"\r\n", 1)[0], (
                "same-uid peer must be served under forced netlink "
                "miss (the scan second opinion owns the verdict)")
            assert proxy_mod._SOCK_DIAG_USABLE is True
        finally:
            proxy.stop()

    def test_unresolvable_peer_fails_closed_under_forced_miss(
            self, reset_proxy, monkeypatch):
        # Netlink misses AND the scan cannot resolve the peer either:
        # on hosts with the socket table the retry-once-then-refuse
        # policy must survive the executor routing (drop with no HTTP
        # response, exactly two dispatcher consultations).
        calls: list = []

        def scan_never_resolves(peer, sockname):
            calls.append(peer)
            return None

        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: None)
        monkeypatch.setattr(proxy_mod, "_peer_uid_via_proc_scan",
                            scan_never_resolves)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        monkeypatch.setattr(proxy_mod, "_PEER_UID_TABLE_AVAILABLE",
                            True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _connect_raw(proxy.port)
            assert buf == b"", (
                "an unverifiable peer must still be dropped when the "
                "miss-path scan rides the executor")
            assert len(calls) == 2, (
                "the retry-once policy must survive the routing")
        finally:
            proxy.stop()


class TestGateEndToEnd:
    """The gate's refusal must be load-bearing with the new primary
    path live: a wrong-uid answer — wherever it came from — still
    drops the connection before any HTTP response."""

    @pytest.fixture
    def reset_proxy(self):
        proxy_mod._reset_for_tests()
        yield
        proxy_mod._reset_for_tests()

    def test_wrong_uid_from_sock_diag_is_dropped(self, reset_proxy,
                                                 monkeypatch):
        # Patch one level BELOW the dispatcher: the netlink primitive
        # itself reports a foreign owner. If the gate were stubbed
        # out (or the dispatcher stopped consulting the primitive),
        # the CONNECT would be served (403 policy response) and this
        # asserts empty-drop — red.
        monkeypatch.setattr(proxy_mod, "_sock_diag_peer_uid",
                            lambda peer, sockname: os.geteuid() + 1)
        monkeypatch.setattr(proxy_mod, "_SOCK_DIAG_USABLE", True)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            s = socket.create_connection(("127.0.0.1", proxy.port),
                                         timeout=5.0)
            try:
                s.sendall(b"CONNECT denied-host.invalid:443 HTTP/1.1\r\n"
                          b"Host: denied-host.invalid:443\r\n\r\n")
                buf = b""
                try:
                    while b"\r\n" not in buf:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                except OSError:
                    pass
            finally:
                s.close()
            assert buf == b"", (
                "cross-user peer (as reported by sock_diag) must be "
                "dropped without a response")
        finally:
            proxy.stop()
