"""Per-lane scoping of the egress proxy's audit-log-only mode.

The audit leniency used to be a process-global flag: while ANY audit
sandbox was active, every consumer of the proxy singleton — concurrent
non-audit sandboxes and in-process HTTP/LLM clients alike — had gate 1
downgraded to allow-and-log. Lanes scope the decision to the transport
the connection arrived on: per-context unix sockets (netns tier) and
per-context TCP listeners (Landlock-TCP / seatbelt tiers) carry their
own audit bit; the shared main listener has no lane and stays
enforcing.
"""

import os
import socket

import pytest

import core.sandbox.proxy as proxy_mod

pytestmark = pytest.mark.skipif(
    os.environ.get("RAPTOR_SKIP_PROXY_TESTS") == "1",
    reason="proxy tests disabled",
)

_DENIED = "denied.invalid:443"


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _connect_tcp(port: int, target: str, timeout: float = 5.0) -> int:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        return _drive_connect(s, target)
    finally:
        s.close()


def _connect_unix(path: str, target: str, timeout: float = 5.0) -> int:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    try:
        return _drive_connect(s, target)
    finally:
        s.close()


def _drive_connect(s: socket.socket, target: str) -> int:
    s.sendall((f"CONNECT {target} HTTP/1.1\r\n"
               f"Host: {target}\r\n\r\n").encode("latin-1"))
    buf = b""
    while b"\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = line.split(None, 2)
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0


class TestUnixLaneIsolation:
    def test_audit_bit_scoped_to_one_lane(self, reset_proxy,
                                          short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        try:
            proxy.bind_unix(path_a, label="audit-ctx")
            proxy.bind_unix(path_b, label="normal-ctx")
            assert proxy.set_lane_audit(path_a, True) is True

            token = proxy.register_sandbox(caller_label="lane-test")

            # Audit lane: would-deny falls through to the connect
            # attempt (guaranteed-failing .invalid DNS -> 502-ish,
            # never the gate's 403).
            assert _connect_unix(path_a, _DENIED) != 403
            # Sibling lane and the main listener stay enforcing.
            assert _connect_unix(path_b, _DENIED) == 403
            assert _connect_tcp(proxy.port, _DENIED) == 403

            events = proxy.unregister_sandbox(token)
            would = [e for e in events
                     if e.get("result") == "would_deny_host"]
            denied = [e for e in events
                      if e.get("result") == "denied_host"]
            assert len(would) == 1
            assert would[0].get("lane") == "audit-ctx"
            assert {e.get("lane") for e in denied} == {
                "normal-ctx", "main"}
        finally:
            proxy.stop()

    def test_unbound_lane_key_returns_false(self, reset_proxy, tmp_path):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            assert proxy.set_lane_audit(str(tmp_path / "no.sock"),
                                        True) is False
            assert proxy.set_lane_audit(65001, True) is False
        finally:
            proxy.stop()

    def test_in_flight_connection_keeps_its_lane(self, reset_proxy,
                                                 short_sock_dir):
        # A connection ACCEPTED before unbind is decided by the
        # lane object captured at accept time — deterministic, no
        # enforce/lenient flapping during teardown.
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path = str(short_sock_dir / "w5.sock")
        try:
            proxy.bind_unix(path, label="w5")
            assert proxy.set_lane_audit(path, True) is True
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(path)
            # Deterministic ACCEPTED-before-unbind ordering: wait for
            # the handler task to exist. (A connection still sitting
            # in the backlog at close time is simply never served —
            # verified separately — which also fails closed.)
            import time as _time
            deadline = _time.monotonic() + 5.0
            while not proxy._unix_tasks and _time.monotonic() < deadline:
                _time.sleep(0.01)
            assert proxy._unix_tasks, "handler never accepted"
            try:
                proxy.unbind_unix(path)
                # Lane registry entry is gone...
                assert proxy.set_lane_audit(path, True) is False
                # ...but the accepted connection still carries it.
                assert _drive_connect(s, _DENIED) != 403
            finally:
                s.close()
        finally:
            proxy.stop()


class TestTcpLanes:
    def test_tcp_lane_scoping_and_lifecycle(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            port = proxy.bind_tcp_lane(label="tier2-ctx")
            assert port != proxy.port
            assert proxy.set_lane_audit(port, True) is True
            assert _connect_tcp(port, _DENIED) != 403
            assert _connect_tcp(proxy.port, _DENIED) == 403

            proxy.close_tcp_lane(port)
            assert proxy.set_lane_audit(port, True) is False
            with pytest.raises(OSError):
                socket.create_connection(("127.0.0.1", port),
                                         timeout=1.0)
            # Idempotent.
            proxy.close_tcp_lane(port)
        finally:
            proxy.stop()

    def test_lane_churn_leaves_no_residue(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            for _ in range(30):
                port = proxy.bind_tcp_lane(label="churn")
                proxy.close_tcp_lane(port)
            assert not proxy._tcp_lanes
            assert not proxy._tcp_lane_servers
        finally:
            proxy.stop()


class TestContextWiring:
    """The sandbox() context engages lanes, never the global flag."""

    def _fake_proxy(self):
        class _Fake:
            port = 18080

            def __init__(self):
                self.calls = []

            def bind_unix(self, path, *, label="sandbox",
                          allowed_hosts=None, allowed_ports=None):
                self.calls.append(("bind_unix", path, label))
                self.lane_hosts = allowed_hosts
                self.lane_ports = allowed_ports

            def unbind_unix(self, path):
                self.calls.append(("unbind_unix", path))

            def bind_tcp_lane(self, *, label="sandbox",
                              allowed_hosts=None, allowed_ports=None):
                self.calls.append(("bind_tcp_lane", label))
                self.lane_hosts = allowed_hosts
                self.lane_ports = allowed_ports
                return 18081

            def close_tcp_lane(self, port):
                self.calls.append(("close_tcp_lane", port))

            def set_lane_audit(self, key, value):
                self.calls.append(("set_lane_audit", key, value))
                return True

            def acquire_audit_log_only(self):
                self.calls.append(("acquire_audit",))

            def release_audit_log_only(self):
                self.calls.append(("release_audit",))

            def register_sandbox(self, caller_label=None,
                                 lane_key=None,
                                 host_recon_threshold=None):
                self.calls.append(("register", caller_label, lane_key))
                return 1

            def unregister_sandbox(self, token):
                self.calls.append(("unregister", token))
                return []

            def add_hosts(self, hosts):
                self.calls.append(("add_hosts", tuple(sorted(hosts))))

            def update_idle_timeout(self, seconds):
                pass

        return _Fake()

    def test_tier2_audit_uses_tcp_lane_not_global(self, tmp_path,
                                                  monkeypatch):
        import core.sandbox.context as ctx
        fake = self._fake_proxy()
        monkeypatch.setattr(proxy_mod, "get_proxy",
                            lambda *a, **k: fake)
        # Force the Landlock-TCP tier: no netns capability.
        monkeypatch.setattr(ctx, "check_net_available", lambda: False)
        with ctx.sandbox(use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         audit=True, output=str(tmp_path)):
            pass
        names = [c[0] for c in fake.calls]
        assert "acquire_audit" not in names
        assert "release_audit" not in names
        assert ("bind_tcp_lane", "sandbox") in fake.calls
        assert ("set_lane_audit", 18081, True) in fake.calls
        # Teardown clears the bit and closes the lane.
        assert ("set_lane_audit", 18081, False) in fake.calls
        assert ("close_tcp_lane", 18081) in fake.calls

    def test_audit_clear_precedes_lane_close(self, tmp_path,
                                             monkeypatch):
        """The clear must run BEFORE close_tcp_lane / unbind pops the
        lane from the registry: the real set_lane_audit resolves the
        key through the registry and returns False once the lane is
        popped, so a clear ordered after the pop was a silent no-op —
        connections in flight on the lane (handlers hold the lane
        object) kept log-and-allow leniency until they finished."""
        import core.sandbox.context as ctx
        fake = self._fake_proxy()
        monkeypatch.setattr(proxy_mod, "get_proxy",
                            lambda *a, **k: fake)
        monkeypatch.setattr(ctx, "check_net_available", lambda: False)
        with ctx.sandbox(use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         audit=True, output=str(tmp_path)):
            pass
        clear_idx = fake.calls.index(("set_lane_audit", 18081, False))
        close_idx = fake.calls.index(("close_tcp_lane", 18081))
        assert clear_idx < close_idx, (
            "audit bit cleared after the lane was popped — no-op clear"
        )


class TestLaneScopedEventBuffers:
    """Event buffers subscribe by lane. Pre-fix every event fanned
    into EVERY registered buffer, so concurrent runs saw each other's
    would-deny records."""

    def test_live_events_segregate_across_lanes(self, reset_proxy,
                                                short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        try:
            proxy.bind_unix(path_a, label="run-a")
            proxy.bind_unix(path_b, label="run-b")
            tok_a = proxy.register_sandbox(caller_label="run-a",
                                           lane_key=path_a)
            tok_b = proxy.register_sandbox(caller_label="run-b",
                                           lane_key=path_b)
            tok_g = proxy.register_sandbox(caller_label="global")

            assert _connect_unix(path_a, "a-target.invalid:443") == 403
            assert _connect_unix(path_b, "b-target.invalid:443") == 403

            ev_a = proxy.unregister_sandbox(tok_a)
            ev_b = proxy.unregister_sandbox(tok_b)
            ev_g = proxy.unregister_sandbox(tok_g)
            # Each lane-scoped buffer holds ONLY its own lane's event.
            assert {e["host"] for e in ev_a} == {"a-target.invalid"}
            assert {e["lane"] for e in ev_a} == {"run-a"}
            assert {e["host"] for e in ev_b} == {"b-target.invalid"}
            assert {e["lane"] for e in ev_b} == {"run-b"}
            # The run-global buffer preserves the full pre-lane view.
            assert {e["host"] for e in ev_g} == {
                "a-target.invalid", "b-target.invalid"}
        finally:
            proxy.stop()

    def test_unlaned_event_reaches_global_buffer_only(self, reset_proxy,
                                                      short_sock_dir):
        """Fail-closed direction: an event with no lane attribution
        (main listener, handler errors) lands in the run-global
        buffer — never dropped, never leaked into a lane view."""
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path = str(short_sock_dir / "a.sock")
        try:
            proxy.bind_unix(path, label="run-a")
            tok_lane = proxy.register_sandbox(caller_label="run-a",
                                              lane_key=path)
            tok_g = proxy.register_sandbox(caller_label="global")

            # Main-listener CONNECT: lane is None -> lane_id None.
            assert _connect_tcp(proxy.port, _DENIED) == 403
            # Handler-error-shaped event with NO lane keys at all.
            proxy._record({
                "t": 0.0, "host": None, "port": None,
                "result": "handler_error", "reason": "boom",
                "resolved_ip": None,
                "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
            })

            ev_lane = proxy.unregister_sandbox(tok_lane)
            ev_g = proxy.unregister_sandbox(tok_g)
            assert ev_lane == []
            results = [e["result"] for e in ev_g]
            assert "denied_host" in results
            assert "handler_error" in results
        finally:
            proxy.stop()

    def test_lane_key_lookup_miss_degrades_to_global_view(
            self, reset_proxy, short_sock_dir):
        """A lane_key matching no live lane must over-capture (global
        view), never produce a silently empty audit buffer."""
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path = str(short_sock_dir / "live.sock")
        try:
            proxy.bind_unix(path, label="live")
            tok = proxy.register_sandbox(
                caller_label="orphan",
                lane_key=str(short_sock_dir / "never-bound.sock"),
            )
            assert _connect_unix(path, _DENIED) == 403
            events = proxy.unregister_sandbox(tok)
            assert [e["result"] for e in events] == ["denied_host"]
        finally:
            proxy.stop()

    def test_same_label_lanes_still_segregate(self, reset_proxy,
                                              short_sock_dir):
        """Labels are not unique across concurrent contexts; the
        subscription must key on lane identity, not the label."""
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        try:
            proxy.bind_unix(path_a, label="sandbox")
            proxy.bind_unix(path_b, label="sandbox")
            tok_a = proxy.register_sandbox(lane_key=path_a)
            tok_b = proxy.register_sandbox(lane_key=path_b)
            assert _connect_unix(path_a, "only-a.invalid:443") == 403
            ev_a = proxy.unregister_sandbox(tok_a)
            ev_b = proxy.unregister_sandbox(tok_b)
            assert {e["host"] for e in ev_a} == {"only-a.invalid"}
            assert ev_b == []
        finally:
            proxy.stop()

    def test_context_registers_buffers_with_its_lane(self, tmp_path,
                                                     monkeypatch):
        """The sandbox() context subscribes its event buffers (per-
        spawn and cm-block) to its own transport's lane."""
        import core.sandbox.context as ctx
        fake = TestContextWiring._fake_proxy(TestContextWiring())
        monkeypatch.setattr(proxy_mod, "get_proxy",
                            lambda *a, **k: fake)
        monkeypatch.setattr(ctx, "check_net_available", lambda: False)
        with ctx.sandbox(use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         audit=True, output=str(tmp_path)):
            pass
        registers = [c for c in fake.calls if c[0] == "register"]
        assert registers, "no register_sandbox call observed"
        # Tier-2: the tcp lane port (18081 in the fake) is the key.
        for _name, _label, lane_key in registers:
            assert lane_key == 18081


class TestLaneHostAllowlists:
    """Per-lane hostname allowlists (cross-run confused-deputy
    defence). The proxy's global allowlist is a UNION across
    concurrent runs (get_proxy semantics). Before lane scoping, any
    sandbox could CONNECT to hosts a sibling run had allowlisted. A
    lane bound with allowed_hosts is now additionally scoped to its
    own set; gate 1 denies the rest with a lane-specific reason."""

    def test_lane_scoped_to_its_own_hosts(self, reset_proxy,
                                          short_sock_dir):
        """Host in the GLOBAL union but not in THIS lane's set -> 403;
        the lane's own host passes gate 1 (then fails at DNS -> 502,
        which proves gate-1 passage, not a policy deny)."""
        proxy = proxy_mod.EgressProxy(
            allowed_hosts={"run-a.invalid", "run-b.invalid"},
        )
        try:
            sock_a = str(short_sock_dir / "lane-a.sock")
            proxy.bind_unix(sock_a, label="run-a",
                            allowed_hosts=["run-a.invalid"])
            token = proxy.register_sandbox(caller_label="run-a",
                                           lane_key=sock_a)
            try:
                # Sibling run's host: globally allowlisted, lane-denied.
                assert _connect_unix(sock_a, "run-b.invalid:443") == 403
                # Own host: gate 1 passes; .invalid never resolves -> 502.
                assert _connect_unix(sock_a, "run-a.invalid:443") == 502
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()

        denied = [e for e in events if e.get("result") == "denied_host"]
        assert len(denied) == 1
        assert denied[0]["reason"] == "host not in lane allowlist"
        assert denied[0]["host"] == "run-b.invalid"

    def test_lane_without_allowlist_keeps_global_semantics(
            self, reset_proxy, short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"run-a.invalid"})
        try:
            sock = str(short_sock_dir / "lane.sock")
            proxy.bind_unix(sock, label="legacy")
            # Global-allowed host passes gate 1 (DNS 502); unknown -> 403.
            assert _connect_unix(sock, "run-a.invalid:443") == 502
            assert _connect_unix(sock, "other.invalid:443") == 403
        finally:
            proxy.stop()

    def test_lane_allowlist_case_insensitive(self, reset_proxy,
                                             short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"run-a.invalid"})
        try:
            sock = str(short_sock_dir / "lane.sock")
            proxy.bind_unix(sock, label="run-a",
                            allowed_hosts=["RUN-A.invalid"])
            assert _connect_unix(sock, "Run-A.Invalid:443") == 502
        finally:
            proxy.stop()
