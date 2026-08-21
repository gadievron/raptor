"""Tests for proxy enforcement via network namespace + unix socket bridge.

Validates that when Landlock's TCP allowlist is unavailable (ABI < 4),
the sandbox falls back to putting the child in an empty network
namespace and relaying through a TCP→Unix forwarder.
"""
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

RAPTOR_DIR = Path(__file__).resolve().parents[3]
# Hard-SET (never setdefault): the code under test derives paths from
# RAPTOR_DIR; an ambient value for another checkout must not win.
os.environ["RAPTOR_DIR"] = str(RAPTOR_DIR)
if str(RAPTOR_DIR) not in sys.path:
    sys.path.insert(0, str(RAPTOR_DIR))


# ---------------------------------------------------------------------------
# proxy.py: bind_unix / unbind_unix
# ---------------------------------------------------------------------------

class TestProxyUnixSocket:
    """EgressProxy.bind_unix / unbind_unix lifecycle."""

    @pytest.fixture(autouse=True)
    def _proxy(self, tmp_path):
        from core.sandbox.proxy import EgressProxy
        self.proxy = EgressProxy(["example.com"])
        # macOS AF_UNIX sun_path limit is 104 bytes; pytest tmp_path
        # under /private/var/folders/… can exceed that. Use a short
        # name under /tmp when the default path would be too long.
        candidate = str(tmp_path / "p.sock")
        if len(candidate) > 100:
            import tempfile
            short_dir = tempfile.mkdtemp(prefix="rpt_")
            self.sock_path = os.path.join(short_dir, "p.sock")
            self._short_dir = short_dir
        else:
            self.sock_path = candidate
            self._short_dir = None
        yield
        self.proxy.stop(drain_timeout=0)
        if self._short_dir:
            import shutil
            shutil.rmtree(self._short_dir, ignore_errors=True)

    def test_bind_creates_socket_file(self):
        self.proxy.bind_unix(self.sock_path)
        assert os.path.exists(self.sock_path)
        st = os.stat(self.sock_path)
        import stat
        assert stat.S_ISSOCK(st.st_mode)

    def test_unbind_removes_socket_file(self):
        self.proxy.bind_unix(self.sock_path)
        assert os.path.exists(self.sock_path)
        self.proxy.unbind_unix(self.sock_path)
        assert not os.path.exists(self.sock_path)

    def test_unbind_idempotent(self):
        self.proxy.bind_unix(self.sock_path)
        self.proxy.unbind_unix(self.sock_path)
        self.proxy.unbind_unix(self.sock_path)  # no error

    def test_connect_via_unix_socket(self):
        """CONNECT through the unix socket and get a response."""
        self.proxy.bind_unix(self.sock_path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.sock_path)
            s.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n\r\n"
            )
            resp = s.recv(4096)
            # Proxy may return 200 (if DNS resolves) or 502 (if not).
            # Either is a valid protocol response proving the unix
            # socket path works end-to-end.
            assert resp.startswith(b"HTTP/1.1 ")
        finally:
            s.close()

    def test_denied_host_via_unix_socket(self):
        """Non-allowlisted host is denied through unix socket too."""
        self.proxy.bind_unix(self.sock_path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.sock_path)
            s.sendall(
                b"CONNECT evil.example:443 HTTP/1.1\r\n"
                b"Host: evil.example:443\r\n\r\n"
            )
            resp = s.recv(4096)
            assert b"403" in resp
        finally:
            s.close()

    def test_stop_cleans_up_unix_servers(self):
        self.proxy.bind_unix(self.sock_path)
        self.proxy.stop(drain_timeout=0)
        assert not os.path.exists(self.sock_path)

    def test_peer_check_allows_unix(self):
        """Unix socket connections have no peer IP — must not be
        rejected by the loopback-only check."""
        self.proxy.bind_unix(self.sock_path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.sock_path)
            s.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n\r\n"
            )
            resp = s.recv(4096)
            # NOT rejected with "non-loopback peer"
            assert b"non-loopback" not in resp.lower()
            assert resp.startswith(b"HTTP/1.1 ")
        finally:
            s.close()


# ---------------------------------------------------------------------------
# _proxy_bridge.py: bring_up_loopback + _run_forwarder
# ---------------------------------------------------------------------------

def _free_loopback_port() -> int:
    """Ephemeral free port on 127.0.0.1.

    The forwarder tests used FIXED ports (19876/19877): a concurrent
    session running the same suite collides outright, and even a
    solo back-to-back rerun used to fail on the TIME_WAIT remnant
    before _run_forwarder gained SO_REUSEADDR. A kernel-assigned
    port sidesteps both.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _connect_with_retry(port: int, deadline_s: float = 5.0) -> socket.socket:
    """Connect to a just-spawned forwarder, retrying while it binds.

    A fixed pre-connect sleep is not hermetic: under full-suite load
    the spawned forwarder can take longer than the sleep to import and
    bind, and the parent's connect() then fails with ECONNREFUSED.
    Retry until the deadline instead.
    """
    end = time.monotonic() + deadline_s
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
            return s
        except OSError:
            s.close()
            if time.monotonic() >= end:
                raise
            time.sleep(0.05)


def _spawn_forwarder(port, sock_path, death_r):
    """Run ``_run_forwarder`` in a FRESH single-threaded interpreter.

    These tests used to ``os.fork()`` the forwarder, but the test
    process is legitimately multi-threaded by the time they run under
    a full-suite order: the egress-proxy singleton's daemon thread
    (``raptor-egress-proxy``), started by any earlier sandbox test,
    lives for the whole process, and two of the tests below start
    their own echo threads before launching the forwarder. Forking
    there draws Python's multi-threaded-fork DeprecationWarning on
    every run. The forwarder only needs importable module code plus
    one inherited fd, so a subprocess (fork+exec into a fresh,
    single-threaded interpreter) preserves the semantics without the
    fork hazard. ``pass_fds`` keeps ``death_r``'s descriptor number
    intact in the child; the caller still closes its own copy.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(RAPTOR_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    code = (
        "import sys\n"
        "from core.sandbox._proxy_bridge import _run_forwarder\n"
        "_run_forwarder(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))\n"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code, str(port), sock_path, str(death_r)],
        pass_fds=(death_r,), env=env,
    )


class TestProxyBridge:
    """TCP-to-Unix forwarder integration."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        # Short tmpdir for AF_UNIX path limit on macOS (104 bytes).
        candidate = str(tmp_path / "r.sock")
        if len(candidate) > 100:
            import tempfile
            self.tmp = Path(tempfile.mkdtemp(prefix="rpt_"))
            self._short_dir = self.tmp
        else:
            self.tmp = tmp_path
            self._short_dir = None
        yield
        if self._short_dir:
            import shutil
            shutil.rmtree(str(self._short_dir), ignore_errors=True)

    @pytest.mark.skipif(sys.platform != "linux", reason="os.unshare is Linux-only")
    def test_bring_up_loopback_in_netns(self):
        """bring_up_loopback works inside a fresh netns (requires
        CAP_NET_ADMIN in a user-ns)."""
        script = (
            "import os, socket, struct\n"
            "os.unshare(0x40000000 | 0x10000000)\n"  # NEWUSER | NEWNET
            "from core.sandbox._proxy_bridge import _bring_up_loopback\n"
            "_bring_up_loopback()\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.bind(('127.0.0.1', 0))\n"
            "print('OK', s.getsockname())\n"
            "s.close()\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=10, check=False,
            env={"PYTHONPATH": str(RAPTOR_DIR), "PATH": os.environ["PATH"]},
        )
        if result.returncode != 0 and "PermissionError" in result.stderr:
            pytest.skip(
                "SIOCSIFFLAGS denied — kernel or seccomp blocks "
                "CAP_NET_ADMIN inside user namespaces"
            )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_forwarder_relays_data(self):
        """_run_forwarder bridges TCP ↔ Unix socket."""
        sock_path = str(self.tmp / "relay.sock")
        port = _free_loopback_port()

        # Stand up a simple unix socket echo server.
        echo_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        echo_srv.bind(sock_path)
        echo_srv.listen(1)

        def _echo():
            conn, _ = echo_srv.accept()
            try:
                data = conn.recv(4096)
                if data:
                    conn.sendall(data)
            finally:
                conn.close()
            echo_srv.close()

        echo_thread = threading.Thread(target=_echo, daemon=True)
        echo_thread.start()

        # Launch a forwarder in a fresh interpreter.
        death_r, death_w = os.pipe()
        fwd = _spawn_forwarder(port, sock_path, death_r)
        os.close(death_r)

        try:
            # Connect via TCP → forwarder → unix → echo server → back.
            # Retries while the spawned forwarder starts up and binds — a
            # fixed sleep is not hermetic under full-suite load.
            s = _connect_with_retry(port)
            s.sendall(b"hello-bridge")
            s.settimeout(5.0)
            got = s.recv(4096)
            s.close()

            assert got == b"hello-bridge"
        finally:
            os.close(death_w)
            fwd.wait(timeout=10)

    def test_forwarder_concurrent_connections_with_churn(self):
        """Multiple simultaneous relays with interleaved teardown must
        not cross-contaminate. Regression cover for the readable-
        snapshot restructure: a relay fd closed earlier in a select
        iteration must be skipped (not read/closed again), and accepts
        are deferred until after the snapshot is processed so a fresh
        connection can't alias a just-closed fd number."""
        sock_path = str(self.tmp / "churn.sock")
        echo_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        echo_srv.bind(sock_path)
        echo_srv.listen(64)
        stop = threading.Event()

        def _echo_loop():
            # Echo each connection's bytes back until EOF.
            conns = []
            echo_srv.settimeout(0.1)
            while not stop.is_set():
                try:
                    conn, _ = echo_srv.accept()
                except OSError:
                    pass
                else:
                    conn.setblocking(False)
                    conns.append(conn)
                for c in list(conns):
                    try:
                        data = c.recv(4096)
                    except BlockingIOError:
                        continue
                    except OSError:
                        conns.remove(c)
                        c.close()
                        continue
                    if not data:
                        conns.remove(c)
                        c.close()
                        continue
                    try:
                        c.sendall(data)
                    except OSError:
                        conns.remove(c)
                        c.close()
            for c in conns:
                c.close()
            echo_srv.close()

        echo_thread = threading.Thread(target=_echo_loop, daemon=True)
        echo_thread.start()

        port = _free_loopback_port()
        death_r, death_w = os.pipe()
        fwd = _spawn_forwarder(port, sock_path, death_r)
        os.close(death_r)

        try:
            # Rapid rounds of: open several connections, exchange a
            # unique payload on each, abruptly close some while others
            # are mid-flight, verify the survivors' payloads are
            # intact (no bytes from a torn-down relay leak in).
            for round_no in range(10):
                socks = []
                for i in range(6):
                    s = _connect_with_retry(port)
                    s.settimeout(5.0)
                    socks.append(s)
                # Abruptly close half BEFORE any traffic — their
                # teardown lands in the same select snapshots as the
                # survivors' data + new accepts.
                for s in socks[::2]:
                    s.close()
                survivors = socks[1::2]
                for i, s in enumerate(survivors):
                    payload = f"r{round_no}-c{i}".encode() * 50
                    s.sendall(payload)
                    got = b""
                    while len(got) < len(payload):
                        chunk = s.recv(4096)
                        assert chunk, (
                            f"round {round_no} conn {i}: relay died "
                            f"mid-payload (got {len(got)} bytes)"
                        )
                        got += chunk
                    assert got == payload, (
                        f"round {round_no} conn {i}: payload corrupted"
                    )
                for s in survivors:
                    s.close()
        finally:
            stop.set()
            os.close(death_w)
            fwd.wait(timeout=10)
            echo_thread.join(timeout=5)

    def test_forwarder_exits_on_death_pipe(self):
        """Forwarder exits when death pipe write end is closed."""
        sock_path = str(self.tmp / "noop.sock")
        # Bind a unix socket so the path exists (forwarder won't
        # actually reach it since we close the death pipe immediately).
        noop_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        noop_srv.bind(sock_path)
        noop_srv.listen(1)

        death_r, death_w = os.pipe()
        fwd = _spawn_forwarder(_free_loopback_port(), sock_path, death_r)
        os.close(death_r)

        # Close write end → forwarder should exit promptly.
        os.close(death_w)
        assert fwd.wait(timeout=10) == 0
        noop_srv.close()


# ---------------------------------------------------------------------------
# context.py: proxy_netns fallback path
# ---------------------------------------------------------------------------

def _spawn_backend_live() -> bool:
    """Production gates for the netns bridge tier (Tier 1): the
    forwarder rides the fork spawn backend, which needs REAL userns +
    mount-ns capability — the same probes context.py consults. Late
    attribute lookup (``probes.check_...``) so a harness that patches
    the probe module is honoured."""
    if sys.platform != "linux":
        return False
    from core.sandbox import probes
    return probes.check_net_available() and probes.check_mount_available()


class TestProxyNetnsContextWiring:
    """Verify context.py routes between the egress tiers on the
    production gates: netns bridge (Tier 1) needs the SPAWN backend
    (net capability AND the mount probe), any Landlock ABI; without
    the backend the context takes the Landlock TCP pin (ABI >= 4) /
    advisory (ABI < 4) tier — both reported as ``landlock_tcp``.

    The probe inputs are pinned by mock so each test asserts the TIER
    DECISION for one explicit host shape; tests whose decision lands
    on the netns tier additionally gate on the REAL probes because
    they spawn a live child through that tier."""

    @pytest.fixture(autouse=True)
    def _tmpdir(self, tmp_path):
        self.out = str(tmp_path / "out")
        os.makedirs(self.out, exist_ok=True)

    @pytest.fixture
    def _fresh_tier2_latch(self):
        """Give the test an unfired tier-2 warn-once latch.

        The warning is once-per-PROCESS; under shuffled full-suite
        order any earlier egress-proxy sandbox that lands on the
        Landlock tier — including tests OUTSIDE this directory, which
        this dir's ``_sandbox_state_guard`` conftest cannot restore —
        consumes the once and the assertions below see zero WARNING
        records. Resetting up front makes each tier-2 test own its
        latch state; the conftest guard still restores the pre-test
        value afterwards, so process-global semantics are preserved
        for everything else."""
        from core.sandbox import state
        state.reset_warn_once("_proxy_tier2_port_pin_warned")

    def _enforcement_with(self, *, abi: int, net: bool, mount: bool):
        """Run a trivial child with the probe surface pinned; return
        the proxy_enforcement the context chose."""
        from core.sandbox import sandbox

        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=abi,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available",
            return_value=net,
        ), mock.patch(
            "core.sandbox.context.check_mount_available",
            return_value=mount,
        ), sandbox(
            target=self.out,
            output=self.out,
            use_egress_proxy=True,
            proxy_hosts=["example.com"],
        ) as run:
            result = run(
                ["echo", "proxy-tier-test"],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0
            return result.sandbox_info.get("proxy_enforcement")

    @pytest.mark.skipif(
        not _spawn_backend_live(),
        reason="netns tier spawns a live child through the fork "
               "backend (needs real userns + mount-ns capability)",
    )
    def test_netns_path_selected_on_low_abi(self):
        """ABI < 4 with the spawn backend live → netns enforcement."""
        assert self._enforcement_with(abi=3, net=True, mount=True) == "netns"

    @pytest.mark.skipif(
        not _spawn_backend_live(),
        reason="netns tier spawns a live child through the fork "
               "backend (needs real userns + mount-ns capability)",
    )
    def test_netns_tier_wins_on_high_abi(self):
        """netns is the strongest tier and wins on ANY ABI when the
        spawn backend is live — the Landlock pin is port-scoped to
        any host and needs the seccomp UDP block, so ABI >= 4 no
        longer routes to landlock_tcp on backend-capable hosts."""
        assert self._enforcement_with(abi=4, net=True, mount=True) == "netns"

    def test_landlock_tcp_when_mount_probe_fails_on_high_abi(self):
        """netns capability alone is NOT enough: without the mount-ns
        spawn backend there is no forwarder, so the context must take
        the Landlock TCP pin tier (the netns tier would hand the child
        an empty namespace with no route to the proxy)."""
        assert (self._enforcement_with(abi=4, net=True, mount=False)
                == "landlock_tcp")

    def test_advisory_tier_when_mount_probe_fails_on_low_abi(self):
        """Same mount-gate routing on ABI < 4: the advisory tier
        (env-vars only) is reported under the same non-netns label."""
        assert (self._enforcement_with(abi=3, net=True, mount=False)
                == "landlock_tcp")

    def _egress_with(self, *, abi, net, mount, require_proxy_netns):
        """Like _enforcement_with but lets the caller set
        require_proxy_netns; returns the chosen proxy_enforcement."""
        from core.sandbox import sandbox
        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=abi,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available", return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available", return_value=net,
        ), mock.patch(
            "core.sandbox.context.check_mount_available", return_value=mount,
        ), sandbox(
            target=self.out, output=self.out, use_egress_proxy=True,
            proxy_hosts=["example.com"], require_proxy_netns=require_proxy_netns,
        ) as run:
            result = run(["echo", "x"], capture_output=True, text=True, timeout=15)
            return result.sandbox_info.get("proxy_enforcement")

    def _enter_egress(self, *, platform, net, mount, require, env=None, monkeypatch=None):
        """Enter sandbox() with the probe/platform surface pinned and exit
        WITHOUT running a child — exercises the 00015 setup-time guard,
        which fires (or not) at __enter__ before any child executes."""
        import core.sandbox.context as ctx
        from core.sandbox import sandbox
        if env and monkeypatch:
            monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", env)
        with mock.patch.object(ctx.sys, "platform", platform), mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=4,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available", return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available", return_value=net,
        ), mock.patch(
            "core.sandbox.context.check_mount_available", return_value=mount,
        ):
            with sandbox(
                target=self.out, output=self.out, use_egress_proxy=True,
                proxy_hosts=["example.com"], require_proxy_netns=require,
            ):
                pass

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_require_proxy_netns_fails_closed_on_linux_degraded(self):
        """00015: on a Linux net-yes/mount-no host, an untrusted-egress
        caller requiring the netns tier is REFUSED (not silently port-pinned)."""
        from core.sandbox.errors import SandboxSetupError
        with pytest.raises(SandboxSetupError, match="netns egress tier"):
            self._enter_egress(platform="linux", net=True, mount=False, require=True)

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_require_proxy_netns_override_bypasses_guard_on_linux(self, monkeypatch):
        """The operator override lets the degraded tier through explicitly
        (the setup-time guard does not fire)."""
        # No SandboxSetupError('netns egress tier') should be raised.
        self._enter_egress(platform="linux", net=True, mount=False, require=True,
                           env="1", monkeypatch=monkeypatch)

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_require_proxy_netns_falsey_override_keeps_guard(self, monkeypatch):
        """A falsey override value (0/false/off) must NOT bypass the guard —
        the guard uses strict truthiness, matching _require_userns_or_optin."""
        from core.sandbox.errors import SandboxSetupError
        for val in ("0", "false", "off", "no", ""):
            with pytest.raises(SandboxSetupError, match="netns egress tier"):
                self._enter_egress(platform="linux", net=True, mount=False,
                                   require=True, env=val, monkeypatch=monkeypatch)

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_require_proxy_netns_not_enforced_on_darwin(self):
        """Regression (macOS blocker): macOS uses seatbelt (a different
        enforcement path) where _use_proxy_netns is always False; the guard
        must NOT fire there, or every macOS untrusted-egress caller breaks."""
        # net/mount irrelevant on darwin; the guard is scoped out entirely.
        self._enter_egress(platform="darwin", net=True, mount=False, require=True)

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_require_proxy_netns_flag_off_does_not_fire_on_linux(self):
        """Without the flag (trusted egress callers), the guard never fires."""
        self._enter_egress(platform="linux", net=True, mount=False, require=False)

    def test_tcp_path_when_netns_unavailable(self):
        """Without netns capability, ABI >= 4 falls back to the
        Landlock TCP pin tier — the pre-generalisation posture."""
        from core.sandbox import sandbox

        abi = 4
        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=abi,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available",
            return_value=False,
        ), sandbox(
            target=self.out,
            output=self.out,
            use_egress_proxy=True,
            proxy_hosts=["example.com"],
        ) as run:
            result = run(
                ["echo", "proxy-tcp-test"],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0
            assert result.sandbox_info.get("proxy_enforcement") == "landlock_tcp"

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_tier2_port_pin_warns_and_records_evidence(self, caplog):
        """Tier-2 engagement (Landlock TCP port pin) must be
        operator-visible — a WARNING naming the weaker port-scoped
        guarantee (pre-fix it was DEBUG-silent) — and the reduced
        guarantee must land in the per-run sandbox_info evidence."""
        import logging

        from core.sandbox import sandbox

        abi = 4
        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=abi,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available",
            return_value=False,
        ), caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
            with sandbox(
                target=self.out,
                output=self.out,
                use_egress_proxy=True,
                proxy_hosts=["example.com"],
            ) as run:
                result = run(
                    ["echo", "tier2-warn-test"],
                    capture_output=True, text=True, timeout=15,
                )
        assert result.returncode == 0
        assert result.sandbox_info.get("proxy_enforcement") == "landlock_tcp"
        tier2_warnings = [
            r for r in caplog.records
            if "Landlock TCP port pin" in r.getMessage()
            and "ANY address" in r.getMessage()
        ]
        assert tier2_warnings, (
            "tier-2 engagement must emit an operator-visible WARNING "
            "naming the any-address-on-port weakening")
        evidence = result.sandbox_info.get("evidence", "")
        assert "landlock_tcp port pin" in evidence
        assert "any address on the proxy port" in evidence

    @pytest.mark.usefixtures("_fresh_tier2_latch")
    def test_tier2_warning_is_once_per_process(self, caplog):
        """Two tier-2 contexts → exactly one WARNING (warn_once)."""
        import logging

        from core.sandbox import sandbox

        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=4,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ), mock.patch(
            "core.sandbox.context.check_net_available",
            return_value=False,
        ), caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
            for _ in range(2):
                with sandbox(
                    target=self.out,
                    output=self.out,
                    use_egress_proxy=True,
                    proxy_hosts=["example.com"],
                ):
                    pass
        tier2_warnings = [
            r for r in caplog.records
            if "Landlock TCP port pin" in r.getMessage()
        ]
        assert len(tier2_warnings) == 1

    def test_fallback_on_unix_bind_failure(self):
        """If bind_unix fails, falls back to TCP-only without crash."""
        from core.sandbox import sandbox

        def _fail_bind(*a, **kw):
            raise OSError("mock bind failure")

        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=3,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ), mock.patch(
            "core.sandbox.proxy.EgressProxy.bind_unix",
            side_effect=_fail_bind,
        ), sandbox(
            target=self.out,
            output=self.out,
            use_egress_proxy=True,
            proxy_hosts=["example.com"],
        ) as run:
            result = run(
                ["echo", "fallback-test"],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0
            assert result.sandbox_info.get("proxy_enforcement") == "landlock_tcp"
