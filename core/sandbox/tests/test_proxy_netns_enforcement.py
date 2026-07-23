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
os.environ.setdefault("RAPTOR_DIR", str(RAPTOR_DIR))
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

@pytest.mark.filterwarnings("ignore::DeprecationWarning:multiprocessing")
@pytest.mark.filterwarnings("ignore:.*multi-threaded.*fork:DeprecationWarning")
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
            capture_output=True, text=True, timeout=10,
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

        # Fork a forwarder.
        death_r, death_w = os.pipe()
        from core.sandbox._proxy_bridge import _run_forwarder

        fwd_pid = os.fork()
        if fwd_pid == 0:
            os.close(death_w)
            try:
                _run_forwarder(19876, sock_path, death_r)
            finally:
                os._exit(0)
        os.close(death_r)

        try:
            time.sleep(0.2)  # let forwarder bind

            # Connect via TCP → forwarder → unix → echo server → back.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 19876))
            s.sendall(b"hello-bridge")
            s.settimeout(5.0)
            got = s.recv(4096)
            s.close()

            assert got == b"hello-bridge"
        finally:
            os.close(death_w)
            os.waitpid(fwd_pid, 0)

    def test_forwarder_exits_on_death_pipe(self):
        """Forwarder exits when death pipe write end is closed."""
        sock_path = str(self.tmp / "noop.sock")
        # Bind a unix socket so the path exists (forwarder won't
        # actually reach it since we close the death pipe immediately).
        noop_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        noop_srv.bind(sock_path)
        noop_srv.listen(1)

        death_r, death_w = os.pipe()
        from core.sandbox._proxy_bridge import _run_forwarder

        fwd_pid = os.fork()
        if fwd_pid == 0:
            os.close(death_w)
            try:
                _run_forwarder(19877, sock_path, death_r)
            finally:
                os._exit(0)
        os.close(death_r)

        # Close write end → forwarder should exit promptly.
        os.close(death_w)
        _, status = os.waitpid(fwd_pid, 0)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0
        noop_srv.close()


# ---------------------------------------------------------------------------
# context.py: proxy_netns fallback path
# ---------------------------------------------------------------------------

class TestProxyNetnsContextWiring:
    """Verify context.py picks the netns path on low ABI."""

    @pytest.fixture(autouse=True)
    def _tmpdir(self, tmp_path):
        self.out = str(tmp_path / "out")
        os.makedirs(self.out, exist_ok=True)

    @pytest.mark.skipif(sys.platform != "linux", reason="netns is Linux-only")
    def test_netns_path_selected_on_low_abi(self):
        """When ABI < 4, sandbox_info reports netns enforcement."""
        from core.sandbox import sandbox

        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=3,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ):
            with sandbox(
                target=self.out,
                output=self.out,
                use_egress_proxy=True,
                proxy_hosts=["example.com"],
            ) as run:
                result = run(
                    ["echo", "proxy-netns-test"],
                    capture_output=True, text=True, timeout=15,
                )
                assert result.returncode == 0
                assert result.sandbox_info.get("proxy_enforcement") == "netns"

    def test_tcp_path_on_high_abi(self):
        """When ABI >= 4, sandbox_info reports landlock_tcp."""
        from core.sandbox import sandbox

        abi = 4
        with mock.patch(
            "core.sandbox.context._get_landlock_abi", return_value=abi,
        ), mock.patch(
            "core.sandbox.context.check_landlock_available",
            return_value=True,
        ):
            with sandbox(
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
        ):
            with sandbox(
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
