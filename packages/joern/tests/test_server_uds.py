"""JoernServer unix-socket tier: client shim, tier selection, live E2E.

The client-shim tests run against a stub unix-socket HTTP server — no
joern, no namespaces (CI-safe). Tier-selection tests patch the netns
probe both ways. The live round-trip needs a joern install and user
namespaces, and is skipped elsewhere.
"""

from __future__ import annotations

import json
import logging
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.joern import server as server_mod
from packages.joern.server import JoernServer


# ── stub unix-socket HTTP server ────────────────────────────────────


class _UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class _StubHandler(BaseHTTPRequestHandler):
    server_version = "stub"
    seen: list[dict] = []  # rebound per fixture

    def _reply(self, obj: dict) -> None:
        out = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8")
        type(self).seen.append({
            "method": "POST", "path": self.path,
            "auth": self.headers.get("Authorization"), "body": body,
        })
        if self.path == "/query":
            self._reply({"uuid": "u-42"})
        else:
            self._reply({"success": True, "stdout": "res0: Int = 2"})

    def do_GET(self) -> None:
        type(self).seen.append({
            "method": "GET", "path": self.path,
            "auth": self.headers.get("Authorization"), "body": "",
        })
        self._reply({"success": True, "stdout": "async-done"})

    def log_message(self, *args) -> None:
        # Also keeps the default implementation's address_string() off
        # the code path — AF_UNIX peers have no host:port client_address.
        pass


@pytest.fixture
def stub_uds():
    """(socket_path, seen-requests list) for a running stub server."""
    with tempfile.TemporaryDirectory(prefix="raptor-joern-uds-test-") as d:
        path = os.path.join(d, "joern.sock")
        handler = type("Handler", (_StubHandler,), {"seen": []})
        srv = _UnixHTTPServer(path, handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            yield path, handler.seen
        finally:
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def short_socket_dir():
    """A tempdir whose paths fit AF_UNIX's sun_path limit.

    pytest's ``tmp_path`` nests deeply under TMPDIR
    (pytest-of-<user>/pytest-N/<long-test-name>N/...), and on hosts
    with a session-scoped TMPDIR the socket path exceeds the ~107-byte
    limit — ``bind()`` errors before the behaviour under test runs.
    ``tempfile.TemporaryDirectory`` (the stub fixture's own idiom)
    stays shallow; when even that is too long the test skips instead
    of erroring on the harness's environment.
    """
    with tempfile.TemporaryDirectory(prefix="raptor-uds-") as d:
        if len(os.path.join(d, "stall.sock")) > 100:
            pytest.skip("TMPDIR too long for an AF_UNIX socket path")
        yield d


def _uds_server(path: str) -> JoernServer:
    srv = JoernServer()
    srv._port = 9999
    srv._base_url = "http://127.0.0.1:9999"
    srv._uds_path = path
    srv._auth_user = "raptor"
    srv._auth_password = "secret-token"
    return srv


class TestUdsClientShim:
    def test_post_sync_roundtrip_preserves_auth(self, stub_uds):
        path, seen = stub_uds
        srv = _uds_server(path)
        data = srv._post_sync("1+1", timeout=5)
        assert data == {"success": True, "stdout": "res0: Int = 2"}
        assert seen[-1]["path"] == "/query-sync"
        assert seen[-1]["auth"] == srv._auth_headers()["Authorization"]
        assert json.loads(seen[-1]["body"]) == {"query": "1+1"}

    def test_post_sync_ignores_httpx_on_uds_tier(self, stub_uds):
        """A present httpx must not re-route the strong tier to TCP."""
        path, _seen = stub_uds
        srv = _uds_server(path)
        httpx_stub = MagicMock()
        with patch("packages.joern.server._httpx", httpx_stub):
            data = srv._post_sync("1+1", timeout=5)
        assert data is not None and data["success"] is True
        httpx_stub.Client.assert_not_called()

    def test_post_async_over_uds(self, stub_uds):
        path, seen = stub_uds
        srv = _uds_server(path)
        assert srv._post_async("1+1") == "u-42"
        assert seen[-1]["path"] == "/query"
        assert seen[-1]["auth"] == srv._auth_headers()["Authorization"]

    def test_get_result_over_uds(self, stub_uds):
        path, seen = stub_uds
        srv = _uds_server(path)
        data = srv._get_result("u-42")
        assert data is not None and data["stdout"] == "async-done"
        assert seen[-1] == {
            "method": "GET", "path": "/result/u-42",
            "auth": srv._auth_headers()["Authorization"], "body": "",
        }

    def test_health_check_over_uds(self, stub_uds):
        path, seen = stub_uds
        srv = _uds_server(path)
        assert srv.health_check() is True
        assert seen[-1]["path"] == "/query-sync"

    def test_missing_socket_classified_as_connection_failure(
        self, short_socket_dir,
    ):
        srv = _uds_server(os.path.join(short_socket_dir, "gone.sock"))
        assert srv._post_sync("1+1", timeout=5) is None
        assert srv._last_post_error.startswith("connection failed:")

    def test_unresponsive_socket_classified_as_timeout(
        self, short_socket_dir,
    ):
        """query() keys its stuck-REPL restart on "timed out" — the
        socket tier must classify a stalled read the same way."""
        import socket as socket_mod

        path = os.path.join(short_socket_dir, "stall.sock")
        listener = socket_mod.socket(socket_mod.AF_UNIX,
                                     socket_mod.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)  # accepts, never reads/answers
        try:
            srv = _uds_server(path)
            assert srv._post_sync("1+1", timeout=1) is None
            assert srv._last_post_error == "query timed out after 1s"
        finally:
            listener.close()


# ── tier selection ──────────────────────────────────────────────────


class TestTierSelection:
    @staticmethod
    def _boot(srv: JoernServer, *, netns: bool) -> list[str]:
        captured: list[str] = []

        def fake_popen(cmd, **kwargs):
            captured.extend(cmd)
            proc = MagicMock()
            proc.pid = 2_000_000_000  # inert: beyond pid_max
            proc.poll.return_value = None
            proc.stderr = MagicMock()
            proc.wait = MagicMock()
            return proc

        with (
            patch("packages.joern.prereqs._java_version", return_value=21),
            patch("packages.joern.server._netns_isolation_available",
                  return_value=netns),
            patch("packages.joern.server._server_auth_supported",
                  return_value=True),
            patch("packages.joern.server._repl_bridge_path",
                  return_value="/opt/joern/repl-bridge"),
            patch("packages.joern.server.subprocess.Popen",
                  side_effect=fake_popen),
            patch.object(srv, "_wait_for_ready", return_value=True),
            patch.object(srv, "_warmup_imports"),
        ):
            srv.start()
        return captured

    @staticmethod
    def _safe_stop(srv: JoernServer) -> None:
        with patch("packages.joern.server.os.killpg",
                   side_effect=ProcessLookupError):
            srv.stop()

    def test_strong_tier_wraps_joern_in_forwarder(self):
        srv = JoernServer()
        cmd = self._boot(srv, netns=True)
        try:
            assert cmd[0] == sys.executable
            assert cmd[1].endswith("netns_forwarder.py")
            assert srv._uds_path is not None
            assert cmd[cmd.index("--socket") + 1] == srv._uds_path
            assert cmd[cmd.index("--port") + 1] == str(srv._port)
            # The wrapped joern command, with its auth flags, follows
            # the "--" separator intact.
            tail = cmd[cmd.index("--") + 1:]
            assert tail[0] == "/opt/joern/repl-bridge"
            assert "--server-auth-password" in tail
            pw = tail[tail.index("--server-auth-password") + 1]
            assert pw == srv._auth_password
            # 0700 socket dir exists before the process is launched.
            assert srv._uds_dir is not None
            assert (os.stat(srv._uds_dir).st_mode & 0o777) == 0o700
        finally:
            self._safe_stop(srv)
        assert srv._uds_path is None
        assert srv._uds_dir is None

    def test_fallback_tier_runs_joern_directly_and_warns(self, caplog):
        srv = JoernServer()
        with caplog.at_level(logging.WARNING, logger="packages.joern.server"):
            cmd = self._boot(srv, netns=False)
        try:
            assert cmd[0] == "/opt/joern/repl-bridge"
            assert srv._uds_path is None
            assert srv._uds_dir is None
            messages = " ".join(r.getMessage() for r in caplog.records)
            assert "network-namespace isolation UNAVAILABLE" in messages
            assert "/proc/<pid>/cmdline" in messages
            assert "DEGRADED" in messages
        finally:
            self._safe_stop(srv)

    def test_strong_tier_does_not_warn(self, caplog):
        srv = JoernServer()
        with caplog.at_level(logging.WARNING, logger="packages.joern.server"):
            self._boot(srv, netns=True)
        try:
            assert "DEGRADED" not in " ".join(
                r.getMessage() for r in caplog.records)
        finally:
            self._safe_stop(srv)

    def test_stop_removes_socket_dir(self):
        srv = JoernServer()
        self._boot(srv, netns=True)
        uds_dir = srv._uds_dir
        assert uds_dir is not None and os.path.isdir(uds_dir)
        self._safe_stop(srv)
        assert not os.path.exists(uds_dir)


class TestMakeUdsDir:
    def test_short_tmpdir_used_as_is(self):
        d = server_mod._make_uds_dir()
        try:
            assert os.path.basename(d).startswith("raptor-joern-uds-")
            assert (os.stat(d).st_mode & 0o777) == 0o700
        finally:
            os.rmdir(d)

    def test_long_tmpdir_falls_back_to_tmp(self, monkeypatch, tmp_path):
        """AF_UNIX sun_path caps at ~108 bytes; a long TMPDIR must not
        produce a socket path the forwarder cannot bind (the probe
        runs under the scrubbed env and would not catch it)."""
        long_root = tmp_path / ("x" * 120)
        long_root.mkdir()
        real_mkdtemp = tempfile.mkdtemp

        def fake_mkdtemp(prefix: str, dir: str | None = None) -> str:
            # No explicit dir = the TMPDIR-honouring call.
            if dir is None:
                dir = str(long_root)
            return real_mkdtemp(prefix=prefix, dir=dir)

        monkeypatch.setattr(server_mod.tempfile, "mkdtemp", fake_mkdtemp)
        d = server_mod._make_uds_dir()
        try:
            sock = os.path.join(d, "joern.sock")
            assert len(sock) <= server_mod._SUN_PATH_MAX_SAFE
            assert d.startswith("/tmp/")
        finally:
            os.rmdir(d)
        assert not any(long_root.iterdir())  # long candidate cleaned up


class TestNetnsProbeCache:
    def test_probe_result_cached(self, monkeypatch) -> None:
        monkeypatch.setattr(server_mod, "_NETNS_PROBE_CACHE", None)
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            proc = MagicMock()
            proc.returncode = 0
            proc.stderr = ""
            return proc

        with patch("packages.joern.server.subprocess.run",
                   side_effect=fake_run):
            assert server_mod._netns_isolation_available() is True
            assert server_mod._netns_isolation_available() is True
        assert len(calls) == 1
        assert calls[0][0] == sys.executable
        assert calls[0][1].endswith("netns_forwarder.py")
        assert calls[0][2] == "--self-probe"
        monkeypatch.setattr(server_mod, "_NETNS_PROBE_CACHE", None)

    def test_probe_failure_means_fallback(self, monkeypatch):
        monkeypatch.setattr(server_mod, "_NETNS_PROBE_CACHE", None)

        def fake_run(cmd, **kwargs):
            proc = MagicMock()
            proc.returncode = 1
            proc.stderr = "netns self-probe failed: refused"
            return proc

        with patch("packages.joern.server.subprocess.run",
                   side_effect=fake_run):
            assert server_mod._netns_isolation_available() is False
        monkeypatch.setattr(server_mod, "_NETNS_PROBE_CACHE", None)


# ── live E2E (joern install + user namespaces required) ─────────────


def _live_ready() -> bool:
    from packages.joern.prereqs import _joern_path
    if _joern_path() is None:
        return False
    try:
        return subprocess.run(
            [sys.executable,
             str(Path(server_mod.__file__).parent / "netns_forwarder.py"),
             "--self-probe"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _live_ready(),
                    reason="needs a joern install and user namespaces")
class TestLiveJoernOverUds:
    def test_boot_query_stop(self):
        srv = JoernServer(boot_timeout_s=240)
        srv.start()
        try:
            assert srv._uds_path is not None, "strong tier expected"
            resp = srv._post_sync("1+1", timeout=60)
            assert resp is not None
            assert resp.get("success", True) is not False
            # The in-namespace TCP port must not exist on the host.
            import socket as socket_mod
            with pytest.raises(OSError):
                socket_mod.create_connection(
                    ("127.0.0.1", srv.port), timeout=2)
        finally:
            srv.stop()
        assert srv._uds_path is None
