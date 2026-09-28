"""Tests for the private-netns supervisor / unix-socket forwarder.

Two layers, per CI reality (joern and user namespaces may both be
absent):

* Forwarder mechanics (splice, perms, cleanup) run the ``Forwarder``
  in-process against stub TCP servers — no namespaces, no joern.
* Isolation mechanics run the full script in a subprocess with a
  stub python child standing in for joern — skipped without
  unprivileged user namespaces.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from packages.joern import netns_forwarder
from packages.joern.netns_forwarder import Forwarder, create_listener

_SCRIPT = Path(__file__).resolve().parents[1] / "netns_forwarder.py"


def _userns_available() -> bool:
    """Same capability the strong tier needs, probed the same way."""
    try:
        return subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


_HAS_USERNS = _userns_available()
needs_userns = pytest.mark.skipif(
    not _HAS_USERNS, reason="unprivileged user namespaces unavailable",
)


# ── stub upstreams (plain TCP, host namespace) ──────────────────────


class _EchoServer:
    """Reads until client EOF, echoes everything back, closes."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port: int = self._listener.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve, args=(conn,), daemon=True,
            ).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        chunks = []
        try:
            while data := conn.recv(65536):
                chunks.append(data)
            conn.sendall(b"".join(chunks))
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._listener.close()


class _BlastServer:
    """Sends ``size`` bytes immediately on connect, then closes."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port: int = self._listener.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        payload = b"\xab" * self._size
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            try:
                conn.sendall(payload)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._listener.close()


@pytest.fixture
def uds_dir():
    with tempfile.TemporaryDirectory(prefix="raptor-joern-uds-test-") as d:
        yield d


def _forwarder_to(port: int, uds_dir: str) -> tuple[Forwarder, str]:
    path = os.path.join(uds_dir, "joern.sock")
    fwd = Forwarder(create_listener(path), ("127.0.0.1", port),
                    socket_path=path)
    fwd.start()
    return fwd, path


def _uds_client(path: str, timeout: float = 10.0) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except BaseException:
        s.close()
        raise
    return s


class TestForwarderSplice:
    def test_roundtrip_with_half_close(self, uds_dir):
        """Client half-close must reach the upstream as EOF (the echo
        server only responds after EOF), and the response must still
        flow back — the exact shape of an HTTP request over the UDS."""
        upstream = _EchoServer()
        fwd, path = _forwarder_to(upstream.port, uds_dir)
        try:
            c = _uds_client(path)
            c.sendall(b"hello-through-the-namespace")
            c.shutdown(socket.SHUT_WR)
            got = b""
            while data := c.recv(65536):
                got += data
            assert got == b"hello-through-the-namespace"
            c.close()
        finally:
            fwd.stop()
            upstream.close()

    def test_concurrent_connections(self, uds_dir) -> None:
        upstream = _EchoServer()
        fwd, path = _forwarder_to(upstream.port, uds_dir)
        results: dict[int, bytes] = {}
        errors: list[Exception] = []

        def one(i: int) -> None:
            try:
                c = _uds_client(path)
                payload = f"conn-{i}-".encode() * 100
                c.sendall(payload)
                c.shutdown(socket.SHUT_WR)
                got = b""
                while data := c.recv(65536):
                    got += data
                results[i] = got
                c.close()
            except Exception as e:  # noqa: BLE001 — collected for assert
                errors.append(e)

        try:
            threads = [threading.Thread(target=one, args=(i,))
                       for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert not errors
            assert set(results) == set(range(8))
            for i, got in results.items():
                assert got == f"conn-{i}-".encode() * 100
        finally:
            fwd.stop()
            upstream.close()

    def test_large_response_splice(self, uds_dir):
        size = 8 * 1024 * 1024
        upstream = _BlastServer(size)
        fwd, path = _forwarder_to(upstream.port, uds_dir)
        try:
            c = _uds_client(path, timeout=30)
            total = 0
            while data := c.recv(1 << 20):
                total += len(data)
            assert total == size
            c.close()
        finally:
            fwd.stop()
            upstream.close()

    def test_upstream_down_drops_client(self, uds_dir):
        """Boot window: the socket exists before joern accepts — a
        client arriving early must get a clean EOF, not a hang."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            dead_port = s.getsockname()[1]
        fwd, path = _forwarder_to(dead_port, uds_dir)
        try:
            c = _uds_client(path)
            assert c.recv(1) == b""  # EOF, promptly
            c.close()
        finally:
            fwd.stop()


class TestListenerPermissions:
    def test_socket_and_dir_owner_only(self, uds_dir):
        path = os.path.join(uds_dir, "joern.sock")
        listener = create_listener(path)
        try:
            st = os.stat(path)
            assert stat.S_ISSOCK(st.st_mode)
            assert stat.S_IMODE(st.st_mode) == 0o700
            assert stat.S_IMODE(os.stat(uds_dir).st_mode) == 0o700
            assert st.st_uid == os.getuid()
        finally:
            listener.close()

    def test_refuses_lax_parent_dir(self, uds_dir):
        os.chmod(uds_dir, 0o755)
        with pytest.raises(RuntimeError, match="group/world accessible"):
            create_listener(os.path.join(uds_dir, "joern.sock"))

    def test_umask_restored(self, uds_dir):
        before = os.umask(0o022)
        os.umask(before)
        create_listener(os.path.join(uds_dir, "joern.sock")).close()
        after = os.umask(0o022)
        os.umask(after)
        assert after == before


class TestForwarderStop:
    def test_stop_unlinks_socket_and_refuses_new_connections(self, uds_dir):
        upstream = _EchoServer()
        fwd, path = _forwarder_to(upstream.port, uds_dir)
        assert os.path.exists(path)
        fwd.stop()
        upstream.close()
        assert not os.path.exists(path)
        with pytest.raises(OSError):
            _uds_client(path, timeout=2)

    def test_track_after_stop_refuses_and_closes(self, uds_dir):
        # A connection accepted just before stop() can reach _track
        # just after stop()'s sweep of the active set; it must be
        # refused and closed, not registered where no sweep will ever
        # reach it (the peer would hang to its own timeout).
        upstream = _EchoServer()
        fwd, _path = _forwarder_to(upstream.port, uds_dir)
        fwd.stop()
        upstream.close()
        a, b = socket.socketpair()
        try:
            with pytest.raises(OSError):
                fwd._track(a)
            b.settimeout(2)
            assert b.recv(1) == b""  # refused socket was closed: EOF
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def test_handle_after_stop_returns_cleanly(self, uds_dir):
        # The accept loop can hand _handle a connection accepted just
        # before stop(); _track's deliberate refusal must be a clean
        # handler exit, not an exception escaping the handler thread
        # (observed as PytestUnhandledThreadExceptionWarning under
        # shuffled full runs). Called synchronously so a regression is
        # a direct test failure instead of a thread-exception warning.
        upstream = _EchoServer()
        fwd, _path = _forwarder_to(upstream.port, uds_dir)
        fwd.stop()
        upstream.close()
        a, b = socket.socketpair()
        try:
            fwd._handle(a)  # must not raise
            b.settimeout(2)
            assert b.recv(1) == b""  # refused socket was closed: EOF
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def test_stop_closes_inflight_connections(self, uds_dir):
        upstream = _EchoServer()
        fwd, path = _forwarder_to(upstream.port, uds_dir)
        c = _uds_client(path)
        c.sendall(b"partial")  # no half-close: connection stays open
        fwd.stop()
        upstream.close()
        # The forwarder closed its side; the client sees EOF (or a
        # reset) instead of a hang.
        try:
            assert c.recv(65536) == b""
        except OSError:
            pass
        c.close()


# ── full-script isolation mechanics (need user namespaces) ─────────


_STUB_HTTP_CHILD = r"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        out = json.dumps({
            "success": True,
            "auth": self.headers.get("Authorization"),
            "echo": body.decode("utf-8"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"""


class _UnixClientConn(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("127.0.0.1", timeout=10)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self._path)
        self.sock = s


def _wait_for(predicate, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        assert time.monotonic() < deadline, "condition never became true"
        time.sleep(0.1)


@needs_userns
class TestNamespaceIsolation:
    @pytest.fixture
    def running_stack(self, uds_dir):
        """Forwarder script + stub in-namespace HTTP child."""
        path = os.path.join(uds_dir, "joern.sock")
        # Free on the host right now (so "connection refused" below
        # can only come from the namespace boundary); guaranteed free
        # inside the fresh namespace.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        proc = subprocess.Popen(
            [sys.executable, str(_SCRIPT),
             "--socket", path, "--port", str(port),
             "--", sys.executable, "-c", _STUB_HTTP_CHILD, str(port)],
        )
        try:
            _wait_for(lambda: os.path.exists(path))
            yield path, port, proc
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    @staticmethod
    def _uds_roundtrip(path: str) -> dict:
        deadline = time.monotonic() + 15
        while True:
            conn = _UnixClientConn(path)
            try:
                conn.request(
                    "POST", "/query-sync",
                    body=b'{"query":"1+1"}',
                    headers={"Authorization": "Basic dGVzdA==",
                             "Content-Type": "application/json"},
                )
                return json.loads(conn.getresponse().read())
            except (OSError, http.client.HTTPException):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
            finally:
                conn.close()

    def test_host_tcp_unreachable_uds_reachable(self, running_stack):
        """The heart of the design: the in-namespace TCP port does not
        exist on the host, while the unix socket carries a full HTTP
        round-trip with the Authorization header intact."""
        path, port, _proc = running_stack
        data = self._uds_roundtrip(path)  # child is up and serving
        assert data["success"] is True
        assert data["auth"] == "Basic dGVzdA=="
        assert data["echo"] == '{"query":"1+1"}'
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2)

    def test_socket_perms_under_script(self, running_stack):
        path, _port, _proc = running_stack
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700

    def test_supervisor_exits_with_child(self, uds_dir):
        path = os.path.join(uds_dir, "joern.sock")
        proc = subprocess.Popen(
            [sys.executable, str(_SCRIPT),
             "--socket", path, "--port", "46252",
             "--", sys.executable, "-c", "import sys; sys.exit(7)"],
        )
        assert proc.wait(timeout=30) == 7
        assert not os.path.exists(path)

    def test_sigterm_forwarded_and_socket_cleaned(self, running_stack):
        path, _port, proc = running_stack
        self._uds_roundtrip(path)  # fully booted first
        proc.terminate()
        assert proc.wait(timeout=10) != 0
        assert not os.path.exists(path)


class TestSelfProbe:
    def test_probe_exit_code_is_boolean(self):
        rc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe"],
            capture_output=True, timeout=30, check=False,
        ).returncode
        assert rc in (0, 1)

    @needs_userns
    def test_probe_passes_where_userns_works(self):
        assert _HAS_USERNS  # gate and assertion agree by construction


class TestUnmappedEuidHint:
    """The EPERM hint fires only for PermissionError + an empty uid_map."""

    @pytest.fixture
    def empty_map(self, tmp_path, monkeypatch):
        path = tmp_path / "uid_map"
        path.write_bytes(b"")
        monkeypatch.setattr(netns_forwarder, "_UID_MAP_PATH", str(path))
        return path

    def test_euid_unmapped_false_on_this_process(self):
        # Whatever namespace pytest runs in, its creator wrote a map —
        # an empty map would mean this very process couldn't have been
        # set up the way it was.
        assert netns_forwarder._euid_unmapped() is False

    def test_euid_unmapped_true_on_empty_map(self, empty_map):
        assert netns_forwarder._euid_unmapped() is True

    def test_euid_unmapped_false_when_map_unreadable(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            netns_forwarder, "_UID_MAP_PATH", str(tmp_path / "absent"),
        )
        assert netns_forwarder._euid_unmapped() is False

    def _probe_stderr(self, capsys, exc, include_pid=False, monkeypatch=None):
        def _refuse(include_pid=False):
            raise exc

        monkeypatch.setattr(netns_forwarder, "enter_private_netns", _refuse)
        rc = netns_forwarder.self_probe(include_pid=include_pid)
        assert rc == 1
        return capsys.readouterr().err

    def test_hint_on_eperm_with_empty_map(self, capsys, monkeypatch, empty_map):
        err = self._probe_stderr(
            capsys, PermissionError(1, "Operation not permitted"),
            monkeypatch=monkeypatch,
        )
        assert "netns self-probe failed" in err
        assert netns_forwarder._UNMAPPED_EUID_HINT in err

    def test_hint_on_pidns_arm_too(self, capsys, monkeypatch, empty_map):
        err = self._probe_stderr(
            capsys, PermissionError(1, "Operation not permitted"),
            include_pid=True, monkeypatch=monkeypatch,
        )
        assert "pidns self-probe failed" in err
        assert netns_forwarder._UNMAPPED_EUID_HINT in err

    def test_no_hint_when_map_is_populated(self, capsys, monkeypatch, tmp_path):
        path = tmp_path / "uid_map"
        path.write_text("0 0 4294967295\n")
        monkeypatch.setattr(netns_forwarder, "_UID_MAP_PATH", str(path))
        err = self._probe_stderr(
            capsys, PermissionError(1, "Operation not permitted"),
            monkeypatch=monkeypatch,
        )
        assert "self-probe failed" in err
        assert netns_forwarder._UNMAPPED_EUID_HINT not in err

    def test_no_hint_on_other_failures(self, capsys, monkeypatch, empty_map):
        err = self._probe_stderr(
            capsys, RuntimeError("loopback refused"), monkeypatch=monkeypatch,
        )
        assert "self-probe failed" in err
        assert netns_forwarder._UNMAPPED_EUID_HINT not in err

    @needs_userns
    @pytest.mark.skipif(
        shutil.which("unshare") is None, reason="needs the unshare binary",
    )
    def test_hint_end_to_end_under_unmapped_userns(self):
        # A bare `unshare -U` (no uid map) is exactly the misuse the
        # hint exists for: the probe's nested CLONE_NEWUSER gets EPERM.
        proc = subprocess.run(
            ["unshare", "-U", sys.executable, str(_SCRIPT), "--self-probe"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert proc.returncode == 1
        assert "self-probe failed" in proc.stderr
        assert "unshare --map-current-user" in proc.stderr
