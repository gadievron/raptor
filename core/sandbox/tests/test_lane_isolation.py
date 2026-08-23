"""Unix-lane instance isolation: private lane dirs + peer-credential gate.

Battery shape (cross-context lane confused deputy): two sandbox
contexts sharing an output directory each had their proxy lane socket
placed IN that directory. Any process sharing the rw bind — the
sibling sandbox's child included — could readdir-discover the other
context's `.raptor-proxy-*.sock` and connect, having its CONNECTs
judged by the sibling's allowlist and audit bit.

Two-layer fix pinned here:
1. Lane sockets live in a private per-instance 0700 directory
   (mkdtemp token in the name), never in the shared output dir; the
   directory is removed with the context.
2. The lane itself verifies SO_PEERCRED at accept: same uid AND a pid
   that is either the proxy's own process or inside a process tree the
   spawn layer registered for the current run. Anything else is
   dropped without a protocol response.
"""

import glob
import os
import socket
import subprocess
import sys
import tempfile

import pytest

import core.sandbox.proxy as proxy_mod

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux",
                       reason="SO_PEERCRED lane gate is Linux-only"),
    pytest.mark.skipif(
        os.environ.get("RAPTOR_SKIP_PROXY_TESTS") == "1",
        reason="proxy tests disabled"),
]

_DENIED = "denied.invalid:443"


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _drive_connect(s: socket.socket, target: str) -> bytes:
    s.sendall((f"CONNECT {target} HTTP/1.1\r\n"
               f"Host: {target}\r\n\r\n").encode("latin-1"))
    buf = b""
    try:
        while b"\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (ConnectionResetError, TimeoutError):
        pass
    return buf


def _connect_unix(path: str, target: str = _DENIED) -> bytes:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    try:
        return _drive_connect(s, target)
    finally:
        s.close()


# Child program: wait for a go-byte on stdin (so the parent can
# register/skip-register its pid first), connect to the lane socket,
# CONNECT to a denied host, and report the raw response.
_CHILD = r"""
import socket, sys
sys.stdin.buffer.read(1)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sys.argv[1])
buf = b""
try:
    # The send sits inside the tolerant block: when the peer gate
    # rejects this process, the proxy may close the socket before the
    # bytes are written, so under load sendall itself raises
    # BrokenPipeError/ConnectionResetError. A refusal during send is
    # the same (stronger) outcome as EOF during recv — either way the
    # child saw no protocol response.
    s.sendall(b"CONNECT denied.invalid:443 HTTP/1.1\r\n"
              b"Host: denied.invalid\r\n\r\n")
    while b"\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
except (BrokenPipeError, ConnectionResetError, TimeoutError):
    pass
sys.stdout.buffer.write(buf or b"NO-RESPONSE")
"""


def _child_connect(path: str) -> tuple[subprocess.Popen, "callable"]:
    """Start the connecting child, paused before its connect."""
    p = subprocess.Popen(
        [sys.executable, "-c", _CHILD, path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )

    def go() -> bytes:
        out, _ = p.communicate(input=b"g", timeout=30)
        return out

    return p, go


class TestUnixLanePeerGate:
    def test_own_process_still_served(self, reset_proxy, short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path = str(short_sock_dir / "own.sock")
        try:
            proxy.bind_unix(path, label="ctx")
            # In-process consumer (== proxy pid): gate admits, policy
            # answers 403 for the denied host.
            assert b"403" in _connect_unix(path)
        finally:
            proxy.stop()

    def test_unregistered_foreign_pid_dropped(self, reset_proxy,
                                              short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path = str(short_sock_dir / "victim.sock")
        try:
            proxy.bind_unix(path, label="victim-ctx")
            p, go = _child_connect(path)
            out = go()
            assert p.returncode == 0
            assert b"HTTP/" not in out, (
                f"foreign process received a protocol response from a "
                f"lane it was never registered for: {out!r}"
            )
        finally:
            proxy.stop()

    def test_registered_tree_admitted(self, reset_proxy, short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path = str(short_sock_dir / "run.sock")
        try:
            proxy.bind_unix(path, label="run-ctx")
            p, go = _child_connect(path)
            assert proxy.add_lane_peer_root(path, p.pid) is True
            try:
                out = go()
                assert b"403" in out, (
                    f"registered run tree must be served (got {out!r})"
                )
            finally:
                proxy.discard_lane_peer_root(path, p.pid)
        finally:
            proxy.stop()

    def test_registration_withdrawn_after_run(self, reset_proxy,
                                              short_sock_dir):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path = str(short_sock_dir / "done.sock")
        try:
            proxy.bind_unix(path, label="done-ctx")
            p1, go1 = _child_connect(path)
            proxy.add_lane_peer_root(path, p1.pid)
            assert b"403" in go1()
            proxy.discard_lane_peer_root(path, p1.pid)
            p2, go2 = _child_connect(path)
            assert b"HTTP/" not in go2(), (
                "peer-root authorisation must not outlive the run"
            )
        finally:
            proxy.stop()

    def test_cross_lane_registration_does_not_transfer(
            self, reset_proxy, short_sock_dir):
        """b6-lane-cross unit shape: a tree registered for lane A must
        not be served by sibling lane B."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        try:
            proxy.bind_unix(path_a, label="ctx-a")
            proxy.bind_unix(path_b, label="ctx-b",
                            allowed_hosts=["cross-victim.example.com"])
            p, go = _child_connect(path_b)
            proxy.add_lane_peer_root(path_a, p.pid)  # registered for A
            out = go()  # ...connects to B
            assert b"HTTP/" not in out, (
                f"lane B served a tree registered only for lane A: {out!r}"
            )
        finally:
            proxy.stop()

    def test_add_peer_root_unknown_lane_returns_false(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            assert proxy.add_lane_peer_root("/nonexistent.sock", 1) is False
        finally:
            proxy.stop()


class TestLaneSocketPlacement:
    """The lane socket must not live in the shared output dir."""

    def _netns_capable(self):
        from core.sandbox import (
            check_mount_available,
            check_net_available,
        )
        import shutil
        return (check_net_available() and check_mount_available()
                and shutil.which("newuidmap"))

    def test_lane_socket_outside_output_dir(self, reset_proxy):
        if not self._netns_capable():
            pytest.skip("netns proxy tier unavailable on this host")
        from core.sandbox import sandbox
        with tempfile.TemporaryDirectory(prefix="raptor-lanep-") as out:
            lane_dirs_before = set(glob.glob(
                os.path.join(tempfile.gettempdir(), ".raptor-lane-*")))
            with sandbox(use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         output=out, block_network=True) as _run:
                assert not glob.glob(os.path.join(
                    out, ".raptor-proxy-*.sock")), (
                    "lane socket leaked into the shared output dir"
                )
                new_dirs = set(glob.glob(os.path.join(
                    tempfile.gettempdir(), ".raptor-lane-*"),
                )) - lane_dirs_before
                assert new_dirs, "expected a private per-instance lane dir"
                for d in new_dirs:
                    mode = os.stat(d).st_mode & 0o777
                    assert mode == 0o700, (
                        f"lane dir {d} mode {oct(mode)}, want 0700"
                    )
            after = set(glob.glob(os.path.join(
                tempfile.gettempdir(), ".raptor-lane-*"))) - lane_dirs_before
            assert not after, f"lane dir not cleaned up: {after}"
