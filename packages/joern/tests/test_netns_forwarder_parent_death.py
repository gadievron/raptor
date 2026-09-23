"""Orphan+idle containment for the netns forwarder supervisor.

Parent death alone is NORMAL for this pair — the lifecycle layer keeps
warm servers alive across RAPTOR runs for reuse — so the watchdog
reaps only when the supervisor is orphaned AND has seen no client
activity for the lifecycle's staleness horizon. No spawn-side signal
can cover this: PR_SET_PDEATHSIG is cleared by the forwarder's own
``unshare(CLONE_NEWUSER)``.

Two layers, mirroring test_netns_forwarder.py:

* ``Forwarder.idle_seconds()`` mechanics run in-process against stub
  TCP upstreams (no namespaces, no killpg risk in the test process).
* Watchdog semantics run the REAL ``_start_orphan_watchdog`` in a
  real process tree (namespace-independent): a parent spawns a
  supervisor standing in for the forwarder's main(); the test SIGKILLs
  the parent and asserts the reap-vs-keep direction within a bounded
  window. Every process is test-spawned, in its own session, and
  reaped in ``finally``.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from packages.joern.netns_forwarder import Forwarder, create_listener

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _wait_for(predicate, timeout_s: float, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"timed out after {timeout_s}s waiting for {what}")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


# ── idle clock mechanics (in-process, stub upstream) ────────────────


class _EchoOnce:
    """Accepts one connection and echoes until EOF."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port = self._listener.getsockname()[1]
        import threading
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            import threading
            threading.Thread(
                target=self._echo, args=(conn,), daemon=True,
            ).start()

    @staticmethod
    def _echo(conn: socket.socket) -> None:
        try:
            while data := conn.recv(65536):
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._listener.close()


@pytest.fixture
def uds_stack(monkeypatch):
    # Short private root: AF_UNIX paths cap at ~108 chars and a nested
    # pytest basetemp blows past it (same workaround as the sibling
    # forwarder tests).
    import shutil
    import tempfile
    root = tempfile.mkdtemp(prefix="rpt_", dir="/tmp")
    upstream = _EchoOnce()
    sock_path = os.path.join(root, "lane.sock")
    listener = create_listener(sock_path)
    fwd = Forwarder(
        listener, ("127.0.0.1", upstream.port), socket_path=sock_path,
    )
    fwd.start()
    try:
        yield fwd, sock_path
    finally:
        fwd.stop()
        upstream.close()
        shutil.rmtree(root, ignore_errors=True)


class TestIdleClock:
    def test_idle_grows_without_clients(self, uds_stack):
        fwd, _ = uds_stack
        first = fwd.idle_seconds()
        assert first is not None
        time.sleep(0.1)
        later = fwd.idle_seconds()
        assert later is not None and later > first

    def test_open_connection_reads_as_active(self, uds_stack):
        fwd, sock_path = uds_stack
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(sock_path)
        try:
            client.sendall(b"ping")
            _wait_for(lambda: client.recv(4) == b"ping", 5.0,
                      "echo roundtrip")
            # Connection (client + upstream leg) is open: active.
            _wait_for(lambda: fwd.idle_seconds() is None, 5.0,
                      "open connection to read as active")
        finally:
            client.close()
        # Closed: the clock restarts from the disconnect.
        _wait_for(
            lambda: (idle := fwd.idle_seconds()) is not None
            and idle < 3.0,
            5.0, "idle clock to restart after disconnect",
        )


# ── watchdog semantics (real process tree) ──────────────────────────

# Supervisor stand-ins for the forwarder's main(). Both arm the REAL
# watchdog; they differ in the idle source: `real` builds nothing and
# uses a permanently-idle stub (no clients exist), `active` reads a
# flag file so the test can flip activity off.
_SUPERVISOR_CODE = (
    "import os, subprocess, sys, time\n"
    "sys.path.insert(0, os.environ['RAPTOR_DIR'])\n"
    "from packages.joern.netns_forwarder import _start_orphan_watchdog\n"
    "flag = os.environ.get('ACTIVE_FLAG_FILE')\n"
    "class _Idle:\n"
    "    def idle_seconds(self):\n"
    "        if flag and os.path.exists(flag):\n"
    "            return None\n"
    "        return 999999.0\n"
    "child = None\n"
    "_start_orphan_watchdog(lambda: child, _Idle(),\n"
    "                       poll_s=0.1, grace_s=2.0, idle_ttl_s=0.5)\n"
    "child = subprocess.Popen([sys.executable, '-c', sys.argv[1]])\n"
    "with open(os.environ['READY_FILE'], 'w') as f:\n"
    "    f.write(f'{os.getpid()} {child.pid}')\n"
    "child.wait()\n"
)

_PARENT_CODE = (
    "import os, subprocess, sys, time\n"
    "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]],\n"
    "                 start_new_session=True)\n"
    "time.sleep(300)\n"
)

_COOPERATIVE_CHILD = "import time; time.sleep(300)"
_SIGTERM_IGNORING_CHILD = (
    "import signal, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "time.sleep(300)\n"
)


@pytest.mark.linux_native
@pytest.mark.darwin_native
class TestOrphanReap:
    def _launch(self, tmp_path, child_body, active_flag=None):
        ready = tmp_path / "ready"
        env = dict(os.environ)
        env["RAPTOR_DIR"] = str(_REPO_ROOT)
        env["READY_FILE"] = str(ready)
        if active_flag is not None:
            env["ACTIVE_FLAG_FILE"] = str(active_flag)
        parent = subprocess.Popen(
            [sys.executable, "-c", _PARENT_CODE, _SUPERVISOR_CODE,
             child_body],
            env=env, start_new_session=True,
        )
        _wait_for(ready.exists, 30.0, "supervised tree to come up")
        sup_pid, wrapped_pid = (
            int(x) for x in ready.read_text().split()
        )
        return parent, sup_pid, wrapped_pid

    @staticmethod
    def _reap_all(parent, *pids):
        for pid in (parent.pid, *pids):
            if pid is None:
                continue
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except OSError:
                pass
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        parent.poll()

    @pytest.mark.parametrize(
        "child_body",
        [_COOPERATIVE_CHILD, _SIGTERM_IGNORING_CHILD],
        ids=["sigterm-exits", "sigterm-ignored-escalates-to-group-kill"],
    )
    def test_orphaned_idle_group_reaped(self, tmp_path, child_body):
        parent, sup_pid, wrapped_pid = self._launch(tmp_path, child_body)
        try:
            os.kill(parent.pid, signal.SIGKILL)
            parent.wait(timeout=10)
            # 0.1s poll + 0.5s idle ttl + 2s escalation grace; 20s wall.
            _wait_for(lambda: not _pid_alive(sup_pid), 20.0,
                      "orphaned idle supervisor to exit")
            _wait_for(lambda: not _pid_alive(wrapped_pid), 20.0,
                      "orphaned idle wrapped child to exit")
        finally:
            self._reap_all(parent, sup_pid, wrapped_pid)

    def test_orphaned_but_active_server_survives_until_idle(
        self, tmp_path,
    ):
        # Direction two: a warm/in-use server must NOT die on parent
        # death — the lifecycle layer hands servers to later runs.
        flag = tmp_path / "active"
        flag.write_text("busy")
        parent, sup_pid, wrapped_pid = self._launch(
            tmp_path, _COOPERATIVE_CHILD, active_flag=flag,
        )
        try:
            os.kill(parent.pid, signal.SIGKILL)
            parent.wait(timeout=10)
            time.sleep(2.0)  # well past poll + ttl
            assert _pid_alive(sup_pid), (
                "active orphaned server was reaped — warm reuse broken"
            )
            assert _pid_alive(wrapped_pid)
            flag.unlink()  # activity stops: the idle horizon now runs
            _wait_for(lambda: not _pid_alive(sup_pid), 20.0,
                      "idle-expired supervisor to exit")
            _wait_for(lambda: not _pid_alive(wrapped_pid), 20.0,
                      "idle-expired wrapped child to exit")
        finally:
            self._reap_all(parent, sup_pid, wrapped_pid)
