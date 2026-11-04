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
  window. Each test-spawned tree occupies one private session, so failed
  setup can terminate it even before the supervisor publishes its PID.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from pathlib import Path

import pytest

from core.sandbox.tests.socket_server import SocketServer
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
    """True while *pid* is actually RUNNING — a zombie reads as dead.

    The reap-direction waits below poll the condition the watchdog
    CONTROLS: the fatal signal landing. A kill victim is observable
    the instant it dies — it disappears outright or turns zombie
    awaiting its reaper — but WHEN the zombie is reaped belongs to
    whoever inherited it, not to the watchdog. On an idle host init
    adopts the orphaned tree and reaps near-instantly, so kill-0
    aliveness happens to work; under load the reap lags, and inside a
    nested pid namespace (the mandated runner for kill-exercising
    tests) the orphans reparent to ns-init — the test process itself —
    which never waits on strangers, so the zombie persists for the
    life of the run and any reap-based deadline times out. Counting a
    zombie as dead is equally required by the keep direction: a
    killed-but-unreaped supervisor must FAIL the warm-reuse assertion,
    not ride a stale kill-0 probe past it. Same semantics as the
    sibling escalation tests' ``_pid_gone`` and the production
    ``_pgid_alive`` zombie confirmation; without procfs the coarse
    kill-0 answer stands (there the platform reaper owns orphans).
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        pass  # EPERM-class: somebody is there — check its state below.
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True  # no procfs — accept the coarse kill-0 answer
    return stat.rsplit(")", 1)[-1].split()[0] != "Z"


# ── idle clock mechanics (in-process, stub upstream) ────────────────


class _EchoOnce:
    """Accepts one connection and echoes until EOF."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port = self._listener.getsockname()[1]
        self._server = SocketServer(self._listener, self._echo)

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
        self._server.close()


@pytest.fixture
def uds_stack():
    # Own the short socket root and every resource before startup can fail.
    with ExitStack() as cleanup:
        root = cleanup.enter_context(TemporaryDirectory(prefix="rpt_", dir="/tmp"))
        upstream = _EchoOnce()
        cleanup.callback(upstream.close)
        sock_path = os.path.join(root, "lane.sock")
        listener = cleanup.enter_context(create_listener(sock_path))
        fwd = Forwarder(
            listener, ("127.0.0.1", upstream.port), socket_path=sock_path,
        )
        cleanup.callback(fwd.stop)
        fwd.start()
        yield fwd, sock_path


def test_uds_stack_cleans_up_after_partial_start_failure(monkeypatch):
    module = sys.modules[__name__]
    upstreams = []
    forwarders = []
    original_upstream = _EchoOnce
    original_start = Forwarder.start

    def upstream():
        server = original_upstream()
        upstreams.append(server)
        return server

    def start_then_fail(self):
        original_start(self)
        forwarders.append((self, self._accept_thread))
        raise RuntimeError("forwarder startup failed")

    monkeypatch.setattr(module, "_EchoOnce", upstream)
    monkeypatch.setattr(Forwarder, "start", start_then_fail)
    fixture = uds_stack.__wrapped__()
    try:
        with pytest.raises(RuntimeError, match="forwarder startup failed"):
            next(fixture)
    finally:
        fixture.close()

    assert len(upstreams) == len(forwarders) == 1
    assert upstreams[0]._listener.fileno() == -1
    assert not upstreams[0]._server._accept_thread.is_alive()
    assert not forwarders[0][1].is_alive()
    assert not os.path.exists(forwarders[0][0]._socket_path)


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
    # grace_s bills directly to the escalation-path test's wall time
    # (a TERM-ignoring child waits out the whole grace before the
    # group KILL): keep it small. It still needs headroom above a
    # cooperative child's TERM-exit latency, or every run would
    # escalate and the sigterm-exits lane would stop exercising the
    # graceful rung — don't shrink it towards the poll interval.
    "_start_orphan_watchdog(lambda: child, _Idle(),\n"
    "                       poll_s=0.1, grace_s=1.0, idle_ttl_s=0.5)\n"
    "child = subprocess.Popen([sys.executable, '-c', sys.argv[1]])\n"
    # The reader's existence check must see the complete supervisor/child pair.
    "ready = os.environ['READY_FILE']\n"
    "pending = ready + '.pending'\n"
    "with open(pending, 'w') as f:\n"
    "    f.write(f'{os.getpid()} {child.pid}')\n"
    "os.replace(pending, ready)\n"
    "while True:\n"
    "    try:\n"
    "        child.wait(timeout=0.1)\n"
    "        break\n"
    "    except subprocess.TimeoutExpired:\n"
    "        pass\n"
)

_PARENT_CODE = (
    "import os, subprocess, sys, time\n"
    # The outer Popen owns the private session; retain all fixture descendants
    # in that group so startup failures do not require a published PID list.
    "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])\n"
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
        try:
            _wait_for(ready.exists, 30.0, "supervised tree to come up")
            sup_pid, wrapped_pid = (
                int(x) for x in ready.read_text().split()
            )
        except BaseException:
            self._reap_all(parent)
            raise
        return parent, sup_pid, wrapped_pid

    @staticmethod
    def _reap_all(parent):
        try:
            os.killpg(parent.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        parent.wait(timeout=10)

    @pytest.mark.parametrize("fault", ["before-ready", "ready-wait", "invalid-pids"])
    def test_failed_setup_reclaims_owned_processes(self, tmp_path, monkeypatch, fault):
        from types import SimpleNamespace

        started = []
        owned_pids = []
        real_popen = subprocess.Popen
        real_wait_for = _wait_for

        def start(command, **options):
            if fault == "before-ready":
                # No unreported descendants in this injected failure case.
                command = [sys.executable, "-I", "-c", "import time; time.sleep(30)"]
            process = real_popen(command, **options)
            started.append(process)
            return process

        def fail_readiness(predicate, timeout_s, what):
            if fault == "before-ready":
                raise RuntimeError("owned readiness failure")
            real_wait_for(predicate, timeout_s, what)
            ready = tmp_path / "ready"
            owned_pids.extend(int(value) for value in ready.read_text().split())
            if fault == "ready-wait":
                raise RuntimeError("owned readiness failure")
            ready.write_text("invalid PID data")

        module = sys.modules[__name__]
        try:
            with monkeypatch.context() as patcher:
                patcher.setattr(module, "subprocess", SimpleNamespace(Popen=start))
                patcher.setattr(module, "_wait_for", fail_readiness)
                error = ValueError if fault == "invalid-pids" else RuntimeError
                match = "invalid literal" if fault == "invalid-pids" else "owned readiness failure"
                with pytest.raises(error, match=match):
                    self._launch(tmp_path, _COOPERATIVE_CHILD)
            assert len(started) == 1
            assert started[0].poll() is not None, "failed setup left its launcher running"
            real_wait_for(lambda: all(not _pid_alive(pid) for pid in owned_pids),
                          3, "failed setup descendants to exit")
        finally:
            # Keep the regression test itself contained if setup cleanup breaks.
            for pid in owned_pids:
                try:
                    if _pid_alive(pid):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for process in started:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)

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
            # 0.1s poll + 0.5s idle ttl + 1s escalation grace; 20s wall.
            _wait_for(lambda: not _pid_alive(sup_pid), 20.0,
                      "orphaned idle supervisor to exit")
            _wait_for(lambda: not _pid_alive(wrapped_pid), 20.0,
                      "orphaned idle wrapped child to exit")
        finally:
            self._reap_all(parent)

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
            # Must-survive window: a buggy watchdog would reap the
            # active server at ~poll(0.1) + ttl(0.5); observe well
            # past that. Longer only buys detection margin against a
            # starved watchdog thread — it can't make the passing
            # direction flake — while billing every run, so keep it
            # a small multiple of poll + ttl, never below it.
            time.sleep(1.2)
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
            self._reap_all(parent)
