"""pid-namespace supervision tier of the netns forwarder (--pidns).

Three layers, per CI reality (user/pid namespaces may be refused):

* Refusal, exit-code, and tier-report logic runs ``main()`` /
  ``_supervise_ns_init`` in-process with the unshare seam stubbed —
  no namespaces, no privileges (CI-safe).
* The waiter contract battery drives ``_ns_init_split`` through a
  real fork WITHOUT any unshare: forwarding, mirroring, and reaping
  are pure process logic. The battery is parametrized so the
  ``core.sandbox`` supervised waiter can join the same assertions
  once both lanes are in-tree (the twins may not drift apart without
  a battery failure saying so).
* Namespace mechanics run the full script in a subprocess and skip
  where the pidns self-probe refuses, each naming its boundary.

None of these tests asserts process-group properties (``getpgrp()``
can legitimately be 0 on nested-pid-ns runners); every signalled pid
comes from our own ``fork``/``Popen`` or a ``pgrep -P`` walk of it.

In-namespace authorship note: when the battery itself runs as a
pid-namespace init (the kill-containment idiom), every collapsed
orphan reparents to the TEST PROCESS unreaped — ``os.kill(pid, 0)``
succeeds on those adopted zombies, so "is it gone yet" probes must
also read ``/proc/<pid>/stat`` and count state ``Z`` as gone. And
never reap with ``os.waitpid(-1, ...)``: under xdist that can steal
a sibling fixture's child; wait on the specific pid you forked.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from packages.joern import netns_forwarder as nf

_SCRIPT = Path(__file__).resolve().parents[1] / "netns_forwarder.py"
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _pidns_available() -> bool:
    """Same capability the pidns tier needs, probed the same way."""
    try:
        return subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe-pidns"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


_HAS_PIDNS = _pidns_available()
needs_pidns = pytest.mark.skipif(
    not _HAS_PIDNS,
    reason="single-call unshare(USER|NET|PID) unavailable on this host",
)


@pytest.fixture
def restore_signal_handlers():
    """Snapshot/restore TERM+INT handlers around in-process supervisor
    calls (``_supervise_ns_init`` installs its own)."""
    saved = {s: signal.getsignal(s)
             for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


def _close_quietly(*fds: int) -> None:
    for fd in fds:
        with contextlib.suppress(OSError):
            os.close(fd)


# ── in-process: fail-closed refusal + tier report ───────────────────


class TestPidnsRefusalFailsClosed:
    _BASE = ["--socket", "/nonexistent-pidns-test/fwd.sock",
             "--port", "12345", "--", "true"]

    def test_runtime_unshare_refusal_exit_code(self, monkeypatch, capsys):
        def _refuse(include_pid: bool = False) -> None:
            raise OSError("unshare refused by policy")

        monkeypatch.setattr(nf, "enter_private_netns", _refuse)
        rc = nf.main(["--pidns", *self._BASE])
        assert rc == nf.EXIT_PIDNS_UNSHARE_REFUSED
        err = capsys.readouterr().err
        assert "--pidns requested" in err
        assert "refused at runtime" in err

    def test_refused_boot_never_reports_a_tier(self, monkeypatch):
        """Misstamp regression: a refused --pidns boot must write NO
        tier report — the parent's read then falls back to the weaker
        tier instead of recording a pidns that was never established."""
        def _refuse(include_pid: bool = False) -> None:
            raise OSError("unshare refused by policy")

        monkeypatch.setattr(nf, "enter_private_netns", _refuse)
        ready_r, ready_w = os.pipe()
        try:
            rc = nf.main(["--pidns", "--ready-fd", str(ready_w),
                          *self._BASE])
            assert rc == nf.EXIT_PIDNS_UNSHARE_REFUSED
            readable, _, _ = select.select([ready_r], [], [], 0)
            assert readable == [], "refused boot wrote a tier report"
        finally:
            _close_quietly(ready_r, ready_w)

    def test_refusal_exits_before_listener_and_child(
        self, monkeypatch, tmp_path,
    ):
        """The distinct-exit-code path must have no side effects for
        the relaunch to double: no socket bound, no child spawned."""
        def _refuse(include_pid: bool = False) -> None:
            raise OSError("unshare refused by policy")

        monkeypatch.setattr(nf, "enter_private_netns", _refuse)
        spawned: list[list[str]] = []
        monkeypatch.setattr(
            nf.subprocess, "Popen",
            lambda cmd: spawned.append(list(cmd)),
        )
        sock = tmp_path / "fwd.sock"
        rc = nf.main(["--pidns", "--socket", str(sock),
                      "--port", "12345", "--", "true"])
        assert rc == nf.EXIT_PIDNS_UNSHARE_REFUSED
        assert not sock.exists()
        assert spawned == []

    def test_group_path_still_uses_zero_arg_unshare(self, monkeypatch):
        """Without --pidns the unshare call keeps its original shape
        (include_pid defaulted) — the group tier is byte-for-byte
        today's behavior."""
        calls: list[tuple] = []
        monkeypatch.setattr(
            nf, "enter_private_netns",
            lambda *a, **kw: calls.append((a, kw)) or (_ for _ in ()).throw(
                OSError("stop the boot here")),
        )
        with pytest.raises(OSError, match="stop the boot here"):
            nf.main(list(self._BASE))
        assert calls == [((), {})]


class TestSuperviseNsInit:
    """(P)-side logic against real forked stand-ins for the ns-init."""

    def test_unarmed_waiter_fails_closed(self, restore_signal_handlers):
        """A waiter that dies before the arm byte must fail the boot
        with the distinct unarmed exit code — never proceed."""
        arm_r, arm_w = os.pipe()
        gone_r, gone_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os._exit(0)  # dies without ever arming
        os.close(arm_w)
        try:
            rc = nf._supervise_ns_init(
                pid, arm_r, gone_w, None,
                poll_s=0.05, arm_timeout_s=10.0,
            )
            assert rc == nf.EXIT_PIDNS_WAITER_UNARMED
        finally:
            _close_quietly(gone_r, gone_w)

    def test_arm_timeout_fails_closed(self, restore_signal_handlers):
        """A waiter that never arms within the budget is killed and
        the boot refused."""
        arm_r, arm_w = os.pipe()
        gone_r, gone_w = os.pipe()
        pid = os.fork()
        if pid == 0:  # never writes the arm byte
            time.sleep(60)
            os._exit(0)
        os.close(arm_w)
        try:
            rc = nf._supervise_ns_init(
                pid, arm_r, gone_w, None,
                poll_s=0.05, arm_timeout_s=0.3,
            )
            assert rc == nf.EXIT_PIDNS_WAITER_UNARMED
            # The supervisor SIGKILLed and reaped its own child.
            with pytest.raises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
        finally:
            _close_quietly(gone_r, gone_w)

    def test_armed_exit_mirrored_and_tier_reported(
        self, restore_signal_handlers,
    ):
        """After the arm byte the achieved tier is reported and the
        waiter's exit status is mirrored."""
        arm_r, arm_w = os.pipe()
        gone_r, gone_w = os.pipe()
        ready_r, ready_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.write(arm_w, b"A")
            os._exit(7)
        os.close(arm_w)
        try:
            rc = nf._supervise_ns_init(
                pid, arm_r, gone_w, ready_w, poll_s=0.05,
            )
            assert rc == 7
            assert os.read(ready_r, 64) == b"supervision_tier=pidns\n"
            assert os.read(ready_r, 64) == b""  # report fd closed
        finally:
            _close_quietly(gone_r, gone_w, ready_r)

    def test_signalled_waiter_mirrored_as_128_plus_signum(
        self, restore_signal_handlers,
    ):
        arm_r, arm_w = os.pipe()
        gone_r, gone_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.write(arm_w, b"A")
            os.kill(os.getpid(), signal.SIGTERM)
            os._exit(99)  # unreachable
        os.close(arm_w)
        try:
            rc = nf._supervise_ns_init(
                pid, arm_r, gone_w, None, poll_s=0.05,
            )
            assert rc == 128 + signal.SIGTERM
        finally:
            _close_quietly(gone_r, gone_w)

    def test_no_tier_report_before_arm(self, restore_signal_handlers):
        """The tier report may only follow the arm byte: an unarmed
        death leaves the ready fd silent (misstamp direction)."""
        arm_r, arm_w = os.pipe()
        gone_r, gone_w = os.pipe()
        ready_r, ready_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os._exit(3)  # dies unarmed
        os.close(arm_w)
        try:
            rc = nf._supervise_ns_init(
                pid, arm_r, gone_w, ready_w,
                poll_s=0.05, arm_timeout_s=10.0,
            )
            assert rc == nf.EXIT_PIDNS_WAITER_UNARMED
            readable, _, _ = select.select([ready_r], [], [], 0)
            assert readable == [], "tier reported before supervision armed"
        finally:
            _close_quietly(gone_r, gone_w, ready_r, ready_w)


# ── waiter contract battery (fork, no namespaces) ───────────────────
#
# Parametrization point for the shared waiter-contract battery: the
# forwarder's local ns-init mirror and the core.sandbox supervised
# waiter must pass IDENTICAL assertions. The sandbox waiter's driver
# joins this list when its lane is in-tree; until then the battery
# pins the forwarder side of the contract.

_WAITER_DRIVER = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from packages.joern.netns_forwarder import _ns_init_split

mode = sys.argv[2]
live_r, live_w = os.pipe2(os.O_CLOEXEC)
arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
pid = os.fork()
if pid != 0:
    # Stand-in for the supervising process: hold the liveness write
    # end, require the arm byte, reap the waiter, mirror its status.
    os.close(live_r); os.close(arm_w)
    if os.read(arm_r, 1) != b"A":
        sys.exit(96)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    sys.exit(128 + os.WTERMSIG(status))
os.close(live_w); os.close(arm_r)
if mode == "orphan-then-exit":
    # Give the waiter-to-be an extra direct child that dies FIRST
    # (outside a pid namespace nothing reparents to the waiter, so
    # the stray must be its own child from before the split): its
    # status must be reaped and DISCARDED — only the supervised
    # child's status may mirror.
    decoy = os.fork()
    if decoy == 0:
        time.sleep(0.1)
        os._exit(1)
_ns_init_split(live_r, arm_w)  # returns only in the working child

# --- the working child (the waiter's supervised target) ---
if mode == "exit7":
    os._exit(7)
if mode == "die-by-term":
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTERM)
    os._exit(99)
if mode == "orphan-then-exit":
    time.sleep(0.6)  # the decoy's exit(1) lands in the waiter first
    os._exit(5)
if mode == "wait-for-term":
    signal.signal(signal.SIGTERM, lambda *_: os._exit(43))
    print("READY", flush=True)
    for _ in range(600):
        time.sleep(0.1)
    os._exit(9)
os._exit(64)
"""

_WAITER_BATTERY_DRIVERS = {
    "forwarder-ns-init": _WAITER_DRIVER,
}


@pytest.fixture(params=sorted(_WAITER_BATTERY_DRIVERS))
def waiter_driver(request) -> str:
    return _WAITER_BATTERY_DRIVERS[request.param]


def _run_driver(driver: str, mode: str, **popen_kw) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", driver, str(_REPO_ROOT), mode],
        **popen_kw,
    )


class TestWaiterContractBattery:
    def test_exit_status_mirrored(self, waiter_driver):
        proc = _run_driver(waiter_driver, "exit7")
        assert proc.wait(timeout=30) == 7

    def test_signal_death_mirrored_128_plus_signum(self, waiter_driver):
        proc = _run_driver(waiter_driver, "die-by-term")
        assert proc.wait(timeout=30) == 128 + signal.SIGTERM

    def test_orphans_reaped_not_mirrored(self, waiter_driver):
        proc = _run_driver(waiter_driver, "orphan-then-exit")
        assert proc.wait(timeout=30) == 5

    def test_term_forwarded_through_waiter(self, waiter_driver):
        """TERM sent to the waiter reaches the supervised child, and
        the child's chosen exit code mirrors back up."""
        proc = _run_driver(
            waiter_driver, "wait-for-term",
            stdout=subprocess.PIPE, text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "READY"
            # The waiter is the driver's only child; walk down with
            # pgrep -P from our own verified Popen pid (never a
            # pattern sweep).
            deadline = time.monotonic() + 10
            waiter_pids: list[str] = []
            while not waiter_pids and time.monotonic() < deadline:
                waiter_pids = subprocess.run(
                    ["pgrep", "-P", str(proc.pid)],
                    capture_output=True, text=True, check=False,
                ).stdout.split()
                if not waiter_pids:
                    time.sleep(0.05)
            assert len(waiter_pids) == 1
            os.kill(int(waiter_pids[0]), signal.SIGTERM)
            assert proc.wait(timeout=30) == 43
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)


# ── namespace mechanics (probe-gated; boundaries named) ─────────────


_STUB_HTTP_CHILD = r"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        out = json.dumps({"echo": body.decode("utf-8")}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"""


@pytest.fixture
def uds_dir():
    with tempfile.TemporaryDirectory(prefix="raptor-joern-uds-test-") as d:
        yield d


def _kids(pid: int) -> list[int]:
    """Direct children via pgrep -P only — never a pattern sweep."""
    out = subprocess.run(
        ["pgrep", "-P", str(pid)],
        capture_output=True, text=True, check=False,
    )
    return [int(x) for x in out.stdout.split()]


def _tree_levels(root: int, depth: int) -> list[list[int]]:
    levels: list[list[int]] = []
    frontier = [root]
    for _ in range(depth):
        nxt: list[int] = []
        for pid in frontier:
            nxt.extend(_kids(pid))
        levels.append(nxt)
        frontier = nxt
    return levels


def _gone(pid: int) -> bool:
    """True once *pid* is dead — reaped, or an adopted zombie.

    kill-0 alone is not enough: when this battery runs inside a pid
    namespace (kill-containment idiom), collapsed orphans reparent to
    the in-namespace pid 1 UNREAPED, and kill-0 keeps succeeding on
    those zombies forever (the docstring's authorship note).
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return True


def _wait_all_gone(pids: list[int], timeout_s: float = 10.0) -> list[int]:
    """Poll (kill-0 + procfs state on verified pids) until the set is
    empty or the deadline passes; returns the survivors."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        alive = [pid for pid in pids if not _gone(pid)]
        if not alive:
            return []
        time.sleep(0.1)
    return alive


class TestSelfProbePidns:
    def test_probe_exit_code_is_boolean(self):
        # Boundary: forwarder --self-probe-pidns on this host.
        rc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe-pidns"],
            capture_output=True, timeout=30, check=False,
        ).returncode
        assert rc in (0, 1)

    @needs_pidns
    def test_probe_passes_where_pidns_works(self):
        assert _HAS_PIDNS  # gate and assertion agree by construction


@needs_pidns
class TestPidnsNamespaceMechanics:
    def _spawn(self, uds_dir: str, port: int, tail: list[str],
               **popen_kw) -> subprocess.Popen:
        return subprocess.Popen(
            [sys.executable, str(_SCRIPT), "--pidns",
             "--socket", os.path.join(uds_dir, "joern.sock"),
             "--port", str(port), "--", *tail],
            **popen_kw,
        )

    def test_wrapped_command_is_not_pid1(self, uds_dir):
        # Boundary: single-call unshare(USER|NET|PID) engages and the
        # exec'd target is never PID 1 — its parent is the working
        # forwarder (PID 2), the ns-init having taken PID 1.
        proc = self._spawn(
            uds_dir, 45998,
            [sys.executable, "-c",
             "import os, sys; sys.exit(0 if (os.getppid() == 2 "
             "and 2 < os.getpid() < 64) else 33)"],
        )
        assert proc.wait(timeout=60) == 0

    def test_exit_code_mirrored_through_the_chain(self, uds_dir):
        # Boundary: exit-status mirroring across supervisor, ns-init,
        # and working forwarder.
        proc = self._spawn(
            uds_dir, 45997,
            [sys.executable, "-c", "import sys; sys.exit(7)"],
        )
        assert proc.wait(timeout=60) == 7

    def test_tier_report_says_pidns(self, uds_dir):
        # Boundary: achieved-tier report on the ready fd.
        r, w = os.pipe()
        os.set_inheritable(w, True)
        proc = subprocess.Popen(
            [sys.executable, str(_SCRIPT), "--pidns",
             "--ready-fd", str(w),
             "--socket", os.path.join(uds_dir, "joern.sock"),
             "--port", "45996", "--",
             sys.executable, "-c", "import sys; sys.exit(0)"],
            pass_fds=(w,),
        )
        os.close(w)
        try:
            line = b""
            while not line.endswith(b"\n"):
                chunk = os.read(r, 64)
                if not chunk:
                    break
                line += chunk
            assert line == b"supervision_tier=pidns\n"
        finally:
            os.close(r)
            proc.wait(timeout=60)

    def test_sigkill_of_forwarder_collapses_namespace(self, uds_dir):
        # Boundary: PDEATHSIG chain — SIGKILL of the forwarder kills
        # the ns-init, and init death collapses every namespace
        # member (kernel-guaranteed, asynchronous).
        marker = os.path.join(uds_dir, "up")
        proc = self._spawn(
            uds_dir, 45995,
            [sys.executable, "-c",
             f"import os, time; open({marker!r}, 'w').write('x'); "
             "time.sleep(300)"],
        )
        try:
            deadline = time.monotonic() + 30
            while not os.path.exists(marker):
                assert time.monotonic() < deadline, "stack never came up"
                time.sleep(0.1)
            levels = _tree_levels(proc.pid, 3)
            members = [pid for lvl in levels for pid in lvl]
            assert members, "no supervision tree found"
            proc.kill()
            proc.wait(timeout=10)
            assert _wait_all_gone(members) == []
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    def test_term_forwarded_and_mirrored_no_survivors(self, uds_dir):
        # Boundary: graceful TERM rides the whole chain down and the
        # signal death mirrors back as 128+SIGTERM.
        marker = os.path.join(uds_dir, "up")
        proc = self._spawn(
            uds_dir, 45994,
            [sys.executable, "-c",
             f"import os, time; open({marker!r}, 'w').write('x'); "
             "time.sleep(300)"],
        )
        try:
            deadline = time.monotonic() + 30
            while not os.path.exists(marker):
                assert time.monotonic() < deadline, "stack never came up"
                time.sleep(0.1)
            levels = _tree_levels(proc.pid, 3)
            members = [pid for lvl in levels for pid in lvl]
            proc.terminate()
            assert proc.wait(timeout=30) == 128 + signal.SIGTERM
            assert _wait_all_gone(members) == []
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    def test_uds_roundtrip_and_host_tcp_unreachable(self, uds_dir):
        # Boundary: the UDS stays the namespace's sole ingress under
        # --pidns — HTTP round-trips over the socket while the in-ns
        # TCP port does not exist on the host.
        path = os.path.join(uds_dir, "joern.sock")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        proc = self._spawn(
            uds_dir, port,
            [sys.executable, "-c", _STUB_HTTP_CHILD, str(port)],
        )

        class _UnixConn(http.client.HTTPConnection):
            def __init__(self, p: str) -> None:
                super().__init__("127.0.0.1", timeout=10)
                self._path = p

            def connect(self) -> None:
                sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sk.settimeout(10)
                sk.connect(self._path)
                self.sock = sk

        try:
            deadline = time.monotonic() + 30
            data = None
            while True:
                conn = _UnixConn(path)
                try:
                    conn.request(
                        "POST", "/q", body=b'{"query":"1+1"}',
                        headers={"Content-Type": "application/json"},
                    )
                    data = json.loads(conn.getresponse().read())
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.2)
                finally:
                    conn.close()
            assert data == {"echo": '{"query":"1+1"}'}
            with pytest.raises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=2)
        finally:
            proc.terminate()
            proc.wait(timeout=30)
