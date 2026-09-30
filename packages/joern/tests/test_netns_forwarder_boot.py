"""Boot-window terminal-signal tests for the netns forwarder script.

The non-pidns boot used to expose two windows to a consumer that
signals early:

* pre-handler: the unix socket appeared on disk (and the group-tier
  ready line fired) before the SIGTERM/SIGINT handlers installed, so
  a signal keyed on either milestone hit the default disposition —
  supervisor dead by signal, socket left behind;
* handlers-installed/child-``None``: the old handler silently dropped
  a terminal signal when no child existed yet, and the subsequent
  ``child.wait()`` then blocked forever (signal absorbed).

These tests pin the fixed contract: the handlers install before any
observable boot milestone, and a terminal signal arriving before the
child exists is honoured (prompt teardown, child never spawned; or
delivery right after the spawn) — never dropped. The child-``None``
window is microseconds wide in a real boot, so the deterministic
window tests drive the forwarder's test-only pre-spawn gate
(RAPTOR_NETNS_FORWARDER_TEST_PRESPAWN_GATE) instead of racing a
sleep; the milestone tests gate their signal on the observable event
itself (socket path exists / ready line read).

Everything here runs the full script in a subprocess with a stub
python child standing in for joern, so it is skipped without
unprivileged user namespaces (same probe as test_netns_forwarder.py).
Kill discipline: every signalled pid is this file's own verified
``Popen`` child, and the last-resort straggler sweep re-reads
``/proc/<pid>/cmdline`` for the test's unique marker path before any
kill — never a pid <= 1, never an unverified pid.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from packages.joern import netns_forwarder

_SCRIPT = Path(__file__).resolve().parents[1] / "netns_forwarder.py"

#: The wrapped stand-in for joern: reports that it ran (the marker
#: file doubles as this test's unique cmdline token for the straggler
#: sweep), then sleeps. 600s in both directions: an order of magnitude
#: past every wait bound in this file, so a stub exiting on its own
#: can never fake "the supervisor tore down the child"; finite, so an
#: orphan self-collects within the CI job even if every kill path
#: failed.
_STUB_SLEEPER = (
    "import os, sys, time\n"
    "with open(sys.argv[1], 'w') as f:\n"
    "    f.write(str(os.getpid()))\n"
    "time.sleep(600)\n"
)


def _userns_available() -> bool:
    """Same capability the boot needs, probed the same way as
    test_netns_forwarder.py (deliberately a local copy: importing a
    sibling test module for its probe would couple this file to that
    module's internals and re-run its module-level probe anyway)."""
    try:
        return subprocess.run(
            [sys.executable, str(_SCRIPT), "--self-probe"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


needs_userns = pytest.mark.skipif(
    not _userns_available(),
    reason="unprivileged user namespaces unavailable",
)


def _free_port() -> int:
    """A TCP port currently free on the host (guaranteed free inside
    the forwarder's fresh namespace)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn_supervisor(
    uds_dir: str,
    stub_marker: str,
    *,
    env: dict[str, str] | None = None,
    ready_fd: int | None = None,
) -> tuple[subprocess.Popen[bytes], str]:
    """Launch the forwarder script wrapping the stub sleeper; returns
    the Popen handle and the socket path."""
    path = os.path.join(uds_dir, "joern.sock")
    argv = [sys.executable, str(_SCRIPT),
            "--socket", path, "--port", str(_free_port())]
    if ready_fd is not None:
        argv += ["--ready-fd", str(ready_fd)]
    argv += ["--", sys.executable, "-c", _STUB_SLEEPER, stub_marker]
    proc = subprocess.Popen(
        argv,
        env=env,
        pass_fds=() if ready_fd is None else (ready_fd,),
    )
    return proc, path


def _reap(proc: subprocess.Popen[bytes]) -> None:
    """Last-resort teardown of this test's own supervisor handle (a
    red run on an unfixed tree leaves it absorbed-and-hung)."""
    if proc.poll() is None:
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=15)


def _sweep_stub_stragglers(stub_marker: str) -> None:
    """SIGKILL any stub that outlived its supervisor.

    Verified-pid discipline: candidates come from a /proc scan (no
    pgrep dependency), and each is re-verified by re-reading its
    ``/proc/<pid>/cmdline`` for this test's unique marker path
    immediately before the kill; pids <= 1 and our own are never
    touched. Inside the battery's pid namespace the scan cannot even
    see other sessions' processes.
    """
    needle = os.fsencode(stub_marker)
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid <= 1 or pid == os.getpid():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmdline = f.read()
        except OSError:
            continue  # exited between scan and read
        if needle not in cmdline:
            continue
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)


@pytest.fixture
def stub_marker(tmp_path: Path) -> str:
    """Unique path the stub creates when (and only when) it ran; its
    uniqueness also makes it the straggler sweep's cmdline token."""
    return str(tmp_path / "stub-ran")


@needs_userns
def test_sigterm_at_socket_exists_is_honoured(
    uds_dir: str, stub_marker: str,
) -> None:
    """A consumer that signals the instant the socket appears on disk
    gets the documented shutdown — exit 143, socket cleaned — never
    the default disposition (exit BY signal, socket left behind) and
    never an absorbed signal (supervisor hung in ``child.wait()``).

    The signal is gated on the observable socket-exists event and the
    poll is a busy loop (no sleep), landing it at the shortest
    achievable distance from the bind — exactly where the pre-fix
    windows sat.
    """
    proc, path = _spawn_supervisor(uds_dir, stub_marker)
    try:
        deadline = time.monotonic() + 15
        while not os.path.exists(path):  # busy-poll: land the signal ASAP
            assert time.monotonic() < deadline, "socket never appeared"
        proc.terminate()  # our own verified, unreaped Popen child
        # 30s: generous for a boot-window teardown (milliseconds when
        # honoured) so xdist load cannot flake it, yet small enough
        # that an absorbed-signal hang fails the test long before the
        # battery's own timeout envelope.
        assert proc.wait(timeout=30) == 143  # 128+SIGTERM, honoured
        assert not os.path.exists(path), "socket not cleaned up"
    finally:
        _reap(proc)
        _sweep_stub_stragglers(stub_marker)


@needs_userns
def test_sigterm_at_ready_line_is_honoured(
    uds_dir: str, stub_marker: str,
) -> None:
    """The group-tier ready line must imply the terminal-signal
    handlers are installed: a consumer signalling the instant it reads
    ``supervision_tier=group`` gets the documented shutdown, never the
    default disposition. (Pre-fix the line fired before both the
    listener and the handlers.)"""
    r, w = os.pipe()
    try:
        proc, path = _spawn_supervisor(uds_dir, stub_marker, ready_fd=w)
    finally:
        os.close(w)
    try:
        line = b""
        while not line.endswith(b"\n"):
            chunk = os.read(r, 64)
            # EOF before a full line means the supervisor died (or
            # closed the fd) without reporting — that is a failure.
            assert chunk, "ready fd closed before a tier line"
            line += chunk
        assert line == b"supervision_tier=group\n"
        proc.terminate()  # our own verified, unreaped Popen child
        assert proc.wait(timeout=30) == 143
        assert not os.path.exists(path), "socket not cleaned up"
    finally:
        os.close(r)
        _reap(proc)
        _sweep_stub_stragglers(stub_marker)


@needs_userns
@pytest.mark.parametrize(
    ("signum", "expected_rc"),
    [(signal.SIGTERM, 143), (signal.SIGINT, 130)],
    ids=["SIGTERM", "SIGINT"],
)
def test_terminal_signal_in_prespawn_window_exits_before_spawn(
    uds_dir: str,
    stub_marker: str,
    tmp_path: Path,
    signum: signal.Signals,
    expected_rc: int,
) -> None:
    """Deterministic reproduction of the absorbed-signal window: park
    the boot in the handlers-installed/child-``None`` window via the
    forwarder's test-only pre-spawn gate, land the terminal signal
    there, then release. The supervisor must honour it — prompt exit
    with the shell-convention status, socket cleaned, and the wrapped
    command NEVER spawned. Pre-fix boots offer no such safe point: the
    gate marker never appears on the old script, and with the window
    reached by timing instead, the old handler dropped the signal and
    the supervisor hung in ``child.wait()`` forever.
    """
    gate = tmp_path / "gate"
    gate.mkdir()
    env = dict(os.environ)
    env["RAPTOR_NETNS_FORWARDER_TEST_PRESPAWN_GATE"] = str(gate)
    proc, path = _spawn_supervisor(uds_dir, stub_marker, env=env)
    try:
        held = gate / "held"
        deadline = time.monotonic() + 15
        while not held.exists():
            assert time.monotonic() < deadline, (
                "pre-spawn gate never engaged: the boot offers no "
                "handlers-installed/child-None hold point"
            )
            time.sleep(0.01)
        # The parked process is the supervisor itself (non-pidns boots
        # never fork), i.e. exactly the pid we own and may signal.
        assert held.read_text(encoding="ascii") == str(proc.pid)
        proc.send_signal(signum)  # our own verified, unreaped child
        # kill(2) queued the signal before returning, and the parked
        # gate loop cannot observe the release below without first
        # returning to userspace — which delivers the pending signal
        # and runs the handler. Handler-before-release is therefore
        # ordered, not raced.
        (gate / "release").write_text("go", encoding="ascii")
        assert proc.wait(timeout=30) == expected_rc
        assert not os.path.exists(path), "socket not cleaned up"
        assert not os.path.exists(stub_marker), (
            "child was spawned despite a terminal signal that arrived "
            "before it existed"
        )
    finally:
        _reap(proc)
        _sweep_stub_stragglers(stub_marker)


@needs_userns
def test_prespawn_gate_hold_is_bounded(
    uds_dir: str, stub_marker: str, tmp_path: Path,
) -> None:
    """Regression for ``_TEST_PRESPAWN_GATE_TIMEOUT_S``: a gate that
    is never released lapses on its own — the boot proceeds and the
    wrapped command spawns — so a stray gate variable can delay a real
    boot by at most the bound, never wedge it. (The other direction —
    the bound being long enough for the held/signal/release handshake
    — is what the window test above proves by finishing inside it.)"""
    gate = tmp_path / "gate"
    gate.mkdir()
    env = dict(os.environ)
    env["RAPTOR_NETNS_FORWARDER_TEST_PRESPAWN_GATE"] = str(gate)
    proc, path = _spawn_supervisor(uds_dir, stub_marker, env=env)
    try:
        held = gate / "held"
        deadline = time.monotonic() + 15
        while not held.exists():
            assert time.monotonic() < deadline, "gate never engaged"
            time.sleep(0.01)
        # No release file, ever. The boot must still reach the spawn
        # within the bound (+ generous xdist-load margin).
        bound = netns_forwarder._TEST_PRESPAWN_GATE_TIMEOUT_S
        deadline = time.monotonic() + bound + 20
        while not os.path.exists(stub_marker):
            assert time.monotonic() < deadline, (
                "unreleased pre-spawn gate wedged the boot"
            )
            time.sleep(0.1)
        proc.terminate()  # normal forwarded-shutdown path from here
        assert proc.wait(timeout=30) == 143
        assert not os.path.exists(path), "socket not cleaned up"
    finally:
        _reap(proc)
        _sweep_stub_stragglers(stub_marker)
