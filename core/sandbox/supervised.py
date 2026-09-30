"""Supervised process trees — reliable teardown plumbing, NOT a sandbox.

``spawn_supervised()`` launches a long-running helper (an analysis
server, a JVM, a tool daemon) as a *supervised tree*: every descendant
the target creates lives inside one teardown domain, and a single
verified stop call — or the death of the owning RAPTOR process — ends
all of it, with the kernel (not a pid scan) as the proof.

**This module provides NO security confinement.** No Landlock, no
seccomp, no mount or filesystem isolation, no network policy — a
supervised target runs with the caller's full ambient authority. It is
process-lifetime containment only. Anything untrusted belongs under
the sandbox profiles (``core.sandbox.run`` / ``run_untrusted``), never
here; that is also why nothing in this module carries a ``run_``
name and why the supervised tiers appear in none of the sandbox
profile or containment-floor tables.

Process topology (pidns tier)::

    caller ──fork── A (supervisor, this module's code)
                    │   os.unshare(CLONE_NEWUSER|CLONE_NEWPID[|CLONE_NEWNET])
                    │   — ONE call, never staged —
                    ├──fork── B (ns-init waiter, PID 1 of the new pid-ns)
                    │         └──fork── C (target, PID 2) ── execvpe
                    └── poll-multiplexed supervision of B

- A performs the single ``unshare`` call (a staged second call is
  refused on restricted-userns hosts — the pid-ns must ride the same
  syscall as the userns grant), writes the deny-setgroups + identity
  uid/gid maps, and reports readiness (achieved tier, B's pid, C's
  pid) plus an SCM_RIGHTS-transferred pidfd on B over a status
  socketpair before settling into supervision.
- B arms ``PR_SET_PDEATHSIG(SIGKILL)`` keyed to A, then closes the
  post-fork race with a poll(timeout=0) POLLHUP probe on a liveness
  pipe whose SOLE write end lives in A (``getppid()`` is useless to a
  pid-ns init — its parent reads as 0 — and is used NOWHERE in this
  module). If the prctl itself fails, B ``_exit``s with a distinct
  code and the boot fails closed. B forwards SIGTERM/SIGINT/SIGHUP/
  SIGQUIT to C, reaps every orphan that reparents to it, and mirrors
  C's fate (exit status, or 128+signum for a signal death).
- C reports its outside-the-namespace pid, wires stdio, and execs.

Exit-path invariant (pinned by test): **on its own code paths A exits
only because B exited (mirroring B's status) or because the death pipe
reported the caller gone (collapse the tree, then exit).** A forwards
SIGTERM and SIGINT to B and keeps supervising; any other fatal signal
(SIGHUP/SIGQUIT included — only B forwards those onward to C) kills A
with its default disposition, and the tree then collapses via B's
PDEATHSIG rather than by supervision — a collapse, never abandonment
of a live B. Even the last-ditch internal-error path SIGKILLs B and
awaits it before exiting.

Session posture (kill mode vs survive mode): in ``survive`` mode A
calls ``setsid()`` immediately post-fork so session-scoped teardown of
the caller cannot reap a tree the caller asked to outlive it. In
``kill`` mode A DELIBERATELY stays in the caller's session and process
group — group-directed teardown aimed at the caller is allowed to take
the supervisor with it, and the PDEATHSIG chain plus namespace
collapse then take the tree.

Degraded (group) tier: hosts that refuse unprivileged user namespaces
degrade — loudly (a logged warning names the refusal and the weaker
teardown scope) but never a crash — to a plain
``subprocess.Popen(..., start_new_session=True)`` with the shared
``set_pdeathsig`` preexec in kill mode. That is exactly the
pre-existing posture of RAPTOR's tool spawns: nothing a caller has
today gets worse, and ``pid_ns="require"`` turns the degrade into a
refusal instead.

Kill-path safety: every handle-side signal to the tree goes through
``signal.pidfd_send_signal`` on the SCM_RIGHTS-received pidfd for B
(pid-reuse safe); ``ns_init_pid`` / ``target_pid`` are diagnostic
metadata and are never signalled by number. No kill path in this
module can address a pid or pgid <= 1 or the caller's own process
group. On the pidns tier the death proof is ``waitpid`` completion on
A (whose own exit paths are gated on reaping B, whose exit the kernel
gates on the namespace being empty) — there is no /proc scanning
anywhere. That gate exists only on A's OWN exit paths: an exit of A
recorded without it (A killed from outside) is not yet a proof, and
the handle then demands the kernel's direct witness — B's pidfd
turning readable — before reporting a verified teardown.
"""

from __future__ import annotations

import array
import contextlib
import ctypes
import logging
import os
import select
import struct
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import IO, Callable, NamedTuple, NoReturn, Union

from . import probes
from ._fork_safe_warn import warn_post_fork
from ._proxy_bridge import _bring_up_loopback
from ._spawn import (
    _DEATH_W_LOCK,
    CLONE_NEWNET,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    _kill_and_reap,
    close_death_w,
    open_death_pipe,
)
from .errors import SandboxSetupError
from .preexec import _get_libc, set_pdeathsig

__all__ = [
    "SupervisedHandle",
    "SupervisedTeardownError",
    "spawn_supervised",
]

logger = logging.getLogger(__name__)

_PR_SET_PDEATHSIG = 1

# ns-init waiter (B) boot-failure exit codes. Distinct from each other
# and interpreted by A only for exits that happen BEFORE the target-pid
# report arrived (a post-report exit is a mirror of the target's fate,
# so a target legitimately exiting with one of these values is never
# misread — the phase disambiguates).
NS_INIT_EXIT_PRCTL_FAILED = 118
NS_INIT_EXIT_PARENT_GONE = 119
NS_INIT_EXIT_TARGET_FORK_FAILED = 120

# Exit code C uses after a failed exec (the classic shell convention;
# the actual diagnostic travels on the exec-status pipe, not this code).
_TARGET_EXEC_FAILED_EXIT = 127

# A's exit code on the death-pipe collapse path — 128+SIGKILL, i.e. the
# same value the mirror chain would produce for a SIGKILLed tree, so a
# post-mortem observer reads one consistent story.
_A_EXIT_COLLAPSE = 137

# How long spawn_supervised() waits for A's ready/failure message.
# The tree boot is three forks + one unshare + one exec — milliseconds
# — so this bounds pathological hangs (fd leaked to a stuck process),
# not normal operation. Too low: a loaded CI host spuriously fails a
# healthy spawn. Too high: a caller blocks pointlessly on a wedged
# boot before getting its SandboxSetupError.
_READY_DEADLINE_S = 15.0

# Post-SIGKILL reap budget for terminate()/kill(). SIGKILL teardown of
# a namespace is kernel-guaranteed except for members stuck in
# uninterruptible sleep (D-state), so this bounds how long a caller
# blocks on that pathology before getting SupervisedTeardownError
# (refuse-and-leak-loudly; the handle stays waitable and the kernel
# finishes the collapse when the stall clears). Too low: a healthy
# teardown under heavy load misreads as a stall. Too high: callers
# hang on a genuinely wedged tree with no signal to act on.
_KILL_REAP_BUDGET_S = 5.0

# procfs superblock magic (linux/magic.h PROC_SUPER_MAGIC): what
# fstatfs() reports for a file genuinely served by procfs. The group
# scan requires it of the mounts fd it latches — a non-procfs object
# bind-mounted at /proc/self/mounts serves an attacker-authored table,
# so a mismatch is occlusion.
_PROC_SUPER_MAGIC = 0x9FA0

# Bounded rescan budget for CHURN-ONLY occlusion in
# _group_sighted_members: when a scan's only occlusion signal is the
# verdict poll's "mount table changed mid-scan", the scan re-latches
# on a fresh fd and tries again, at most this many scans TOTAL. Not
# lower (1 = no retry): the mount-event counter is namespace-global
# and container hosts mount in bursts at pod/exec churn points, so a
# single unrelated transient event would turn the one-shot call sites
# (the natural-exit view, the graceful-rung check) into spurious
# occlusion refusals. Not higher: each attempt costs a full /proc
# scan (~25-45 ms at ~1000 entries), the loop-shaped callers already
# rescan every ~20 ms inside a 5 s budget, and exhaustion terminates
# in the pre-existing fail-closed refusal plumbing — more attempts
# would only let sustained churn (an unprivileged co-resident looping
# a setuid mount helper such as fusermount3 can produce it) hold
# every caller longer without changing the verdict class.
_SCAN_CHURN_RETRIES = 3

# Occlusion wording shared by the no-argument detector read and the
# scan's own latched-fd reads.
_MOUNTS_UNREADABLE = ("/proc/self/mounts is unreadable — mount "
                      "options unknown")

# Type accepted for stdout/stderr: an fd, an open file object, or
# subprocess.DEVNULL; None inherits. subprocess.PIPE and
# subprocess.STDOUT are rejected (a supervised long-runner writing to
# an unread pipe would wedge; STDOUT-merging is tier-divergent).
_StdioArg = Union[int, IO[bytes], IO[str], None]


class SupervisedTeardownError(RuntimeError):
    """terminate()/kill() could not VERIFY the tree's death.

    Raised when the group-tier ladder refuses to escalate (pgid <= 1
    guard, own-process-group guard) or when a bounded post-SIGKILL
    reap window expires without the death proof (pidns tier: A not
    reaped; group tier: leader unreaped or the group still
    corroborates as alive). The handle is left LIVE — refuse and leak
    loudly rather than report a teardown that did not happen. The
    caller may retry ``wait()``/``terminate()``; a D-state stall
    resolves when the kernel unblocks the member.
    """


# ---------------------------------------------------------------------------
# ns-init waiter (B)
# ---------------------------------------------------------------------------


def _arm_pdeathsig() -> bool:
    """Arm PR_SET_PDEATHSIG(SIGKILL) on the calling process.

    Returns True only when the prctl definitively succeeded. Post-fork
    safe: ``_get_libc()`` is a pure cache read here — the spawn path
    (and any test launcher) primes it PRE-fork, because a first-time
    ``find_library("c")`` can shell out to ldconfig, the banned
    post-fork fork-storm pattern.
    """
    libc = _get_libc()
    if libc is None:
        return False
    try:
        return libc.prctl(_PR_SET_PDEATHSIG, int(signal.SIGKILL)) == 0
    except (OSError, ValueError):
        return False


def _run_ns_init_waiter(
    live_r: int,
    target: Callable[[], NoReturn],
    post_fork_close: tuple[int, ...] = (),
) -> NoReturn:
    """Body of B, the ns-init waiter (PID 1 of the new pid namespace).

    Contract mirror of ``core/sandbox/_spawn.py``'s
    ``_pid1_split_for_waiter`` (see that function's docstring for the
    waiter doctrine): fork the target, forward SIGTERM/SIGINT/SIGHUP/
    SIGQUIT to it, reap orphans that reparent to init, and mirror the
    target's fate — its exit status verbatim, or 128+signum for a
    signal death. Keep the two implementations behaviourally aligned;
    the shared waiter-contract test battery
    (core/sandbox/tests/test_supervised_waiter_contract.py) runs this
    one and is parametrized so sibling waiter implementations can be
    added to the same assertions.

    Boot fails CLOSED, before the target ever exists:

    - ``_arm_pdeathsig()`` failure → ``_exit(NS_INIT_EXIT_PRCTL_FAILED)``.
      An unarmed waiter would survive its supervisor, which as a pid-ns
      init means an immortal namespace.
    - POLLHUP already pending on ``live_r`` (a pipe whose sole write
      end lives in the supervisor) → ``_exit(NS_INIT_EXIT_PARENT_GONE)``:
      the supervisor died in the fork-to-prctl window, so the pdeathsig
      never had a live parent to key to. ``getppid()`` cannot serve
      here — a pid-ns init reads its parent as 0.

    ``target`` runs in the fork child and must never return (it execs
    or ``os._exit``s). ``post_fork_close`` fds are closed on the waiter
    side once the target holds its own copies.
    """
    if not _arm_pdeathsig():
        os._exit(NS_INIT_EXIT_PRCTL_FAILED)
    poller = select.poll()
    poller.register(live_r, select.POLLIN)
    events = poller.poll(0)
    if any(ev & (select.POLLHUP | select.POLLERR) for _fd, ev in events):
        os._exit(NS_INIT_EXIT_PARENT_GONE)

    try:
        child = os.fork()
    except OSError:
        os._exit(NS_INIT_EXIT_TARGET_FORK_FAILED)
    if child == 0:
        target()
        os._exit(_TARGET_EXEC_FAILED_EXIT)  # target() must not return

    for fd in (live_r, *post_fork_close):
        with contextlib.suppress(OSError):
            os.close(fd)

    def _forward(signum: int, _frame: object) -> None:
        with contextlib.suppress(OSError):
            os.kill(child, signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, _forward)

    while True:
        try:
            pid, wstatus = os.wait()
        except InterruptedError:
            continue
        except ChildProcessError:
            # No children left and the target was never seen to exit —
            # cannot happen while the target is our child; defensive.
            os._exit(0)
        if pid != child:
            continue  # an orphan reparented to init — reaped, ignored
        if os.WIFEXITED(wstatus):
            os._exit(os.WEXITSTATUS(wstatus))
        if os.WIFSIGNALED(wstatus):
            os._exit(128 + os.WTERMSIG(wstatus))
        # Stopped/continued notifications are not delivered by os.wait
        # without WUNTRACED; anything else is unreachable — keep waiting.


# ---------------------------------------------------------------------------
# supervisor (A)
# ---------------------------------------------------------------------------


def _write_proc(path: str, data: str) -> None:
    fd = os.open(path, os.O_WRONLY)
    try:
        os.write(fd, data.encode("ascii"))
    finally:
        os.close(fd)


def _ns_setup(net_ns: bool) -> None:
    """Create and configure the namespaces. Runs in A, post-fork.

    ONE ``os.unshare`` call carrying every requested namespace: the
    pid-ns (and net-ns) grant must ride the same syscall as the
    CLONE_NEWUSER grant — restricted-userns hosts (AppArmor's
    unprivileged-userns transition) allow single-call multi-namespace
    creation but refuse a staged second unshare with EPERM.

    Identity uid/gid maps via the deny-setgroups sequence (the
    unprivileged single-uid mapping the kernel permits without
    newuidmap). Raises OSError on refusal — the caller converts that
    into the typed 'U' failure.
    """
    uid = os.getuid()
    gid = os.getgid()
    flags = CLONE_NEWUSER | CLONE_NEWPID
    if net_ns:
        flags |= CLONE_NEWNET
    os.unshare(flags)
    _write_proc("/proc/self/setgroups", "deny")
    _write_proc("/proc/self/gid_map", f"{gid} {gid} 1")
    _write_proc("/proc/self/uid_map", f"{uid} {uid} 1")
    if net_ns:
        # A fresh netns has lo DOWN — bring it up (same best-effort
        # posture as _spawn's step 3.5: on failure the netns behaves
        # like any pre-fix private netns, loopback IPC unavailable).
        try:
            _bring_up_loopback()
        except OSError as e:
            warn_post_fork(
                b"supervised: netns loopback bringup failed (errno=%d); "
                b"loopback IPC unavailable in this tree\n" % (e.errno or 0)
            )


def _send_status(sock: socket.socket, line: bytes,
                 fds: tuple[int, ...] = ()) -> None:
    """One-shot status message A → parent (SOCK_SEQPACKET preserves
    the message boundary; SCM_RIGHTS rides the same message)."""
    anc = []
    if fds:
        anc.append((socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    array.array("i", fds).tobytes()))
    with contextlib.suppress(OSError):
        sock.sendmsg([line], anc)


def _send_fail(sock: socket.socket, category: str, reason: str) -> None:
    # Category letters deliberately mirror the _spawn exec-status
    # vocabulary where the meaning matches: 'U' = namespace setup
    # refused (isolation never engaged), 'X' = every layer engaged and
    # the target's own exec failed. 'W' is this module's own: the
    # ns-init waiter failed closed before the target existed.
    reason = reason.replace("\n", " ")[:400]
    _send_status(sock, f"fail {category} {reason}".encode())


def _make_target_exec(
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    out_fd: int | None,
    err_fd: int | None,
    rep_w: int,
    xstat_w: int,
) -> Callable[[], NoReturn]:
    """Build C's post-fork body: report own outside pid, wire stdio,
    exec. Never returns."""

    def _target() -> NoReturn:
        try:
            # C's pid as the mounted procfs's namespace sees it (the
            # caller's view) — os.getpid() would return 2, the in-ns
            # pid. Diagnostic metadata only; -1 when procfs is
            # unavailable. Nothing ever signals this number.
            try:
                outside_pid = os.readlink("/proc/self")
            except OSError:
                outside_pid = "-1"
            os.write(rep_w, outside_pid.encode("ascii") + b"\n")
            os.close(rep_w)
            if cwd is not None:
                os.chdir(cwd)
            if out_fd is not None:
                os.dup2(out_fd, 1)
            if err_fd is not None:
                os.dup2(err_fd, 2)
            # xstat_w is close-on-exec: a successful exec closes it
            # (EOF, no bytes = the positive confirmation); the failure
            # arm below writes the diagnostic instead.
            os.execvpe(cmd[0], cmd, env)
            failure = "execvpe returned"  # unreachable
        except OSError as e:
            failure = f"errno {e.errno} ({e.strerror}): {cmd[0]}"
        except BaseException as e:  # never let C unwind into A's code
            failure = f"{type(e).__name__} before exec"
        with contextlib.suppress(OSError):
            os.write(xstat_w, failure.replace("\n", " ")[:400].encode())
        os._exit(_TARGET_EXEC_FAILED_EXIT)

    return _target


def _read_line_deadline(fd: int, deadline_s: float) -> bytes | None:
    """Read one newline-terminated line from fd within deadline_s.

    Returns the line without the newline, b"" on EOF-before-data, or
    None on deadline expiry.
    """
    buf = b""
    deadline = time.monotonic() + deadline_s
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if not poller.poll(remaining * 1000):
            continue
        try:
            chunk = os.read(fd, 64)
        except OSError:
            return b""
        if chunk == b"":
            return buf if buf else b""
        buf += chunk
        if buf.endswith(b"\n"):
            return buf[:-1]
        if len(buf) > 512:
            # Oversized report: return what arrived (truncated data —
            # NEVER b"", which readers treat as clean EOF: on the
            # exec-status pipe that would misread a long failure
            # diagnostic as exec success).
            return buf


def _map_waiter_boot_exit(code: int) -> str:
    if code == NS_INIT_EXIT_PRCTL_FAILED:
        return ("ns-init waiter could not arm PR_SET_PDEATHSIG — "
                "boot failed closed (an unarmed pid-ns init would be "
                "an immortal namespace)")
    if code == NS_INIT_EXIT_PARENT_GONE:
        return "ns-init waiter found its supervisor already gone at boot"
    if code == NS_INIT_EXIT_TARGET_FORK_FAILED:
        return "ns-init waiter could not fork the target"
    return f"ns-init waiter exited during boot (code {code})"


def _install_forwarders(b_pidfd: int) -> None:
    """Arm A's TERM/INT forwarding. MUST run before A reports
    readiness on the status socket: the moment spawn_supervised()
    returns, the caller may signal A, and an unarmed A would die with
    default disposition instead of forwarding — violating the
    supervisor-outlives-signal invariant (caught live: a SIGTERM in
    the report-to-arm window returned -15 instead of 143)."""

    def _forward_term(_signum: int, _frame: object) -> None:
        # A signal aimed at A becomes SIGTERM to B (which forwards to
        # the target); A keeps supervising until B actually exits —
        # the exit-path invariant.
        with contextlib.suppress(OSError):
            signal.pidfd_send_signal(b_pidfd, signal.SIGTERM)

    signal.signal(signal.SIGTERM, _forward_term)
    signal.signal(signal.SIGINT, _forward_term)


def _supervise(b_pid: int, b_pidfd: int, death_r: int | None) -> NoReturn:
    """A's supervision loop. poll-multiplexes {death_r, pidfd(B)};
    reaps B with WNOHANG only — never a blocking waitpid while B may
    still be running (the death pipe must stay observable throughout).
    Signal forwarders are already armed (_install_forwarders, before
    the readiness report)."""
    poller = select.poll()
    poller.register(b_pidfd, select.POLLIN)
    if death_r is not None:
        poller.register(death_r, select.POLLIN)
    while True:
        events = poller.poll()
        for fd, _ev in events:
            if fd == b_pidfd:
                pid, wstatus = os.waitpid(b_pid, os.WNOHANG)
                if pid == b_pid:
                    if os.WIFEXITED(wstatus):
                        os._exit(os.WEXITSTATUS(wstatus))
                    if os.WIFSIGNALED(wstatus):
                        os._exit(128 + os.WTERMSIG(wstatus))
                    os._exit(_A_EXIT_COLLAPSE)
            elif death_r is not None and fd == death_r:
                try:
                    data = os.read(death_r, 1)
                except OSError:
                    data = b""
                if data == b"":
                    # Every death_w copy is closed: the caller is gone,
                    # however it died. Collapse the tree — SIGKILL B via
                    # the pidfd; B's exit is kernel-gated on the
                    # namespace being empty, so this ONE blocking reap
                    # (nothing left to multiplex) is the whole proof.
                    with contextlib.suppress(OSError):
                        signal.pidfd_send_signal(b_pidfd, signal.SIGKILL)
                    with contextlib.suppress(OSError):
                        os.waitpid(b_pid, 0)
                    os._exit(_A_EXIT_COLLAPSE)


def _supervisor_main(
    a_sock: socket.socket,
    death_r: int | None,
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    out_fd: int | None,
    err_fd: int | None,
    net_ns: bool,
    survive: bool,
) -> NoReturn:
    """Body of A. Runs post-fork in the caller's memory image: no
    imports, no logging, no locks — every name here was resolved at
    module import; diagnostics travel on the status socket."""
    b_pid = -1
    b_pidfd = -1
    try:
        if survive:
            # Survive mode: detach from the caller's session so
            # session/group-directed teardown of the caller can't reap
            # a tree the caller asked to outlive it.
            with contextlib.suppress(OSError):
                os.setsid()
        # Kill mode: DELIBERATELY no setsid — A stays in the caller's
        # session and process group so teardown aimed at the caller's
        # group legitimately takes the supervisor (and, via the
        # PDEATHSIG chain + namespace collapse, the tree) with it.

        try:
            _ns_setup(net_ns)
        except OSError as e:
            _send_fail(a_sock, "U",
                       f"unshare/userns setup refused: errno {e.errno} "
                       f"({e.strerror})")
            os._exit(81)

        live_r, live_w = os.pipe()   # sole write end lives in A, for B's probe
        rep_r, rep_w = os.pipe()     # C reports its outside pid
        xstat_r, xstat_w = os.pipe()  # CLOEXEC exec-status: EOF = exec'd

        b_pid = os.fork()
        if b_pid == 0:
            # ---- B: PID 1 of the new pid namespace ----
            for fd in (live_w, rep_r, xstat_r):
                with contextlib.suppress(OSError):
                    os.close(fd)
            if death_r is not None:
                with contextlib.suppress(OSError):
                    os.close(death_r)
            with contextlib.suppress(OSError):
                a_sock.close()
            close_after_fork = tuple(
                fd for fd in (rep_w, xstat_w, out_fd, err_fd)
                if fd is not None
            )
            _run_ns_init_waiter(
                live_r,
                _make_target_exec(cmd, env, cwd, out_fd, err_fd,
                                  rep_w, xstat_w),
                post_fork_close=close_after_fork,
            )

        # ---- A continues ----
        for fd in (live_r, rep_w, xstat_w):
            os.close(fd)
        # A holds live_w for its lifetime: B's boot probe needs a live
        # write end, and A's death (any path) closing it is the design.

        try:
            b_pidfd = os.pidfd_open(b_pid)
        except OSError as e:
            with contextlib.suppress(OSError):
                os.kill(b_pid, signal.SIGKILL)  # own un-reaped child: safe
            with contextlib.suppress(OSError):
                os.waitpid(b_pid, 0)
            _send_fail(a_sock, "W", f"pidfd_open on ns-init failed: "
                                    f"errno {e.errno}")
            os._exit(82)

        line = _read_line_deadline(rep_r, _READY_DEADLINE_S)
        if not line:
            # EOF / garbage / deadline: B died (or wedged) before the
            # target reported. Collect B's fate for the diagnostic.
            with contextlib.suppress(OSError):
                signal.pidfd_send_signal(b_pidfd, signal.SIGKILL)
            code = -1
            with contextlib.suppress(OSError):
                _, wstatus = os.waitpid(b_pid, 0)
                if os.WIFEXITED(wstatus):
                    code = os.WEXITSTATUS(wstatus)
            _send_fail(a_sock, "W", _map_waiter_boot_exit(code))
            os._exit(83)
        try:
            c_pid = int(line)
        except ValueError:
            c_pid = -1

        # Exec confirmation: EOF with no bytes == the CLOEXEC status
        # pipe died at exec (the 'G'-equivalent); bytes == C's typed
        # exec failure.
        xline = _read_line_deadline(xstat_r, _READY_DEADLINE_S)
        if xline is None or xline != b"":
            with contextlib.suppress(OSError):
                signal.pidfd_send_signal(b_pidfd, signal.SIGKILL)
            with contextlib.suppress(OSError):
                os.waitpid(b_pid, 0)
            detail = (xline or b"exec confirmation timed out").decode(
                "utf-8", "replace")
            _send_fail(a_sock, "X", detail)
            os._exit(84)
        os.close(rep_r)
        os.close(xstat_r)
        for fd in (out_fd, err_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)

        # Arm forwarding BEFORE reporting ready: once the caller has
        # the handle it may signal A immediately.
        _install_forwarders(b_pidfd)
        _send_status(a_sock, b"ok pidns %d %d\n" % (b_pid, c_pid),
                     fds=(b_pidfd,))
        with contextlib.suppress(OSError):
            a_sock.close()

        _supervise(b_pid, b_pidfd, death_r)
    except BaseException:
        # Last-ditch arm of the exit-path invariant: an internal error
        # in A must not abandon a live B — kill it, await it (its exit
        # is gated on the namespace emptying), then exit.
        if b_pid > 0:
            if b_pidfd >= 0:
                with contextlib.suppress(OSError):
                    signal.pidfd_send_signal(b_pidfd, signal.SIGKILL)
            else:
                with contextlib.suppress(OSError):
                    os.kill(b_pid, signal.SIGKILL)
            with contextlib.suppress(OSError):
                os.waitpid(b_pid, 0)
        os._exit(85)
    os._exit(86)  # unreachable — _supervise never returns


# ---------------------------------------------------------------------------
# handle
# ---------------------------------------------------------------------------


def _decode_wait_status(wstatus: int) -> int:
    """waitpid status → Popen-convention returncode (>=0 exit status,
    -signum for a signal death of the waited process itself).

    Note the layering: a signal death INSIDE the tree surfaces as
    128+signum (the waiter mirror contract, a normal exit of A); a
    negative value here means the supervisor/leader process itself was
    signalled from outside.
    """
    if os.WIFEXITED(wstatus):
        return os.WEXITSTATUS(wstatus)
    if os.WIFSIGNALED(wstatus):
        return -os.WTERMSIG(wstatus)
    return -255  # unreachable for a terminated child


def _group_signal_refusal(pgid: int, own_pgid: int) -> str | None:
    """Pure refusal predicate for the group-tier killpg ladder.

    Returns the refusal reason, or None when signalling pgid is safe.
    Never signal a pgid <= 1 — killpg semantics make 0 "the caller's
    own group" and negative/1 values can address init or every
    process the uid can signal — and never the caller's own group.
    """
    if pgid <= 1:
        return (f"refusing killpg on pgid {pgid} (pgid <= 1 can address "
                f"the caller's own group, init, or every signallable "
                f"process)")
    if pgid == own_pgid:
        return "refusing killpg on the caller's own process group"
    return None


class _GroupMember(NamedTuple):
    """One sighted group member: pid, process-level state, and the
    kernel's start_time tick (stat field 22) — the (pid, start_time)
    pair is the member's identity across pid reuse."""
    pid: int
    state: bytes
    start_time: int


class _GroupView(NamedTuple):
    """Result of one group-membership /proc scan. ``occlusion`` is
    None only when the view is trustworthy as death evidence: a
    non-None occlusion names why the scan may have MISSED live members
    (mount-declared pid filtering, an unreadable entry, a listing that
    omits this process itself). Positive sightings remain valid under
    occlusion — only absence claims do not."""
    members: tuple[_GroupMember, ...]
    occlusion: str | None


def _proc_pid_view_filtered(table: bytes | None = None) -> str | None:
    """Mount-declared occlusion of the procfs pid view. Two shapes:
    ``hidepid=`` other than 0/off or ``subset=`` on the /proc mount
    (the mount that actually backs /proc is the LAST /proc line in
    /proc/self/mounts), and ANY mount whose mountpoint is a pid dir
    (/proc/<pid>) or below one — an overmount there shadows the pid's
    entries, so its stat reads ENOENT while the process lives. Either
    way the view can hide some pids while showing others: its
    sightings are insufficient evidence of ABSENCE. Returns the
    declaration found, or None for a clean view; an unreadable mounts
    table is itself occlusion (conservative).

    ``table`` lets the group scan pass bytes it read through its own
    latched fd (see ``_group_scan_attempt``); with no argument the
    helper reads /proc/self/mounts itself.

    A per-pid overmount is flagged regardless of a later /proc mount.
    The last-/proc-line-wins rule exists for the standard shape of a
    stale filtered /proc line under a fresh ``--mount-proc``; a
    lingering /proc/<pid> entry has no standard-runtime source —
    container runtimes mask non-pid paths (/proc/sys, /proc/kcore,
    ...) only — so the conservative reading errs toward refusal,
    never verification."""
    if table is None:
        try:
            with open("/proc/self/mounts", "rb") as f:
                table = f.read()
        except OSError:
            return _MOUNTS_UNREADABLE
    verdict: str | None = None
    pid_overmount: str | None = None
    for line in table.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        mountpoint = fields[1]
        if mountpoint.startswith(b"/proc/"):
            head = mountpoint[6:].split(b"/", 1)[0]
            if head.isdigit():
                pid_overmount = (
                    f"a mount is declared over "
                    f"/proc/{head.decode('ascii')} — that pid's "
                    f"entries are shadowed (per-pid overmount)")
            continue
        if mountpoint != b"/proc":
            continue
        verdict = None  # later /proc mounts shadow earlier ones
        for opt in fields[3].split(b","):
            if opt.startswith(b"subset="):
                verdict = (f"/proc is mounted with "
                           f"{opt.decode('ascii', 'replace')}")
            elif (opt.startswith(b"hidepid=")
                    and opt not in (b"hidepid=0", b"hidepid=off")):
                verdict = (f"/proc is mounted with "
                           f"{opt.decode('ascii', 'replace')}")
    return pid_overmount or verdict


def _proc_self_stat_pid() -> int | None:
    """The pid the mounted /proc reports for this process (field 1 of
    /proc/self/stat), or None when unreadable/garbled. A mismatch with
    ``os.getpid()`` means the view belongs to a DIFFERENT pid
    namespace — a strictly stronger tell than own-pid-in-listing,
    which a small namespace pid passes coincidentally against a
    foreign /proc (pid 1/2 are always listed)."""
    try:
        with open("/proc/self/stat", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    try:
        return int(raw.split(b" ", 1)[0])
    except ValueError:
        return None


def _mounts_latch_open() -> int | None:
    """Open the group scan's own fd on /proc/self/mounts — THE OPEN IS
    THE LATCH: it captures this mount namespace's mount-event counter,
    and every table mutation after it leaves a signal pending on the
    fd until a poll consumes it (change-and-revert cannot clear it).
    Deliberately opened BEFORE the pre-scan declaration read — churn
    landing between the open and the end of that read also flags, a
    slightly wider occluded window than the evidence strictly needs,
    and strictly fail-safe; do not "optimize" the open closer to the
    scan. Returns None when the open fails — the caller declares the
    table unreadable (occlusion, today's behaviour)."""
    try:
        return os.open("/proc/self/mounts", os.O_RDONLY)
    except OSError:
        return None


def _fstatfs_f_type(fd: int) -> int | None:
    """``fstatfs(fd)``'s ``f_type``, or None when the capability is
    unavailable on this host (no resolvable libc/fstatfs symbol) — the
    caller must then add NO signal, degrading to the plain reads.
    Raises OSError when the syscall itself fails. ``f_type`` is the
    first ``__fsword_t`` (native long) of ``struct statfs`` on every
    Linux libc this module runs under."""
    libc = _get_libc()
    if libc is None:
        return None
    try:
        fstatfs = libc.fstatfs
    except AttributeError:
        return None
    # 256 bytes comfortably covers struct statfs on every Linux ABI
    # (88-120 bytes); only the leading f_type word is decoded.
    buf = ctypes.create_string_buffer(256)
    if fstatfs(ctypes.c_int(fd), buf) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return struct.unpack_from("@l", buf.raw)[0]


def _mounts_fd_not_procfs(fd: int) -> str | None:
    """Superblock-magic check on the scan's latched mounts fd: a
    reason string when the object behind the fd is provably NOT served
    by procfs (a non-procfs file bind-mounted at /proc/self/mounts
    feeds the declaration reads an attacker-authored table), or when
    the check errors (fail-closed: the fd is process-private, no
    external party can provoke that). None when the fd is genuine
    procfs — or when fstatfs is unavailable on this host, which adds
    no signal (graceful degradation, never a false refusal)."""
    try:
        f_type = _fstatfs_f_type(fd)
    except OSError as exc:
        return (f"fstatfs on the /proc/self/mounts fd failed "
                f"({exc.__class__.__name__}) — the mounts table's "
                f"filesystem cannot be confirmed as procfs")
    if f_type is None or f_type == _PROC_SUPER_MAGIC:
        return None
    return (f"/proc/self/mounts is not served by procfs (fstatfs "
            f"f_type {f_type:#x}) — the mount table read through it "
            f"is not the kernel's")


def _mounts_table_read(fd: int) -> bytes:
    """Rewind and read the whole mounts table through the scan's
    latched fd. An open mounts fd is a LIVE table, not a snapshot, so
    the re-read at the scan's far end sees current state — and reads
    never touch the latch, so the pending-signal verdict survives
    both reads. Raises OSError; the caller treats that as an
    unreadable table (occlusion)."""
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _mounts_churn_pending(fd: int) -> bool:
    """The scan's VERDICT POLL: True when a mount-table mutation
    signal is pending on the latched fd (``POLLERR|POLLPRI`` is the
    kernel's mounts-changed report; kernels whose mounts file lacks
    the poll hook never raise it, so absence of the mechanism reads
    as absence of churn — exactly today's behaviour). THE POLL
    CONSUMES THE SIGNAL and re-latches: each pending signal is
    delivered exactly once, so this must be the fd's ONLY poll-type
    operation and must run AFTER the last evidence read (the
    single-consumer contract — a stray select(), a second call here,
    or an EPOLL_CTL_ADD registration would EAT the signal the verdict
    depends on and turn real churn into a silent clean scan). Raises
    OSError; the caller treats that as occlusion (fail-closed)."""
    poller = select.poll()
    poller.register(fd, select.POLLPRI)
    events = poller.poll(0)
    return any(ev & (select.POLLERR | select.POLLPRI)
               for _watched, ev in events)


def _group_sighted_members(pgid: int) -> _GroupView | None:
    """/proc scan for the group-tier death proof: every process whose
    pgrp is ``pgid``, or None when /proc itself cannot be listed (no
    view, no proof — the caller must refuse, never claim death).

    Retry shape: churn-only occlusion — a scan whose SOLE occlusion
    signal is the verdict poll's mid-scan mount-table change — is
    transient by nature, so the scan re-latches on a FRESH fd (the
    consumed signal died with the closed one) and rescans, at most
    ``_SCAN_CHURN_RETRIES`` scans total, then returns the
    churn-occluded view. Exhaustion therefore terminates in the
    callers' pre-existing fail-closed refusal plumbing; no occlusion
    is ever cleared or downgraded, and kills never gate on any of
    this. The priced trade: any mount churn in this namespace —
    including an unprivileged co-resident looping a setuid mount
    helper such as fusermount3 — can DELAY or REFUSE verification
    loudly; it can never suppress a kill or manufacture a false
    verify. Scan semantics per attempt: ``_group_scan_attempt``."""
    view: _GroupView | None = None
    for _attempt in range(_SCAN_CHURN_RETRIES):
        view, churn_only = _group_scan_attempt(pgid)
        if view is None or not churn_only:
            return view
    return view


def _group_scan_attempt(pgid: int) -> tuple[_GroupView | None, bool]:
    """One latched /proc scan — the single-attempt body of
    ``_group_sighted_members``. Returns ``(view, churn_only)``;
    ``churn_only`` is True only when the view's sole occlusion signal
    is the verdict poll's churn report (the one retriable shape —
    every other occlusion is declared state or a failed read, which a
    rescan cannot honestly clear).

    Field parsing splits on the LAST ')' — comm may contain spaces and
    parens. Entries that VANISH mid-scan (ENOENT/ESRCH) are gone, not
    members; an entry that is PRESENT but unreadable (EACCES-class —
    e.g. hidepid=1 with a setuid member) is OCCLUSION, never "gone":
    it marks the whole view untrustworthy for absence claims, exactly
    the ENOENT/EACCES distinction ``_member_provably_dead`` draws. A
    listing that omits this process's own pid, a /proc/self/stat that
    disagrees with getpid (a foreign pid namespace's view), or a
    mount-declared filter, is occlusion for the same reason.

    Mount declarations are read at BOTH ends of the scan through one
    fd whose OPEN latches the namespace's mount-event counter
    (``_mounts_latch_open``); after the post-scan read, a single
    verdict poll on that fd (``_mounts_churn_pending``) turns any
    mount-table mutation inside the window — attach, detach, move,
    remount, propagated events, and attach-and-detach pairs that the
    two reads alone would miss — into occlusion. That NARROWS the
    scan-window race, it does not close it: a hidepid-class option
    flipped on the shared proc SUPERBLOCK from a sibling mount
    namespace never bumps this namespace's event counter, so a
    flip-and-revert through that channel stays invisible mid-scan
    (bounded to other-uid members — hidepid hides only those; a
    PERSISTING flip is still declared by the ordinary reads), and a
    coherently forged /proc mounted before the scan opened was never
    detectable by reads through it — the pidns tier's pidfd witness
    is the answer to that attacker. On kernels whose mounts file
    lacks the poll hook the verdict poll never fires and the scan
    degrades to exactly the two-read behaviour."""
    latch_fd = _mounts_latch_open()
    try:
        filtered: str | None
        if latch_fd is None:
            filtered = _MOUNTS_UNREADABLE
        else:
            filtered = _mounts_fd_not_procfs(latch_fd)
            if filtered is None:
                try:
                    filtered = _proc_pid_view_filtered(
                        _mounts_table_read(latch_fd))
                except OSError:
                    filtered = _MOUNTS_UNREADABLE
        try:
            entries = os.listdir("/proc")
        except OSError:
            return None, False  # /proc unavailable: cannot prove anything
        occlusion = filtered
        if occlusion is None and str(os.getpid()) not in entries:
            occlusion = ("the /proc listing omits this process's own "
                         "pid — a filtered or foreign pid view")
        if occlusion is None:
            self_pid = _proc_self_stat_pid()
            if self_pid is None:
                occlusion = ("/proc/self/stat is unreadable — the view "
                             "cannot be confirmed as this pid "
                             "namespace's")
            elif self_pid != os.getpid():
                occlusion = (f"/proc/self/stat reads pid {self_pid} but "
                             f"this process is pid {os.getpid()} — a "
                             f"foreign pid view")
        members: list[_GroupMember] = []
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "rb") as f:
                    raw = f.read()
            except (FileNotFoundError, ProcessLookupError):
                continue  # vanished mid-scan — gone, not occluded
            except OSError as exc:
                if occlusion is None:
                    occlusion = (f"/proc/{entry}/stat is present but "
                                 f"unreadable "
                                 f"({exc.__class__.__name__}) — "
                                 f"hidepid-class occlusion, the entry "
                                 f"cannot be attributed")
                continue
            if not raw:
                continue  # exited between open and read — gone
            try:
                rest = raw.rsplit(b")", 1)[1].split()
                state, proc_pgrp = rest[0], int(rest[2])
                start_time = int(rest[19])
            except (IndexError, ValueError):
                if occlusion is None:
                    occlusion = (f"/proc/{entry}/stat is unparseable — "
                                 f"the entry cannot be attributed")
                continue
            if proc_pgrp == pgid:
                members.append(
                    _GroupMember(int(entry), state, start_time))
        if occlusion is None and latch_fd is not None:
            # A filter or per-pid overmount landing AFTER the mounts
            # table was read but BEFORE (or during) the listing is
            # applied to the scan yet undeclared by the first read:
            # re-read once the scan is complete — through the SAME
            # latched fd — so a mount present at either end of the
            # scan window occludes the view. (Reads never touch the
            # latch; the verdict poll below still covers the middle.)
            try:
                occlusion = _proc_pid_view_filtered(
                    _mounts_table_read(latch_fd))
            except OSError:
                occlusion = _MOUNTS_UNREADABLE
        if occlusion is None and latch_fd is not None:
            # SINGLE-CONSUMER CONTRACT: the verdict poll runs AFTER
            # the last evidence read and is this fd's ONLY poll-type
            # operation, ever. The poll CONSUMES the pending signal
            # (the kernel latch contract: the open latches, reads
            # never touch the latch, a poll consumes and re-latches)
            # — any earlier poll/select/epoll registration on this fd
            # would eat the signal this verdict depends on and turn
            # real mid-scan churn into a silent clean scan. Never add
            # one; the fd is fresh and process-private per scan
            # precisely to bound that exposure.
            try:
                if _mounts_churn_pending(latch_fd):
                    return _GroupView(
                        tuple(members),
                        ("the mount table changed during the scan "
                         "(mount-event signal latched on "
                         "/proc/self/mounts) — an attach-and-detach "
                         "inside the scan window cannot be ruled "
                         "out")), True
            except OSError as exc:
                occlusion = (f"the mount-churn verdict poll failed "
                             f"({exc.__class__.__name__}) — mid-scan "
                             f"table changes cannot be ruled out")
        return _GroupView(tuple(members), occlusion), False
    finally:
        if latch_fd is not None:
            with contextlib.suppress(OSError):
                os.close(latch_fd)


def _fd_readable_now(fd: int) -> bool:
    """Non-blocking POLLIN probe (no read, no side effects). For a
    pidfd, readable means the process has terminated."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    try:
        events = poller.poll(0)
    except OSError:
        return False
    return bool(events and events[0][1] & select.POLLIN)


def _member_provably_dead(pid: int, state: bytes) -> bool:
    """True only when ``pid`` is PROVABLY dead: process-level state Z
    AND every task in /proc/<pid>/task reads state Z.

    The process-level stat alone is not a death proof — a process
    whose thread-group leader called pthread_exit() reads Z there
    while worker threads run on (alive, killable, killpg-visible).
    Vanished tasks/dirs are dead; a present-but-unreadable task is NOT
    provable (the refuse direction, never a death claim)."""
    if state != b"Z":
        return False
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except FileNotFoundError:
        return True  # whole process vanished — dead
    except OSError:
        return False  # present but unreadable: cannot prove — refuse
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/stat", "rb") as f:
                tstate = f.read().rsplit(b")", 1)[1].split()[0]
        except FileNotFoundError:
            continue  # task exited mid-scan — dead
        except (OSError, IndexError):
            return False  # unreadable/garbled: cannot prove — refuse
        if tstate != b"Z":
            return False
    return True


class SupervisedHandle:
    """Live handle on a supervised tree. Construct via
    ``spawn_supervised`` only.

    Attributes (all read-only by convention):

    - ``tier``: ``"pidns"`` or ``"group"`` — documented as an OPEN set;
      match known values and treat unknown tiers conservatively.
    - ``confinement``: always ``"none"``. This is NOT a sandbox: no
      security confinement of any kind is applied to the target.
    - ``pid``: A (the supervisor) on the pidns tier; the Popen child on
      the group tier. Always this process's direct, waitable child.
    - ``ns_init_pid`` / ``ns_init_pidfd``: B's pid (diagnostic — never
      signalled by number) and the SCM_RIGHTS-received pidfd (the ONLY
      route this handle signals the tree through). None on the group
      tier.
    - ``target_pid``: C's outside-the-namespace pid (diagnostic; -1 if
      procfs was unavailable to C) / the Popen child on the group tier.
    - ``returncode``: None while running; then the Popen convention —
      >= 0 exit status (which is 128+signum for a signal death INSIDE
      the tree, per the waiter mirror), or -signum if the supervisor/
      leader itself was signalled from outside.
    """

    def __init__(
        self,
        *,
        tier: str,
        pid: int,
        target_pid: int,
        on_parent_death: str,
        name: str | None,
        ns_init_pid: int | None = None,
        ns_init_pidfd: int | None = None,
        pidfd: int | None = None,
        popen: subprocess.Popen | None = None,
        death_w: int | None = None,
    ) -> None:
        self.tier = tier
        self.confinement = "none"
        self.pid = pid
        self.target_pid = target_pid
        self.on_parent_death = on_parent_death
        self.name = name
        self.ns_init_pid = ns_init_pid
        self.ns_init_pidfd = ns_init_pidfd
        self.returncode: int | None = None
        self._pidfd = pidfd
        self._popen = popen
        self._death_w = death_w
        # Group tier: True only after a CORROBORATED group teardown — a
        # naturally-exited leader's returncode alone is not a teardown
        # proof (descendants may linger in the group). The pidns tier
        # starts True and is re-checked at reap time: A's OWN exit
        # paths are kernel-gated on the namespace emptying, but an
        # external kill of A is not — _record_exit then demands B's
        # pidfd as the namespace-empty witness and flips this to False
        # until _confirm_ns_collapse_locked sees it.
        self._group_verified: bool = popen is None
        # Group tier: the group view captured at the reap that recorded
        # the leader's exit — the identity anchor the natural-exit
        # corroboration needs before it may signal (see
        # _teardown_after_natural_exit_locked).
        self._group_exit_view: _GroupView | None = None
        # RLock: terminate() re-enters the poll path under the lock.
        self._lock = threading.RLock()

    # -- state ------------------------------------------------------------

    def _record_exit(self, returncode: int) -> None:
        self.returncode = returncode
        if self._popen is not None and not self._group_verified:
            # Identity anchor for the natural-exit corroboration: this
            # reap is the last instant self.pid is kernel-guaranteed
            # OURS (an unreaped child's pid cannot be recycled), so
            # members sighted NOW provably belonged to this tree's
            # group. Occlusion or an unlistable /proc merely shrinks
            # or drops the anchor — the refuse direction later, never
            # a false identity claim.
            self._group_exit_view = _group_sighted_members(self.pid)
        if self.ns_init_pidfd is not None:
            # pidns tier: A's OWN exit paths prove the namespace empty
            # (A reaps B, whose exit the kernel gates on
            # zap_pid_ns_processes draining every member), but an
            # EXTERNAL kill of A records this exit without that gate.
            # B's pidfd is the kernel's direct witness — readable
            # means B (PID 1) exited, so the namespace is empty. Not
            # readable: keep the fd and demand the proof at teardown
            # (_confirm_ns_collapse_locked).
            if _fd_readable_now(self.ns_init_pidfd):
                with contextlib.suppress(OSError):
                    os.close(self.ns_init_pidfd)
                self.ns_init_pidfd = None
            else:
                self._group_verified = False
        if self._pidfd is not None:
            with contextlib.suppress(OSError):
                os.close(self._pidfd)
            self._pidfd = None
        if self._death_w is not None:
            close_death_w(self._death_w)
            self._death_w = None

    def _poll_locked(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if self._popen is not None:
            rc = self._popen.poll()
            if rc is not None:
                self._record_exit(rc)
            return self.returncode
        try:
            pid, wstatus = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: supervisor was "
                f"reaped outside this handle (a broad os.wait() in this "
                f"process?) — exit status lost, tree state unverifiable"
            ) from None
        if pid == self.pid:
            self._record_exit(_decode_wait_status(wstatus))
        return self.returncode

    def poll(self) -> int | None:
        """Non-blocking: returncode if the tree's supervisor/leader has
        exited (reaping it), else None."""
        with self._lock:
            return self._poll_locked()

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the tree to end; returns the returncode.

        Raises TimeoutError on expiry with the handle state UNCHANGED
        (still waitable, still terminatable)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                rc = self._poll_locked()
            if rc is not None:
                return rc
            remaining: float | None = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"supervised[{self.name or self.pid}]: still "
                        f"running after {timeout}s")
            self._block_for_exit(remaining)

    def _block_for_exit(self, remaining: float | None) -> None:
        """Block (bounded) until the child MAY have exited. Slice-capped
        so a concurrent reaper's fd close/reuse can't strand us on a
        stale pidfd for longer than one slice."""
        slice_s = 0.5 if remaining is None else max(min(remaining, 0.5), 0.0)
        if self._popen is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                self._popen.wait(timeout=slice_s)
            return
        fd = self._pidfd
        if fd is None:
            time.sleep(min(slice_s, 0.05))
            return
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        with contextlib.suppress(OSError):
            poller.poll(slice_s * 1000)

    # -- teardown ---------------------------------------------------------

    def _signal_ns_init(self, sig: signal.Signals) -> None:
        # pidfd only: pid-reuse safe by construction. ESRCH = already
        # dead, which the reap that always follows will prove.
        fd = self.ns_init_pidfd
        if fd is None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            signal.pidfd_send_signal(fd, sig)

    def _reap_supervisor_bounded(self, budget_s: float) -> bool:
        deadline = time.monotonic() + budget_s
        while True:
            if self._poll_locked() is not None:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._block_for_exit(remaining)

    def _teardown_pidns_locked(self, grace_s: float, *,
                               graceful: bool) -> int:
        if graceful:
            self._signal_ns_init(signal.SIGTERM)
            if self._reap_supervisor_bounded(grace_s):
                return self._pidns_verified_rc_locked()
        self._signal_ns_init(signal.SIGKILL)
        if self._reap_supervisor_bounded(_KILL_REAP_BUDGET_S):
            return self._pidns_verified_rc_locked()
        raise SupervisedTeardownError(
            f"supervised[{self.name or self.pid}]: supervisor not reaped "
            f"within {_KILL_REAP_BUDGET_S}s of SIGKILL — a namespace "
            f"member is likely in uninterruptible sleep; handle left "
            f"live, retry wait()/terminate()")

    def _pidns_verified_rc_locked(self) -> int:
        """A is reaped; return the recorded returncode once the
        namespace-empty proof is in (which A's own exit paths
        guarantee; a racing external kill of A may not — then demand
        B's pidfd witness)."""
        if self._group_verified:
            return self.returncode  # type: ignore[return-value]
        return self._confirm_ns_collapse_locked()

    def _confirm_ns_collapse_locked(self) -> int:
        """The supervisor exited WITHOUT the namespace-empty gate (an
        external kill of A): demand the kernel's own witness — B's
        (PID 1's) pidfd turning readable, which the kernel gates on
        zap_pid_ns_processes having drained every namespace member —
        before reporting the teardown verified. The namespace is
        already collapsing via B's PDEATHSIG; SIGKILL through the
        pidfd is belt-and-braces (ESRCH means already dead)."""
        fd = self.ns_init_pidfd
        if fd is None:
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: supervisor died "
                f"externally ({self.returncode}) and no namespace-empty "
                f"witness is available (B's pidfd is gone) — teardown "
                f"NOT verified")
        self._signal_ns_init(signal.SIGKILL)
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        deadline = time.monotonic() + _KILL_REAP_BUDGET_S
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: supervisor "
                    f"died externally ({self.returncode}) and the "
                    f"namespace is not confirmed empty within "
                    f"{_KILL_REAP_BUDGET_S}s — a member is likely in "
                    f"uninterruptible sleep; teardown NOT verified, "
                    f"retry terminate()")
            try:
                events = poller.poll(remaining * 1000)
            except OSError:
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: the "
                    f"namespace-empty witness fd is unusable — "
                    f"teardown NOT verified") from None
            if events and events[0][1] & select.POLLIN:
                break
            if events:  # POLLERR/POLLHUP/POLLNVAL: witness unusable
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: the "
                    f"namespace-empty witness fd reported "
                    f"{events[0][1]:#x} instead of readable — "
                    f"teardown NOT verified")
        self._group_verified = True
        if self.ns_init_pidfd is not None:
            with contextlib.suppress(OSError):
                os.close(self.ns_init_pidfd)
            self.ns_init_pidfd = None
        return self.returncode  # type: ignore[return-value]

    def _teardown_group_locked(self, grace_s: float, *,
                               graceful: bool) -> int:
        popen = self._popen
        assert popen is not None
        try:
            pgid = os.getpgid(self.pid)
        except ProcessLookupError:
            # Leader already dead but not yet reaped through this
            # handle — reap it, then the GROUP still needs its death
            # proof (descendants may linger past the leader).
            if not self._reap_supervisor_bounded(_KILL_REAP_BUDGET_S):
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: leader "
                    f"vanished but could not be reaped") from None
            return self._teardown_after_natural_exit_locked(
                grace_s, graceful=graceful)
        refusal = _group_signal_refusal(pgid, os.getpgrp())
        if refusal:
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: {refusal} — "
                f"handle left live")
        if graceful:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGTERM)
            if self._reap_supervisor_bounded(grace_s):
                return self._corroborate_group_dead_locked(pgid)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        if self._reap_supervisor_bounded(_KILL_REAP_BUDGET_S):
            return self._corroborate_group_dead_locked(pgid)
        raise SupervisedTeardownError(
            f"supervised[{self.name or self.pid}]: group leader not "
            f"reaped within {_KILL_REAP_BUDGET_S}s of SIGKILL — handle "
            f"left live, retry wait()/terminate()")

    def _corroborate_group_dead_locked(self, pgid: int) -> int:
        """Leader reaped; corroborate the WHOLE group is gone (the group
        tier's weaker analogue of the namespace-empty proof), escalating
        stragglers. pgid was captured pre-kill and passed the refusal
        predicate.

        The group counts dead ONLY on positive evidence:

        (a) ``killpg(pgid, 0)`` raises ESRCH — the kernel's own "no
            such group" (it counts zombies as members, so this also
            covers a promptly-reaping init); or
        (b) the /proc scan's view is UNOCCLUDED (no mount-declared pid
            filtering, no unreadable entry, own pid listed), it SIGHTED
            at least one member with matching pgrp, every sighted
            member reads state Z, and each sighted member's
            /proc/<pid>/task holds only Z tasks (state Z at the process
            level alone is NOT death: a zombie thread-group leader can
            front a live worker thread; a Z-through-tasks member is
            dead, merely awaiting a reap that is not ours to perform
            under a non-reaping init).

        Everything else refuses at the deadline. An unlistable /proc is
        no proof; an OCCLUDED view proves only what it sighted, never
        absence — a hidden live member cannot be ruled out. Zero
        sighted members while killpg-0 still SUCCEEDS is a positive
        CONTRADICTION — a skewed procfs pid view (this /proc does not
        show the pid namespace the signals travel in), so keep
        escalating and refuse loudly, never claim death. This seam owns
        a group it has already signalled, so escalation continues
        throughout; only the VERIFY claim needs the trustworthy view."""
        deadline = time.monotonic() + _KILL_REAP_BUDGET_S
        while True:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                self._group_verified = True
                return self.returncode  # type: ignore[return-value]
            except PermissionError:
                pass  # exists but not ours to probe — treat as survivor
            view = _group_sighted_members(pgid)
            if view is None:
                detail = ("/proc is unlistable — no view of the group, "
                          "death cannot be corroborated")
            elif not view.members:
                detail = (f"killpg({pgid}, 0) sees the group but the "
                          f"/proc scan sights no member — procfs "
                          f"pid-view skew, this /proc does not show the "
                          f"pid namespace the signals travel in")
            else:
                unproven = [m.pid for m in view.members
                            if not _member_provably_dead(m.pid, m.state)]
                if unproven:
                    detail = f"members not provably dead: {unproven}"
                elif view.occlusion is not None:
                    detail = (f"every sighted member is dead but the "
                              f"/proc view is occluded "
                              f"({view.occlusion}) — a hidden live "
                              f"member cannot be ruled out")
                else:
                    self._group_verified = True
                    return self.returncode  # type: ignore[return-value]
            if time.monotonic() >= deadline:
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: leader is "
                    f"dead ({self.returncode}) but process group {pgid} "
                    f"is NOT corroborated dead after SIGKILL escalation "
                    f"— {detail}; returncode is recorded, teardown NOT "
                    f"verified")
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGKILL)
            time.sleep(0.02)

    def _teardown_after_natural_exit_locked(self, grace_s: float, *,
                                            graceful: bool) -> int:
        """First terminate()/kill() after the leader was reaped without
        a verified group teardown (natural exit, or an exit noticed by
        poll()/wait()): descendants may linger in the group, so the
        leader's returncode alone is not a teardown proof —
        corroborate, escalating sighted survivors.

        Signal safety: once the whole group is gone its pgid may be
        RECYCLED by an unrelated process, so this path never signals on
        killpg-0 evidence alone — and sighting a live member with a
        matching pgrp proves only that the pgid is held NOW, not that
        it was held continuously since this tree owned it. Continuity
        is anchored at the reap that recorded the leader's exit: an
        unreaped child's pid cannot be recycled, so the group view
        captured at that reap (``_group_exit_view``) names members that
        provably belonged to this tree, identified by
        (pid, start_time). A signal is sent only when some CURRENTLY
        sighted live member matches the anchor — a member spanning the
        anchor to now held the pgid the whole time, so the group is
        still this tree's. No match, no trustworthy anchor, an occluded
        current view over an absence claim, or a zero-sighted
        contradiction: refuse loudly, unsignalled.
        """
        pgid = self.pid  # start_new_session: pgid == leader pid
        refusal = _group_signal_refusal(pgid, os.getpgrp())
        if refusal:
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: {refusal} — "
                f"group teardown not corroborated")
        view = _group_sighted_members(pgid)
        if view is None:
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: leader exited "
                f"({self.returncode}) but /proc is unlistable — group "
                f"teardown cannot be corroborated")
        live = [m for m in view.members
                if not _member_provably_dead(m.pid, m.state)]
        if not live:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                self._group_verified = True
                return self.returncode  # type: ignore[return-value]
            except PermissionError:
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: leader "
                    f"exited ({self.returncode}) but killpg({pgid}, 0) "
                    f"is EPERM — a group member this handle cannot "
                    f"probe exists; teardown NOT verified") from None
            if view.occlusion is not None:
                # killpg-0 sees the group and the view that claims
                # "nothing alive" is untrustworthy: a hidden live
                # member cannot be ruled out, and an occluded view is
                # no identity proof to signal on either.
                raise SupervisedTeardownError(
                    f"supervised[{self.name or self.pid}]: leader "
                    f"exited ({self.returncode}) but killpg({pgid}, 0) "
                    f"still sees the group and the /proc view is "
                    f"occluded ({view.occlusion}) — a hidden live "
                    f"member cannot be ruled out; refusing to signal, "
                    f"teardown NOT verified")
            if view.members:
                # Unoccluded view, sighted members, every one
                # Z-through-tasks: dead, held un-reaped by a
                # non-reaping init — verified.
                self._group_verified = True
                return self.returncode  # type: ignore[return-value]
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: leader exited "
                f"({self.returncode}) but killpg({pgid}, 0) still sees "
                f"the group while the /proc scan sights no member — "
                f"procfs pid-view skew or a recycled pgid; refusing to "
                f"signal, teardown NOT verified")
        # Live members sighted: signal only with identity continuity —
        # some current live member must match the reap-time anchor by
        # (pid, start_time).
        anchor = self._group_exit_view
        anchor_ids = (frozenset((m.pid, m.start_time)
                                for m in anchor.members)
                      if anchor is not None else frozenset())
        if not any((m.pid, m.start_time) in anchor_ids for m in live):
            raise SupervisedTeardownError(
                f"supervised[{self.name or self.pid}]: leader exited "
                f"({self.returncode}) and live pgrp-{pgid} members "
                f"{[m.pid for m in live]} are sighted, but none "
                f"matches the group view anchored at the leader's reap "
                f"— the pgid may have been recycled by an unrelated "
                f"process (or the group repopulated after the anchor); "
                f"refusing to signal, teardown NOT verified")
        # An anchored survivor proves the group is still this tree's —
        # run the normal rung ladder at the group. (A concurrently
        # occluded view does not block the ladder: the match is
        # positive identity evidence, and the corroboration below
        # refuses to VERIFY through an occluded view anyway.)
        if graceful:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGTERM)
            grace_deadline = time.monotonic() + grace_s
            while time.monotonic() < grace_deadline:
                remaining = _group_sighted_members(pgid)
                if (remaining is not None
                        and remaining.occlusion is None
                        and all(_member_provably_dead(m.pid, m.state)
                                for m in remaining.members)):
                    break
                time.sleep(0.02)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        return self._corroborate_group_dead_locked(pgid)

    def terminate(self, grace_s: float = 5.0) -> int:
        """Graceful teardown: SIGTERM the tree, wait ``grace_s``, then
        SIGKILL. Returns the recorded returncode ONLY when death is
        verified (pidns: A reaped WITH the namespace-empty proof —
        A's own exit paths carry it, and after an external kill of A
        the kernel's witness, B's pidfd turning readable, is demanded
        instead; group: leader reaped AND the group corroborates
        dead). Idempotent after a VERIFIED teardown — it
        then just returns the recorded returncode; a leader that exited
        on its own is NOT yet a verified teardown (descendants may
        linger in the group), so the first terminate()/kill() after a
        natural exit still corroborates — and escalates — the group.
        Raises SupervisedTeardownError (handle left LIVE) when the
        ladder must refuse or death cannot be verified in time."""
        with self._lock:
            if self._poll_locked() is not None:
                if self._group_verified:
                    return self.returncode  # type: ignore[return-value]
                if self._popen is not None:
                    return self._teardown_after_natural_exit_locked(
                        grace_s, graceful=True)
                return self._confirm_ns_collapse_locked()
            if self._popen is not None:
                return self._teardown_group_locked(grace_s, graceful=True)
            return self._teardown_pidns_locked(grace_s, graceful=True)

    def kill(self) -> int:
        """terminate() without the grace phase: straight to SIGKILL,
        same verified-death contract."""
        with self._lock:
            if self._poll_locked() is not None:
                if self._group_verified:
                    return self.returncode  # type: ignore[return-value]
                if self._popen is not None:
                    return self._teardown_after_natural_exit_locked(
                        0.0, graceful=False)
                return self._confirm_ns_collapse_locked()
            if self._popen is not None:
                return self._teardown_group_locked(0.0, graceful=False)
            return self._teardown_pidns_locked(0.0, graceful=False)

    def __enter__(self) -> "SupervisedHandle":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.terminate()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"<SupervisedHandle {self.name or ''} tier={self.tier} "
                f"pid={self.pid} target_pid={self.target_pid} "
                f"returncode={self.returncode}>")

    # NO __del__ / finalizer, deliberately: an interpreter-shutdown or
    # gc-timed signal from a stale handle is exactly the fleet-kill
    # hazard class. Teardown is the owner's explicit act; in kill mode
    # the death pipe already guarantees collapse when the owner dies.


# ---------------------------------------------------------------------------
# spawn
# ---------------------------------------------------------------------------


def _resolve_stdio_fd(stream: _StdioArg, label: str) -> tuple[int | None, bool]:
    """Normalise a stdout/stderr argument to (fd | None, owned).

    ``owned`` fds (the DEVNULL open) are the spawner's to close."""
    if stream is None:
        return None, False
    if stream == subprocess.PIPE or stream == subprocess.STDOUT:
        raise ValueError(
            f"{label}={stream!r} is not supported by spawn_supervised "
            f"(a supervised long-runner writing to an unread pipe would "
            f"wedge) — pass an fd, an open file, subprocess.DEVNULL, or "
            f"None to inherit")
    if stream == subprocess.DEVNULL:
        return os.open(os.devnull, os.O_WRONLY), True
    if isinstance(stream, int):
        if stream < 0:
            raise ValueError(f"{label}: negative fd {stream}")
        return stream, False
    fileno = getattr(stream, "fileno", None)
    if fileno is None:
        raise TypeError(f"{label}: expected fd, file object, "
                        f"subprocess.DEVNULL, or None — got {stream!r}")
    flush = getattr(stream, "flush", None)
    if flush is not None:
        with contextlib.suppress(OSError, ValueError):
            flush()
    return fileno(), False


def _recv_ready(p_sock: socket.socket, a_pid: int,
                death_w: int | None) -> tuple[int, int, int]:
    """Block (bounded) on A's one-shot ready/failure message.

    Returns (ns_init_pid, target_pid, ns_init_pidfd) on success;
    raises SandboxSetupError (after cleaning up A and the tree — A's
    SIGKILL propagates through the PDEATHSIG chain) otherwise."""

    def _fail(reason: str, category: str | None,
              *, reap_only: bool = False) -> NoReturn:
        if reap_only:
            with contextlib.suppress(OSError):
                os.waitpid(a_pid, 0)
        else:
            _kill_and_reap(a_pid)
        if death_w is not None:
            close_death_w(death_w)
        raise SandboxSetupError(
            f"supervised spawn failed: {reason}",
            setup_category=category)

    p_sock.settimeout(_READY_DEADLINE_S)
    fds: list[int] = []
    try:
        msg, ancdata, _flags, _addr = p_sock.recvmsg(
            512, socket.CMSG_SPACE(array.array("i", [0]).itemsize))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == socket.SOL_SOCKET
                    and cmsg_type == socket.SCM_RIGHTS):
                arr = array.array("i")
                usable = len(cmsg_data) - (len(cmsg_data) % arr.itemsize)
                arr.frombytes(cmsg_data[:usable])
                fds.extend(arr)
    except TimeoutError:
        _fail(f"no ready message within {_READY_DEADLINE_S}s", None)
    except OSError as e:
        _fail(f"status socket error: {e}", None)

    try:
        if msg == b"":
            # A died without reaching any reporting site — the
            # synthetic '!' category, mirroring _spawn's vocabulary.
            _fail("supervisor died before reporting", "!", reap_only=True)
        text = msg.decode("utf-8", "replace").strip()
        if text.startswith("fail "):
            _, _, rest = text.partition(" ")
            category, _, reason = rest.partition(" ")
            _fail(reason or "unspecified", category or None, reap_only=True)
        parts = text.split()
        # The tier word is part of the acceptance predicate: this
        # reader mints a pidns-tier handle, so only "ok pidns ..." may
        # stamp it — any other tier claim is malformed here.
        if (len(parts) != 4 or parts[0] != "ok" or parts[1] != "pidns"
                or len(fds) != 1):
            _fail(f"malformed ready message: {text!r}", None)
        return int(parts[2]), int(parts[3]), fds[0]
    except BaseException:
        for fd in fds:
            with contextlib.suppress(OSError):
                os.close(fd)
        raise


def _spawn_pidns_tier(
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    stdout: _StdioArg,
    stderr: _StdioArg,
    net_ns: bool,
    kill_mode: bool,
    name: str | None,
) -> SupervisedHandle:
    # Prime the libc cache for B's post-fork _arm_pdeathsig (a
    # first-time find_library can shell out — banned post-fork).
    _get_libc()
    out_fd = err_fd = None
    owned: list[int] = []
    death_r: int | None = None
    death_w: int | None = None
    p_sock: socket.socket | None = None
    try:
        out_fd, out_owned = _resolve_stdio_fd(stdout, "stdout")
        if out_owned:
            owned.append(out_fd)  # type: ignore[arg-type]
        err_fd, err_owned = _resolve_stdio_fd(stderr, "stderr")
        if err_owned:
            owned.append(err_fd)  # type: ignore[arg-type]
        # SOCK_SEQPACKET: one message, one boundary, SCM_RIGHTS rides it.
        p_sock, a_sock = socket.socketpair(socket.AF_UNIX,
                                           socket.SOCK_SEQPACKET)
        if kill_mode:
            death_r, death_w = open_death_pipe()
        # Fork under the registry lock (the _spawn discipline): the
        # at-fork hook closes EVERY registered death_w copy in A —
        # including this spawn's own, so A watches death_r only.
        with _DEATH_W_LOCK:
            a_pid = os.fork()
        if a_pid == 0:
            # ---- A ----
            try:
                with contextlib.suppress(OSError):
                    p_sock.close()
                _supervisor_main(a_sock, death_r, cmd, env, cwd,
                                 out_fd, err_fd, net_ns,
                                 survive=not kill_mode)
            finally:
                os._exit(87)  # _supervisor_main never returns
        # ---- caller ----
        a_sock.close()
        if death_r is not None:
            os.close(death_r)
            death_r = None
        b_pid, c_pid, b_pidfd = _recv_ready(p_sock, a_pid, death_w)
        p_sock.close()
        p_sock = None
        a_pidfd: int | None = None
        with contextlib.suppress(OSError):
            a_pidfd = os.pidfd_open(a_pid)
        handle = SupervisedHandle(
            tier="pidns", pid=a_pid, target_pid=c_pid,
            on_parent_death="kill" if kill_mode else "survive",
            name=name, ns_init_pid=b_pid, ns_init_pidfd=b_pidfd,
            pidfd=a_pidfd, death_w=death_w)
        death_w = None  # ownership moved to the handle
        return handle
    finally:
        for fd in owned:
            with contextlib.suppress(OSError):
                os.close(fd)
        if death_r is not None:
            with contextlib.suppress(OSError):
                os.close(death_r)
        if death_w is not None:
            close_death_w(death_w)
        if p_sock is not None:
            with contextlib.suppress(OSError):
                p_sock.close()


def _spawn_group_tier(
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    stdout: _StdioArg,
    stderr: _StdioArg,
    kill_mode: bool,
    name: str | None,
) -> SupervisedHandle:
    # Degraded tier: plain process group, exactly the pre-existing
    # posture of RAPTOR tool spawns. Kill mode arms the shared
    # set_pdeathsig preexec (which also applies the sacrificial-child
    # oom_score_adj, its documented companion behaviour): the caller's
    # death SIGKILLs the leader — descendants beyond the leader are
    # this tier's honest gap, which the pidns tier exists to close.
    preexec = set_pdeathsig() if kill_mode else None
    try:
        popen = subprocess.Popen(
            cmd, env=env, cwd=cwd, stdout=stdout, stderr=stderr,
            start_new_session=True, preexec_fn=preexec)
    except OSError as e:
        raise SandboxSetupError(
            f"supervised spawn (group tier) exec failed: {e}",
            setup_category="X") from e
    return SupervisedHandle(
        tier="group", pid=popen.pid, target_pid=popen.pid,
        on_parent_death="kill" if kill_mode else "survive",
        name=name, popen=popen)


def spawn_supervised(
    cmd: list[str],
    *,
    on_parent_death: str,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    stdout: _StdioArg = None,
    stderr: _StdioArg = None,
    pid_ns: str = "auto",
    net_ns: bool = False,
    name: str | None = None,
) -> SupervisedHandle:
    """Spawn ``cmd`` as a supervised process tree; returns a live
    :class:`SupervisedHandle` only after the tree is actually up (the
    target exec confirmed), else raises the typed failure.

    This is NOT a sandbox: no security confinement of any kind is
    applied to the target. For untrusted code use the sandbox
    profiles; this primitive only guarantees teardown.

    - ``cmd``: argv list only — no shell-string form exists.
    - ``on_parent_death`` (REQUIRED, no default — the caller must own
      this fate decision explicitly): ``"kill"`` = the owning process's
      death, however it dies, collapses the tree (death pipe on the
      pidns tier; PDEATHSIG on the group-tier leader). ``"survive"`` =
      the tree outlives the caller (the supervisor detaches into its
      own session).
    - ``env=None`` snapshots ``RaptorConfig.get_safe_env()`` at spawn
      time; a caller-provided mapping is used VERBATIM.
    - ``stdout``/``stderr``: fd, open file object, or
      ``subprocess.DEVNULL``; None inherits. PIPE/STDOUT are rejected.
    - ``pid_ns``: ``"auto"`` (probe; degrade to the group tier on
      refusal), ``"require"`` (SandboxSetupError instead of degrading),
      ``"off"`` (group tier unconditionally).
    - ``net_ns=True`` adds a private network namespace to the SAME
      unshare call (loopback brought up). It exists only on the pidns
      tier: combinations that would silently drop it (``pid_ns="off"``,
      or a refused/failed namespace under ``"auto"``) raise
      SandboxSetupError instead — requested isolation is never
      silently downgraded.
    - ``name``: diagnostic label for errors and repr.

    Runtime-refusal discipline: if the probe said the pidns tier
    engages but the live spawn's unshare is refused anyway, the cached
    probe verdict is flipped to refused (so later ``"auto"`` spawns
    skip the doomed attempt) and this call degrades to the group tier
    (``"auto"``) or raises (``"require"``).
    """
    if isinstance(cmd, (str, bytes)):
        raise TypeError("spawn_supervised takes an argv list — there is "
                        "deliberately no shell-string form")
    if not isinstance(cmd, (list, tuple)) or not cmd or not all(
            isinstance(a, str) for a in cmd):
        raise ValueError("cmd must be a non-empty list of str")
    cmd = list(cmd)
    if on_parent_death not in ("kill", "survive"):
        raise ValueError(f"on_parent_death must be 'kill' or 'survive', "
                         f"got {on_parent_death!r}")
    if pid_ns not in ("auto", "require", "off"):
        raise ValueError(f"pid_ns must be 'auto', 'require', or 'off', "
                         f"got {pid_ns!r}")
    # Validate stdio shapes up front so both tiers reject identically.
    _resolve_stdio_fd_probe(stdout, "stdout")
    _resolve_stdio_fd_probe(stderr, "stderr")

    if env is None:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()

    kill_mode = on_parent_death == "kill"

    want_pidns = pid_ns != "off"
    if want_pidns and sys.platform != "linux":
        if pid_ns == "require":
            raise SandboxSetupError(
                "pid_ns='require': pid-namespace supervision is "
                "Linux-only")
        want_pidns = False
    if want_pidns:
        verdict, reason = probes.check_pidns_supervision_available()
        if verdict is False:
            if pid_ns == "require":
                raise SandboxSetupError(
                    f"pid_ns='require' but pid-namespace supervision "
                    f"cannot engage: {reason}",
                    setup_category="U")
            logger.warning(
                "supervised[%s]: pid-namespace supervision unavailable "
                "(%s) — degrading to the group tier (teardown scope: "
                "process group only, no kernel namespace-empty proof)",
                name or cmd[0], reason)
            want_pidns = False
        # verdict None (probe infra-failure) attempts the pidns tier:
        # the live spawn's own unshare is the authoritative test, and
        # its refusal handler below caches the definitive verdict.
    if net_ns and not want_pidns:
        raise SandboxSetupError(
            "net_ns=True requires the pidns tier (a private netns "
            "cannot engage without the same-call userns) — refusing "
            "to silently drop requested isolation")

    if want_pidns:
        try:
            return _spawn_pidns_tier(cmd, env, cwd, stdout, stderr,
                                     net_ns, kill_mode, name)
        except SandboxSetupError as e:
            if e.setup_category == "U":
                # Live refusal after a positive/indeterminate probe:
                # flip the cached verdict (refused-and-cached).
                probes.note_pidns_supervision_refused(e.reason)
                if pid_ns == "auto" and not net_ns:
                    logger.warning(
                        "supervised[%s]: pid-namespace supervision "
                        "refused by the live spawn (%s) — verdict "
                        "re-cached; degrading to the group tier "
                        "(teardown scope: process group only, no "
                        "kernel namespace-empty proof)",
                        name or cmd[0], e.reason)
                    return _spawn_group_tier(cmd, env, cwd, stdout,
                                             stderr, kill_mode, name)
            raise

    return _spawn_group_tier(cmd, env, cwd, stdout, stderr, kill_mode, name)


def _resolve_stdio_fd_probe(stream: _StdioArg, label: str) -> None:
    """Validation-only pass over a stdio argument (no fds opened):
    raises on the shapes both tiers reject."""
    if stream is None or stream == subprocess.DEVNULL:
        return
    if stream == subprocess.PIPE or stream == subprocess.STDOUT:
        # Reuse the real resolver's error text.
        _resolve_stdio_fd(stream, label)
    if isinstance(stream, int):
        if stream < 0:
            raise ValueError(f"{label}: negative fd {stream}")
        return
    if getattr(stream, "fileno", None) is None:
        raise TypeError(f"{label}: expected fd, file object, "
                        f"subprocess.DEVNULL, or None — got {stream!r}")
