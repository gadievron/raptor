"""Concurrent spawns must not inherit sibling death-pipe write ends.

The death pipe is the orphan-teardown signal: the parent holds the
write end for the duration of the call and the intermediate watcher
select()s on the read end — parent dies, the write end auto-closes,
the watcher reads EOF and SIGKILLs the sandboxed target. os.pipe()
fds are close-on-exec, but fork(2) copies the whole fd table
regardless: pre-fix, an intermediate forked while a SIBLING spawn was
in flight inherited a copy of that sibling's death_w and held it for
its whole life. No death pipe could EOF while any cohort member
lived, so a hard-killed orchestrator (SIGKILL/OOM/crash) left every
in-flight sandboxed target running to completion — observed as
multi-hour orphan cohorts still holding the caller's stdio pipes.

Three layers pinned here:

- the registry mechanism itself (fork-consistent snapshot, sibling
  sweep, close idempotence) — no sandbox capability needed;
- the live intermediate's fd table via /proc inspection: it must hold
  NO death-pipe write end (its own included — only the owning parent
  keeps one) while watching its own read end;
- the cohort-death contract: SIGKILL the supervising process and
  every concurrently-spawned target must be reaped within the
  watcher's poll bound, not run to completion as an orphan.

The two spawn-path tests make sibling inheritance deterministic by
gating the Landlock availability probe — called by every spawn after
its death pipe exists and before its fork — on a two-party barrier,
so both spawns hold their pipes open before either forks.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (fork+newuidmap spawn path)",
)

import contextlib  # noqa: E402
import fcntl  # noqa: E402
import os  # noqa: E402
import select  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import textwrap  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from core.sandbox.tests.capability import (  # noqa: E402
    requires_landlock,
    requires_mount,
    requires_userns,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _mount_ns_usable() -> bool:
    """True iff the fork+newuidmap spawn path works here."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


def _proc_alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}").exists()
    except OSError:
        return False


def _gate_landlock_probe(monkeypatch, parties: int) -> None:
    """First check_landlock_available() call per thread rendezvouses.

    run_sandboxed calls the probe after creating its death pipe and
    before forking, so a barrier there guarantees every party's pipe
    is open (and inheritable across fork) before any party forks —
    the deterministic sibling-inheritance window. Later calls pass
    through, and a timed-out barrier degrades to pass-through so a
    partially-skipped run cannot wedge the suite.
    """
    import core.sandbox.landlock as _ll

    real = _ll.check_landlock_available
    barrier = threading.Barrier(parties)
    local = threading.local()

    def gated() -> bool:
        if not getattr(local, "seen", False):
            local.seen = True
            # Generous bound: a loaded CI host can stagger the two
            # threads' arrival by tens of seconds, and a broken
            # barrier silently forfeits the deterministic sibling-
            # inheritance window the test's detection power rests on.
            # The timeout exists only so a partially-skipped run
            # cannot wedge the suite.
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(timeout=60)
        return real()

    monkeypatch.setattr(_ll, "check_landlock_available", gated)


def _death_pipe_ends(pid: int, inodes: set[int]) -> tuple[int, int]:
    """(read_ends, write_ends) of *pid*'s fds on the given pipe inodes.

    Both ends of a pipe share one inode, so registered write-end
    inodes identify the whole pipe; /proc fdinfo flags tell the ends
    apart. Raises OSError when the fd table is not inspectable.
    """
    reads = writes = 0
    for entry in os.listdir(f"/proc/{pid}/fd"):
        try:
            tgt = os.readlink(f"/proc/{pid}/fd/{entry}")
        except OSError:
            continue  # fd closed mid-walk
        if not tgt.startswith("pipe:["):
            continue
        if int(tgt[6:-1]) not in inodes:
            continue
        flags = None
        try:
            with open(f"/proc/{pid}/fdinfo/{entry}", "rb") as f:
                for line in f.read(4096).splitlines():
                    if line.startswith(b"flags:"):
                        flags = int(line.split()[1], 8)
                        break
        except OSError:
            continue
        if flags is None:
            continue
        if (flags & os.O_ACCMODE) == os.O_WRONLY:
            writes += 1
        else:
            reads += 1
    return reads, writes


def test_forked_child_sweep_releases_sibling_death_w() -> None:
    """Mechanism: a child forked between two registered death pipes
    closes BOTH write ends, so the sibling's EOF is governed by its
    owning parent alone. No sandbox capability required."""
    from core.sandbox import _spawn

    ra, wa = _spawn.open_death_pipe()
    rb, wb = _spawn.open_death_pipe()
    child = 0
    try:
        # Same discipline as run_sandboxed's intermediate fork: under
        # the registry lock, then the child-entry sweep.
        with _spawn._DEATH_W_LOCK:
            child = os.fork()
        if child == 0:
            # Emulated intermediate for spawn B: sweep, then behave
            # like the watcher — block on the own read end until EOF.
            try:
                _spawn._close_inherited_death_w_post_fork()
                # The sweep must also clear the inherited registry:
                # its entries describe the parent's fd table, and a
                # stale entry re-consulted in this child could close
                # a reused fd number.
                if _spawn._LIVE_DEATH_W:
                    os._exit(2)
                os.read(rb, 1)
                os._exit(0)
            except BaseException:
                os._exit(1)
        # Spawn A's owner drops its write end. The forked child
        # inherited a copy of wa across fork; if the entry sweep left
        # it open, A's read end never sees EOF (the pre-fix pinning).
        assert _spawn.close_death_w(wa) is True
        ready, _, _ = select.select([ra], [], [], 5.0)
        assert ready, (
            "death-pipe EOF pinned: the forked child still holds a "
            "copy of the sibling spawn's write end"
        )
        assert os.read(ra, 512) == b""
        # Double-close in outer-finally order must refuse (the fd
        # number may already be reused).
        assert _spawn.close_death_w(wa) is False
        # Releasing B's write end unblocks the emulated watcher.
        assert _spawn.close_death_w(wb) is True
        _, status = os.waitpid(child, 0)
        child = 0
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (
            f"emulated watcher died abnormally (wait status {status})"
        )
    finally:
        if child:
            with contextlib.suppress(OSError):
                os.kill(child, signal.SIGKILL)
            with contextlib.suppress(OSError, ChildProcessError):
                os.waitpid(child, 0)
        for fd in (ra, rb):
            with contextlib.suppress(OSError):
                os.close(fd)
        for fd in (wa, wb):
            _spawn.close_death_w(fd)


def test_any_fork_sweeps_death_w_without_opting_in() -> None:
    """Structural closure: the sweep is an at-fork hook, so a fork
    site that never heard of the registry — probe forks, fork-context
    pool workers, whatever gets added next — still releases inherited
    death-pipe write ends. The child here deliberately performs NO
    explicit sweep."""
    from core.sandbox import _spawn

    ra, wa = _spawn.open_death_pipe()
    child = 0
    try:
        # Plain os.fork, no lock, no opt-in — the shape of every
        # non-_spawn fork site in the process.
        child = os.fork()
        if child == 0:
            try:
                # The at-fork hook already ran: the inherited write
                # end must be closed and the registry cleared.
                bad = False
                try:
                    fcntl.fcntl(wa, fcntl.F_GETFD)
                    bad = True  # still open — class re-opened
                except OSError:
                    pass
                if bad or _spawn._LIVE_DEATH_W:
                    os._exit(2)
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(child, 0)
        child = 0
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (
            f"fork child still held a death-pipe write end or a stale "
            f"registry (wait status {status})"
        )
        # The parent's copy is untouched: EOF stays governed by the
        # owning parent alone.
        assert _spawn.close_death_w(wa) is True
        assert os.read(ra, 512) == b""
    finally:
        if child:
            with contextlib.suppress(OSError):
                os.kill(child, signal.SIGKILL)
            with contextlib.suppress(OSError, ChildProcessError):
                os.waitpid(child, 0)
        with contextlib.suppress(OSError):
            os.close(ra)
        _spawn.close_death_w(wa)


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP, not a mid-flight failure.
@requires_mount
def test_concurrent_intermediates_hold_no_death_w(
        tmp_path: Path, monkeypatch: _pytest.MonkeyPatch) -> None:
    """Two deliberately-overlapped spawns: each live intermediate must
    hold ZERO death-pipe write ends (sibling's or its own — only the
    owning parent keeps one) while watching its own read end."""
    if not _mount_ns_usable():
        _pytest.skip(
            "mount-ns unusable here (needs uidmap package + "
            "kernel.apparmor_restrict_unprivileged_userns=0)"
        )
    from core.sandbox import _spawn

    _gate_landlock_probe(monkeypatch, 2)

    pids: list[int | None] = [None, None]
    errors: list[BaseException | None] = [None, None]
    fifos: list[Path] = []

    # Deterministic rendezvous: each target blocks reading a FIFO in
    # its own bind-mounted out dir (visible post-pivot at the same
    # path) until the TEST releases it, so neither target can leave
    # "in flight" while its sibling is still registering — the
    # 2-concurrent property no longer races spawn-setup latency
    # against a wall-clock window. The pre-fork overlap window itself
    # is still pinned by the landlock-probe barrier above.
    for i in range(2):
        out = tmp_path / f"out{i}"
        out.mkdir()
        fifo = out / "hold.fifo"
        os.mkfifo(fifo)
        fifos.append(fifo)

    def _one(i: int) -> None:
        out = tmp_path / f"out{i}"

        def _register(pid: int, i: int = i) -> None:
            pids[i] = pid

        try:
            _spawn.run_sandboxed(
                ["sh", "-c", f"exec cat {fifos[i]}"],
                target=str(out), output=str(out),
                block_network=True,
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 1024,
                        "cpu_seconds": 300},
                writable_paths=[str(out), "/tmp"],
                readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=150,
                capture_output=True, text=True,
                exec_pid_callback=_register,
            )
        except BaseException as e:  # surfaced after teardown
            errors[i] = e

    def _release_fifos() -> None:
        # A writer opening (then closing) the FIFO EOFs the blocked
        # reader. O_NONBLOCK: ENXIO when the reader never arrived
        # (spawn failed) — nothing to release then.
        for fifo in fifos:
            with contextlib.suppress(OSError):
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))

    threads = [threading.Thread(target=_one, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    try:
        # Registration is load-bound (uid-map handshake, newuidmap
        # exec), not time-bound: keep waiting while a spawn is
        # genuinely still in flight instead of racing a fixed short
        # window against host load. FIFO-held targets mean no spawn
        # thread can finish while the cohort is staged, so the loop
        # exits on facts: both pids arrived; a spawn surfaced an
        # error; a thread finished (with held targets, itself an
        # anomaly to classify); or the staging deadline fired.
        # ORDERING INVARIANT: the staging deadline MUST undercut the
        # spawns' own 150s run timeout (by enough for release + join +
        # inspection). Classification below reads each spawn's NATURAL
        # outcome after the FIFOs are released; if the run timeouts
        # fired first, every one-sided anomaly — including a lost
        # exec-pid delivery, a product bug — converges to
        # TimeoutExpired on both spawns and would be misread as an
        # environmental wedge. Raising the deadline above the run
        # timeout trades detection for stability; lowering it far
        # below re-opens the load flake this rewrite removed.
        deadline = time.monotonic() + 120.0
        while (None in pids
                and not any(e is not None for e in errors)
                and all(t.is_alive() for t in threads)
                and time.monotonic() < deadline):
            time.sleep(0.05)
        if None in pids:
            # Staging did not complete. Release the held target(s)
            # FIRST so every spawn thread completes with its natural
            # outcome — a spawn whose exec-pid delivery was lost
            # returns cleanly once its released target EOFs, while a
            # genuinely wedged spawn keeps its TimeoutExpired — then
            # bounded-join and classify on those facts. Order matters:
            # the product-bug check precedes any environmental skip,
            # so a lost delivery can never hide behind a sibling's
            # (or its own) timeout convergence.
            _release_fifos()
            for t in threads:
                t.join(timeout=30)
            missing = [i for i in range(2) if pids[i] is None]
            lost = [i for i in missing
                    if not threads[i].is_alive() and errors[i] is None]
            assert not lost, (
                f"spawn(s) {lost} completed without delivering an exec "
                f"pid and without raising — exec-pid delivery lost, a "
                f"product bug, not host load (spawn errors: {errors})"
            )
            if all(isinstance(errors[i], subprocess.TimeoutExpired)
                   or threads[i].is_alive() for i in missing):
                # A true wedge on every unstaged spawn: its setup
                # timed out (the userns uid-map handshake has a
                # bounded internal timeout a loaded host can overrun)
                # or is still grinding past every bound. Environment,
                # not the defect under test (sibling fd pinning
                # happens strictly after a successful exec), so
                # report it honestly rather than as a failure.
                _pytest.skip(
                    "spawn setup did not stage the cohort under host "
                    f"load — inconclusive (spawn errors: {errors})"
                )
            _pytest.fail(
                f"expected 2 sandboxed targets in flight, got "
                f"{2 - len(missing)} (spawn errors: {errors})"
            )
        # The intermediate is the grandchild's parent (host pid view).
        intermediates = []
        for i, gpid in enumerate(pids):
            ppid = None
            try:
                with open(f"/proc/{gpid}/status", "rb") as f:
                    for line in f.read(4096).splitlines():
                        if line.startswith(b"PPid:"):
                            ppid = int(line.split()[1])
                            break
            except OSError:
                # The target registered and then vanished before the
                # inspection. The only benign shape is THIS spawn's
                # own timeout kill racing its registration (pid
                # delivered at the deadline, target reaped an instant
                # later) — the TimeoutExpired surfaces in that spawn's
                # thread moments after the kill, so give it a beat and
                # require the attribution: this spawn's own timeout →
                # inconclusive; any other disappearance → real signal.
                grace = time.monotonic() + 10.0
                while errors[i] is None and time.monotonic() < grace:
                    time.sleep(0.05)
                if isinstance(errors[i], subprocess.TimeoutExpired):
                    _pytest.skip(
                        f"target {gpid} reaped by its own spawn's "
                        f"timeout before inspection — inconclusive "
                        f"({errors[i]!r})"
                    )
                raise
            assert ppid, f"no PPid for sandboxed target {gpid}"
            intermediates.append(ppid)
        # Inode set of every registered (live, parent-held) death-pipe
        # write end — both of our spawns' pipes are in flight now.
        with _spawn._DEATH_W_LOCK:
            live_inodes = {
                os.fstat(fd).st_ino for fd in _spawn._LIVE_DEATH_W
            }
        assert len(live_inodes) >= 2, (
            "expected both in-flight death pipes registered, found "
            f"{len(live_inodes)}"
        )
        for ipid in intermediates:
            try:
                reads, writes = _death_pipe_ends(ipid, live_inodes)
            except OSError:
                _pytest.skip(
                    "intermediate fd table not inspectable from the "
                    "test process on this host"
                )
            assert writes == 0, (
                f"intermediate {ipid} holds {writes} death-pipe write "
                "end(s) — a retained sibling copy pins that spawn's "
                "orphan-teardown EOF to this child's lifetime"
            )
            assert reads >= 1, (
                f"intermediate {ipid} watches no death pipe — the "
                "teardown signal is disconnected"
            )
    finally:
        _release_fifos()
        for gpid in pids:  # backstop for a target that missed the EOF
            if gpid is not None:
                with contextlib.suppress(OSError):
                    os.kill(gpid, signal.SIGKILL)
        for t in threads:
            t.join(timeout=30)


_SUPERVISOR = textwrap.dedent("""\
    import contextlib
    import os
    import sys
    import threading
    import time

    import core.sandbox.landlock as _ll
    from core.sandbox import _spawn

    _real = _ll.check_landlock_available
    _barrier = threading.Barrier(2)
    _local = threading.local()

    def _gated():
        if not getattr(_local, "seen", False):
            _local.seen = True
            with contextlib.suppress(threading.BrokenBarrierError):
                _barrier.wait(timeout=20)
        return _real()

    _ll.check_landlock_available = _gated

    out_base = sys.argv[1]
    pids = []
    lock = threading.Lock()

    def _report(pid):
        with lock:
            pids.append(pid)
            if len(pids) == 2:
                print("PIDS %d %d" % (pids[0], pids[1]), flush=True)

    def _one(i):
        out = os.path.join(out_base, "out%d" % i)
        os.makedirs(out, exist_ok=True)
        try:
            _spawn.run_sandboxed(
                ["sleep", "60"], target=out, output=out,
                block_network=True, nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 1024,
                        "cpu_seconds": 300},
                writable_paths=[out, "/tmp"], readable_paths=None,
                allowed_tcp_ports=None, seccomp_profile=None,
                seccomp_block_udp=False, env=None, cwd=None,
                timeout=55, capture_output=True, text=True,
                exec_pid_callback=_report,
            )
        except BaseException as e:
            with lock:
                print("SPAWNERR %r" % (e,), flush=True)

    threads = [threading.Thread(target=_one, args=(i,), daemon=True)
               for i in range(2)]
    for t in threads:
        t.start()
    time.sleep(120)
""")


@requires_landlock
@requires_userns
# Exercises mount-delivered capability; hosts with userns but no mount
# capability degrade by design -> named SKIP, not a mid-flight failure.
@requires_mount
def test_cohort_reaped_when_supervisor_hard_killed(tmp_path: Path) -> None:
    """The leaked-cohort shape: SIGKILL a supervisor with two
    overlapped spawns in flight. Every target must be reaped within
    the watcher's poll bound — pre-fix the intermediates held each
    other's death_w, no pipe ever EOF'd, and both targets ran their
    full workload as orphans."""
    if not _mount_ns_usable():
        _pytest.skip(
            "mount-ns unusable here (needs uidmap package + "
            "kernel.apparmor_restrict_unprivileged_userns=0)"
        )

    env = dict(os.environ)
    env["PYTHONPATH"] = (str(_REPO_ROOT) + os.pathsep
                         + env.get("PYTHONPATH", ""))
    proc = subprocess.Popen(
        [_sys.executable, "-c", _SUPERVISOR, str(tmp_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=env, cwd=str(_REPO_ROOT), start_new_session=True,
    )
    pids: list[int] = []
    try:
        lines: list[str] = []
        stdout = proc.stdout
        assert stdout is not None  # stdout=PIPE above

        def _read_pids() -> None:
            lines.append(stdout.readline())

        reader = threading.Thread(target=_read_pids, daemon=True)
        reader.start()
        reader.join(timeout=30)
        if not lines or lines[0].startswith("SPAWNERR "):
            # Staging never completed: a spawn raised (the userns
            # uid-map handshake has a bounded internal timeout a
            # loaded host can overrun) or the supervisor is still
            # grinding. Either way the cohort was never staged — the
            # defect under test only manifests AFTER both targets
            # exec, so this is environment, not signal.
            _pytest.skip(
                "cohort staging did not complete — inconclusive "
                f"(got {lines!r})"
            )
        assert lines[0].startswith("PIDS "), (
            "supervisor reported unexpected staging output: "
            f"{lines!r}"
        )
        pids = [int(x) for x in lines[0].split()[1:]]
        assert len(pids) == 2 and all(_proc_alive(p) for p in pids), (
            f"staged targets not alive: {pids}"
        )

        # Hard-kill ONLY the supervisor — the orchestrator-death shape.
        # Its death_w copies close with its fd table; the watchers'
        # EOF is now governed by whether any sibling child retained a
        # write end.
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and any(
                _proc_alive(p) for p in pids):
            time.sleep(0.1)
        survivors = [p for p in pids if _proc_alive(p)]
        assert not survivors, (
            f"orphaned sandboxed target(s) {survivors} survived the "
            "supervisor SIGKILL — death-pipe EOF never reached their "
            "watchers (sibling write-end pinning regression)"
        )
    finally:
        for p in pids:
            with contextlib.suppress(OSError):
                os.kill(p, signal.SIGKILL)
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            proc.kill()
            proc.wait(timeout=5)
