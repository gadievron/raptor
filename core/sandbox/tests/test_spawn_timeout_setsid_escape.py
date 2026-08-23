"""Regression: a setsid()'d target must not survive the timeout kill path.

Pre-fix, ``run_sandboxed``'s timeout path called ``_kill_and_reap(child_pid)``
directly: it SIGKILLed the intermediate — the process holding the death-pipe
watcher — and then killpg'd the intermediate's process group. A hostile
target that called ``setsid()`` (or ``setpgid()``) had left that group,
carried no PR_SET_PDEATHSIG, and ``death_w`` closed only in the outer
``finally``, after its watcher was already dead. The target therefore
outlived the run teardown with its write grants (output dir, /tmp) intact.

The fix (``_teardown_target``) closes ``death_w`` FIRST, while the watcher
is alive: the intermediate's select loop reads EOF and SIGKILLs the
grandchild BY PID — immune to session/group escapes, and fatal to the whole
pid namespace when the grandchild is its init.

Skips when the mount-ns spawn prerequisites are unavailable (same gate as
test_spawn_mount_ns.py).
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (fork+newuidmap spawn path)",
)

import os  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402


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


def test_setsid_target_killed_on_timeout(tmp_path):
    """A target that immediately re-execs under ``setsid`` (leaving the
    intermediate's process group AND session) and then stalls past the
    timeout must be dead once ``run_sandboxed`` raises TimeoutExpired."""
    if not _mount_ns_usable():
        _pytest.skip(
            "mount-ns unusable here (needs uidmap package + "
            "kernel.apparmor_restrict_unprivileged_userns=0)"
        )
    if not shutil.which("setsid"):
        _pytest.skip("util-linux setsid binary required")

    from core.sandbox._spawn import run_sandboxed

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    marker = out_dir / "escapee-started"

    exec_pids: list[int] = []
    try:
        with _pytest.raises(subprocess.TimeoutExpired):
            run_sandboxed(
                # The exec'd grandchild is NOT a process-group leader
                # (its pgid is the intermediate's), so util-linux
                # setsid calls setsid(2) directly and execs sh in
                # place — the escapee keeps the grandchild's host pid
                # while leaving the killable group/session.
                ["setsid", "sh", "-c",
                 f"touch {marker} && exec sleep 60"],
                target=str(out_dir), output=str(out_dir),
                block_network=True,
                nproc_limit=1024,
                limits={"memory_mb": 0, "max_file_mb": 1024,
                        "cpu_seconds": 300},
                writable_paths=[str(out_dir), "/tmp"],
                readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=3,
                capture_output=True, text=True,
                exec_pid_callback=exec_pids.append,
            )

        assert exec_pids and exec_pids[0] > 0, (
            "exec_pid_callback did not deliver the grandchild pid — "
            "cannot verify the escapee's fate"
        )
        assert marker.exists(), (
            "target never started inside the sandbox — the timeout "
            "fired before the hostile workload ran; test inconclusive"
        )
        escapee = exec_pids[0]
        # The teardown is synchronous (the death-pipe grace window is
        # bounded), but give the process table a moment to settle.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _proc_alive(escapee):
            time.sleep(0.05)
        assert not _proc_alive(escapee), (
            f"setsid()'d target (host pid {escapee}) survived the "
            f"run_sandboxed timeout teardown — kill-escape regression"
        )
    finally:
        # Belt-and-braces: never leak the sleeper, even when the
        # assertion above fails (pre-fix behaviour).
        for pid in exec_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
