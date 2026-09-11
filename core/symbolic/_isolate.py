"""Hard-budget process isolation for symbolic primitives.

Why this exists: a hostile binary can steer one claripy/z3 call into
work that ignores every cooperative bound we set — the wall-clock
deadline is only polled between exploration steps, claripy's
per-frontend timeout never reaches its backend solver in the pinned
version, and the z3 global parameter proved unreliable once the
backend context pre-exists (all verified live; the failing call sits
in native ``Z3_solver_check_assumptions``, where even SIGTERM is
deferred). The only enforcement that cannot be argued with is a
separate process and SIGKILL.

Every public primitive therefore runs its implementation in a
spawned child; the parent waits until ``timeout`` plus a grace
window, then escalates terminate → kill and returns an honest
timeout :class:`SymbolicResult`. Cost: a process spawn + angr import
per call (seconds) and no cross-call project cache — acceptable for
a verification substrate whose alternative failure mode is an
unkillable analysis thread. The in-child z3 budget (``_budget``)
still applies as the soft layer so well-behaved solves end early
with precise diagnostics; isolation is the backstop.

The child receives (module, function, kwargs) by name and returns
the primitive's result via a pipe. Spawn (not fork): angr's native
state does not survive forks reliably, and spawn gives the child a
clean interpreter.
"""
from __future__ import annotations

import importlib
import multiprocessing as mp
import shutil
import tempfile
import time
from typing import Any

from core.symbolic._types import SymbolicResult

#: Extra seconds past the caller's timeout before terminate/kill.
#: Covers child interpreter start + angr import (~3-5s measured) +
#: result pickling.
GRACE_SECONDS = 15.0

#: terminate → kill escalation gap.
_KILL_GRACE_SECONDS = 5.0


def _apply_symex_sandbox(private_tmp: str | None = None) -> None:
    """Install Landlock: deny filesystem writes outside a private
    per-child temp directory + deny TCP connect.

    Best-effort — if Landlock is unavailable (old kernel, container),
    logs a warning and returns. The process isolation (timeout +
    SIGKILL) is the primary defence; Landlock adds defence-in-depth
    against hostile binaries that try to write to disk or phone home.

    The temp-directory write grant is load-bearing, not a
    convenience: ``import angr`` needs it. pyvex resolves
    ``tempfile.gettempdir()`` at import time (which PROBES candidate
    directories by creating a file) and unconditionally writes its
    ffi-parser cache there when absent. Under a blanket write deny
    that import raises, the availability guard reports angr as
    uninstalled, and every isolated primitive — this sandbox's own
    beneficiaries — degrades to an 'unavailable' result.

    The grant covers only ``private_tmp`` — the empty directory
    :func:`run_isolated` creates for this child and removes after it
    exits — never the shared system temp directory: a lifter/solver
    compromise must not be able to tamper with other same-user temp
    content. ``tempfile.tempdir`` is pinned to it here, pre-restrict,
    so pyvex's cache write and any later scratch use land inside the
    grant (cost: a per-child ffi-cache regeneration, ~0.1s). Writes
    everywhere else (home, the repo, the analysed binary's tree, the
    shared temp dir) stay denied, as does outbound TCP.

    If the grant cannot be installed (``private_tmp`` is None or
    unusable), the restrict is SKIPPED rather than engaged as a
    blanket deny — a blanket deny disables the very primitives this
    sandbox protects; hard-kill process isolation remains in force.

    Must be called BEFORE importing angr / the target module.
    """
    import ctypes
    import ctypes.util
    import os
    import platform

    # Pin the process's temp directory to the private grant target
    # while writes are still allowed, so no later caller (pyvex's
    # import-time cache write included) probes or writes the shared
    # system temp dir. Deliberately ABOVE the Landlock gates: the
    # parent creates and cleans the directory on every host, so the
    # scratch-goes-to-the-managed-dir behaviour must not depend on
    # whether Landlock can engage.
    tmpdir: str | None = None
    if private_tmp is not None:
        try:
            resolved = os.path.realpath(private_tmp)
            if os.path.isdir(resolved):
                tmpdir = resolved
                tempfile.tempdir = resolved
        except OSError:
            tmpdir = None

    if platform.machine() not in (
        "x86_64", "aarch64", "riscv64", "loongarch64", "s390x",
    ):
        return

    SYS_CREATE = 444
    SYS_ADD_RULE = 445
    SYS_RESTRICT = 446
    PR_SET_NO_NEW_PRIVS = 38
    RULE_PATH_BENEATH = 1

    WRITE_FILE = 1 << 1
    REMOVE_DIR = 1 << 4
    REMOVE_FILE = 1 << 5
    MAKE_CHAR = 1 << 6
    MAKE_DIR = 1 << 7
    MAKE_REG = 1 << 8
    MAKE_SOCK = 1 << 9
    MAKE_FIFO = 1 << 10
    MAKE_BLOCK = 1 << 11
    MAKE_SYM = 1 << 12
    NET_CONNECT_TCP = 1 << 1

    class RulesetAttr(ctypes.Structure):
        _fields_ = [
            ("handled_access_fs", ctypes.c_uint64),
            ("handled_access_net", ctypes.c_uint64),
            ("scoped", ctypes.c_uint64),
        ]

    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [
            ("allowed_access", ctypes.c_uint64),
            ("parent_fd", ctypes.c_int),
        ]

    lib_path = ctypes.util.find_library("c")
    if not lib_path:
        return
    try:
        libc = ctypes.CDLL(lib_path, use_errno=True)
    except OSError:
        return

    abi = libc.syscall(SYS_CREATE, None, 0, 1)
    if abi < 1:
        return

    write_mask = (WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR |
                  MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO |
                  MAKE_BLOCK | MAKE_SYM)
    if abi >= 2:
        write_mask |= 1 << 13   # REFER
    if abi >= 3:
        write_mask |= 1 << 14   # TRUNCATE
    if abi >= 5:
        write_mask |= 1 << 15   # IOCTL_DEV
    net_access = NET_CONNECT_TCP if abi >= 4 else 0

    attr = RulesetAttr(
        handled_access_fs=write_mask,
        handled_access_net=net_access,
        scoped=0,
    )
    fd = libc.syscall(
        SYS_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0,
    )
    if fd < 0:
        return

    # One allow rule: write access beneath the private per-child temp
    # directory (see the docstring — angr's import chain requires
    # it). If the grant cannot be installed, skip the restrict rather
    # than engage a ruleset that breaks the primitive this sandbox
    # protects; hard-kill process isolation remains in force either
    # way.
    def _grant_tmpdir_write() -> bool:
        if tmpdir is None:
            return False
        try:
            dfd = os.open(
                tmpdir, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            )
        except OSError:
            return False
        try:
            rule = PathBeneathAttr(
                allowed_access=write_mask, parent_fd=dfd,
            )
            ret = libc.syscall(
                SYS_ADD_RULE, fd, RULE_PATH_BENEATH,
                ctypes.byref(rule), 0,
            )
            return ret == 0
        finally:
            os.close(dfd)

    if not _grant_tmpdir_write():
        os.close(fd)
        import logging
        logging.getLogger(__name__).warning(
            "symex sandbox: temp-dir write grant failed — skipping "
            "Landlock (process isolation still enforced)",
        )
        return

    # Every other handled access is denied.
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    ret = libc.syscall(SYS_RESTRICT, fd, 0)
    os.close(fd)
    if ret < 0:
        import logging
        logging.getLogger(__name__).warning(
            "symex sandbox: Landlock restrict_self failed (ret=%d)", ret,
        )


def _remove_private_tmp(path: str) -> None:
    """Remove the child's private temp dir after the child exits.

    Defeats permission griefing: a compromised child can leave a
    mode-0 subdirectory inside its grant, which makes a plain
    ``rmtree(ignore_errors=True)`` fail silently — the per-call dirs
    would then accumulate without bound. Restore traversal
    permissions top-down first (the walk chmods each subdirectory
    before descending into it), then remove. Never raises.
    """
    import os
    try:
        for root, dirs, _files in os.walk(path):
            for name in dirs:
                entry = os.path.join(root, name)
                # os.walk(followlinks=False) still LISTS a symlink-to-
                # directory in dirnames (it just doesn't descend), and
                # os.chmod follows symlinks (Linux has no lchmod) — so
                # chmoding it would apply 0700 to the symlink's TARGET,
                # which a hostile child can point anywhere OUTSIDE its
                # private tmp. Skip links: rmtree below removes the
                # link itself without descending, and a link needs no
                # permission restore anyway.
                if os.path.islink(entry):
                    continue
                try:
                    os.chmod(entry, 0o700)
                except OSError:
                    pass
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _child_entry(
    conn,
    module_name: str,
    func_name: str,
    kwargs: dict,
    private_tmp: str | None = None,
) -> None:
    """Child-side runner. Everything heavyweight imports here."""
    import logging

    _apply_symex_sandbox(private_tmp)

    # angr logs an ERROR at import when optional acceleration is
    # missing; that is operator noise, not a result channel.
    for name in ("angr", "claripy", "cle", "pyvex"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        module = importlib.import_module(module_name)
        result = getattr(module, func_name)(**kwargs)
        conn.send(result)
    except BaseException as exc:  # noqa: BLE001 — one channel out
        try:
            conn.send(SymbolicResult(
                succeeded=False,
                reason=f"primitive raised: {type(exc).__name__}: {exc}",
                wall_seconds=0.0,
                states_explored=0,
                metadata={},
            ))
        except Exception:  # noqa: BLE001 — pipe gone; parent times out
            pass
    finally:
        conn.close()


def run_isolated(
    module_name: str,
    func_name: str,
    kwargs: dict[str, Any],
    *,
    timeout: float,
) -> SymbolicResult:
    """Run ``module_name.func_name(**kwargs)`` in a spawned child with
    a hard kill at ``timeout + GRACE_SECONDS``."""
    t0 = time.monotonic()
    # The child's entire writable world (see _apply_symex_sandbox).
    # Created here so the parent can remove it after the child exits
    # — the sandboxed child cannot unlink a directory that sits in
    # the shared temp dir, outside its own write grant.
    private_tmp: str | None
    try:
        private_tmp = tempfile.mkdtemp(prefix="raptor-symex-")
    except OSError:
        private_tmp = None
    try:
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        proc = ctx.Process(
            target=_child_entry,
            args=(child_conn, module_name, func_name, kwargs, private_tmp),
            daemon=True,
        )
        proc.start()
        child_conn.close()

        budget = timeout + GRACE_SECONDS
        result: SymbolicResult | None = None
        # A crashed child closes the pipe, so poll() returns promptly
        # (EOF is readable) and recv() raises — timed_out separates
        # "budget genuinely elapsed" from "child died with no result".
        timed_out = not parent_conn.poll(budget)
        if not timed_out:
            try:
                result = parent_conn.recv()
            except (EOFError, OSError):
                result = None
        parent_conn.close()

        proc.join(timeout=0.5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=_KILL_GRACE_SECONDS)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=_KILL_GRACE_SECONDS)
    finally:
        if private_tmp is not None:
            _remove_private_tmp(private_tmp)

    if result is not None:
        return result
    if timed_out:
        return SymbolicResult(
            succeeded=False,
            reason=(
                f"hard-killed after exceeding the {timeout:.0f}s budget "
                f"(+{GRACE_SECONDS:.0f}s grace) — solver work ignored "
                "every cooperative bound (hostile or pathological target)"
            ),
            wall_seconds=time.monotonic() - t0,
            states_explored=0,
            metadata={"isolated": True, "killed": True},
        )
    # No result but the budget never elapsed: the child crashed
    # (segfault, spawn failure, unpicklable payload) — reporting it as
    # a budget kill made operators and telemetry misdiagnose crashes
    # as timeouts (wall_seconds contradicted the text).
    exitcode = proc.exitcode
    detail = (
        f"killed by signal {-exitcode}"
        if isinstance(exitcode, int) and exitcode < 0
        else f"exit code {exitcode}"
    )
    return SymbolicResult(
        succeeded=False,
        reason=(
            f"child exited without returning a result ({detail}) — "
            f"crash, not a budget kill"
        ),
        wall_seconds=time.monotonic() - t0,
        states_explored=0,
        metadata={"isolated": True, "killed": False, "crashed": True,
                  "exitcode": exitcode},
    )
