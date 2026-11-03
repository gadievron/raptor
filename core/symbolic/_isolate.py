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

The broker launches a fresh interpreter through the shared sandbox,
with restricted reads, private scratch/HOME, blocked networking and the
normal untrusted containment floor. It never parses the target itself.
The executor receives (module, function, kwargs) by name and returns
the primitive's result via a pipe. Spawn (not fork): angr's native
state does not survive forks reliably, and spawn gives the child a
clean broker interpreter. The parent decodes the returned bytes with a
restricted unpickler (:class:`_RestrictedResultUnpickler`): the child
is sandboxed precisely because its inputs are hostile, so its OUTPUT
channel must not be a plain ``pickle.loads`` in the unsandboxed
parent — a child compromised through a CLE/pyvex/z3 parsing bug could
otherwise send a crafted pickle and execute code outside every
sandbox layer this module builds.
"""
from __future__ import annotations

import importlib
import io
import multiprocessing as mp
from multiprocessing.connection import Connection
import os
import pickle
import selectors
import struct
import subprocess
import sys
from pathlib import Path
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

#: Upper bound on the child's serialized result. Trade-off, both
#: directions: too low refuses legitimate results (concrete stdin
#: witnesses are engine-capped well below 1 MiB, but overflow-engine
#: metadata carries register/memory snapshots); too high lets a
#: compromised child force the parent to buffer an allocation bomb.
#: 64 MiB clears every legitimate result shape by orders of magnitude
#: while keeping the worst-case parent allocation bounded.
_MAX_RESULT_BYTES = 64 << 20


class _RestrictedResultUnpickler(pickle.Unpickler):
    """Unpickler that can construct ONLY :class:`SymbolicResult`.

    Builtin scalars/containers (str, bytes, int, float, bool, None,
    dict, list, tuple) are opcode-native and need no class lookup;
    every other global reference — the vector by which a pickle
    stream reaches ``os.system`` and friends — is refused. Calling
    the one allowed class with attacker-chosen arguments constructs
    an inert dataclass, nothing more.
    """

    _ALLOWED = {("core.symbolic._types", "SymbolicResult")}

    def find_class(self, module: str, name: str) -> type:
        if (module, name) in self._ALLOWED:
            return SymbolicResult
        raise pickle.UnpicklingError(
            f"symex child result: refusing to unpickle {module}.{name}"
        )


def _loads_result(payload: bytes) -> SymbolicResult:
    """Decode a child result under the restricted unpickler; the
    decoded object must BE a SymbolicResult, not merely be built
    from allowed pieces."""
    obj = _RestrictedResultUnpickler(io.BytesIO(payload)).load()
    if not isinstance(obj, SymbolicResult):
        raise pickle.UnpicklingError(
            "symex child result: expected SymbolicResult, got "
            f"{type(obj).__name__}"
        )
    return obj


class _FrameRefused(Exception):
    """Result frame malformed or over the cap — hostile-child signal."""


def _read_exact_deadline(
    fd: int, n: int, deadline: float,
) -> bytes | None:
    """Read exactly ``n`` bytes from ``fd``, never blocking past
    ``deadline`` (monotonic). Returns ``None`` when the deadline
    expires mid-read; raises :class:`EOFError` on a closed pipe.

    The wait uses :class:`selectors.DefaultSelector` (epoll/kqueue),
    never ``select.select``: ``select()`` raises ``ValueError`` for
    any fd >= FD_SETSIZE (1024), which a long-running many-fd
    orchestrator reaches on a fully legitimate run — and an exception
    escaping this read would skip the caller's kill escalation, the
    one guarantee this module exists to provide. ``Connection.poll``
    (the pre-read gate) has no such limit for the same reason.
    """
    buf = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if not selector.select(remaining):
                return None
            chunk = os.read(fd, n - len(buf))
            if not chunk:
                raise EOFError(
                    "symex child closed the result pipe mid-frame"
                )
            buf += chunk
    return bytes(buf)


def _recv_frame_deadline(
    conn: Any, deadline: float, maxlength: int,
) -> bytes | None:
    """Deadline-bounded replacement for ``Connection.recv_bytes``.

    ``poll()`` returns as soon as ONE byte is readable, but
    ``recv_bytes`` then blocks until the whole length-prefixed frame
    arrives — a compromised child (this module's stated adversary)
    can write a partial header and sleep, parking the unsandboxed
    parent forever and disarming the hard-kill budget, the one
    guarantee this file exists to provide. Reading the frame in
    ``select``-gated chunks keeps every wait bounded by ``deadline``.

    Frame layout matches CPython's ``Connection._send_bytes``: a
    4-byte ``!i`` length, with ``-1`` escaping to an 8-byte ``!Q``
    length for >2 GiB payloads (always over our cap — refused without
    reading further). Returns the payload bytes, ``None`` when the
    deadline expired mid-frame (the caller's kill escalation then
    fires), raises :class:`EOFError` on a closed pipe (child crash)
    or :class:`_FrameRefused` on a malformed/over-cap header.
    """
    fd = conn.fileno()
    header = _read_exact_deadline(fd, 4, deadline)
    if header is None:
        return None
    (size,) = struct.unpack("!i", header)
    if size == -1:
        # 8-byte escape frame: legitimate only for >2 GiB payloads,
        # which the result cap refuses categorically.
        raise _FrameRefused("result frame declares a >2 GiB payload")
    if size < 0:
        raise _FrameRefused(f"result frame declares negative size {size}")
    if size > maxlength:
        raise _FrameRefused(
            f"result frame declares {size} bytes (cap {maxlength})"
        )
    payload = _read_exact_deadline(fd, size, deadline)
    return payload


# The request is authored by this trusted parent. Only the confined worker
# unpickles it; the parent still uses the restricted result decoder below.
_WORKER_SOURCE = r"""
import os, sys, tempfile
os.environ["TMPDIR"] = sys.argv[3]
tempfile.tempdir = sys.argv[3]
sys.path.insert(0, sys.argv[1])
from core.symbolic._isolate import _execute_request
_execute_request(int(sys.argv[2]))
"""

_POLICY_STATE = ('_cli_sandbox_profile', '_cli_sandbox_disabled',
                 '_cli_sandbox_disable_consent', '_cli_sandbox_floor',
                 '_project_sandbox_floor', '_cli_sandbox_readable_paths',
                 '_cli_sandbox_tool_paths', '_cli_sandbox_audit',
                 '_cli_sandbox_audit_verbose', '_cli_sandbox_audit_budget')


def _execute_request(result_fd: int) -> None:
    """Runs only after the shared sandbox has confined the interpreter."""
    import logging
    import site
    request = pickle.loads(sys.stdin.buffer.read())
    module_name, func_name, kwargs, private_tmp, user_site = request
    conn = Connection(result_fd, readable=False, writable=True)
    try:
        if not module_name.startswith(_SYMBOLIC_MODULE_PREFIX):
            raise ValueError('symbolic worker module outside allowed prefix')
        # -I removes implicit cwd/user imports. Explicit installed user packages
        # remain supported, with their site hooks running AFTER confinement.
        tempfile.tempdir = private_tmp
        if user_site:
            site.USER_SITE = user_site
            site.addsitedir(user_site)
        for name in ('angr', 'claripy', 'cle', 'pyvex'):
            logging.getLogger(name).setLevel(logging.CRITICAL)
        module = importlib.import_module(module_name)
        result = getattr(module, func_name)(**kwargs)
        conn.send_bytes(pickle.dumps(result))
    except BaseException as exc:  # noqa: BLE001 — one bounded channel out
        conn.send_bytes(pickle.dumps(SymbolicResult(
            succeeded=False, reason=f'primitive raised: {type(exc).__name__}: {exc}',
            wall_seconds=0.0, states_explored=0, metadata={})))
    finally:
        conn.close()


def _run_confined(conn, module_name, func_name, kwargs, private_tmp, timeout):
    """Trusted broker; hostile parsing occurs only in the sandboxed exec."""
    import site
    from core.sandbox import run
    from core.sandbox.context import untrusted_fresh_procfs_required
    from core.sandbox.python_paths import python_runtime_tool_paths, _home_roots
    from core.sandbox.errors import SandboxSetupError
    root = Path(__file__).resolve().parents[2]
    paths = [str(root), *python_runtime_tool_paths()]
    user_site = site.getusersitepackages()
    if not isinstance(user_site, str) or not Path(user_site).is_dir():
        user_site = None
    if user_site:
        paths.append(user_site)
    if any(Path(path).resolve() == home or Path(path).resolve() in home.parents
           for path in paths for home in _home_roots()):
        raise SandboxSetupError('Symbolic runtime requires dedicated code directories, not HOME or its ancestors')
    target = kwargs.get('binary_path')
    if target is not None:
        selected = Path(target).resolve()
        if not selected.is_file():
            raise SandboxSetupError(f'binary not found or not a regular file: {target}')
        paths.extend(dict.fromkeys([str(Path(target).absolute()), str(selected)]))
    fresh = untrusted_fresh_procfs_required()
    return run(
        [sys.executable, '-I', '-c', _WORKER_SOURCE, str(root), str(conn.fileno()), private_tmp],
        target=private_tmp, output=private_tmp, tool_paths=paths,
        block_network=True, restrict_reads=True, fake_home=True,
        strict_env=True, strip_trust_markers=True, start_new_session=True,
        require_fresh_procfs=fresh, omit_proc_reads=not fresh,
        _untrusted_workload=True, exclude_tmp_baseline=True,
        caller_label='symbolic-worker', pass_fds=(conn.fileno(),),
        input=pickle.dumps((module_name, func_name, kwargs, private_tmp, user_site)),
        capture_output=True, max_capture_bytes=16384, timeout=timeout,
    )


def _remove_private_tmp(path: str) -> None:
    """Remove the child's private temp dir after the child exits.

    Defeats permission griefing (a compromised child leaving a mode-0
    subdirectory inside its grant defeats a plain
    ``rmtree(ignore_errors=True)``): delegates to the shared
    chmod-walk-then-rmtree helper. Never raises.
    """
    from core.atomic_fs import rmtree_hardened
    rmtree_hardened(path)


_SYMBOLIC_MODULE_PREFIX: str = "core.symbolic."


def _child_entry(conn, module_name, func_name, kwargs, private_tmp,
                 timeout, policy_state) -> None:
    """Disposable trusted broker; preserve the parent's approved floor state."""
    from core.sandbox import state
    from core.sandbox.errors import SandboxSetupError
    for name, value in policy_state.items():
        setattr(state, name, value)
    started = time.monotonic()
    try:
        result = _run_confined(conn, module_name, func_name, kwargs, private_tmp, timeout)
        if result.returncode:
            # Report executor crashes separately from a hard wall timeout.
            # If it already sent a result, that first frame remains authoritative.
            detail = (result.stderr or b'')[-2000:]
            if isinstance(detail, bytes):
                detail = detail.decode('utf-8', errors='replace')
            conn.send_bytes(pickle.dumps(SymbolicResult(
                succeeded=False,
                reason=f'child exited without returning a result (exit code {result.returncode}) — crash, not a budget kill: {detail}',
                wall_seconds=time.monotonic() - started, metadata={'isolated': True, 'crashed': True,
                                          'killed': False, 'exitcode': result.returncode})))
    except SandboxSetupError as exc:
        conn.send_bytes(pickle.dumps(SymbolicResult(
            succeeded=False, reason=f'symbolic sandbox refused: {exc}',
            wall_seconds=time.monotonic() - started, metadata={'isolated': False, 'sandbox_refused': True})))
    except subprocess.TimeoutExpired:
        # Keep EOF from laundering the executor's wall timeout into a crash.
        conn.send_bytes(pickle.dumps(SymbolicResult(
            succeeded=False, reason='symbolic sandbox exceeded the hard wall budget',
            wall_seconds=timeout, metadata={'isolated': True, 'killed': True})))
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
    if not module_name.startswith(_SYMBOLIC_MODULE_PREFIX):
        raise ValueError(
            f"run_isolated: module {module_name!r} outside "
            f"allowed prefix {_SYMBOLIC_MODULE_PREFIX!r}"
        )
    t0 = time.monotonic()
    if 'binary_path' in kwargs:
        kwargs = dict(kwargs)
        # Lexical only: target-controlled filesystem I/O belongs in the
        # disposable broker/executor, under the parent's hard deadline.
        kwargs['binary_path'] = Path(kwargs['binary_path']).absolute()
    # Scratch is required; never parse a target after its creation fails.
    # Created here so the parent can remove it after the child exits
    # — the sandboxed child cannot unlink a directory that sits in
    # the shared temp dir, outside its own write grant.
    private_tmp: str | None
    try:
        private_tmp = tempfile.mkdtemp(prefix="raptor-symex-")
    except OSError as exc:
        return SymbolicResult(
            succeeded=False, reason=f'symbolic scratch unavailable: {exc}',
            wall_seconds=time.monotonic() - t0,
            metadata={'isolated': False, 'sandbox_refused': True})
    from core.sandbox import state
    policy_state = {name: getattr(state, name) for name in _POLICY_STATE}
    try:
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        proc = ctx.Process(
            target=_child_entry,
            args=(child_conn, module_name, func_name, kwargs, private_tmp,
                  timeout + GRACE_SECONDS, policy_state),
            daemon=True,
        )
        proc.start()
        child_conn.close()

        budget = timeout + GRACE_SECONDS
        deadline = time.monotonic() + budget
        result: SymbolicResult | None = None
        rejected_reason: str | None = None
        # A crashed child closes the pipe, so poll() returns promptly
        # (EOF is readable) and the frame read raises — timed_out
        # separates "budget genuinely elapsed" from "child died with
        # no result". The frame read itself is deadline-bounded
        # (_recv_frame_deadline): poll() only proves ONE byte is
        # readable, and a hostile child that writes a partial frame
        # and sleeps must still hit the kill escalation below.
        timed_out = not parent_conn.poll(budget)
        if not timed_out:
            try:
                payload = _recv_frame_deadline(
                    parent_conn, deadline, _MAX_RESULT_BYTES,
                )
            except EOFError:
                result = None
            except (_FrameRefused, OSError):
                # Oversized/malformed frame or a torn transport —
                # either way the child produced no decodable result;
                # fail closed with the cap named.
                rejected_reason = (
                    "child result payload unreadable or over the "
                    f"{_MAX_RESULT_BYTES}-byte cap — refused"
                )
            else:
                if payload is None:
                    # Deadline expired mid-frame: a partial result is
                    # a budget overrun (or a stalling hostile child),
                    # handled by the timeout lane + kill escalation.
                    timed_out = True
                else:
                    try:
                        result = _loads_result(payload)
                    except Exception as exc:  # noqa: BLE001 — hostile bytes
                        rejected_reason = (
                            "restricted result decoder refused the "
                            f"child's payload ({type(exc).__name__}: "
                            f"{str(exc)[:200]})"
                        )
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
    if rejected_reason is not None:
        # A payload the restricted decoder refused is a HOSTILE-CHILD
        # signal (or a result-shape bug), never laundered into a
        # timeout or crash report.
        return SymbolicResult(
            succeeded=False,
            reason=rejected_reason,
            wall_seconds=time.monotonic() - t0,
            states_explored=0,
            metadata={"isolated": True, "rejected_payload": True},
        )
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
