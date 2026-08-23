#!/usr/bin/env python3
"""Persistent sandbox host — RPC daemon (inherited-fd transport).

Runs INSIDE the sandbox as the argv sandbox_run sees. The RPC
endpoints are two pipe fds the parent created and passed across the
sandbox spawn (``pass_fds``); their numbers arrive on argv
(``--rpc-in-fd N`` parent→daemon, ``--rpc-out-fd M`` daemon→parent).
The daemon opens nothing by path — no rendezvous name exists in any
filesystem for a hostile target to squat, replace, or open.

Pipes instead of AF_UNIX sockets because seccomp:full (which
matches parse_result's target posture for env parity) blocks
``socket()``. The seccomp filter is a blocklist that leaves
``pipe``/``pipe2`` alone, and at daemon runtime the channel needs
only ``read()``/``write()``/``close()``, which pass the filter.
Pipes instead of the daemon's own stdin/stdout because
``core.sandbox.run`` blocks the caller, captures stdout itself,
and doesn't expose a caller-provided stdout fd.

Immediately after argv parsing the daemon re-arms FD_CLOEXEC on
both RPC fds: CLOEXEC was cleared only so they survive the daemon's
own exec chain. Targets the daemon later spawns must never inherit
the channel — a target holding the write end could forge verdict
frames, and one holding the read end could steal parent requests.
(The subprocess module's default ``close_fds=True`` already keeps
them out of spawned targets; the CLOEXEC re-arm covers any exec
that bypasses subprocess.)

Protocol — length-prefixed JSON, big-endian u32 length header:

  parent → daemon:
    {"cmd": "ping"}
    {"cmd": "spawn", "argv": [...], "stdin_hex": "", "timeout": 30.0}
    {"cmd": "probe",
     "target_argv": [...],
     "steps": [...],
     "per_recv_timeout": 3.0,
     "total_wait_seconds": 5.0,
     "flag_string": "WIN_NO_FLAG_FILE"}
    {"cmd": "conversation",
     "target_argv": [...],
     "sends": [...],
     "per_recv_timeout": 2.0,
     "total_wait_seconds": 3.0,
     "close_after": true}
    {"cmd": "close"}

  daemon → parent:
    {"ok": true, ...}
    {"ok": false, "error": "..."}

Design notes:

* NO imports from raptor-engine tree — stdlib + pwntools only.
* Step-driver logic copied from tools.py::interactive_probe. Two
  copies will converge into core/sandbox when the A/B measurement
  proves the persistent-sandbox pattern.
* The RPC fd numbers are passed as argv (``--rpc-in-fd``/
  ``--rpc-out-fd``) not discovered — the parent controls them, and
  ``pass_fds`` keeps the numbers stable across the spawn.
"""
from __future__ import annotations

import argparse
import ast
import ctypes
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import time
from typing import Any


def _log(msg: str) -> None:
    sys.stderr.write(f"[host-daemon] {msg}\n")
    sys.stderr.flush()


# prctl(2) option numbers — stable Linux ABI values.
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4


def _set_non_dumpable() -> bool:
    """Set PR_SET_DUMPABLE=0 on this process; True on success.

    A non-dumpable process's ``/proc/<pid>/`` entries are owned by
    root, so a same-UID non-root process — in particular a target the
    daemon spawns — can no longer open ``/proc/<daemon>/fd/<n>`` to
    reopen the RPC pipe ends and forge daemon→parent frames or steal
    parent→daemon requests. CLOEXEC keeps the fds out of the target's
    fd table; this closes the /proc reopen side door (which Yama does
    NOT cover: ptrace_scope 1 restricts ATTACH-mode access, while
    /proc fd opens need only READ-mode).

    Children the daemon spawns are unaffected: execve resets the
    dumpable flag, so target crash-dumps and target /proc
    introspection keep working.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def _get_dumpable() -> int | None:
    """Return this process's PR_GET_DUMPABLE value (None if unknown)."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        v = libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0)
        return None if v < 0 else v
    except (OSError, AttributeError):
        return None


def _read_frame(fd: int) -> dict | None:
    hdr = b""
    while len(hdr) < 4:
        chunk = os.read(fd, 4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    (length,) = struct.unpack("!I", hdr)
    if length > 64 * 1024 * 1024:
        msg = f"frame too large: {length}"
        raise ValueError(msg)
    body = b""
    while len(body) < length:
        chunk = os.read(fd, length - len(body))
        if not chunk:
            return None
        body += chunk
    return json.loads(body.decode("utf-8"))


def _write_frame(fd: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    hdr = struct.pack("!I", len(body))
    # Loop the write: a frame larger than the pipe buffer may be
    # written partially, and a torn frame desyncs the whole channel.
    view = memoryview(hdr + body)
    while view:
        n = os.write(fd, view)
        view = view[n:]


# --------------------------------------------------------------------
# Helpers copied from tools.py — kept inline so daemon has no
# dependency on raptor-engine's import path inside the sandbox.
# --------------------------------------------------------------------


# Allowlisted AST nodes for compute expressions. The compute language
# is arithmetic/bit-ops over recv-derived bindings (ints or raw bytes)
# plus the packing helpers in _SAFE_EVAL_CALLABLES — called by bare
# name only. Subscript/Slice/Index stay: slicing raw recv bytes (e.g.
# ``u64(leak[8:16])``) is part of the language. Attribute is
# deliberately ABSENT: nothing in the language needs dotted access,
# and admitting it opens ``p64.__globals__['os']``-shaped escape
# chains through an otherwise allowlisted expression.
_SAFE_EVAL_NODES = {
    "Expression", "BinOp", "UnaryOp", "Constant", "Name", "Load",
    "Add", "Sub", "Mult", "FloorDiv", "Mod", "BitAnd", "BitOr",
    "BitXor", "LShift", "RShift", "USub", "Invert",
    "Subscript", "Slice", "Index", "Call",
}
_SAFE_EVAL_CALLABLES = {"p64", "p32", "p16", "u64", "u32", "u16", "int"}

# Compute budgets. The compute language exists for exploit arithmetic
# over leaked pointers/values — 64-to-a-few-hundred-bit quantities.
# CPython's int_max_str_digits guard does NOT cover base-16 parsing,
# so a hostile target printing "0x" + megabytes of hex used to mint a
# multi-megabit binding, and LLM-authored squaring/shift chains over
# such bindings burned unbounded daemon CPU (no timeout existed).
# _INT_BIT_CEILING bounds every binding and every intermediate result
# (2**20 bits ≈ 131 KB — orders of magnitude past any legitimate
# exploit arithmetic, cheap for a single op); _MAX_HEX_DIGITS bounds
# the parse (512-bit headroom over 64-bit leaks); the per-expression
# wall-clock deadline is the belt-and-braces backstop.
_MAX_HEX_DIGITS = 128
_INT_BIT_CEILING = 1 << 20
_COMPUTE_DEADLINE_S = 2.0


def _cap_result(value: Any, expr: str) -> Any:
    """Enforce the magnitude budget on a compute (sub)result."""
    if isinstance(value, int) and not isinstance(value, bool):
        if value.bit_length() > _INT_BIT_CEILING:
            msg = (
                f"compute result exceeds {_INT_BIT_CEILING}-bit "
                f"budget in {expr!r}"
            )
            raise ValueError(msg)
    elif isinstance(value, (bytes, str)) and len(value) > (
            _INT_BIT_CEILING // 8):
        msg = f"compute result exceeds byte budget in {expr!r}"
        raise ValueError(msg)
    return value


def _safe_eval(expr: str, bindings: dict) -> Any:
    """Evaluate a compute expression under explicit budgets.

    A hand-rolled recursive evaluator (NOT compile+eval): every
    intermediate result is magnitude-capped as it is produced, the
    fast-blowup operators (int*int, <<) are pre-checked so the
    oversized value is never materialised, and a wall-clock deadline
    bounds the whole expression. The node/callable allowlists are
    unchanged from the eval-based predecessor.
    """
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        cls_name = type(node).__name__
        if cls_name not in _SAFE_EVAL_NODES:
            msg = f"disallowed node: {cls_name} in {expr!r}"
            raise ValueError(msg)
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None)
            if fname not in _SAFE_EVAL_CALLABLES:
                msg = f"disallowed call: {fname!r} in {expr!r}"
                raise ValueError(msg)

    def _p(n: int, sz: int) -> bytes:
        return int(n).to_bytes(sz, "little", signed=False)

    def _u(b: bytes, sz: int) -> int:
        return int.from_bytes(bytes(b)[:sz], "little", signed=False)

    ns = {
        **bindings,
        "p64": lambda n: _p(n, 8),
        "p32": lambda n: _p(n, 4),
        "p16": lambda n: _p(n, 2),
        "u64": lambda b: _u(b, 8),
        "u32": lambda b: _u(b, 4),
        "u16": lambda b: _u(b, 2),
        "int": int,
    }

    deadline = time.monotonic() + _COMPUTE_DEADLINE_S

    def _ev(node: ast.AST) -> Any:
        if time.monotonic() > deadline:
            msg = f"compute deadline exceeded in {expr!r}"
            raise ValueError(msg)
        if isinstance(node, ast.Constant):
            return _cap_result(node.value, expr)
        if isinstance(node, ast.Name):
            if node.id not in ns:
                # NameError, matching the eval-based predecessor's
                # contract: bare names resolve only against bindings +
                # helpers, never builtins.
                msg = f"name {node.id!r} is not defined in {expr!r}"
                raise NameError(msg)
            return ns[node.id]
        if isinstance(node, ast.UnaryOp):
            operand = _ev(node.operand)
            if isinstance(node.op, ast.USub):
                return _cap_result(-operand, expr)
            if isinstance(node.op, ast.Invert):
                return _cap_result(~operand, expr)
            msg = f"disallowed unary op in {expr!r}"
            raise ValueError(msg)
        if isinstance(node, ast.BinOp):
            left = _ev(node.left)
            right = _ev(node.right)
            return _cap_result(_binop(left, node.op, right), expr)
        if isinstance(node, ast.Subscript):
            value = _ev(node.value)
            sl = node.slice
            # py3.8 wrapped plain indices in ast.Index; 3.9+ inlines.
            if type(sl).__name__ == "Index":
                sl = sl.value  # type: ignore[attr-defined]
            if isinstance(sl, ast.Slice):
                lower = _ev(sl.lower) if sl.lower is not None else None
                upper = _ev(sl.upper) if sl.upper is not None else None
                step = _ev(sl.step) if sl.step is not None else None
                return _cap_result(value[lower:upper:step], expr)
            return _cap_result(value[_ev(sl)], expr)
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None)
            fn = ns.get(fname)
            if not callable(fn):
                msg = f"disallowed call: {fname!r} in {expr!r}"
                raise ValueError(msg)
            args = [_ev(a) for a in node.args]
            if node.keywords:
                msg = f"keyword arguments not allowed in {expr!r}"
                raise ValueError(msg)
            return _cap_result(fn(*args), expr)
        msg = f"disallowed node: {type(node).__name__} in {expr!r}"
        raise ValueError(msg)

    def _binop(left: Any, op: ast.AST, right: Any) -> Any:
        both_int = (
            isinstance(left, int) and not isinstance(left, bool)
            and isinstance(right, int) and not isinstance(right, bool)
        )
        if isinstance(op, ast.Mult):
            # Pre-check: never materialise an over-budget product.
            if both_int and (
                left.bit_length() + right.bit_length()
                > _INT_BIT_CEILING + 1
            ):
                msg = f"compute product exceeds bit budget in {expr!r}"
                raise ValueError(msg)
            if isinstance(left, (bytes, str)) or isinstance(
                    right, (bytes, str)):
                seq, count = (
                    (left, right)
                    if isinstance(left, (bytes, str)) else (right, left)
                )
                if isinstance(count, int) and len(seq) * max(count, 0) \
                        > _INT_BIT_CEILING // 8:
                    msg = (
                        f"compute repetition exceeds byte budget in "
                        f"{expr!r}"
                    )
                    raise ValueError(msg)
            return left * right
        if isinstance(op, ast.LShift):
            # Pre-check: `1 << leak` with a large in-budget VALUE as
            # the shift count would materialise a gigabit int.
            if both_int and (
                right > _INT_BIT_CEILING
                or left.bit_length() + max(right, 0) > _INT_BIT_CEILING
            ):
                msg = f"compute shift exceeds bit budget in {expr!r}"
                raise ValueError(msg)
            return left << right
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.FloorDiv):
            return left // right
        if isinstance(op, ast.Mod):
            return left % right
        if isinstance(op, ast.BitAnd):
            return left & right
        if isinstance(op, ast.BitOr):
            return left | right
        if isinstance(op, ast.BitXor):
            return left ^ right
        if isinstance(op, ast.RShift):
            return left >> right
        msg = f"disallowed operator {type(op).__name__} in {expr!r}"
        raise ValueError(msg)

    return _cap_result(_ev(tree.body), expr)


def _parse_bytes_to_int(raw: bytes) -> int | None:
    text = raw.decode("utf-8", errors="replace")
    m = re.search(r"0x([0-9a-fA-F]+)", text)
    if m:
        digits = m.group(1)
        # Hex parsing is EXEMPT from CPython's int_max_str_digits
        # guard, so a hostile target printing "0x" + megabytes of hex
        # used to mint a multi-megabit int binding in one call. Budget
        # the digit count; an over-budget run is treated as no hex
        # match (never silently truncated to a wrong-but-plausible
        # value) and the decimal branch below still applies (bounded
        # by int_max_str_digits).
        if len(digits) <= _MAX_HEX_DIGITS:
            try:
                return int(digits, 16)
            except ValueError:
                pass
    m = re.search(r"(-?\d{2,})", text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None


def _build_fmtstr_write(spec: dict, bindings: dict) -> bytes:
    from pwn import context, fmtstr_payload  # type: ignore[import-untyped, import-not-found]
    prev_arch = getattr(context, "arch", None)
    context.arch = "amd64"

    offset = spec.get("offset")
    if isinstance(offset, str):
        offset = _safe_eval(offset, bindings)
    offset = int(offset)
    numbwritten = spec.get("numbwritten", 0)
    if isinstance(numbwritten, str):
        numbwritten = _safe_eval(numbwritten, bindings)
    numbwritten = int(numbwritten)
    write_size = spec.get("write_size", "short")
    if write_size not in ("byte", "short", "int"):
        msg = f"write_size invalid: {write_size!r}"
        raise ValueError(msg)
    raw_writes = spec.get("writes") or {}
    if not raw_writes:
        msg = "writes dict required"
        raise ValueError(msg)
    resolved: dict[int, int] = {}
    for addr_expr, value_expr in raw_writes.items():
        resolved[int(_safe_eval(str(addr_expr), bindings))] = int(
            _safe_eval(str(value_expr), bindings)
        )
    try:
        payload = fmtstr_payload(
            offset, resolved, numbwritten=numbwritten, write_size=write_size,
        )
    finally:
        if prev_arch is not None:
            context.arch = prev_arch
    return bytes(payload)


_CANARY_ABORT_SIGNAL = b"stack smashing detected"


def _render_compose(chunks, recvs):
    """Render a stdin_conversation compose spec against prior recvs.

    Mirrors ``tools.py::_render_compose`` — chunks are either
    ``{"kind": "hex", "value": "<hex>"}`` (literal bytes) or
    ``{"kind": "recv_le64", "recv_index": N}`` (first whitespace
    token of ``recvs[N]`` parsed as a hex int, packed little-endian
    to 8 bytes). Kept here rather than reused from tools.py because
    the daemon has NO raptor-engine imports.
    """
    import struct as _struct
    out = bytearray()
    for chunk in chunks:
        kind = chunk.get("kind")
        if kind == "hex":
            out += bytes.fromhex(
                chunk["value"].replace(" ", "").replace("\n", ""),
            )
        elif kind == "recv_le64":
            idx = chunk["recv_index"]
            if idx >= len(recvs):
                msg = (
                    f"recv_le64 references recv_index={idx} but only "
                    f"{len(recvs)} recv(s) available"
                )
                raise IndexError(msg)
            raw = recvs[idx].decode("utf-8", errors="replace").strip()
            tok = raw.split()[0] if raw.split() else ""
            tok = tok.removeprefix("0x")
            if not tok:
                msg = f"recv_le64: recvs[{idx}] is empty after tokenization"
                raise ValueError(msg)
            value = int(tok, 16)
            out += _struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
        else:
            msg = f"unknown compose chunk kind: {kind!r}"
            raise ValueError(msg)
    return bytes(out)


def _recv_until(proc, terminator, per_recv_timeout: float,
                max_bytes: int | None = None) -> bytes:
    """Bounded step-recv; retains at most ``max_bytes`` (default
    ``_MAX_CAPTURE_BYTES``). Reading stops at the cap — unread bytes
    stay in the pipe for the end-of-request drain, which discards
    them (bounded) and reports the truncation."""
    cap = _MAX_CAPTURE_BYTES if max_bytes is None else max(max_bytes, 0)
    deadline = time.monotonic() + per_recv_timeout
    buf = b""
    fd = proc.stdout.fileno()

    def _read_bounded(max_chunk: int) -> bytes | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        r, _, _ = select.select([fd], [], [], remaining)
        if not r:
            return None
        # Read the raw fd directly. Popen's default-buffered
        # ``proc.stdout.read1`` pulls a full buffer (8 KiB) from the
        # kernel and returns at most ``max_chunk`` — the remainder sits
        # in the Python-level buffer where select() on the raw fd
        # cannot see it, so the next bounded read stalls a full
        # ``per_recv_timeout`` (or attributes the bytes to the wrong
        # step). Nothing else reads through ``proc.stdout`` until the
        # final end-of-request drain (also raw-fd), so its buffer
        # stays empty and mixing fd-level reads here is safe.
        return os.read(fd, max_chunk)

    if isinstance(terminator, int):
        want = min(terminator, cap)
        while len(buf) < want:
            chunk = _read_bounded(want - len(buf))
            if chunk is None or not chunk:
                break
            buf += chunk
        return buf
    if terminator == "newline":
        while b"\n" not in buf and len(buf) < cap:
            chunk = _read_bounded(min(4096, cap - len(buf)))
            if chunk is None or not chunk:
                break
            buf += chunk
        return buf
    while len(buf) < cap:
        chunk = _read_bounded(min(4096, cap - len(buf)))
        if chunk is None or not chunk:
            break
        buf += chunk
    return buf


def _communicate_capped(
    proc: subprocess.Popen,
    stdin_bytes: bytes,
    timeout: float,
    *,
    stdout_cap: int | None = None,
    stderr_cap: int | None = None,
) -> tuple[bytes, bytes, bool, bool]:
    """Bounded ``Popen.communicate`` stand-in.

    Streams the child's stdout/stderr off the raw fds, retaining at
    most ``*_cap`` bytes per stream (default ``_MAX_CAPTURE_BYTES``).
    Bytes beyond a cap are still read — the child never blocks on a
    full pipe — but discarded, and the per-stream truncated flag
    reports the loss. ``communicate()`` had no ceiling: a target
    could grow the daemon's buffers (and, hex-doubled, the reply
    frame) without bound.

    Returns ``(stdout, stderr, stdout_truncated, stderr_truncated)``.
    Raises ``subprocess.TimeoutExpired`` at the deadline with the
    capped buffers attached as ``output``/``stderr`` and the flags as
    ``stdout_truncated``/``stderr_truncated`` attributes.
    """
    if stdout_cap is None:
        stdout_cap = _MAX_CAPTURE_BYTES
    if stderr_cap is None:
        stderr_cap = _MAX_CAPTURE_BYTES
    deadline = time.monotonic() + timeout
    out_fd = err_fd = None
    if proc.stdout is not None and not proc.stdout.closed:
        out_fd = proc.stdout.fileno()
    if proc.stderr is not None and not proc.stderr.closed:
        err_fd = proc.stderr.fileno()
    bufs: dict[int, bytearray] = {}
    caps: dict[int, int] = {}
    trunc: dict[int, bool] = {}
    for fd, cap in ((out_fd, stdout_cap), (err_fd, stderr_cap)):
        if fd is not None:
            bufs[fd] = bytearray()
            caps[fd] = max(cap, 0)
            trunc[fd] = False
    pending = set(bufs)

    def _got(fd: int | None) -> bytes:
        return bytes(bufs[fd]) if fd is not None else b""

    def _truncated(fd: int | None) -> bool:
        return fd is not None and trunc[fd]

    def _timeout_exc() -> subprocess.TimeoutExpired:
        exc = subprocess.TimeoutExpired(
            proc.args, timeout, output=_got(out_fd), stderr=_got(err_fd),
        )
        exc.stdout_truncated = _truncated(out_fd)
        exc.stderr_truncated = _truncated(err_fd)
        return exc

    in_file = proc.stdin if (
        proc.stdin is not None and not proc.stdin.closed) else None
    view = memoryview(stdin_bytes)

    def _close_stdin() -> None:
        nonlocal in_file
        if in_file is not None:
            try:
                in_file.close()
            except (BrokenPipeError, OSError):
                pass
            in_file = None

    if in_file is not None:
        if not view:
            _close_stdin()
        else:
            # Non-blocking sends: a blocking >PIPE_BUF write could
            # stall this loop while the child waits for its stdout to
            # be drained — a mutual-blocking deadlock.
            os.set_blocking(in_file.fileno(), False)

    while pending or in_file is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _timeout_exc()
        wlist = [in_file.fileno()] if in_file is not None else []
        r, w, _ = select.select(list(pending), wlist, [], remaining)
        if not r and not w:
            raise _timeout_exc()
        for fd in r:
            chunk = os.read(fd, 65536)
            if not chunk:
                pending.discard(fd)
                continue
            room = caps[fd] - len(bufs[fd])
            if room > 0:
                bufs[fd] += chunk[:room]
            if len(chunk) > room:
                trunc[fd] = True
        if w:
            try:
                n = os.write(in_file.fileno(), view[:65536])
                view = view[n:]
            except BlockingIOError:
                pass
            except (BrokenPipeError, OSError):
                view = view[:0]
            if not view:
                _close_stdin()

    try:
        proc.wait(timeout=max(deadline - time.monotonic(), 0))
    except subprocess.TimeoutExpired:
        raise _timeout_exc() from None
    return (_got(out_fd), _got(err_fd),
            _truncated(out_fd), _truncated(err_fd))


def _drain_target(
    proc: subprocess.Popen, wait_seconds: float, stdout_cap: int,
) -> tuple[bytes, bytes, bool, bool, bool]:
    """Wait for a request target to exit, draining bounded output.

    Returns ``(tail_stdout, stderr, stdout_truncated,
    stderr_truncated, timed_out)``. On timeout the request's process
    group is killed first, then a final short bounded drain collects
    what the pipes still hold.
    """
    try:
        out, err, ot, et = _communicate_capped(
            proc, b"", wait_seconds, stdout_cap=stdout_cap,
        )
        return out, err, ot, et, False
    except subprocess.TimeoutExpired as e:
        _kill_request_group(proc)
        out = e.stdout or b""
        err = e.stderr or b""
        ot = bool(getattr(e, "stdout_truncated", False))
        et = bool(getattr(e, "stderr_truncated", False))
        try:
            t_out, t_err, t_ot, t_et = _communicate_capped(
                proc, b"", 1.0,
                stdout_cap=max(stdout_cap - len(out), 0),
                stderr_cap=max(_MAX_CAPTURE_BYTES - len(err), 0),
            )
            out += t_out
            err += t_err
            ot = ot or t_ot
            et = et or t_et
        except subprocess.TimeoutExpired:
            pass
        return out, err, ot, et, True


# --------------------------------------------------------------------
# RPC handlers
# --------------------------------------------------------------------


def _spawn_request_target(argv: list) -> subprocess.Popen:
    """Start a request target as the leader of its own session.

    ``start_new_session=True`` gives every request a dedicated
    process group (pgid == the direct child's pid), so
    ``_kill_request_group`` can sweep double-fork descendants when
    the request ends. Without it the target shares the daemon's
    group and only the direct pid could be killed — a detached
    descendant survived into later RPCs inside the persistent
    sandbox, retaining pipes and mutating shared state.
    """
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _kill_request_group(proc: subprocess.Popen) -> None:
    """SIGKILL the request's whole process group; reap the leader.

    Runs on EVERY exit path (success, timeout, exception) of the
    spawn/probe/conversation handlers. ESRCH — the group already
    fully exited — is the common case and is suppressed.
    """
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as e:
        _log(f"killpg({proc.pid}) failed: {e}")
    if proc.poll() is None:
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            _log(f"request target {proc.pid} unreaped after SIGKILL")


def _handle_ping(payload: dict) -> dict:
    # ``dumpable`` lets the parent (and the hardening tests) verify
    # the /proc-reopen defence engaged without needing to read the
    # daemon's /proc entries (which non-dumpability itself hides).
    return {"ok": True, "pong": True, "pid": os.getpid(),
            "dumpable": _get_dumpable()}


def _handle_spawn(payload: dict) -> dict:
    argv = payload["argv"]
    stdin_bytes = bytes.fromhex(payload.get("stdin_hex", ""))
    if len(stdin_bytes) > _MAX_STDIN_BYTES:
        return {"ok": False,
                "error": f"stdin_bytes={len(stdin_bytes)} exceeds "
                         f"{_MAX_STDIN_BYTES}"}
    try:
        timeout = _cap("timeout", payload.get("timeout", 30.0),
                       _MAX_SPAWN_TIMEOUT)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    t0 = time.monotonic()
    try:
        proc = _spawn_request_target(argv)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    try:
        try:
            stdout, stderr, out_trunc, err_trunc = _communicate_capped(
                proc, stdin_bytes, timeout,
            )
            returncode: int | None = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as e:
            # Kill the whole request group first so pipe-holding
            # descendants can't keep the drain below blocked.
            _kill_request_group(proc)
            stdout = e.stdout or b""
            stderr = e.stderr or b""
            out_trunc = bool(getattr(e, "stdout_truncated", False))
            err_trunc = bool(getattr(e, "stderr_truncated", False))
            try:
                t_out, t_err, t_ot, t_et = _communicate_capped(
                    proc, b"", 1.0,
                    stdout_cap=max(_MAX_CAPTURE_BYTES - len(stdout), 0),
                    stderr_cap=max(_MAX_CAPTURE_BYTES - len(stderr), 0),
                )
                stdout += t_out
                stderr += t_err
                out_trunc = out_trunc or t_ot
                err_trunc = err_trunc or t_et
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass
            returncode = None
            timed_out = True
        return {
            "ok": True,
            "stdout_hex": stdout.hex(),
            "stderr_hex": stderr.hex(),
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
            "stdout_bytes_kept": len(stdout),
            "stderr_bytes_kept": len(stderr),
            "returncode": returncode,
            "timed_out": timed_out,
            "wall_seconds": round(time.monotonic() - t0, 3),
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        _kill_request_group(proc)


def _handle_probe(payload: dict) -> dict:
    steps = payload.get("steps") or []
    target_argv = payload.get("target_argv")
    if not target_argv:
        return {"ok": False, "error": "target_argv required"}
    if len(steps) > _MAX_STEPS:
        return {"ok": False,
                "error": f"steps={len(steps)} exceeds {_MAX_STEPS}"}
    try:
        per_recv_timeout = _cap("per_recv_timeout",
                                payload.get("per_recv_timeout", 3.0),
                                _MAX_PER_RECV_TIMEOUT)
        total_wait_seconds = _cap("total_wait_seconds",
                                  payload.get("total_wait_seconds", 5.0),
                                  _MAX_TOTAL_WAIT_SECONDS)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    flag_string = payload.get("flag_string") or ""

    bindings: dict[str, Any] = {}
    recvs: list = []
    stdout_buf = b""
    # Cumulative stdout retention budget for the whole request —
    # bounds recvs, bindings, and the tail together (they all derive
    # from stdout_buf's bytes).
    stdout_budget = _MAX_CAPTURE_BYTES
    stdout_trunc = False
    stderr_trunc = False
    steps_completed = 0
    exit_class = "unknown"
    proc = _spawn_request_target(target_argv)
    t0 = time.monotonic()
    try:
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                return {"ok": False, "error": f"step {i} not an object"}
            if "compute" in step:
                try:
                    v = _safe_eval(step["compute"], bindings)
                except Exception as e:  # noqa: BLE001
                    return {"ok": False,
                            "error": f"step {i} compute: {type(e).__name__}: {e}",
                            "steps_completed": steps_completed}
                name = step.get("bind_as")
                if name:
                    bindings[name] = v
                steps_completed += 1
                continue

            send_bytes: bytes | None = None
            if "send_hex" in step:
                send_bytes = bytes.fromhex(step["send_hex"].replace(" ", ""))
                if len(send_bytes) > _MAX_SEND_BYTES:
                    return {"ok": False,
                            "error": (f"step {i} send_hex "
                                      f"{len(send_bytes)} > {_MAX_SEND_BYTES}"),
                            "steps_completed": steps_completed}
            elif "send_template" in step:
                raw = step["send_template"]
                try:
                    send_bytes = raw.encode("utf-8").decode(
                        "unicode_escape").encode("latin-1")
                except Exception:  # noqa: BLE001
                    send_bytes = raw.encode("utf-8")
                if len(send_bytes) > _MAX_SEND_BYTES:
                    return {"ok": False,
                            "error": (f"step {i} send_template "
                                      f"{len(send_bytes)} > {_MAX_SEND_BYTES}"),
                            "steps_completed": steps_completed}
            elif "send_p64" in step:
                try:
                    v = _safe_eval(step["send_p64"], bindings)
                except Exception as e:  # noqa: BLE001
                    return {"ok": False,
                            "error": f"step {i} send_p64: {type(e).__name__}: {e}",
                            "steps_completed": steps_completed}
                send_bytes = int(v).to_bytes(8, "little", signed=False)
            elif "build_fmtstr_write" in step:
                try:
                    send_bytes = _build_fmtstr_write(
                        step["build_fmtstr_write"], bindings,
                    )
                except Exception as e:  # noqa: BLE001
                    return {"ok": False,
                            "error": (f"step {i} build_fmtstr_write: "
                                      f"{type(e).__name__}: {e}"),
                            "steps_completed": steps_completed}
                if len(send_bytes) > _MAX_SEND_BYTES:
                    return {"ok": False,
                            "error": (f"step {i} build_fmtstr_write "
                                      f"{len(send_bytes)} > {_MAX_SEND_BYTES}"),
                            "steps_completed": steps_completed}

            if send_bytes is not None:
                try:
                    proc.stdin.write(send_bytes)
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass

            recv_until = step.get("recv_until")
            got = b""
            if recv_until is not None:
                got = _recv_until(proc, recv_until, per_recv_timeout,
                                  max_bytes=stdout_budget)
                stdout_budget -= len(got)
                stdout_buf += got
                name = step.get("bind_as")
                if name:
                    parsed = _parse_bytes_to_int(got)
                    bindings[name] = parsed if parsed is not None else got
                recvs.append({"step": i, "hex": got.hex(),
                              "text": got.decode("utf-8", errors="replace")})
            steps_completed += 1

        try:
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        tail_stdout, target_stderr, stdout_trunc, stderr_trunc, timed_out = \
            _drain_target(proc, total_wait_seconds, stdout_budget)
        stdout_buf += tail_stdout
        if timed_out:
            exit_class = "timeout"
        else:
            rc = proc.returncode
            if rc == 0:
                exit_class = "clean"
            elif rc is not None and rc < 0:
                exit_class = f"signal:{-rc}"
            else:
                exit_class = f"exit:{rc}"
    finally:
        _kill_request_group(proc)

    wall = round(time.monotonic() - t0, 3)
    stderr_text = (target_stderr or b"").decode("utf-8", errors="replace")
    stdout_text = stdout_buf.decode("utf-8", errors="replace")
    flag_captured = bool(flag_string and flag_string in stdout_text)

    bindings_out: dict[str, Any] = {}
    for k, v in bindings.items():
        if isinstance(v, int):
            bindings_out[k] = {"type": "int", "value": v, "hex": hex(v)}
        elif isinstance(v, (bytes, bytearray)):
            bindings_out[k] = {"type": "bytes",
                               "hex": bytes(v).hex(), "len": len(v)}
        else:
            bindings_out[k] = {"type": "other", "repr": repr(v)}

    return {
        "ok": True,
        "flag_captured": flag_captured,
        "flag_string": flag_string if flag_captured else None,
        "steps_completed": steps_completed,
        "steps_total": len(steps),
        "bindings": bindings_out,
        "recvs": [{"step": r["step"], "text": r["text"][:200]}
                  for r in recvs],
        "target_stdout_tail": stdout_text[-2000:],
        "target_stderr_tail": stderr_text[-2000:],
        "stdout_truncated": stdout_trunc,
        "stderr_truncated": stderr_trunc,
        "stdout_bytes_kept": len(stdout_buf),
        "target_exit": exit_class,
        "wall_seconds": wall,
    }


def _handle_conversation(payload: dict) -> dict:
    """stdin_conversation-shaped RPC verb.

    Mirrors ``tools.py::make_stdin_conversation_handler``'s runtime
    semantics: compose rendering against prior recvs, per-step
    ``then_recv_until`` terminators, optional stdin close, wait for
    exit, exit classification (clean / exit:N / signal:NAME /
    stack_smashing / timeout). Returns the same response shape the
    per-call handler emits so the parent-side fast-path wrapper is
    a drop-in.
    """
    target_argv = payload.get("target_argv")
    if not isinstance(target_argv, list) or not target_argv:
        return {"ok": False, "error": "target_argv must be a non-empty list"}
    sends = payload.get("sends") or []
    if not isinstance(sends, list) or not sends:
        return {"ok": False, "error": "sends must be a non-empty list"}
    try:
        _cap("sends_count", len(sends), _MAX_STEPS, fn=int)
        per_recv_timeout = _cap("per_recv_timeout",
                                payload.get("per_recv_timeout", 2.0),
                                _MAX_PER_RECV_TIMEOUT)
        total_wait_seconds = _cap("total_wait_seconds",
                                  payload.get("total_wait_seconds", 3.0),
                                  _MAX_TOTAL_WAIT_SECONDS)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    close_after = bool(payload.get("close_after", True))

    # Pre-validate each send step's shape so the loop below has
    # simple invariants (raw bytes OR a compose list, plus terminator).
    steps: list = []
    for i, step in enumerate(sends):
        if not isinstance(step, dict):
            return {"ok": False, "error": f"sends[{i}] must be an object"}
        if "compose" in step and "bytes_hex" in step:
            return {"ok": False,
                    "error": f"sends[{i}]: bytes_hex and compose are "
                             "mutually exclusive"}
        if "compose" in step:
            compose = step["compose"]
            if not isinstance(compose, list):
                return {"ok": False,
                        "error": f"sends[{i}].compose must be a list"}
            steps.append((compose, step.get("then_recv_until", "timeout")))
        else:
            hexstr = step.get("bytes_hex", "")
            if not isinstance(hexstr, str):
                return {"ok": False,
                        "error": f"sends[{i}].bytes_hex must be a string"}
            try:
                b = bytes.fromhex(
                    hexstr.replace(" ", "").replace("\n", ""),
                )
            except ValueError as e:
                return {"ok": False,
                        "error": f"sends[{i}].bytes_hex: {e}"}
            if len(b) > _MAX_SEND_BYTES:
                return {"ok": False,
                        "error": (f"sends[{i}] {len(b)} > "
                                  f"{_MAX_SEND_BYTES}")}
            steps.append((b, step.get("then_recv_until", "timeout")))

    recvs: list[bytes] = []
    stdout_buf = b""
    # Cumulative stdout retention budget for the whole request —
    # bounds recvs (returned hex-doubled) and the tail together.
    stdout_budget = _MAX_CAPTURE_BYTES
    stdout_trunc = False
    stderr_trunc = False
    exit_class = "unknown"
    target_stderr = b""
    proc = _spawn_request_target(target_argv)
    t0 = time.monotonic()
    try:
        for i, (send_spec, terminator) in enumerate(steps):
            if isinstance(send_spec, bytes):
                send_bytes = send_spec
            else:
                try:
                    send_bytes = _render_compose(send_spec, recvs)
                except (ValueError, IndexError) as e:
                    return {"ok": False,
                            "error": (f"compose render failed: "
                                      f"{type(e).__name__}: {e}"),
                            "recvs_hex": [r.hex() for r in recvs]}
                if len(send_bytes) > _MAX_SEND_BYTES:
                    return {"ok": False,
                            "error": (f"sends[{i}] rendered "
                                      f"{len(send_bytes)} > "
                                      f"{_MAX_SEND_BYTES}")}
            try:
                proc.stdin.write(send_bytes)
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                # Target already exited — subsequent recv still runs
                # so any tail-of-stdout is captured.
                pass
            got = _recv_until(proc, terminator, per_recv_timeout,
                              max_bytes=stdout_budget)
            stdout_budget -= len(got)
            recvs.append(got)
            stdout_buf += got
        if close_after:
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        tail_stdout, target_stderr, stdout_trunc, stderr_trunc, timed_out = \
            _drain_target(proc, total_wait_seconds, stdout_budget)
        stdout_buf += tail_stdout
        if timed_out:
            exit_class = "timeout"
        else:
            rc = proc.returncode
            if rc == 0:
                exit_class = "clean"
            elif rc is not None and rc < 0:
                try:
                    name = signal.Signals(-rc).name
                except (ValueError, AttributeError):
                    name = f"UNKNOWN({-rc})"
                exit_class = f"signal:{name}"
            else:
                exit_class = f"exit:{rc}"
        if _CANARY_ABORT_SIGNAL in (target_stderr or b""):
            exit_class = "stack_smashing"
    finally:
        _kill_request_group(proc)

    wall = round(time.monotonic() - t0, 3)
    stderr_text = (target_stderr or b"").decode("utf-8", errors="replace")
    return {
        "ok": True,
        "recvs_hex": [r.hex() for r in recvs],
        "target_stdout_hex": stdout_buf.hex(),
        "target_stderr_text_tail": stderr_text[-2000:],
        "stdout_truncated": stdout_trunc,
        "stderr_truncated": stderr_trunc,
        "stdout_bytes_kept": len(stdout_buf),
        "target_exit": exit_class,
        "wall_seconds": wall,
    }


# RPC input caps — bound resource use so a runaway LLM probe spec
# can't OOM the daemon or wedge it for hours. Cap values chosen to
# be well above any legitimate use; anything larger is a
# programming error or an attack.
_MAX_STEPS = 64
_MAX_SEND_BYTES = 512 * 1024   # 512 KiB per send
_MAX_PER_RECV_TIMEOUT = 60.0
_MAX_TOTAL_WAIT_SECONDS = 120.0
_MAX_SPAWN_TIMEOUT = 300.0
_MAX_STDIN_BYTES = 8 * 1024 * 1024   # 8 MiB per spawn stdin
# Ceiling on captured child output the daemon RETAINS, per stream
# (spawn stdout/stderr) or per request (probe/conversation cumulative
# stdout). Output beyond the cap is still read — the child never
# blocks on a full pipe — but discarded, with truncated=true + kept
# byte counts in the result payload so callers can tell. Bounds the
# hex expansion too: a reply frame carries at most two capped streams,
# each hex-doubled (host.py sizes its reply-frame ceiling off this).
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024   # 64 MiB retained per stream


def _cap(name: str, value, ceiling, fn=float):
    v = fn(value)
    if v <= 0:
        msg = f"{name}={v} must be positive"
        raise ValueError(msg)
    if v > ceiling:
        msg = (
            f"{name}={v} exceeds cap {ceiling} — reject to bound "
            f"daemon resource use"
        )
        raise ValueError(msg)
    return v


DISPATCH = {
    "ping": _handle_ping,
    "spawn": _handle_spawn,
    "probe": _handle_probe,
    "conversation": _handle_conversation,
}


def _echo_rid(frame: dict, response: dict) -> dict:
    """Bind a response to its request via the parent-minted id.

    The parent stamps each request with an unguessable ``rid`` and
    rejects any reply that does not echo it — a cheap integrity layer
    on the persistent channel: a peer that somehow gains a write
    handle on the daemon→parent pipe but cannot read the request
    stream cannot mint an acceptable reply, and stale/duplicated
    frames desync loudly instead of silently answering the wrong
    request. Requests without a ``rid`` (older parents) get their
    reply unchanged, so the wire format stays backward-compatible.
    """
    rid = frame.get("rid")
    if rid is not None:
        response = {**response, "rid": rid}
    return response


def _run_one_shot() -> int:
    """Execute exactly one verb, then exit.

    Reads a single JSON request from stdin (one length-prefixed
    frame using the same encoding the persistent path uses),
    dispatches to the same handlers as the persistent loop, writes
    the response to stdout, exits with 0.

    Used as the fallback substrate when the persistent SandboxHost
    can't start (missing landlock/seccomp, cc unavailable, etc.),
    so the per-call and persistent paths share the same DISPATCH
    handlers. One divergence: the persistent loop special-cases
    "close" before dispatch (graceful ok:true exit); "close" is
    meaningless in one-shot mode and falls through to the
    unknown-cmd error (exit 1) here.
    """
    in_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()
    # Same /proc-reopen hardening as the persistent loop: the one-shot
    # channel is the daemon's own stdio, equally reopenable via
    # /proc/<daemon>/fd/{0,1} by a spawned target while it runs.
    if not _set_non_dumpable():
        _log("prctl(PR_SET_DUMPABLE, 0) failed — /proc fd reopen "
             "hardening not engaged")
    try:
        frame = _read_frame(in_fd)
    except Exception as e:  # noqa: BLE001
        _write_frame(out_fd, {"ok": False,
                              "error": (f"read_frame failed: "
                                        f"{type(e).__name__}: {e}")})
        return 1
    if frame is None:
        _write_frame(out_fd, {"ok": False, "error": "empty stdin"})
        return 1
    cmd = frame.get("cmd")
    handler = DISPATCH.get(cmd)
    if handler is None:
        _write_frame(out_fd, _echo_rid(frame, {
            "ok": False, "error": f"unknown cmd {cmd!r}"}))
        return 1
    try:
        response = handler(frame)
    except Exception as e:  # noqa: BLE001
        response = {"ok": False,
                    "error": (f"handler {cmd} raised: "
                              f"{type(e).__name__}: {e}")}
    _write_frame(out_fd, _echo_rid(frame, response))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="raptor-sandbox-host-daemon")
    ap.add_argument("--rpc-in-fd", type=int,
                    help="Inherited pipe fd the daemon reads RPC "
                         "frames FROM (parent → daemon). Parent "
                         "creates the pipe and passes this end via "
                         "pass_fds. Persistent mode.")
    ap.add_argument("--rpc-out-fd", type=int,
                    help="Inherited pipe fd the daemon writes RPC "
                         "frames TO (daemon → parent). Parent "
                         "creates the pipe and passes this end via "
                         "pass_fds. Persistent mode.")
    ap.add_argument("--one-shot", action="store_true",
                    help="Read one RPC frame from stdin, execute, "
                         "write response to stdout, exit. Used by "
                         "the per-call fallback substrate.")
    args = ap.parse_args()

    if args.one_shot:
        return _run_one_shot()

    if args.rpc_in_fd is None or args.rpc_out_fd is None:
        ap.error("--rpc-in-fd and --rpc-out-fd required in "
                 "persistent mode")

    in_fd = args.rpc_in_fd
    out_fd = args.rpc_out_fd
    # Re-arm FD_CLOEXEC on the inherited RPC fds before ANY handler
    # can spawn a target. CLOEXEC was cleared at spawn time only so
    # the fds survive our own exec chain; a target that inherited
    # them could forge daemon→parent frames or read parent requests.
    # Also serves as validation that the fds are actually open.
    for fd in (in_fd, out_fd):
        try:
            os.set_inheritable(fd, False)
        except OSError as e:
            _log(f"rpc fd {fd} is not usable: {e}")
            return 1
    # Before ANY handler can spawn a target: make this process
    # non-dumpable so same-UID non-root processes (targets in
    # particular) cannot reopen the RPC pipe ends via
    # /proc/<daemon>/fd/<n>. See _set_non_dumpable's docstring.
    if not _set_non_dumpable():
        _log("prctl(PR_SET_DUMPABLE, 0) failed — /proc fd reopen "
             "hardening not engaged")
    _log(f"rpc fds inherited pid={os.getpid()} "
         f"in_fd={in_fd} out_fd={out_fd}")

    try:
        while True:
            try:
                frame = _read_frame(in_fd)
            except Exception as e:  # noqa: BLE001
                _log(f"read_frame failed: {type(e).__name__}: {e}")
                return 1
            if frame is None:
                _log("rpc-in EOF — exiting")
                return 0
            cmd = frame.get("cmd")
            if cmd == "close":
                _log("close requested — exiting")
                _write_frame(out_fd, _echo_rid(frame, {"ok": True,
                                                       "closed": True}))
                return 0
            handler = DISPATCH.get(cmd)
            if handler is None:
                _write_frame(out_fd, _echo_rid(frame, {
                    "ok": False, "error": f"unknown cmd {cmd!r}"}))
                continue
            try:
                response = handler(frame)
            except Exception as e:  # noqa: BLE001
                response = {"ok": False,
                            "error": (f"handler {cmd} raised: "
                                      f"{type(e).__name__}: {e}")}
            _write_frame(out_fd, _echo_rid(frame, response))
    finally:
        for fd in (in_fd, out_fd):
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
