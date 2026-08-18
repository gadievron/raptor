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
import json
import os
import re
import select
import struct
import subprocess
import sys
import time
from typing import Any


def _log(msg: str) -> None:
    sys.stderr.write(f"[host-daemon] {msg}\n")
    sys.stderr.flush()


def _read_frame(fd: int) -> dict | None:
    hdr = b""
    while len(hdr) < 4:
        chunk = os.read(fd, 4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    (length,) = struct.unpack("!I", hdr)
    if length > 64 * 1024 * 1024:
        raise ValueError(f"frame too large: {length}")
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
    os.write(fd, hdr + body)


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


def _safe_eval(expr: str, bindings: dict) -> Any:
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        cls_name = type(node).__name__
        if cls_name not in _SAFE_EVAL_NODES:
            raise ValueError(f"disallowed node: {cls_name} in {expr!r}")
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None)
            if fname not in _SAFE_EVAL_CALLABLES:
                raise ValueError(f"disallowed call: {fname!r} in {expr!r}")

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
    return eval(compile(tree, "<compute>", "eval"),
                {"__builtins__": {}}, ns)


def _parse_bytes_to_int(raw: bytes) -> int | None:
    text = raw.decode("utf-8", errors="replace")
    m = re.search(r"0x([0-9a-fA-F]+)", text)
    if m:
        try:
            return int(m.group(1), 16)
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
    from pwn import context, fmtstr_payload  # type: ignore
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
        raise ValueError(f"write_size invalid: {write_size!r}")
    raw_writes = spec.get("writes") or {}
    if not raw_writes:
        raise ValueError("writes dict required")
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
                raise IndexError(
                    f"recv_le64 references recv_index={idx} but only "
                    f"{len(recvs)} recv(s) available"
                )
            raw = recvs[idx].decode("utf-8", errors="replace").strip()
            tok = raw.split()[0] if raw.split() else ""
            tok = tok.removeprefix("0x")
            if not tok:
                raise ValueError(
                    f"recv_le64: recvs[{idx}] is empty after tokenization"
                )
            value = int(tok, 16)
            out += _struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
        else:
            raise ValueError(f"unknown compose chunk kind: {kind!r}")
    return bytes(out)


def _recv_until(proc, terminator, per_recv_timeout: float) -> bytes:
    deadline = time.monotonic() + per_recv_timeout
    buf = b""
    fd = proc.stdout.fileno()

    def _read_bounded(max_bytes: int) -> bytes | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        r, _, _ = select.select([fd], [], [], remaining)
        if not r:
            return None
        # Read the raw fd directly. Popen's default-buffered
        # ``proc.stdout.read1`` pulls a full buffer (8 KiB) from the
        # kernel and returns at most ``max_bytes`` — the remainder sits
        # in the Python-level buffer where select() on the raw fd
        # cannot see it, so the next bounded read stalls a full
        # ``per_recv_timeout`` (or attributes the bytes to the wrong
        # step). Nothing else reads through ``proc.stdout`` until the
        # final ``proc.communicate``, so its buffer stays empty and
        # mixing fd-level reads here is safe.
        return os.read(fd, max_bytes)

    if isinstance(terminator, int):
        want = terminator
        while len(buf) < want:
            chunk = _read_bounded(want - len(buf))
            if chunk is None or not chunk:
                break
            buf += chunk
        return buf
    if terminator == "newline":
        while b"\n" not in buf:
            chunk = _read_bounded(4096)
            if chunk is None or not chunk:
                break
            buf += chunk
        return buf
    while True:
        chunk = _read_bounded(4096)
        if chunk is None or not chunk:
            break
        buf += chunk
    return buf


# --------------------------------------------------------------------
# RPC handlers
# --------------------------------------------------------------------


def _handle_ping(payload: dict) -> dict:
    return {"ok": True, "pong": True, "pid": os.getpid()}


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
        result = subprocess.run(
            argv, input=stdin_bytes, capture_output=True, timeout=timeout,
            check=False,
        )
        return {
            "ok": True,
            "stdout_hex": (result.stdout or b"").hex(),
            "stderr_hex": (result.stderr or b"").hex(),
            "returncode": result.returncode,
            "timed_out": False,
            "wall_seconds": round(time.monotonic() - t0, 3),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": True,
            "stdout_hex": (e.stdout or b"").hex(),
            "stderr_hex": (e.stderr or b"").hex(),
            "returncode": None,
            "timed_out": True,
            "wall_seconds": round(time.monotonic() - t0, 3),
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


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
    steps_completed = 0
    exit_class = "unknown"
    proc = subprocess.Popen(
        target_argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
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
                got = _recv_until(proc, recv_until, per_recv_timeout)
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
        try:
            tail_stdout, target_stderr = proc.communicate(
                timeout=total_wait_seconds,
            )
            stdout_buf += tail_stdout or b""
            rc = proc.returncode
            if rc == 0:
                exit_class = "clean"
            elif rc is not None and rc < 0:
                exit_class = f"signal:{-rc}"
            else:
                exit_class = f"exit:{rc}"
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                tail_stdout, target_stderr = proc.communicate(timeout=1)
                stdout_buf += tail_stdout or b""
            except subprocess.TimeoutExpired:
                target_stderr = b""
            exit_class = "timeout"
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

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
    import signal as _signal

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
    exit_class = "unknown"
    target_stderr = b""
    proc = subprocess.Popen(
        target_argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
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
            got = _recv_until(proc, terminator, per_recv_timeout)
            recvs.append(got)
            stdout_buf += got
        if close_after:
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            tail_stdout, target_stderr = proc.communicate(
                timeout=total_wait_seconds,
            )
            stdout_buf += tail_stdout or b""
            rc = proc.returncode
            if rc == 0:
                exit_class = "clean"
            elif rc is not None and rc < 0:
                try:
                    name = _signal.Signals(-rc).name
                except (ValueError, AttributeError):
                    name = f"UNKNOWN({-rc})"
                exit_class = f"signal:{name}"
            else:
                exit_class = f"exit:{rc}"
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                tail_stdout, target_stderr = proc.communicate(timeout=1)
                stdout_buf += tail_stdout or b""
            except subprocess.TimeoutExpired:
                target_stderr = b""
            exit_class = "timeout"
        if _CANARY_ABORT_SIGNAL in (target_stderr or b""):
            exit_class = "stack_smashing"
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    wall = round(time.monotonic() - t0, 3)
    stderr_text = (target_stderr or b"").decode("utf-8", errors="replace")
    return {
        "ok": True,
        "recvs_hex": [r.hex() for r in recvs],
        "target_stdout_hex": stdout_buf.hex(),
        "target_stderr_text_tail": stderr_text[-2000:],
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


def _cap(name: str, value, ceiling, fn=float):
    v = fn(value)
    if v <= 0:
        raise ValueError(
            f"{name}={v} must be positive"
        )
    if v > ceiling:
        raise ValueError(
            f"{name}={v} exceeds cap {ceiling} — reject to bound "
            f"daemon resource use"
        )
    return v


DISPATCH = {
    "ping": _handle_ping,
    "spawn": _handle_spawn,
    "probe": _handle_probe,
    "conversation": _handle_conversation,
}


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
        _write_frame(out_fd, {"ok": False,
                              "error": f"unknown cmd {cmd!r}"})
        return 1
    try:
        response = handler(frame)
    except Exception as e:  # noqa: BLE001
        response = {"ok": False,
                    "error": (f"handler {cmd} raised: "
                              f"{type(e).__name__}: {e}")}
    _write_frame(out_fd, response)
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
                _write_frame(out_fd, {"ok": True, "closed": True})
                return 0
            handler = DISPATCH.get(cmd)
            if handler is None:
                _write_frame(out_fd, {"ok": False,
                                      "error": f"unknown cmd {cmd!r}"})
                continue
            try:
                response = handler(frame)
            except Exception as e:  # noqa: BLE001
                response = {"ok": False,
                            "error": (f"handler {cmd} raised: "
                                      f"{type(e).__name__}: {e}")}
            _write_frame(out_fd, response)
    finally:
        for fd in (in_fd, out_fd):
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
