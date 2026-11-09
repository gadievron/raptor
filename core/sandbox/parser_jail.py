"""Parent-side manager for the confined request-line parser worker.

The egress proxy (``proxy.py``) never parses raw CONNECT request-line
bytes in-process: it hands them to a long-lived jailed child
(``_parser_jail_child.py``) over a socketpair and consumes a validated
struct back. This module owns that child: spawn, confinement handshake,
the framed round-trip, re-validation of everything the child returns,
crash containment, and respawn with backoff.

Trust model: the child parses HOSTILE bytes, so the child itself is
treated as compromisable — every field of every verdict is re-validated
here (types, lengths, charset, ranges) before the proxy consumes it,
and any protocol deviation (bad frame, id desync, unsolicited output,
field violation) kills the worker and denies the request. The parent never interprets
the raw request-line bytes itself: there is NO inline-parse fallback.
If the worker cannot be spawned and confined, ``get_parser_jail()``
raises and the proxy refuses to serve (fail-closed).

Singleton: one worker per orchestrator process, shared by every
EgressProxy construction (production has one proxy; tests construct
many, and the parse worker carries no per-proxy state — it is a pure
bytes→struct function). Round-trips are mutex-serialised: a parse is
microseconds of CPU plus one socketpair round-trip, CONNECT handshakes
are per-tunnel (never per-byte), so a single serialised worker
outpaces any realistic CONNECT rate; a pool would add correlation and
respawn complexity for no measurable win. The proxy calls
``parse()`` via ``asyncio.to_thread`` so the blocking round-trip never
occupies its event loop.

Degraded floor: on kernels without Landlock the child still gets
rlimits, fd hygiene, a sanitised environment, and process isolation —
but the parent makes that LOUD (one warning per worker generation
here; an audit marker row per sandbox registration in the proxy).
Landlock available-but-failing is not degraded — it is fail-closed
(the child reports the install error and exits; spawn fails).
"""

import atexit
from contextlib import closing
import json
import logging
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from core.security.log_sanitisation import has_nonprintable, sanitise_for_terminal
from core.security.env_sanitisation import strip_env_vars
from core.source.streams import preserving_stream_error

from ._parser_jail_child import FRAME_HEADER, MAX_FRAME_PAYLOAD, READY_FRAME_ID
from ._request_head import CENSUS_VALUES, ParsedRequestLine, ParseRefusal
from .evidence import _unique_evidence_object

logger = logging.getLogger(__name__)

# Confinement handshake budget: interpreter start + package imports +
# the Landlock probe/self-test/install. Sub-second in practice; 10s
# absorbs a loaded host without masking a hung child for long.
_READY_TIMEOUT_S = 10.0
# Per-request round-trip budget. The parse is microseconds; a worker
# that takes longer is wedged or hostile — kill it and deny the
# request. Deliberately far below the child's own RLIMIT_CPU backstop.
_ROUNDTRIP_TIMEOUT_S = 5.0
# Transport slices observe shutdown without resetting the transaction budget.
_IO_WAIT_TICK_S = 0.05
# Respawn backoff for consecutive SPAWN failures (a crash of a
# previously-healthy worker respawns immediately; only failing spawns
# back off). Counter resets on a successful ready handshake.
_SPAWN_BACKOFF_BASE_S = 0.1
_SPAWN_BACKOFF_CAP_S = 5.0
# Verdict re-validation bounds. Hosts come from a ≤4096-byte request
# line so 4096 is a hard ceiling; refusal reasons are short fixed
# strings plus at most an 80-char repr excerpt (~4x escape inflation).
_MAX_HOST_LEN = 4096
_MAX_REASON_LEN = 512
# Refusal-attribution ports carry the out-of-range value by contract
# ("port out of range" events record it), so 1..65535 cannot apply —
# but an honest value is int()-parsed from the ≤4096-byte request
# line, so it can never have more decimal digits than the line cap.
# The frame cap alone would admit nearly twice that.
_MAX_REFUSAL_PORT_MAGNITUDE = 10 ** _MAX_HOST_LEN


class ParserJailError(RuntimeError):
    """Base: the parser jail could not provide a verdict."""


class ParserJailUnavailable(ParserJailError):
    """No confined worker and (re)spawn is failing/backing off.

    The proxy maps this to a 503 + ``parser_unavailable`` audit event —
    requests are refused, never parsed inline.
    """


class _ProtocolError(Exception):
    """Internal: the worker deviated from the wire/verdict contract."""


def _raptor_dir() -> str:
    """Trusted import root of the parent code that owns this worker."""
    return str(Path(__file__).resolve().parents[2])



def _worker_launch(root: str) -> tuple[list[str], dict[str, str]]:
    """Prepare the confined parser's argv and environment in the parent."""
    # Config imports are deliberately lazy: proxy.py imports this manager
    # before it needs a parser process, and configuration is heavyweight.
    from core.config import RaptorConfig

    env = strip_env_vars(RaptorConfig.get_safe_env(), RaptorConfig.TARGET_ENV_STRIP_SET)
    # This child needs code identity, not launcher credentials or dispatch
    # authority. Reintroduce only its loaded parent's resolved import root.
    env.update(RAPTOR_DIR=root, PYTHONPATH=root, PYTHONDONTWRITEBYTECODE="1")
    argv = [sys.executable, "-s"]
    if sys.version_info >= (3, 11):
        argv.append("-P")
    argv += ["-m", "core.sandbox._parser_jail_child"]
    return argv, env


def _validate_host(host: object) -> str:
    """Charset/length re-validation for a child-supplied host field.

    Empty hosts are legitimate parser output (``CONNECT :443``
    extracts host="" and the allowlist gate denies it downstream), so
    only type, length, and printability are enforced here.
    """
    if not isinstance(host, str) or len(host) > _MAX_HOST_LEN:
        raise _ProtocolError("host field violates type/length contract")
    if has_nonprintable(host):
        # The parser refuses non-printable targets before extracting a
        # host, so an honest worker can never produce one — this only
        # fires against a compromised worker.
        raise _ProtocolError("host field carries non-printable characters")
    return host


def _validate_port(port: object, *, accepted: bool) -> int:
    """Type/range re-validation for a child-supplied port field.

    Accepted verdicts must be in 1..65535 (the parser's own accept
    condition). Refusal attribution ports carry the OUT-of-range value
    by contract ("port out of range" events historically record it),
    so the range rule cannot apply there — instead the magnitude is
    bounded to what an honest parse of a line-cap-sized request line
    could have produced: a hostile worker must not be able to stamp an
    audit-event port no request line could carry.
    """
    if isinstance(port, bool) or not isinstance(port, int):
        raise _ProtocolError("port field violates type contract")
    if accepted:
        if not (0 < port < 65536):
            raise _ProtocolError("accepted port out of range")
    elif abs(port) >= _MAX_REFUSAL_PORT_MAGNITUDE:
        raise _ProtocolError("refusal port exceeds line-derived bound")
    return port


def _validate_verdict(payload: bytes) -> "ParsedRequestLine | ParseRefusal":
    """Parse + re-validate one verdict frame from the worker.

    Every field the proxy will consume is checked for type, length,
    charset, and range — the worker parses hostile bytes and is
    assumed compromisable. Raises ``_ProtocolError`` on any deviation.
    """
    try:
        obj = json.loads(payload, object_pairs_hook=_unique_evidence_object)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise _ProtocolError(f"verdict frame is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise _ProtocolError("verdict frame is not a JSON object")
    ok = obj.get("ok")
    if ok is True:
        return ParsedRequestLine(
            host=_validate_host(obj.get("host")),
            port=_validate_port(obj.get("port"), accepted=True),
        )
    if ok is False:
        reason = obj.get("reason")
        if (not isinstance(reason, str) or not reason
                or len(reason) > _MAX_REASON_LEN):
            raise _ProtocolError("reason field violates type/length contract")
        census = obj.get("census")
        if not isinstance(census, str) or census not in CENSUS_VALUES:
            # Strict enum check (missing field included): the census
            # drives the proxy's requests_connect/requests_non_connect
            # counters, so a worker that stops classifying — or stamps
            # an out-of-vocabulary value — is deviating, not degraded.
            raise _ProtocolError("census field violates enum contract")
        host = obj.get("host")
        port = obj.get("port")
        return ParseRefusal(
            # Identity on every reason an honest worker emits (they are
            # printable by construction); defence-in-depth against a
            # compromised worker injecting terminal escapes into logs.
            reason=sanitise_for_terminal(reason),
            host=None if host is None else _validate_host(host),
            port=None if port is None else _validate_port(
                port, accepted=False),
            census=census,
        )
    raise _ProtocolError("ok field violates type contract")


def _socket_io_timeout(deadline, check_cancel):
    if check_cancel is not None:
        check_cancel()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("parser worker frame deadline exceeded")
    return min(remaining, _IO_WAIT_TICK_S) if check_cancel is not None else remaining

def _restore_socket_timeout(sock, timeout):
    primary = sys.exc_info()[1]
    try:
        sock.settimeout(timeout)
    except BaseException:
        if primary is None:
            raise
        # A second close/mode error must not replace request cancellation
        # or the transport failure that already requires worker retirement.

class ParserJail:
    """Owner of one confined parser worker (see module docstring)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: "subprocess.Popen | None" = None
        self._sock: "socket.socket | None" = None
        self._spawn_failures = 0
        self._next_spawn_attempt = 0.0
        # None until the first ready handshake; then the worker's
        # Landlock status. Survives respawns (same kernel) but is
        # refreshed by every ready frame anyway.
        self._landlocked: "bool | None" = None
        self._degraded_warned = False
        self._stopped = False
        # A failed wait does not release ownership. Keep the Popen handle
        # until wait confirms exit, and never reuse its transport or spawn
        # a replacement while cleanup is unresolved.
        self._reap_pending = False

    # ---- public API ----

    @property
    def landlocked(self) -> "bool | None":
        """True/False once a worker has reported in; None before."""
        return self._landlocked

    def start(self) -> None:
        """Spawn + confine the worker now. Raises on failure (fail-closed)."""
        self._check_running()
        if not self._lock.acquire(timeout=_READY_TIMEOUT_S):
            raise ParserJailUnavailable("parser startup queue deadline exceeded")
        try:
            self._ensure_worker_locked()
        finally:
            self._lock.release()

    def parse(self, raw: bytes) -> "ParsedRequestLine | ParseRefusal":
        """One raw request line in, one re-validated verdict out.

        Mutex-serialised — proxy callers wrap it in ``asyncio.to_thread``.
        Queueing and transport share a bounded request deadline. Startup
        and reaping have their own bounded budgets. A busy queue refuses
        without disturbing the worker serving another caller. Raises ``ParserJailUnavailable`` when
        no confined worker can be obtained; returns a ``ParseRefusal``
        (never raises) when the worker dies on or mangles THIS request
        — poison input costs the attacker their request and us one
        respawn, nothing else.
        """
        self._check_running()
        if len(raw) > MAX_FRAME_PAYLOAD:
            # The proxy's read cap (4096) makes this unreachable; keep
            # the reader's refusal semantics rather than a hard error
            # if a future caller widens the cap without widening the
            # frame.
            return ParseRefusal(reason="empty/overlong CONNECT line")
        queued_at = time.monotonic()
        if not self._lock.acquire(timeout=_ROUNDTRIP_TIMEOUT_S):
            # A queued caller owns no worker or transaction; it must not
            # kill the worker currently serving another caller.
            raise ParserJailUnavailable("parser request queue deadline exceeded")
        try:
            remaining = _ROUNDTRIP_TIMEOUT_S - (time.monotonic() - queued_at)
            if remaining <= 0:
                raise ParserJailUnavailable("parser request deadline exceeded before send")
            # Startup/reaping are separately bounded lifecycle operations.
            # Do not charge a cold worker's ready handshake against its
            # first transaction, or replace the transport budget afterward.
            self._ensure_worker_locked()
            deadline = time.monotonic() + remaining
            try:
                return self._roundtrip_locked(raw, deadline=deadline)
            except _ProtocolError as exc:
                # Dispose before reporting: a handler failure/cancellation
                # must not leave a protocol-invalid worker reusable.
                self._kill_worker_locked()
                logger.warning(
                    "parser-jail: worker protocol violation (%s) — "
                    "killed; denying this request and respawning on "
                    "the next", exc,
                )
                return ParseRefusal(
                    reason="request-line parser protocol violation "
                           "(worker respawned)")
            except OSError:
                # Worker died mid-request (poison input, SIGXCPU/AS
                # kill, external kill) or the socket errored. Deny THIS
                # request; the next request respawns.
                self._kill_worker_locked()
                logger.warning(
                    "parser-jail: worker died mid-request — denying "
                    "this request; respawning on the next",
                )
                return ParseRefusal(
                    reason="request-line parser crashed on this input "
                           "(worker respawned)")
            except BaseException:
                # Cancellation or an unexpected parent failure can interrupt
                # send/receive at any byte boundary. That channel cannot be
                # reused for the next request, even if the worker is alive.
                try:
                    self._kill_worker_locked()
                except BaseException:
                    # Keep the original exception primary. An unreaped
                    # worker remains owned and blocks future spawns.
                    logger.error("parser-jail: interrupted request cleanup incomplete")
                raise
        finally:
            self._lock.release()

    def stop(self) -> None:
        """Refuse future spawns and kill/reap the owned worker.

        Raises ParserJailUnavailable if exit cannot be confirmed. The
        process remains owned; a subsequent stop retries its bounded reap.
        """
        # Publish before queueing: the current owner observes this between
        # socket waits; queued requests refuse rather than delaying teardown.
        self._stopped = True
        if not self._lock.acquire(timeout=_READY_TIMEOUT_S):
            raise ParserJailUnavailable("parser stop queue deadline exceeded; cleanup pending")
        try:
            self._kill_worker_locked()
        finally:
            self._lock.release()

    # ---- internals (all require self._lock held) ----

    def _check_running(self) -> None:
        if self._stopped:
            raise ParserJailUnavailable("parser jail is stopped")

    def _ensure_worker_locked(self) -> None:
        self._check_running()
        try:
            worker_alive = self._proc is not None and self._proc.poll() is None
        except OSError:
            logger.warning("parser-jail: worker status check failed; replacing worker",
                           exc_info=True)
            worker_alive = False
        if worker_alive and self._sock is not None and not self._reap_pending:
            return
        self._kill_worker_locked()
        now = time.monotonic()
        if now < self._next_spawn_attempt:
            raise ParserJailUnavailable(
                "parser worker spawn backing off after "
                f"{self._spawn_failures} consecutive failure(s)")
        try:
            self._spawn_worker_locked()
        except ParserJailError:
            if self._stopped:
                raise
            self._spawn_failures += 1
            # Saturate before doing unbounded exponent arithmetic. A
            # persistent outage must keep producing typed refusals even
            # after thousands of failed attempts.
            backoff = min(_SPAWN_BACKOFF_BASE_S, _SPAWN_BACKOFF_CAP_S)
            remaining = self._spawn_failures - 1
            while remaining and 0 < backoff < _SPAWN_BACKOFF_CAP_S:
                backoff = min(backoff * 2, _SPAWN_BACKOFF_CAP_S)
                remaining -= 1
            self._next_spawn_attempt = time.monotonic() + backoff
            raise
        self._spawn_failures = 0
        self._next_spawn_attempt = 0.0

    def _spawn_worker_locked(self) -> None:
        """Spawn one worker and complete the confinement handshake.

        Raises ``ParserJailUnavailable`` on ANY failure — the caller
        never gets a half-confined worker.
        """
        root = _raptor_dir()
        child_argv, env = _worker_launch(root)

        parent_sock = None
        proc = None
        committed = False
        try:
            parent_sock, child_sock = socket.socketpair()
            with preserving_stream_error(closing(child_sock)):
                try:
                    proc = subprocess.Popen(
                        child_argv + [str(child_sock.fileno())],
                        stdin=subprocess.DEVNULL,
                        # Diagnostics travel in the ready frame; stray
                        # child output must never interleave with the
                        # orchestrator's streams. Residual: post-startup
                        # tracebacks are discarded — the parent logs the
                        # exit context instead.
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        close_fds=True,
                        pass_fds=(child_sock.fileno(),),
                        cwd=root,
                        env=env,
                    )
                except OSError as exc:
                    raise ParserJailUnavailable(
                        f"parser worker spawn failed: {exc}") from exc

            parent_sock.settimeout(_READY_TIMEOUT_S)
            try:
                ready = self._read_ready_frame(parent_sock)
            except (_ProtocolError, OSError) as exc:
                # Attribute the worker's fate before the unconditional
                # kill+reap destroys it: a child that died pre-frame (its
                # stderr is /dev/null and no frame ever arrived) is
                # otherwise a bare "closed the socket" with zero forensic
                # signal. EOF usually races the child's _exit by
                # microseconds, so give it a short beat to become
                # reapable; a genuinely wedged child (ready timeout) is
                # still alive and says so.
                status_unknown = False
                try:
                    exit_status: "int | None" = proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    exit_status = None
                except OSError:
                    status_unknown = True
                    exit_status = None
                if status_unknown:
                    exit_note = "worker exit status unavailable"
                elif exit_status is None:
                    exit_note = "worker was still alive; parent killed it"
                elif exit_status < 0:
                    exit_note = f"worker died to signal {-exit_status}"
                else:
                    exit_note = f"worker exited with code {exit_status}"
                raise ParserJailUnavailable(
                    f"parser worker failed confinement handshake: {exc} "
                    f"({exit_note})"
                ) from exc

            if ready.get("ready") is not True:
                err = ready.get("error")
                err_txt = (sanitise_for_terminal(str(err))[:_MAX_REASON_LEN]
                           if err is not None else "no reason reported")
                raise ParserJailUnavailable(
                    f"parser worker refused to confine: {err_txt}")

            rlimits_failed = ready.get("rlimits_failed")
            if rlimits_failed:
                # Child-supplied text: sanitise + bound before logging,
                # same as the refusal-reason treatment above.
                logger.warning(
                    "parser-jail: worker applied its rlimits only "
                    "partially — failed: %s (best-effort per limit; the "
                    "worker still runs with every limit that did apply)",
                    sanitise_for_terminal(str(rlimits_failed))[:_MAX_REASON_LEN],
                )

            landlocked = ready.get("landlock") is True
            self._landlocked = landlocked
            if not landlocked and not self._degraded_warned:
                self._degraded_warned = True
                logger.warning(
                    "parser-jail: worker running WITHOUT Landlock "
                    "confinement (kernel lacks Landlock) — degraded floor: "
                    "rlimits, fd hygiene, sanitised environment, and "
                    "process isolation only",
                )

            self._check_running()
            parent_sock.settimeout(_ROUNDTRIP_TIMEOUT_S)
            self._proc = proc
            self._sock = parent_sock
            committed = True
        except OSError as exc:
            raise ParserJailUnavailable(
                f"parser worker startup failed: {exc}") from exc
        finally:
            if not committed:
                # Publish ownership before any close can be interrupted.
                # One cleanup path owns both uncommitted startup resources
                # and established workers, including a failed/timed-out wait.
                self._proc, self._sock = proc, parent_sock
                self._reap_pending = proc is not None
                try:
                    self._kill_worker_locked()
                except BaseException:
                    # Preserve the startup failure or cancellation while
                    # retaining the only handle to an unconfirmed child.
                    logger.error("parser-jail: startup worker cleanup incomplete")

    def _read_ready_frame(self, sock: socket.socket) -> dict:
        deadline = time.monotonic() + _READY_TIMEOUT_S
        length, frame_id = FRAME_HEADER.unpack(
            self._recv_exact(sock, FRAME_HEADER.size, deadline=deadline,
                             check_cancel=self._check_running))
        if frame_id != READY_FRAME_ID or length > MAX_FRAME_PAYLOAD:
            raise _ProtocolError("malformed ready frame header")
        try:
            obj = json.loads(self._recv_exact(sock, length, deadline=deadline,
                                             check_cancel=self._check_running),
                             object_pairs_hook=_unique_evidence_object)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise _ProtocolError("ready frame is not valid JSON") from exc
        if not isinstance(obj, dict):
            raise _ProtocolError("ready frame is not a JSON object")
        if type(obj.get("ready")) is not bool:
            raise _ProtocolError("ready frame lacks a boolean ready status")
        if obj["ready"]:
            if type(obj.get("landlock")) is not bool:
                raise _ProtocolError("ready frame lacks a boolean landlock status")
            if "rlimits_failed" in obj:
                failures = obj["rlimits_failed"]
                if not isinstance(failures, list) or any(
                    not isinstance(item, str) for item in failures
                ):
                    raise _ProtocolError("ready frame has invalid rlimit failures")
        elif obj.get("error") is not None and not isinstance(obj["error"], str):
            raise _ProtocolError("ready frame has an invalid refusal reason")
        return obj

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int, *, deadline: float,
                    check_cancel=None) -> bytes:
        timeout = sock.gettimeout()
        buf = bytearray()
        try:
            while len(buf) < n:
                sock.settimeout(_socket_io_timeout(deadline, check_cancel))
                try:
                    chunk = sock.recv(n - len(buf))
                except InterruptedError:
                    continue
                except socket.timeout:
                    if check_cancel is None:
                        raise
                    continue
                if not chunk:
                    raise OSError("parser worker closed the socket")
                buf.extend(chunk)
            return bytes(buf)
        finally:
            _restore_socket_timeout(sock, timeout)

    @staticmethod
    def _send_exact(sock: socket.socket, data: bytes, *, deadline: float,
                    check_cancel=None) -> None:
        # sendall timeout does not disclose its sent offset. Retrying it after
        # a cancellation slice would duplicate bytes and desynchronise frames.
        view = memoryview(data)
        while view:
            sock.settimeout(_socket_io_timeout(deadline, check_cancel))
            try:
                sent = sock.send(view)
            except InterruptedError:
                continue
            except socket.timeout:
                if check_cancel is None:
                    raise
                continue
            if sent <= 0:
                raise OSError("parser worker send made no progress")
            view = view[sent:]

    @staticmethod
    def _new_req_id() -> int:
        """One unpredictable 32-bit request id (READY_FRAME_ID excluded).

        Unpredictability is load-bearing: with guessable (e.g. counter)
        ids a hostile worker could answer request N and pre-queue an
        extra frame stamped with the NEXT id, to be consumed as the
        verdict of a future request with no visible protocol violation.
        A random id makes a pre-queued frame's id wrong (2^-32) — and
        the pre-send pending-bytes check below refuses the queued bytes
        outright.
        """
        while True:
            req_id = int.from_bytes(os.urandom(4), "big")
            if req_id != READY_FRAME_ID:
                return req_id

    def _roundtrip_locked(
        self, raw: bytes, *, deadline: float | None = None,
    ) -> "ParsedRequestLine | ParseRefusal":
        sock = self._sock
        assert sock is not None  # _ensure_worker_locked guarantees it
        if deadline is None:
            deadline = time.monotonic() + _ROUNDTRIP_TIMEOUT_S
        timeout = sock.gettimeout()
        try:
            # One deadline covers queueing, sendall, header and payload.
            # A previous socket timeout is not a fresh per-stage budget.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("parser worker request deadline exceeded")
            sock.settimeout(remaining)
            poller = select.poll()
            poller.register(sock, select.POLLIN)
            if poller.poll(0):
                if sock.recv(1, socket.MSG_PEEK):
                    raise _ProtocolError("unsolicited bytes from worker before request")
                raise OSError("parser worker closed the socket")
            req_id = self._new_req_id()
            # Preparing the id/checking readiness also consumes the budget.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("parser worker request deadline exceeded")
            sock.settimeout(remaining)
            self._send_exact(sock, FRAME_HEADER.pack(len(raw), req_id) + raw,
                             deadline=deadline, check_cancel=self._check_running)
            header = self._recv_exact(sock, FRAME_HEADER.size, deadline=deadline,
                             check_cancel=self._check_running)
            length, resp_id = FRAME_HEADER.unpack(header)
            if length > MAX_FRAME_PAYLOAD:
                raise _ProtocolError("oversized verdict frame")
            if resp_id != req_id:
                raise _ProtocolError("verdict frame id desync")
            payload = self._recv_exact(sock, length, deadline=deadline,
                                       check_cancel=self._check_running)
            return _validate_verdict(payload)
        except socket.timeout as exc:
            raise OSError("parser worker round-trip timed out") from exc
        finally:
            _restore_socket_timeout(sock, timeout)

    def _kill_worker_locked(self) -> None:
        sock, proc = self._sock, self._proc
        self._sock = None
        self._reap_pending = proc is not None
        try:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        finally:
            if proc is not None and self._reap_locked(proc) is True:
                self._proc = None
                self._reap_pending = False
        if self._proc is not None:
            raise ParserJailUnavailable("parser worker cleanup is unconfirmed; retry stop")

    @staticmethod
    def _reap_locked(proc: subprocess.Popen) -> bool:
        """Kill + bounded wait; True only when wait confirms child exit.

        Poll/kill errors do not skip wait: exit may race the signal. A
        failed or timed-out wait is not evidence that the child is gone.
        """
        running = True
        try:
            running = proc.poll() is None
        except OSError:
            logger.warning(
                "parser-jail: could not inspect worker pid %d; attempting kill",
                proc.pid, exc_info=True,
            )
        if running:
            try:
                proc.kill()
            except OSError:
                # Still reap if the worker exited during the signal attempt.
                logger.warning(
                    "parser-jail: could not kill worker pid %d",
                    proc.pid, exc_info=True,
                )
        try:
            proc.wait(timeout=_READY_TIMEOUT_S)
            return True
        except OSError:
            logger.error(
                "parser-jail: could not reap worker pid %d",
                proc.pid, exc_info=True,
            )
        except subprocess.TimeoutExpired:
            # A stuck child may not have exited yet. Keep the wait bounded
            # and retain ownership; the caller must not spawn another.
            logger.error(
                "parser-jail: worker pid %d did not reap after "
                "SIGKILL", proc.pid,
            )
        return False


# ---- module-level singleton ----

_jail_lock = threading.Lock()
_jail: "ParserJail | None" = None


def get_parser_jail() -> ParserJail:
    """Return the process-wide parser jail, spawning it on first call.

    Fail-closed: if the worker cannot be spawned AND confined, this
    raises (``ParserJailUnavailable``); the proxy must refuse to serve.
    A later call retries. If a failed startup cannot confirm child exit,
    its singleton stays owned and cannot spawn a replacement until reaped.
    """
    global _jail
    with _jail_lock:
        if _jail is None:
            jail = ParserJail()
            # Register before creating a child. Registration failure then
            # leaves no process behind; failed startup keeps its cleanup
            # registration while a retained child still needs a wait.
            atexit.register(jail.stop)
            _jail = jail
        try:
            _jail.start()
        except BaseException:
            if _jail._proc is None:
                atexit.unregister(_jail.stop)
                _jail = None
            raise
        return _jail


def _reset_for_tests() -> None:
    """Tear down the singleton worker. Test-only."""
    global _jail
    with _jail_lock:
        if _jail is not None:
            _jail.stop()
            atexit.unregister(_jail.stop)
            _jail = None
