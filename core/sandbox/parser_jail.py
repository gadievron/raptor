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

from ._parser_jail_child import FRAME_HEADER, MAX_FRAME_PAYLOAD, READY_FRAME_ID
from ._request_head import CENSUS_VALUES, ParsedRequestLine, ParseRefusal

logger = logging.getLogger(__name__)

# Confinement handshake budget: interpreter start + package imports +
# the Landlock probe/self-test/install. Sub-second in practice; 10s
# absorbs a loaded host without masking a hung child for long.
_READY_TIMEOUT_S = 10.0
# Per-request round-trip budget. The parse is microseconds; a worker
# that takes longer is wedged or hostile — kill it and deny the
# request. Deliberately far below the child's own RLIMIT_CPU backstop.
_ROUNDTRIP_TIMEOUT_S = 5.0
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
    """Import root for the child's PYTHONPATH.

    PYTHONPATH-to-child is sys.path-equivalent injection, so the
    path-safety doctrine applies: RAPTOR_DIR is authoritative. The
    Path(__file__) fallback is the same BLESSED doctrine exception as
    the landlock-audit tracer spawn: this lane must stay usable as a
    library (bare callers without the launcher), and a hard KeyError
    would kill runs the fallback serves correctly on single-checkout
    hosts — but on a multi-checkout host it silently steers the worker
    to whichever tree this module sits in, so the ambiguity is
    surfaced loudly instead of guessed silently.
    """
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir is None:
        raptor_dir = str(Path(__file__).resolve().parents[2])
        logger.warning(
            "parser-jail: RAPTOR_DIR unset — worker will import from "
            "the tree containing this module (%s); on multi-checkout "
            "hosts export RAPTOR_DIR to pin the intended tree",
            raptor_dir,
        )
    return raptor_dir


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
        obj = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
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
        if census not in CENSUS_VALUES:
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

    # ---- public API ----

    @property
    def landlocked(self) -> "bool | None":
        """True/False once a worker has reported in; None before."""
        return self._landlocked

    def start(self) -> None:
        """Spawn + confine the worker now. Raises on failure (fail-closed)."""
        with self._lock:
            self._ensure_worker_locked()

    def parse(self, raw: bytes) -> "ParsedRequestLine | ParseRefusal":
        """One raw request line in, one re-validated verdict out.

        Blocking (mutex-serialised round-trip) — proxy callers wrap it
        in ``asyncio.to_thread``. Raises ``ParserJailUnavailable`` when
        no confined worker can be obtained; returns a ``ParseRefusal``
        (never raises) when the worker dies on or mangles THIS request
        — poison input costs the attacker their request and us one
        respawn, nothing else.
        """
        if len(raw) > MAX_FRAME_PAYLOAD:
            # The proxy's read cap (4096) makes this unreachable; keep
            # the reader's refusal semantics rather than a hard error
            # if a future caller widens the cap without widening the
            # frame.
            return ParseRefusal(reason="empty/overlong CONNECT line")
        with self._lock:
            self._ensure_worker_locked()
            try:
                return self._roundtrip_locked(raw)
            except _ProtocolError as exc:
                logger.warning(
                    "parser-jail: worker protocol violation (%s) — "
                    "killed; denying this request and respawning on "
                    "the next", exc,
                )
                self._kill_worker_locked()
                return ParseRefusal(
                    reason="request-line parser protocol violation "
                           "(worker respawned)")
            except OSError:
                # Worker died mid-request (poison input, SIGXCPU/AS
                # kill, external kill) or the socket errored. Deny THIS
                # request; the next request respawns.
                logger.warning(
                    "parser-jail: worker died mid-request — denying "
                    "this request; respawning on the next",
                )
                self._kill_worker_locked()
                return ParseRefusal(
                    reason="request-line parser crashed on this input "
                           "(worker respawned)")

    def stop(self) -> None:
        """Kill the worker and refuse further spawns (atexit/teardown)."""
        with self._lock:
            self._stopped = True
            self._kill_worker_locked()

    # ---- internals (all require self._lock held) ----

    def _ensure_worker_locked(self) -> None:
        if self._stopped:
            raise ParserJailUnavailable("parser jail is stopped")
        if (self._proc is not None and self._proc.poll() is None
                and self._sock is not None):
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
            self._spawn_failures += 1
            backoff = min(
                _SPAWN_BACKOFF_BASE_S * (2 ** (self._spawn_failures - 1)),
                _SPAWN_BACKOFF_CAP_S)
            self._next_spawn_attempt = time.monotonic() + backoff
            raise
        self._spawn_failures = 0
        self._next_spawn_attempt = 0.0

    def _spawn_worker_locked(self) -> None:
        """Spawn one worker and complete the confinement handshake.

        Raises ``ParserJailUnavailable`` on ANY failure — the caller
        never gets a half-confined worker.
        """
        # Lazy import: config is heavyweight and proxy.py imports this
        # module at module level (same precedent as the other sandbox
        # modules' function-local RaptorConfig imports).
        from core.config import RaptorConfig

        env = RaptorConfig.get_safe_env()
        env["PYTHONPATH"] = _raptor_dir()
        # Belt-and-braces with the child's RLIMIT_FSIZE=0: imports must
        # not attempt .pyc writes in the first place.
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # The child runs `python -m`, which puts its cwd at sys.path[0]
        # AHEAD of PYTHONPATH — an attacker-influenced inherited cwd
        # could then supply a planted `core/` tree that imports (in the
        # worker, BEFORE self-confinement) instead of the pinned one.
        # Two belts: run the child WITH cwd pinned to the import root,
        # and (Python >= 3.11) `-P`, which removes the cwd sys.path
        # entry entirely.
        child_argv = [sys.executable]
        if sys.version_info >= (3, 11):
            child_argv.append("-P")
        child_argv += ["-m", "core.sandbox._parser_jail_child"]

        parent_sock, child_sock = socket.socketpair()
        try:
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
                    cwd=_raptor_dir(),
                    env=env,
                )
            except OSError as exc:
                raise ParserJailUnavailable(
                    f"parser worker spawn failed: {exc}") from exc
        finally:
            child_sock.close()

        parent_sock.settimeout(_READY_TIMEOUT_S)
        try:
            ready = self._read_ready_frame(parent_sock)
        except (_ProtocolError, OSError) as exc:
            parent_sock.close()
            self._reap_locked(proc)
            raise ParserJailUnavailable(
                f"parser worker failed confinement handshake: {exc}"
            ) from exc

        if ready.get("ready") is not True:
            err = ready.get("error")
            err_txt = (sanitise_for_terminal(str(err))[:_MAX_REASON_LEN]
                       if err is not None else "no reason reported")
            parent_sock.close()
            self._reap_locked(proc)
            raise ParserJailUnavailable(
                f"parser worker refused to confine: {err_txt}")

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

        parent_sock.settimeout(_ROUNDTRIP_TIMEOUT_S)
        self._proc = proc
        self._sock = parent_sock

    def _read_ready_frame(self, sock: socket.socket) -> dict:
        length, frame_id = FRAME_HEADER.unpack(
            self._recv_exact(sock, FRAME_HEADER.size))
        if frame_id != READY_FRAME_ID or length > MAX_FRAME_PAYLOAD:
            raise _ProtocolError("malformed ready frame header")
        try:
            obj = json.loads(self._recv_exact(sock, length))
        except (ValueError, UnicodeDecodeError) as exc:
            raise _ProtocolError("ready frame is not valid JSON") from exc
        if not isinstance(obj, dict):
            raise _ProtocolError("ready frame is not a JSON object")
        return obj

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("parser worker closed the socket")
            buf += chunk
        return buf

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

    def _roundtrip_locked(self, raw: bytes) -> "ParsedRequestLine | ParseRefusal":
        sock = self._sock
        assert sock is not None  # _ensure_worker_locked guarantees it
        # Belt two against queued-frame desync: the socket must be
        # SILENT before a request is sent — one frame in, one frame
        # out. Any already-buffered bytes are unsolicited worker output
        # (a pre-queued frame or stream garbage): kill, deny, respawn.
        # Zero-timeout readability probe, then a peek to distinguish
        # data from EOF (a worker that died between requests).
        readable, _, _ = select.select([sock], [], [], 0)
        if readable:
            if sock.recv(1, socket.MSG_PEEK):
                raise _ProtocolError(
                    "unsolicited bytes from worker before request")
            raise OSError("parser worker closed the socket")
        req_id = self._new_req_id()
        try:
            sock.sendall(FRAME_HEADER.pack(len(raw), req_id) + raw)
            header = self._recv_exact(sock, FRAME_HEADER.size)
        except socket.timeout as exc:
            # Wedged worker: kill via the OSError path in parse().
            raise OSError("parser worker round-trip timed out") from exc
        length, resp_id = FRAME_HEADER.unpack(header)
        if length > MAX_FRAME_PAYLOAD:
            raise _ProtocolError("oversized verdict frame")
        if resp_id != req_id:
            # Desync: a response for some other request means the
            # correlation is gone — nothing further from this worker
            # can be attributed safely.
            raise _ProtocolError("verdict frame id desync")
        try:
            payload = self._recv_exact(sock, length)
        except socket.timeout as exc:
            raise OSError("parser worker round-trip timed out") from exc
        return _validate_verdict(payload)

    def _kill_worker_locked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._proc is not None:
            self._reap_locked(self._proc)
            self._proc = None

    @staticmethod
    def _reap_locked(proc: subprocess.Popen) -> None:
        """Kill + wait one worker we spawned (verified-pid: our handle)."""
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=_READY_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            # SIGKILL is unblockable; a non-reaped zombie here means
            # the host is in serious trouble — log and move on rather
            # than wedging the proxy behind a wait.
            logger.error(
                "parser-jail: worker pid %d did not reap after "
                "SIGKILL", proc.pid,
            )


# ---- module-level singleton ----

_jail_lock = threading.Lock()
_jail: "ParserJail | None" = None


def get_parser_jail() -> ParserJail:
    """Return the process-wide parser jail, spawning it on first call.

    Fail-closed: if the worker cannot be spawned AND confined, this
    raises (``ParserJailUnavailable``) and no singleton is installed —
    the caller (EgressProxy construction) must refuse to serve. A later
    call retries from scratch.
    """
    global _jail
    with _jail_lock:
        if _jail is None:
            jail = ParserJail()
            jail.start()  # raises on failure — nothing half-installed
            atexit.register(jail.stop)
            _jail = jail
        return _jail


def _reset_for_tests() -> None:
    """Tear down the singleton worker. Test-only."""
    global _jail
    with _jail_lock:
        if _jail is not None:
            atexit.unregister(_jail.stop)
            _jail.stop()
            _jail = None
