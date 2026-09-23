"""Persistent Joern server lifecycle — shared across RAPTOR runs.

Replaces the start-per-run / stop-per-run pattern (30-120s JVM boot
each time) with a refcounted singleton.  First ``joern_acquire()``
starts the server; subsequent acquires increment the refcount and
return a client connected to the existing server.  Each
``joern_release()`` decrements; when the refcount hits zero the
server is stopped.

State is stored in ``~/.cache/raptor/joern-server.json`` and
protected by ``fcntl.flock`` for safe concurrent access.  The file
carries the server's per-boot HTTP Basic credential so later runs can
authenticate against the reused server, plus (on the strong isolation
tier) the unix-socket path through which the private-netns server is
reached; it is created (and rewritten) with mode 0600, and legacy
state files are re-chmodded on load.

Usage::

    server = joern_acquire(tunables)
    if server is not None:
        try:
            server.import_cpg(cpg_path)
            result = server.query("cpg.method.l")
        finally:
            joern_release()

Or as a context manager::

    with joern_session(tunables) as server:
        if server is not None:
            ...
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import signal
import time
import uuid
from pathlib import Path
from typing import Any

from .server import JoernServer
from .tunables import JoernTunables

logger = logging.getLogger(__name__)

_STATE_DIR = Path.home() / ".cache" / "raptor"
_STATE_FILE = _STATE_DIR / "joern-server.json"
_LOCK_FILE = _STATE_DIR / "joern-server.lock"

# SIGTERM grace for ``_kill_server``: how long the whole recorded
# server tree gets to exit before SIGKILL escalation. Module-level so
# tests exercising the escalation ladder against stand-in children can
# shrink it; production keeps the 5s a multi-GB JVM's orderly shutdown
# needs.
_KILL_GRACE_S = 5.0

# Staleness horizon for an UNREFERENCED server (see joern_acquire).
# Trade-off, both directions: lower and a warm multi-GB JVM gets
# recycled between closely-spaced runs, re-paying the 30-120s boot
# plus CPG re-import; higher and a server whose state file carries a
# leaked refcount (crashed session that never released) squats on
# multi-GB of RAM for longer before an operator notices. 8h ≈ longer
# than any inter-run gap in a working day, shorter than "forgotten
# overnight". The recycle NEVER applies while refcount > 0 — audit
# runs routinely exceed 8h, and killing a referenced server SIGKILLs
# a JVM another session is mid-query on.
_STALE_THRESHOLD_S = 3600 * 8


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _pid_running(pid: int) -> bool:
    """Alive AND not a zombie.

    A killed process awaiting its parent's reap still answers the
    ``kill(pid, 0)`` probe but holds no memory and needs no further
    signal — the same distinction ``_pgid_alive`` draws for whole
    groups. Only meaningful where procfs exists; the member-anchor
    path that consumes this has already required a readable
    ``/proc/<pid>/stat``.
    """
    if not _pid_alive(pid):
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(
            encoding="ascii", errors="replace",
        )
    except OSError:
        return False
    fields = stat.rsplit(")", 1)[-1].split()
    return bool(fields) and fields[0] != "Z"


def _read_comm(pid: int) -> str | None:
    """Best-effort /proc/<pid>/comm read (None off-Linux or on error)."""
    try:
        return Path(f"/proc/{pid}/comm").read_text(
            encoding="utf-8", errors="replace"
        ).strip()
    except OSError:
        return None


def _pid_is_our_server(state: dict[str, Any]) -> bool:
    """True only if state's pid is alive AND still the process we started.

    The pid comes from an on-disk state file that can outlive the
    server by hours; a reused pid would otherwise receive our
    SIGTERM/SIGKILL (this has bitten operator screen sessions).
    Same pid-reuse defence as core.run.metadata._pid_alive.
    """
    pid = state.get("pid")
    if not pid or not _pid_alive(pid):
        return False
    comm = _read_comm(pid)
    if comm is None:
        # Off-Linux / no procfs — accept the residual reuse risk.
        return True
    expected = state.get("comm")
    if expected:
        return comm == expected
    # Older state file without a recorded comm: require a JVM-shaped
    # process (the joern launcher execs java; comm may also be the
    # launcher script name during early boot).
    return "java" in comm.lower() or "joern" in comm.lower()


def _member_anchor_fields(srv: JoernServer) -> dict[str, Any]:
    """State-file JVM-member anchor fields from a server handle.

    Shape-guarded at the write side: handles reach here from tests
    (mocks whose attribute reads return non-ints) and from lifecycle
    reuse (class-default None) — only a plausible ``(pid, starttime)``
    pair is persisted; anything else records the absence explicitly so
    ``_kill_recorded_member`` declines instead of chasing garbage.
    """
    pid = getattr(srv, "_member_pid", None)
    starttime = getattr(srv, "_member_starttime", None)
    comm = getattr(srv, "_member_comm", None)
    if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
            or not isinstance(starttime, int) or isinstance(starttime, bool)
            or starttime < 0):
        return {
            "member_pid": None,
            "member_starttime": None,
            "member_comm": None,
        }
    return {
        "member_pid": pid,
        "member_starttime": starttime,
        "member_comm": comm if isinstance(comm, str) else None,
    }


def _read_state(_lock_fd: int) -> dict[str, Any] | None:
    if not _STATE_FILE.exists():
        return None
    # The state file carries the server credential; tighten legacy
    # files that predate the 0600 write path.
    with contextlib.suppress(OSError):
        _STATE_FILE.chmod(0o600)
    from core.json import load_json
    return load_json(_STATE_FILE, max_bytes=1024 * 1024)


def _write_state(_lock_fd: int, state: dict[str, Any]) -> None:
    # 0600 from creation — the file carries the server credential.
    # save_json installs the mode on its tempfile before the rename
    # publishes it, so the credential is never readable in transit.
    from core.json import save_json
    save_json(_STATE_FILE, state, mode=0o600)


def _remove_state(_lock_fd: int) -> None:
    try:
        _STATE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


@contextlib.contextmanager
def _locked():
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(_LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _health_check(
    port: int,
    auth_headers: dict[str, str] | None = None,
    socket_path: str | None = None,
) -> bool:
    payload = json.dumps({"query": "1+1"}).encode("utf-8")
    headers = {"Content-Type": "application/json", **(auth_headers or {})}

    if socket_path is not None:
        # Strong tier: the server's TCP port only exists inside its
        # private network namespace — dial the forwarder's unix socket.
        from http.client import HTTPException

        from .server import _UnixHTTPConnection

        conn = _UnixHTTPConnection(socket_path, timeout=5)
        try:
            conn.request("POST", "/query-sync", body=payload,
                         headers=headers)
            data = json.loads(conn.getresponse().read().decode("utf-8"))
            return data.get("success", False) is not False
        except (OSError, HTTPException, json.JSONDecodeError, ValueError):
            return False
        finally:
            conn.close()

    from urllib.error import URLError
    from urllib.request import Request

    from .server import _NO_PROXY_OPENER

    url = f"http://127.0.0.1:{port}/query-sync"
    req = Request(url, data=payload, headers=headers, method="POST")
    try:
        with _NO_PROXY_OPENER.open(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("success", False) is not False
    except (URLError, OSError, json.JSONDecodeError, TimeoutError):
        return False


def _connect_existing(state: dict[str, Any]) -> JoernServer | None:
    port = state.get("port")
    pid = state.get("pid")
    if not port or not pid:
        return None

    auth_user = state.get("auth_user")
    auth_password = state.get("auth_password")
    if not auth_user or not auth_password:
        # State written before server auth existed — the running
        # server is unauthenticated. Refuse to reuse it; the caller
        # kills it and starts a fresh, authenticated one.
        logger.info(
            "joern lifecycle: state has no auth credential — "
            "recycling pre-auth server (pid %s)", pid,
        )
        return None

    if not _pid_alive(pid):
        logger.info("joern lifecycle: stale PID %d — server is dead", pid)
        return None

    socket_path = state.get("socket_path")
    if socket_path and not os.path.exists(socket_path):
        # Strong-tier server whose unix socket vanished (e.g. a tmp
        # cleaner) — unreachable even if the process is alive.
        logger.info(
            "joern lifecycle: unix socket %s is gone — recycling",
            socket_path,
        )
        return None

    # Proper constructor path — the previous ``__new__`` + field-copy
    # here silently drifted from ``__init__`` every time a field was
    # added (``_restarting`` once, then ``_flow_semantics`` /
    # ``_last_import_timeout``), each omission an AttributeError on
    # some method of the reused handle. ``connect_existing`` runs
    # ``__init__`` so new fields get their defaults automatically.
    srv = JoernServer.connect_existing(
        port=port,
        auth_user=auth_user,
        auth_password=auth_password,
        heap_mb=state.get("heap_mb"),
        query_timeout_s=state.get("query_timeout_s", 300),
        socket_path=socket_path,
    )

    if not _health_check(port, srv._auth_headers(), socket_path):
        logger.info("joern lifecycle: PID %d alive but server unhealthy", pid)
        return None

    return srv


def joern_acquire(tunables: JoernTunables | None = None) -> JoernServer | None:
    """Acquire a shared Joern server, starting one if needed.

    Returns a connected JoernServer or None if Joern is unavailable.
    The caller MUST call ``joern_release()`` when done (or use
    ``joern_session()`` as a context manager).
    """
    if tunables is None:
        tunables = JoernTunables()

    with _locked() as fd:
        state = _read_state(fd)

        if state is not None:
            started_at = state.get("started_at", 0)
            if time.time() - started_at > _STALE_THRESHOLD_S:
                # Staleness recycle only at refcount zero. A live
                # refcount means another session acquired this server
                # and may be mid-query — an audit run routinely
                # exceeds 8h, and killing its JVM here loses that
                # window's taint evidence and lets two sessions
                # leapfrog-kill each other's servers. Referenced
                # servers are retired by joern_release at refcount
                # zero (or by the health check below once dead); a
                # leaked refcount from a crashed session keeps the
                # server alive until then — the documented cost of
                # never killing a server in use (see the threshold
                # comment above).
                if state.get("refcount", 0) <= 0:
                    logger.info(
                        "joern lifecycle: unreferenced server older "
                        "than %ds — recycling", _STALE_THRESHOLD_S)
                    _kill_server(state)
                    _remove_state(fd)
                    state = None
                else:
                    logger.info(
                        "joern lifecycle: server older than %ds but "
                        "refcount=%d — leaving it running",
                        _STALE_THRESHOLD_S, state.get("refcount", 0))

        if state is not None:
            srv = _connect_existing(state)
            if srv is not None:
                if (tunables.heap_mb and state.get("heap_mb")
                        and tunables.heap_mb > state["heap_mb"]):
                    logger.warning(
                        "joern lifecycle: requested %dMB heap but existing "
                        "server has %dMB — reusing (stop and restart for "
                        "larger heap)",
                        tunables.heap_mb, state["heap_mb"],
                    )
                state["refcount"] = state.get("refcount", 0) + 1
                # Lineage token: joern_release(token=...) decrements
                # only when the state still records THIS lineage — a
                # concurrent kill-and-replace by another session must
                # not have its fresh server decremented (and killed at
                # zero) by our bookkeeping. Legacy states are upgraded
                # in place.
                if not state.get("boot_nonce"):
                    state["boot_nonce"] = uuid.uuid4().hex
                srv._lifecycle_token = state["boot_nonce"]
                _write_state(fd, state)
                logger.info(
                    "joern lifecycle: reusing server on port %d "
                    "(refcount=%d)",
                    state["port"], state["refcount"],
                )
                return srv

            _kill_server(state)
            _remove_state(fd)

        srv = _start_fresh(tunables)
        if srv is None:
            return None

        new_state = {
            "pid": srv.pid,
            "comm": _read_comm(srv.pid),
            "port": srv.port,
            "heap_mb": tunables.heap_mb,
            "query_timeout_s": tunables.query_timeout_s,
            "refcount": 1,
            "started_at": time.time(),
            # Lineage identity for this server (restart() replacements
            # included — note_server_replaced preserves it). Handed to
            # the acquirer as srv._lifecycle_token; joern_release
            # matches it before touching the record.
            "boot_nonce": uuid.uuid4().hex,
            # Per-boot HTTP Basic credential — required to reconnect
            # to the reused server. The state file is mode 0600.
            "auth_user": srv._auth_user,
            "auth_password": srv._auth_password,
            # Strong tier: unix socket through which the private-netns
            # server is reached (None on the TCP fallback tier).
            "socket_path": srv._uds_path,
            # JVM MEMBER identity anchor (pid + /proc starttime +
            # comm), derived at boot: lets _kill_server reap the JVM
            # after the group leader died mid-stop. Nones when boot
            # could not derive it unambiguously (fail-safe).
            **_member_anchor_fields(srv),
        }
        srv._lifecycle_token = new_state["boot_nonce"]
        _write_state(fd, new_state)
        logger.info(
            "joern lifecycle: started fresh server on port %d (pid %d)",
            srv.port, srv.pid,
        )
        return srv


def joern_release(
    token: str | None = None,
    srv: JoernServer | None = None,
) -> None:
    """Release one reference to the shared Joern server.

    When the refcount reaches zero, the server is stopped.

    ``token`` is the lineage token ``joern_acquire`` attached to the
    handle (``srv._lifecycle_token``). Release used to decrement —
    and kill at zero — WHATEVER the state file recorded: after a
    restart + concurrent-acquire interleaving (this session's server
    replaced mid-restart by another session's fresh one), that killed
    the OTHER session's live server mid-query while this session's
    replacement JVM leaked untracked. With a token, the record is
    only touched when it still belongs to this lineage; on mismatch
    the caller's own untracked handle (``srv``) is stopped directly —
    its per-boot credential was never written to the state file, so
    no other session can be using it. ``token=None`` keeps the legacy
    unverified behaviour for out-of-tree callers.
    """
    with _locked() as fd:
        state = _read_state(fd)
        recorded_nonce = state.get("boot_nonce") if state else None
        if token is not None and (state is None or recorded_nonce != token):
            logger.warning(
                "joern lifecycle: state no longer records this "
                "session's server lineage (replaced by a concurrent "
                "session?) — leaving the recorded server alone and "
                "stopping this session's untracked handle directly",
            )
            if srv is not None:
                with contextlib.suppress(Exception):
                    srv.stop()
            return
        if state is None:
            return

        rc = max(0, state.get("refcount", 1) - 1)
        if rc == 0:
            logger.info("joern lifecycle: last release — stopping server")
            _kill_server(state)
            _remove_state(fd)
        else:
            state["refcount"] = rc
            _write_state(fd, state)
            logger.info("joern lifecycle: released (refcount=%d)", rc)


def joern_cleanup() -> None:
    """Remove stale state if the server process is dead.

    Safe to call from any context (e.g. a crash handler).
    """
    with _locked() as fd:
        state = _read_state(fd)
        if state is None:
            return
        pid = state.get("pid")
        if pid and not _pid_alive(pid):
            logger.info("joern lifecycle: cleanup — PID %d is dead", pid)
            # A dead leader can leave the JVM MEMBER orphaned (TERM
            # landed mid-stop: the leader/forwarder exited, the JVM
            # wedged in its shutdown hook). Dropping the state file
            # here used to discard the boot-time member anchor — the
            # only identity that could still reap that JVM. Attempt
            # the anchored reap first; it refuses safely on identity
            # mismatch or an absent anchor (old state files), which
            # keeps the pre-anchor behaviour.
            if _kill_recorded_member(state):
                logger.info(
                    "joern lifecycle: cleanup reaped the orphaned JVM "
                    "member before dropping state",
                )
            else:
                logger.info(
                    "joern lifecycle: cleanup — no verified member to "
                    "reap (dead, absent anchor, or identity mismatch)",
                )
            _remove_state(fd)


@contextlib.contextmanager
def shared_joern_session(tunables: JoernTunables | None = None):
    """Context manager wrapping acquire/release of the SHARED server.

    Distinct name on purpose: ``packages.joern.joern_session`` boots a
    PRIVATE server (plus CPG build/import) and stops it on exit, while
    this one joins the refcounted singleton and only decrements on
    exit. The two used to share the name ``joern_session``, so a
    caller switching import paths silently swapped server lifetime
    semantics (per-call JVM boot vs shared reuse).
    """
    srv = joern_acquire(tunables)
    try:
        yield srv
    finally:
        if srv is not None:
            joern_release(
                token=getattr(srv, "_lifecycle_token", None), srv=srv,
            )


#: Compatibility alias for the pre-rename import path — prefer
#: :func:`shared_joern_session` (see its docstring for why the name
#: collision with the package-root ``joern_session`` was a trap).
joern_session = shared_joern_session


def _start_fresh(tunables: JoernTunables) -> JoernServer | None:
    try:
        srv = JoernServer.from_tunables(tunables)
        srv.start()
        return srv
    except Exception:
        logger.debug("joern lifecycle: failed to start server", exc_info=True)
        return None


def _signal_server(pid: int, sig: int) -> None:
    """Signal the server's whole process group when we can.

    The joern launcher is a shell wrapper whose JVM child survives a
    plain ``kill(pid)`` — the server was started with
    ``start_new_session=True`` precisely so the group can be
    signalled (``JoernServer.stop()`` does the same). Only ``killpg``
    when the pid leads its own group; anything else means the pid was
    reused and the group is not ours to signal.
    """
    try:
        if os.getpgid(pid) == pid:
            os.killpg(pid, sig)
            return
    except (ProcessLookupError, PermissionError, OSError):
        pass
    os.kill(pid, sig)


def _kill_server(state: dict[str, Any]) -> bool:
    """Kill the recorded server tree. Returns True when a kill was
    actually dispatched; False when the record was empty or the
    pid-reuse comm gate refused (nothing verified ours to signal)."""
    pid = state.get("pid")
    if not pid:
        return False
    if not _pid_is_our_server(state):
        # The leader is dead (or its pid was recycled): there is no
        # live leader identity to anchor a group kill on, and an
        # unverified pgid is not ours to signal (pid-reuse class). A
        # hard kill landing mid-stop produces exactly this state —
        # TERM delivered, the forwarder exits, the JVM wedges in its
        # shutdown hook and is orphaned. Fall back to the boot-time
        # JVM MEMBER anchor, whose /proc starttime proves identity
        # without a live leader.
        return _kill_recorded_member(state)
    # Capture the group BEFORE any signal, while the leader is still
    # verified ours: on the strong tier the leader is only the netns
    # forwarder, and it can die (and stop being resolvable via
    # ``getpgid``) during the grace window while the JVM member
    # survives in the same group. The group id cannot be recycled
    # while any member holds it, so a pgid captured here stays ours
    # for as long as there is anything left to kill. Never our own
    # group (a corrupt state file must not kill the caller's session).
    from .server import _ensure_group_dead, _pgid_alive
    pgid: int | None = None
    try:
        if os.getpgid(pid) == pid and pid != os.getpgrp():
            pgid = pid
    except OSError:
        pgid = None
    try:
        _signal_server(pid, signal.SIGTERM)
        deadline = time.monotonic() + _KILL_GRACE_S
        while time.monotonic() < deadline:
            # Leader-only liveness let the grace loop declare victory
            # while the JVM member lived on — require the whole tree
            # dead.
            if not _pid_alive(pid) and not _pgid_alive(pgid):
                _remove_socket_dir(state)
                return True
            time.sleep(0.5)
        # Re-verify before SIGKILL: the pid may have died and been
        # reused during the grace window — but surviving group
        # MEMBERS still escalate (they are the multi-GB JVM this
        # exists to kill; the captured pgid is pinned by them).
        if _pid_is_our_server(state):
            _signal_server(pid, signal.SIGKILL)
        _ensure_group_dead(
            pgid, label=f"lifecycle kill of pid {pid}",
            member_anchor=(state.get("member_pid"),
                           state.get("member_starttime")),
        )
    except (ProcessLookupError, PermissionError):
        pass
    _remove_socket_dir(state)
    return True


def _kill_recorded_member(state: dict[str, Any]) -> bool:
    """Dead-leader fallback: kill the recorded JVM MEMBER when its
    recorded identity still proves out.

    ``_kill_server`` anchors on the LEADER; with the leader dead there
    is no live pid to comm-verify, so it used to refuse outright and
    the surviving JVM stayed orphaned. The state file's boot-time
    member anchor (pid + ``/proc/<pid>/stat`` starttime + comm)
    restores a safe identity: starttime is assigned once per process
    incarnation, so a live member whose CURRENT starttime equals the
    recorded one is provably the process the server boot recorded — a
    recycled pid cannot match. Starttime mismatch, an unreadable
    starttime (procfs absent off-Linux, or the member exiting under
    us), or a comm that contradicts the record → refuse, loudly.
    Absent anchor fields (old state files, boots that could not derive
    the member) → decline silently, exactly the pre-anchor behaviour.
    Returns True only when a kill was actually dispatched.
    """
    member = state.get("member_pid")
    recorded_start = state.get("member_starttime")
    if (not isinstance(member, int) or isinstance(member, bool)
            or member <= 0
            or not isinstance(recorded_start, int)
            or isinstance(recorded_start, bool)):
        # Old state file / no boot-derived anchor — nothing verified
        # ours to signal, same as before the anchor existed.
        return False
    if not _pid_running(member):
        return False
    from .server import _ensure_group_dead, _pgid_alive, _proc_starttime
    current_start = _proc_starttime(member)
    if current_start is None:
        logger.warning(
            "joern lifecycle: leader pid %s is gone and member pid %d "
            "has no readable /proc starttime — no identity proof; "
            "refusing to kill an unverified pid", state.get("pid"), member,
        )
        return False
    if current_start != recorded_start:
        logger.warning(
            "joern lifecycle: member pid %d starttime %d does not match "
            "recorded %d — the pid was recycled by another process; "
            "refusing to kill it", member, current_start, recorded_start,
        )
        return False
    comm = _read_comm(member)
    expected_comm = state.get("member_comm")
    if comm is not None and expected_comm and comm != expected_comm:
        # Belt-and-braces: a matching starttime with a different comm
        # should be impossible without an in-place exec/prctl — treat
        # it as an identity failure, not a curiosity.
        logger.warning(
            "joern lifecycle: member pid %d comm %r does not match "
            "recorded %r despite matching starttime — refusing to "
            "kill it", member, comm, expected_comm,
        )
        return False
    logger.warning(
        "joern lifecycle: leader pid %s is gone but recorded JVM member "
        "pid %d is alive with matching starttime — reaping the orphaned "
        "member", state.get("pid"), member,
    )
    # Same capture-then-escalate shape as _kill_server: group only
    # when the member leads its own (never the caller's), captured
    # while the member is still verified ours.
    pgid: int | None = None
    try:
        if os.getpgid(member) == member and member != os.getpgrp():
            pgid = member
    except OSError:
        pgid = None
    try:
        _signal_server(member, signal.SIGTERM)
        deadline = time.monotonic() + _KILL_GRACE_S
        while time.monotonic() < deadline:
            if not _pid_running(member) and not _pgid_alive(pgid):
                _remove_socket_dir(state)
                return True
            time.sleep(0.1)
        # Re-verify the incarnation before SIGKILL: the member may
        # have exited and its pid been recycled during the grace.
        if _proc_starttime(member) == recorded_start:
            _signal_server(member, signal.SIGKILL)
        _ensure_group_dead(
            pgid, label=f"lifecycle member kill of pid {member}",
            member_anchor=(member, recorded_start),
        )
    except (ProcessLookupError, PermissionError):
        pass
    _remove_socket_dir(state)
    return True


def kill_recorded_server(
    port: int | None = None,
    socket_path: str | None = None,
) -> bool:
    """Kill the state-file-recorded server when it matches *port* or
    *socket_path*.

    For ``JoernServer.restart()`` on a lifecycle-reused handle
    (``connect_existing``): the handle owns no ``Popen``, so
    ``stop()`` has nothing to signal, and without this the stuck JVM
    survives every restart while ``note_server_replaced`` repoints
    the state file at the replacement — erasing the last record of
    it. Identity-gated so a handle whose server the state file no
    longer tracks cannot kill an unrelated one. Returns True only
    when a kill was actually dispatched — False on an identity
    mismatch AND when ``_kill_server``'s pid-reuse comm gate refused.
    """
    if port is None and socket_path is None:
        return False
    with _locked() as fd:
        state = _read_state(fd)
        if not state:
            return False
        matches = (
            (port is not None and state.get("port") == port)
            or (socket_path is not None
                and state.get("socket_path") == socket_path)
        )
        if not matches:
            return False
        return _kill_server(state)


def _remove_socket_dir(state: dict[str, Any]) -> None:
    """Remove a killed strong-tier server's socket directory.

    The supervisor unlinks its socket on orderly exit, but a group
    SIGKILL skips that cleanup and the killer here holds no
    ``_uds_dir`` handle — derive it from the state's socket path.
    Prefix-gated so a corrupt state file can never aim the rmtree at
    an arbitrary directory.
    """
    sock = state.get("socket_path")
    if not sock:
        return
    parent = os.path.dirname(sock)
    if os.path.basename(parent).startswith("raptor-joern-uds-"):
        import shutil
        shutil.rmtree(parent, ignore_errors=True)


def note_server_replaced(
    old_pid: int | None,
    old_port: int | None,
    srv: JoernServer,
) -> None:
    """Record a restarted server in the lifecycle state file.

    ``JoernServer.restart()`` boots a NEW process with a new pid,
    port, and per-boot credential. When the state file was tracking
    the old process, it must follow the replacement — otherwise
    ``joern_release`` can neither authenticate against nor stop the
    new multi-GB JVM (unreleasable orphan), and later acquires kill
    an unrelated pid. No-op when the state file tracks a different
    server (or none) — the token-checked ``joern_release`` then stops
    the untracked replacement through the caller's own handle.

    Match rule: the handle's lineage token first (survives the
    restart — it lives on the Python object); else the recorded pid;
    else the recorded port ONLY when the recorded pid is dead — a
    live recorded server that merely shares the old port number is a
    DIFFERENT server, and repointing the state at our replacement
    would orphan it unreleasably.
    """
    new_pid = srv.pid
    if new_pid is None:
        return
    with _locked() as fd:
        state = _read_state(fd)
        if state is None:
            return
        token = getattr(srv, "_lifecycle_token", None)
        token_match = (token is not None
                       and state.get("boot_nonce") == token)
        pid_match = state.get("pid") == old_pid
        port_match_dead = (
            state.get("port") == old_port
            and not (state.get("pid") and _pid_alive(state["pid"]))
        )
        if not (token_match or pid_match or port_match_dead):
            return
        state["pid"] = new_pid
        state["comm"] = _read_comm(new_pid)
        state["port"] = srv.port
        state["started_at"] = time.time()
        state["auth_user"] = srv._auth_user
        state["auth_password"] = srv._auth_password
        state["socket_path"] = srv._uds_path
        # The replacement boot re-derived the JVM member anchor.
        state.update(_member_anchor_fields(srv))
        _write_state(fd, state)
        logger.info(
            "joern lifecycle: state updated for restarted server "
            "(pid %s -> %s, port %s -> %s)",
            old_pid, new_pid, old_port, srv.port,
        )
