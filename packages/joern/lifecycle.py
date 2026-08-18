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
authenticate against the reused server; it is created (and rewritten)
with mode 0600, and legacy state files are re-chmodded on load.

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
import threading
import time
from pathlib import Path
from typing import Any

from .server import JoernServer
from .tunables import JoernTunables

logger = logging.getLogger(__name__)

_STATE_DIR = Path.home() / ".cache" / "raptor"
_STATE_FILE = _STATE_DIR / "joern-server.json"
_LOCK_FILE = _STATE_DIR / "joern-server.lock"

_STALE_THRESHOLD_S = 3600 * 8


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


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


def _read_state(lock_fd: int) -> dict[str, Any] | None:
    if not _STATE_FILE.exists():
        return None
    # The state file carries the server credential; tighten legacy
    # files that predate the 0600 write path.
    with contextlib.suppress(OSError):
        _STATE_FILE.chmod(0o600)
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_state(lock_fd: int, state: dict[str, Any]) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    # 0600 from creation — the file carries the server credential.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(state, indent=2) + "\n")
    # O_CREAT mode only applies to fresh files; a leftover tmp keeps
    # its old bits, so re-assert before the rename publishes it.
    os.chmod(tmp, 0o600)
    tmp.rename(_STATE_FILE)


def _remove_state(lock_fd: int) -> None:
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


def _health_check(port: int, auth_headers: dict[str, str] | None = None) -> bool:
    from urllib.error import URLError
    from urllib.request import Request

    from .server import _NO_PROXY_OPENER

    url = f"http://127.0.0.1:{port}/query-sync"
    payload = json.dumps({"query": "1+1"}).encode("utf-8")
    req = Request(url, data=payload,
                  headers={"Content-Type": "application/json",
                           **(auth_headers or {})},
                  method="POST")
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

    srv = JoernServer.__new__(JoernServer)
    srv._heap_mb = state.get("heap_mb")
    srv._boot_timeout_s = 120
    srv._query_timeout_s = state.get("query_timeout_s", 300)
    srv._port = port
    srv._proc = None
    srv._base_url = f"http://127.0.0.1:{port}"
    srv._cpg_loaded = False
    srv._cpg_path = None
    srv._last_post_error = ""
    srv._restart_lock = threading.Lock()
    # ``query()`` consults this event before every post; ``__new__``
    # bypasses ``__init__``, so omitting it made EVERY query on a
    # reused server raise AttributeError.
    srv._restarting = threading.Event()
    srv._relaunch_last_attempt = None
    srv._workdir = None
    srv._auth_user = auth_user
    srv._auth_password = auth_password

    if not _health_check(port, srv._auth_headers()):
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
                logger.info("joern lifecycle: server older than %ds — recycling",
                            _STALE_THRESHOLD_S)
                _kill_server(state)
                _remove_state(fd)
                state = None

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
            # Per-boot HTTP Basic credential — required to reconnect
            # to the reused server. The state file is mode 0600.
            "auth_user": srv._auth_user,
            "auth_password": srv._auth_password,
        }
        _write_state(fd, new_state)
        logger.info(
            "joern lifecycle: started fresh server on port %d (pid %d)",
            srv.port, srv.pid,
        )
        return srv


def joern_release() -> None:
    """Release one reference to the shared Joern server.

    When the refcount reaches zero, the server is stopped.
    """
    with _locked() as fd:
        state = _read_state(fd)
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
            _remove_state(fd)


@contextlib.contextmanager
def joern_session(tunables: JoernTunables | None = None):
    """Context manager wrapping acquire/release."""
    srv = joern_acquire(tunables)
    try:
        yield srv
    finally:
        if srv is not None:
            joern_release()


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


def _kill_server(state: dict[str, Any]) -> None:
    pid = state.get("pid")
    if not pid:
        return
    if not _pid_is_our_server(state):
        return
    try:
        _signal_server(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not _pid_alive(pid):
                return
            time.sleep(0.5)
        # Re-verify before SIGKILL: the pid may have died and been
        # reused during the grace window.
        if _pid_is_our_server(state):
            _signal_server(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


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
    server (or none).
    """
    new_pid = srv.pid
    if new_pid is None:
        return
    with _locked() as fd:
        state = _read_state(fd)
        if state is None:
            return
        if state.get("pid") != old_pid and state.get("port") != old_port:
            return
        state["pid"] = new_pid
        state["comm"] = _read_comm(new_pid)
        state["port"] = srv.port
        state["started_at"] = time.time()
        state["auth_user"] = srv._auth_user
        state["auth_password"] = srv._auth_password
        _write_state(fd, state)
        logger.info(
            "joern lifecycle: state updated for restarted server "
            "(pid %s -> %s, port %s -> %s)",
            old_pid, new_pid, old_port, srv.port,
        )
