"""Persistent Joern server lifecycle — shared across RAPTOR runs.

Replaces the start-per-run / stop-per-run pattern (30-120s JVM boot
each time) with a refcounted singleton.  First ``joern_acquire()``
starts the server; subsequent acquires increment the refcount and
return a client connected to the existing server.  Each
``joern_release()`` decrements; when the refcount hits zero the
server is stopped.

State is stored in ``~/.cache/raptor/joern-server.json`` and
protected by ``fcntl.flock`` for safe concurrent access.

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
from pathlib import Path
from typing import Any, Optional

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


def _read_comm(pid: int) -> Optional[str]:
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


def _read_state(lock_fd: int) -> Optional[dict[str, Any]]:
    if not _STATE_FILE.exists():
        return None
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_state(lock_fd: int, state: dict[str, Any]) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
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


def _health_check(port: int) -> bool:
    from urllib.error import URLError
    from urllib.request import Request

    from .server import _NO_PROXY_OPENER

    url = f"http://127.0.0.1:{port}/query-sync"
    payload = json.dumps({"query": "1+1"}).encode("utf-8")
    req = Request(url, data=payload,
                  headers={"Content-Type": "application/json"},
                  method="POST")
    try:
        with _NO_PROXY_OPENER.open(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("success", False) is not False
    except (URLError, OSError, json.JSONDecodeError, TimeoutError):
        return False


def _connect_existing(state: dict[str, Any]) -> Optional[JoernServer]:
    port = state.get("port")
    pid = state.get("pid")
    if not port or not pid:
        return None

    if not _pid_alive(pid):
        logger.info("joern lifecycle: stale PID %d — server is dead", pid)
        return None

    if not _health_check(port):
        logger.info("joern lifecycle: PID %d alive but server unhealthy", pid)
        return None

    srv = JoernServer.__new__(JoernServer)
    srv._heap_mb = state.get("heap_mb")
    srv._boot_timeout_s = 120
    srv._query_timeout_s = state.get("query_timeout_s", 300)
    srv._port = port
    srv._proc = None
    srv._base_url = f"http://127.0.0.1:{port}"
    srv._cpg_loaded = False
    srv._http_client = None
    srv._last_post_error = ""
    return srv


def joern_acquire(tunables: Optional[JoernTunables] = None) -> Optional[JoernServer]:
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
def joern_session(tunables: Optional[JoernTunables] = None):
    """Context manager wrapping acquire/release."""
    srv = joern_acquire(tunables)
    try:
        yield srv
    finally:
        if srv is not None:
            joern_release()


def _start_fresh(tunables: JoernTunables) -> Optional[JoernServer]:
    try:
        srv = JoernServer.from_tunables(tunables)
        srv.start()
        return srv
    except Exception:
        logger.debug("joern lifecycle: failed to start server", exc_info=True)
        return None


def _kill_server(state: dict[str, Any]) -> None:
    pid = state.get("pid")
    if not pid:
        return
    if not _pid_is_our_server(state):
        return
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not _pid_alive(pid):
                return
            time.sleep(0.5)
        # Re-verify before SIGKILL: the pid may have died and been
        # reused during the grace window.
        if _pid_is_our_server(state):
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
