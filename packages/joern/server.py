"""Persistent Joern server for fast inter-procedural taint queries.

Replaces the subprocess-per-query model (30-60s JVM boot each time)
with a long-lived HTTP server that boots once and handles queries
via REST.  The CPG stays loaded in memory between queries.

Usage::

    with JoernServer() as srv:
        srv.import_cpg("/path/to/cpg.bin")
        result = srv.query("cpg.method.l")
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Self, TYPE_CHECKING
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

try:
    import httpx as _httpx
except ImportError:
    _httpx = None

from .models import JoernMethodSummary, JoernResult, TaintFlow
from .prereqs import _joern_path
from .runner import (
    _escape_scala_string,
    _parse_dark_methods,
    _parse_output,
    _validate_query,
)
from .tunables import JoernTunables

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_BOOT_TIMEOUT_S = 120
_BOOT_POLL_INTERVAL_S = 2
_QUERY_TIMEOUT_S = 300
_HEALTH_QUERY = "1+1"
_SHUTDOWN_GRACE_S = 5
_REPL_BRIDGE_NAME = "repl-bridge"
_AUTH_USERNAME = "raptor"

# Per-binary cache for the --server-auth-* capability probe: the probe
# boots a JVM (a few seconds), so pay it once per process per binary.
_AUTH_SUPPORT_CACHE: dict[str, bool] = {}

# The Joern server only ever listens on 127.0.0.1.  Loopback traffic
# must never route through an HTTP proxy — hosts with HTTP_PROXY set
# (and no localhost NO_PROXY entry) would silently send every query to
# the proxy instead of the server.
_NO_PROXY_OPENER = build_opener(ProxyHandler({}))

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SCALA_ERROR_MARKERS = ("-- [E", "error:", "Error:")

_RESTARTING_ERROR = (
    "server restarting after stuck query — failing fast "
    "(no Joern evidence for this claim)"
)

# Bounded relaunch-on-death window (see ``ensure_alive``): at most one
# relaunch attempt per this many seconds. A relaunch costs a JVM boot
# + CPG reload (~1-2 min) — retrying faster than this would spend the
# run's wall clock on a server that keeps dying.
_RELAUNCH_COOLDOWN_S = 300.0


def _reap_in_background(proc) -> None:
    """Reap a SIGKILLed child whose exit outlived the foreground grace.

    A killed multi-GB JVM can spend >5s in kernel-side address-space
    teardown before it becomes reapable; ``stop()`` must not block a
    restart on that, but abandoning the handle leaks a zombie for the
    rest of the run. A daemon thread holds the ``wait()`` instead.
    """
    pid = getattr(proc, "pid", None)
    started = time.monotonic()

    def _wait() -> None:
        try:
            proc.wait()
        except Exception:  # noqa: BLE001 — reaper must never raise
            logger.debug("background reap failed for pid %s", pid,
                         exc_info=True)
            return
        logger.info(
            "Joern server (pid %s) reaped %.1fs after SIGKILL",
            pid, time.monotonic() - started,
        )

    threading.Thread(
        target=_wait, name=f"joern-reaper-{pid}", daemon=True,
    ).start()


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _has_scala_error(stdout: str) -> bool:
    """Detect Scala compilation errors in stdout.

    The Joern REPL returns success=True even when the Scala compiler
    emits errors. The error text appears in stdout with ANSI codes.

    Scans the FULL output: the REPL echoes the submitted script before
    the compiler diagnostics, so a long batch script pushed the
    ``-- [E`` marker past a fixed 2000-byte prefix window and the
    failed query read as a successful zero-flow ("no taint") result.
    """
    if not stdout:
        return False
    plain = _strip_ansi(stdout)
    return any(marker in plain for marker in _SCALA_ERROR_MARKERS)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _jvm_gc_flags() -> list[str]:
    """GC tuning flags adapted to the host JDK and Joern launcher.

    Newer joern-cli launchers (>= ~4.0.6xx) hardcode ``-XX:+UseG1GC``
    ahead of caller flags, so selecting ZGC alone dies with "Multiple
    garbage collectors selected" — explicitly disable G1 first (later
    ``-XX`` flags win).  ``ZGenerational`` exists only on JDK 21-23:
    JDK 24 removed the flag (ZGC is generational-only there).
    """
    from .prereqs import _java_version

    flags = ["-J-XX:-UseG1GC", "-J-XX:+UseZGC"]
    jdk = _java_version()
    if jdk is not None and 21 <= jdk < 24:
        flags.append("-J-XX:+ZGenerational")
    if jdk is not None and jdk >= 25:
        # JEP 519 (product in 25): 4-byte object headers. CPGs are
        # node/edge-dense — per-object savings compound on exactly
        # this workload. Verified compatible with the joern launcher
        # on this JDK; the flag-set retry below is the safety net
        # for JVMs that reject it.
        flags.append("-J-XX:+UseCompactObjectHeaders")
    flags.append("-J-XX:+UseStringDeduplication")
    return flags


def _repl_bridge_path() -> str | None:
    """Resolve repl-bridge — the real Joern server binary.

    The ``joern`` wrapper script may be a thin shell shim that
    doesn't pass ``--server`` through.  ``repl-bridge`` in the same
    directory as ``joern-cli`` is the actual JVM launcher.
    """
    joern = _joern_path()
    if joern is None:
        return None
    joern_dir = Path(joern).resolve().parent
    # Location moved across joern releases: next to the joern wrapper
    # in older builds, under bin/ in 4.x.
    for bridge in (joern_dir / _REPL_BRIDGE_NAME,
                   joern_dir / "bin" / _REPL_BRIDGE_NAME):
        if bridge.exists():
            return str(bridge)
    import shutil
    return shutil.which(_REPL_BRIDGE_NAME)


def _server_auth_supported(binary: str) -> bool:
    """Probe whether the launcher accepts ``--server-auth-*`` flags.

    Checks the ``--help`` output rather than trial-booting a server.
    Every joern release RAPTOR supports carries the flags, but an
    unexpected install must fail closed — the caller refuses to start
    an unauthenticated server when this returns False.
    """
    cached = _AUTH_SUPPORT_CACHE.get(binary)
    if cached is not None:
        return cached
    from core.config import RaptorConfig
    try:
        proc = subprocess.run(
            [binary, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            env=RaptorConfig.get_safe_env(),
            check=False,
        )
        supported = "--server-auth-username" in (
            (proc.stdout or "") + (proc.stderr or "")
        )
    except (subprocess.TimeoutExpired, OSError):
        supported = False
    _AUTH_SUPPORT_CACHE[binary] = supported
    return supported


class JoernServer:
    """Manages a persistent ``joern --server`` process.

    The server listens on 127.0.0.1 with a random port.  Queries
    are submitted via ``POST /query-sync`` and return synchronously.

    Sandbox note: the server process runs unsandboxed — same trust
    level as the LLM harness itself.  The CPG build step
    (``joern-parse``) that processes untrusted target code runs
    sandboxed via ``core.sandbox.run``.  The server only receives
    RAPTOR-authored CPGQL queries validated by ``_validate_query``,
    not raw target input.  ``POST /query-sync`` executes arbitrary
    Scala, so listening on loopback alone is not enough: every boot
    generates a random HTTP Basic credential (passed via
    ``--server-auth-username`` / ``--server-auth-password``) and every
    client request carries the matching Authorization header — other
    local processes cannot drive the server.  If the installed joern
    does not support the auth flags, ``start()`` raises rather than
    exposing an unauthenticated server; callers fall back to the
    subprocess-per-query runner.
    """

    # Class-level default so ``__del__`` → ``stop()`` never raises
    # AttributeError on an instance whose ``__init__`` did not run to
    # the ``_proc`` assignment: a bad-signature ``TypeError`` fires
    # before the body executes at all, and tests build bare instances
    # via ``__new__``. ``stop()`` early-returns on None, so teardown
    # of such an instance is a no-op instead of an unraisable.
    _proc: subprocess.Popen | None = None

    def __init__(
        self,
        *,
        heap_mb: int | None = None,
        boot_timeout_s: int = _BOOT_TIMEOUT_S,
        query_timeout_s: int = _QUERY_TIMEOUT_S,
    ) -> None:
        self._heap_mb = heap_mb
        self._boot_timeout_s = boot_timeout_s
        self._query_timeout_s = query_timeout_s
        self._port: int | None = None
        self._proc: subprocess.Popen | None = None
        self._base_url: str | None = None
        self._cpg_loaded = False
        self._cpg_path: Path | None = None
        self._last_post_error: str = ""
        self._restart_lock = threading.Lock()
        # Set while a restart is in progress so concurrent queries
        # fail fast instead of posting into a dead/booting server
        # (each such post would block for its full timeout).
        self._restarting = threading.Event()
        # Monotonic timestamp of the last relaunch-on-death attempt
        # (``ensure_alive``); None = never attempted. NOT 0.0: on
        # Linux ``time.monotonic()`` is seconds since boot, so on a
        # freshly booted host (CI runners, just-rebooted operator
        # boxes) ``now - 0.0 < cooldown`` held for the first five
        # minutes of uptime and the FIRST relaunch attempt was
        # silently refused.
        self._relaunch_last_attempt: float | None = None
        self._workdir: str | None = None
        self._auth_user: str | None = None
        self._auth_password: str | None = None
        # Learned FlowSemantic rows (packages.joern.semantics), applied
        # to the dataflow EngineContext of the tiered sweep and batch
        # taint queries. Instance-level: semantics describe the loaded
        # CPG's project.
        self._flow_semantics: list[Any] = []

    def start(self) -> None:
        """Boot the Joern server and wait for readiness."""
        if self._proc is not None:
            return

        binary = _repl_bridge_path() or _joern_path() or "joern"

        # Fail closed on launchers without --server-auth-* support:
        # an unauthenticated /query-sync executes arbitrary Scala for
        # any local process.  Raising here routes callers onto the
        # subprocess-per-query fallback instead.
        if not _server_auth_supported(binary):
            logger.error(
                "installed joern (%s) does not support "
                "--server-auth-username/--server-auth-password; refusing "
                "to start an unauthenticated server — callers fall back "
                "to the subprocess-per-query runner", binary,
            )
            msg = (
                "joern launcher lacks --server-auth-* support; "
                "unauthenticated server mode is disabled"
            )
            raise RuntimeError(msg)

        # Fresh, empty working directory per boot. Joern treats
        # ``$CWD/workspace/`` as its project store and loads EVERY
        # entry at startup — inheriting the caller's cwd (the RAPTOR
        # repo) meant one corrupt entry left by a killed run (a
        # ``cpg.binN/`` with overlays but no project.json) wedged the
        # REPL bridge before it ever bound the port: every subsequent
        # server boot on the machine failed with "failed to start
        # within 120s". The workspace is incidental state (imports use
        # absolute CPG paths), so give each server a disposable one.
        self._workdir = tempfile.mkdtemp(prefix="raptor-joern-ws-")

        heap_flags: list[str] = []
        if self._heap_mb is not None:
            # Ceiling only — no -Xms pin (measured: no benefit at any
            # scale, boot-fragile at very large heaps).
            heap_flags.append(f"-J-Xmx{self._heap_mb}m")

        # Attempt tuned GC flags first; if the JVM rejects them (flag
        # sets drift across JDK releases and joern launcher versions),
        # the process dies within seconds — retry once with launcher
        # defaults rather than failing the whole run.
        parallelism = "-J-Djava.util.concurrent.ForkJoinPool.common.parallelism=6"
        flag_sets = [_jvm_gc_flags() + [parallelism], [parallelism]]

        from core.config import RaptorConfig
        for attempt, tuning_flags in enumerate(flag_sets):
            self._port = _find_free_port()
            self._base_url = f"http://127.0.0.1:{self._port}"

            # Per-boot-attempt state: stop() after a failed attempt
            # clears the credential and removes the workdir.
            self._auth_user = _AUTH_USERNAME
            self._auth_password = secrets.token_urlsafe(32)
            if self._workdir is None:
                self._workdir = tempfile.mkdtemp(prefix="raptor-joern-ws-")

            cmd = [binary] + heap_flags + tuning_flags + [
                # RAPTOR strips ANSI from every response anyway
                # (_strip_ansi); emitting it just bloats payloads.
                "--nocolors",
                "--server",
                "--server-host", "127.0.0.1",
                "--server-port", str(self._port),
                "--server-auth-username", self._auth_user,
                "--server-auth-password", self._auth_password,
            ]

            logger.info("starting Joern server on 127.0.0.1:%d", self._port)

            # New session so stop() can signal the whole process group:
            # the joern launcher may be a shell wrapper that spawns the
            # JVM without exec — terminating just the wrapper orphans it.
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=RaptorConfig.get_safe_env(),
                start_new_session=True,
                cwd=self._workdir,
            )

            if self._wait_for_ready():
                break

            died_during_boot = self._proc.poll() is not None
            self.stop()
            if died_during_boot and attempt + 1 < len(flag_sets):
                logger.warning(
                    "Joern server died with tuned JVM flags; "
                    "retrying with launcher defaults"
                )
                continue
            msg = f"Joern server failed to start within {self._boot_timeout_s}s"
            raise RuntimeError(msg)

        logger.info("Joern server ready on port %d (pid %d)",
                     self._port, self._proc.pid)

        self._warmup_imports()

    def _wait_for_ready(self) -> bool:
        deadline = time.monotonic() + self._boot_timeout_s
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                logger.error("Joern server exited during boot: %s",
                             stderr[:500])
                return False
            # _post_sync returns None on every transport failure
            # (both httpx and urllib paths catch their own errors),
            # so a not-ready server just polls again — no suppression
            # needed, and a wiring bug here should surface.
            resp = self._post_sync(_HEALTH_QUERY, timeout=5)
            if resp is not None:
                return True
            time.sleep(_BOOT_POLL_INTERVAL_S)
        return False

    def _warmup_imports(self) -> None:
        """Pre-compile dataflow engine imports in the persistent REPL.

        The REPL session carries state across queries, so imports compiled
        here avoid re-compilation in every subsequent query script.
        """
        warmup = (
            "import io.joern.dataflowengineoss.queryengine._\n"
            "import io.joern.dataflowengineoss.language._\n"
            "import io.shiftleft.semanticcpg.language._\n"
            "import io.shiftleft.codepropertygraph.generated.nodes.CfgNode\n"
            "import scala.util.Try\n"
            '"warmup-ok"'
        )
        try:
            self._post_sync(warmup, timeout=30)
        except Exception as e:  # noqa: BLE001 — warmup is best-effort
            logger.debug("Joern warmup imports failed: %s", e)

    def _warmup_dataflow(self) -> None:
        """Initialize the dataflow engine after CPG load.

        Fires a reachableBy against non-existent method names.  This
        compiles all dataflow imports, initializes EngineContext, and
        returns immediately (empty input = no work).  Cost: ~2-3s for
        import compilation, near-zero for the actual query.
        """
        warmup = (
            'import io.joern.dataflowengineoss.language._\n'
            'import io.joern.dataflowengineoss.queryengine._\n'
            'import io.shiftleft.semanticcpg.language._\n'
            'cpg.method.name("__RAPTOR_WARMUP_NONEXISTENT__").parameter'
            '.reachableBy(cpg.call.name("__RAPTOR_WARMUP_NONEXISTENT__")'
            '.argument).l'
        )
        try:
            self._post_sync(warmup, timeout=30)
        except Exception as e:  # noqa: BLE001 — warmup is best-effort
            logger.debug("Joern dataflow warmup failed: %s", e)

    def stop(self) -> None:
        """Shut down the Joern server."""
        if self._proc is None:
            return

        pid = self._proc.pid
        logger.info("stopping Joern server (pid %d)", pid)

        def _signal_group(sig: int) -> None:
            # The launcher may be a shell wrapper whose JVM child would
            # survive a plain terminate() — signal the whole group.  Only
            # killpg when pid is the leader of its own group: Popen used
            # start_new_session=True, so anything else means the pid was
            # reused (or mocked) and the group is not ours to signal.
            try:
                if os.getpgid(pid) != pid:
                    raise ProcessLookupError
                os.killpg(pid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                if sig == signal.SIGTERM:
                    self._proc.terminate()
                else:
                    self._proc.kill()

        try:
            _signal_group(signal.SIGTERM)
            self._proc.wait(timeout=_SHUTDOWN_GRACE_S)
        except subprocess.TimeoutExpired:
            _signal_group(signal.SIGKILL)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # SIGKILL is delivered but the process may legitimately
                # take longer than 5s to reach the zombie state: a
                # multi-GB JVM's exit path tears down its whole address
                # space (page tables + anonymous heap pages) BEFORE the
                # parent can reap it, and uninterruptible (D-state)
                # I/O — e.g. CPG pages being written back — pins it
                # further. The process cannot execute anything after
                # SIGKILL, so cleanup proceeds; blocking a restart on
                # kernel teardown would just serialise the recovery
                # behind memory unmapping.
                #
                # But the child must still be wait()ed eventually:
                # pre-fix nothing ever reaped it, so every slow-exit
                # kill leaked a zombie (and its pid) until interpreter
                # exit. Hand the handle to a background reaper.
                logger.warning(
                    "Joern server (pid %d) did not reap within 5s of "
                    "SIGKILL — proceeding with cleanup (multi-GB JVM "
                    "address-space teardown can exceed the grace); "
                    "background reaper attached",
                    pid,
                )
                _reap_in_background(self._proc)
        except OSError:
            pass

        self._proc = None
        self._port = None
        self._base_url = None
        self._cpg_loaded = False
        # Per-boot credential — a fresh one is generated on start().
        self._auth_user = None
        self._auth_password = None

        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None

    def is_alive(self) -> bool:
        if self._proc is None or self._proc.poll() is not None:
            return False
        try:
            resp = self._post_sync(_HEALTH_QUERY, timeout=5)
            return resp is not None
        except Exception:  # noqa: BLE001 — any failure means not alive
            return False

    @property
    def restarting(self) -> bool:
        """True while a restart (stop → boot → CPG reload) is running."""
        return self._restarting.is_set()

    def health_check(self, *, timeout: float = 5.0) -> bool:
        """Cheap endpoint-liveness probe (``1+1`` via /query-sync).

        The authoritative check for handles that don't own their
        process (lifecycle reuse): ``poll()`` has nothing to say
        there. Mirrors ``lifecycle._health_check``. False on any
        transport/parse failure, and when the handle has no endpoint.
        """
        if not self._base_url:
            return False
        from urllib.error import URLError
        from urllib.request import Request

        url = f"{self._base_url}/query-sync"
        payload = json.dumps({"query": "1+1"}).encode("utf-8")
        req = Request(
            url, data=payload,
            headers={"Content-Type": "application/json",
                     **self._auth_headers()},
            method="POST",
        )
        try:
            with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
                data = json.loads(resp.read(1024 * 1024).decode("utf-8"))
                return data.get("success", False) is not False
        except (URLError, OSError, json.JSONDecodeError,
                TimeoutError, ValueError):
            return False

    def ensure_alive(
        self, *, cooldown_s: float = _RELAUNCH_COOLDOWN_S,
    ) -> bool:
        """Process-liveness probe with bounded relaunch-on-death.

        The review loop calls this at dispatch time (the orchestrator's
        joern tick). ``restart()`` is otherwise reachable only from
        query-TIMEOUT branches — but a dead server process fails fast
        BEFORE any HTTP post can time out, so death used to be
        terminal: every subsequent query returned
        ``["server process exited"]`` for the rest of the run and the
        taint tier silently stayed down.

        Bounded: at most one relaunch attempt per ``cooldown_s``
        window, loudly logged both ways. Between attempts — and when
        the relaunch itself fails — the tier stays down and queries
        keep failing fast; the degradation is reported, not silent.

        Returns True when the server is alive (or just came back).
        """
        if self._restarting.is_set():
            return False
        proc = self._proc
        if proc is not None and proc.poll() is None:
            return True
        if proc is None:
            # This object doesn't own a process (lifecycle-reused
            # handle) or a previous relaunch died inside start().
            # poll() can't answer liveness for a reused handle —
            # probe the HTTP endpoint instead. Pre-fix a healthy
            # shared server was judged dead here on the first
            # orchestrator tick after import_cpg, and the relaunch
            # spawned a DUPLICATE multi-GB JVM beside it (with a pid
            # the lifecycle state file never learned about).
            if self.health_check():
                return True
            # Endpoint dead too. Only revive handles that actually
            # served a CPG — a never-started client has nothing to
            # relaunch.
            if self._cpg_path is None:
                return False
        now = time.monotonic()
        if (
            self._relaunch_last_attempt is not None
            and now - self._relaunch_last_attempt < cooldown_s
        ):
            return False
        self._relaunch_last_attempt = now
        logger.warning(
            "Joern server process is dead — attempting relaunch "
            "(bounded: at most one attempt per %.0fs)",
            cooldown_s,
        )
        ok = False
        try:
            ok = self.restart()
        except Exception:  # noqa: BLE001 — probe must not kill the loop
            logger.warning("Joern relaunch raised", exc_info=True)
        if ok:
            logger.warning(
                "Joern server relaunched — taint tier restored",
            )
        else:
            logger.warning(
                "Joern relaunch failed — taint tier remains DOWN "
                "(queries fail fast; next relaunch attempt in %.0fs)",
                cooldown_s,
            )
        return ok

    def restart(self) -> bool:
        """Stop, restart, and reload the CPG.

        Used after a query timeout leaves the single-threaded REPL
        saturated — subsequent queries would queue behind the stuck
        query indefinitely.  Returns True if the server came back and
        the CPG was reloaded successfully.

        Bounded: exactly ONE restarter proceeds. Concurrent callers
        fail fast (return False) instead of queueing behind the
        restart — pre-fix they blocked on ``_restart_lock`` for the
        full boot + CPG reload (minutes), serialising every worker
        that had a query time out during the recovery window. Their
        queries return an error result; the run degrades to
        "no Joern evidence for this claim" instead of stalling.
        """
        if not self._restart_lock.acquire(blocking=False):
            logger.warning(
                "Joern restart already in progress — failing fast "
                "instead of queueing behind it",
            )
            return False
        self._restarting.set()
        try:
            cpg_path = self._cpg_path
            old_pid = self._proc.pid if self._proc is not None else None
            old_port = self._port
            logger.info("restarting Joern server (stuck query recovery)")
            self.stop()
            try:
                self.start()
            except RuntimeError:
                logger.error("Joern server failed to restart")
                return False
            # The restarted JVM has a new pid/port/credential — record
            # it in the lifecycle state file (when this server is the
            # one it tracks) so joern_release can still stop it.
            try:
                from .lifecycle import note_server_replaced
                note_server_replaced(
                    old_pid=old_pid, old_port=old_port, srv=self,
                )
            except Exception:  # noqa: BLE001 — bookkeeping must not fail restart
                logger.debug(
                    "lifecycle state update after restart failed",
                    exc_info=True,
                )
            if cpg_path is not None:
                if not cpg_path.exists():
                    # Pre-fix this returned True with _cpg_loaded
                    # False: ensure_alive kept reporting healthy while
                    # every query failed "no CPG loaded" — a
                    # fabricated-healthy wedge.
                    logger.error(
                        "CPG vanished during restart: %s — reporting "
                        "restart failure (queries would have no CPG)",
                        cpg_path,
                    )
                    return False
                return self.import_cpg(cpg_path)
            return True
        finally:
            self._restarting.clear()
            self._restart_lock.release()

    def import_cpg(self, cpg_path: Path, *, timeout: int = 120) -> bool:
        """Load a pre-built CPG into the running server.

        Returns True on success, False on failure.
        """
        cpg_path = Path(cpg_path).resolve()
        if not cpg_path.exists():
            logger.error("CPG file not found: %s", cpg_path)
            return False

        safe_path = _escape_scala_string(str(cpg_path))
        query = f'importCpg("{safe_path}")'

        logger.info("loading CPG: %s", cpg_path)
        t0 = time.monotonic()

        resp = self._post_sync(query, timeout=timeout)
        if resp is None:
            detail = self._last_post_error or "no response"
            logger.error("importCpg failed (%s)", detail)
            return False

        elapsed = time.monotonic() - t0
        if not resp.get("success", True):
            logger.error("importCpg failed: %s",
                         resp.get("stderr", "")[:500])
            return False

        # "imported into the server", not "loaded": this is the REPL
        # importCpg round-trip for an already-built CPG file — a fast
        # line here does NOT contradict an earlier cache-stale/rebuild
        # message from a CPG *build* cache.
        logger.info("CPG imported into Joern server in %.1fs", elapsed)
        self._cpg_loaded = True
        self._cpg_path = cpg_path

        self._warmup_dataflow()

        return True

    def import_code(self, target_path: Path, *, timeout: int = 300) -> bool:
        """Build and load a CPG from source code.

        Slower than import_cpg (builds the CPG inside the JVM) but
        doesn't require a separate joern-parse step.
        """
        target_path = Path(target_path).resolve()
        if not target_path.is_dir():
            logger.error("target not a directory: %s", target_path)
            return False

        safe_path = _escape_scala_string(str(target_path))
        query = f'importCode("{safe_path}")'

        logger.info("importing code: %s", target_path)
        t0 = time.monotonic()

        resp = self._post_sync(query, timeout=timeout)
        if resp is None:
            detail = self._last_post_error or "no response"
            logger.error("importCode failed (%s)", detail)
            return False

        elapsed = time.monotonic() - t0
        if not resp.get("success", True):
            logger.error("importCode failed: %s",
                         resp.get("stderr", "")[:500])
            return False

        logger.info("code imported in %.1fs", elapsed)
        self._cpg_loaded = True
        return True

    def query(
        self,
        cpgql: str,
        *,
        timeout: int | None = None,
        validate: bool = True,
        check_length: bool = True,
    ) -> JoernResult:
        """Execute a CPGQL query and return parsed results."""
        if timeout is None:
            timeout = self._query_timeout_s

        # Fail fast while a restart is in progress: posting into the
        # dead/booting server would block for the full query timeout
        # and every waiter would then queue on the single-threaded
        # REPL behind the reloading CPG.
        if self._restarting.is_set():
            return JoernResult(
                query=cpgql,
                errors=[_RESTARTING_ERROR],
            )

        # Fast check: if the server process is dead, fail immediately
        # rather than blocking on a stale HTTP connection.
        if self._proc is not None and self._proc.poll() is not None:
            return JoernResult(
                query=cpgql,
                errors=["server process exited"],
            )

        if not self._cpg_loaded:
            return JoernResult(
                query=cpgql,
                errors=["no CPG loaded (call import_cpg first)"],
            )

        if validate:
            err = _validate_query(cpgql, check_length=check_length)
            if err:
                return JoernResult(query=cpgql, errors=[err])

        t0 = time.monotonic()
        resp = self._post_sync(cpgql, timeout=timeout)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if resp is None:
            detail = self._last_post_error or "server did not respond"
            # A timeout means the single-threaded REPL is stuck on this
            # query (or a prior one).  Restart so subsequent queries
            # don't queue behind the stuck one indefinitely.
            if "timed out" in detail:
                self.restart()
            return JoernResult(
                query=cpgql,
                errors=[detail],
                elapsed_ms=elapsed_ms,
            )

        stdout = resp.get("stdout", "")
        stderr = resp.get("stderr", "")
        success = resp.get("success", True)

        errors: list[str] = []
        if not success:
            detail = stderr[:500] or stdout[:500]
            errors.append(f"query failed: {detail}")
        elif _has_scala_error(stdout):
            errors.append(f"query failed: {_strip_ansi(stdout)[:500]}")

        flows, parse_errors = _parse_output(stdout)
        errors.extend(parse_errors)
        dark = _parse_dark_methods(stdout)

        return JoernResult(
            query=cpgql,
            flows=flows,
            raw_output=stdout,
            errors=errors,
            elapsed_ms=elapsed_ms,
            dark_methods=dark,
        )

    def query_script(
        self,
        script_path: Path,
        *,
        timeout: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
        substitutions: dict[str, str] | None = None,
    ) -> JoernResult:
        """Execute a .sc script file via the server.

        Reads the script content and submits it as an inline query.
        When *cancel_check* is provided, uses the async submit+poll
        path so the caller can abort mid-query.  *substitutions* maps
        template-slot markers (e.g. ``__SINK_NAMES__``) to replacement
        text, applied to the script body before submission.
        """
        script_path = Path(script_path)
        if not script_path.exists():
            return JoernResult(
                query=str(script_path),
                errors=[f"script not found: {script_path}"],
            )

        content = script_path.read_text(encoding="utf-8")
        for marker, replacement in (substitutions or {}).items():
            content = content.replace(marker, replacement)
        if cancel_check is not None:
            return self.query_cancellable(
                content, timeout=timeout, cancel_check=cancel_check,
                validate=True, check_length=False,
            )
        return self.query(content, timeout=timeout, validate=True, check_length=False)

    def _auth_headers(self) -> dict[str, str]:
        """HTTP Basic Authorization header for the per-boot credential.

        Empty when no credential is set (e.g. a unit test poking a
        bare instance) — the server rejects such requests with 401
        rather than executing them.
        """
        if not self._auth_user or not self._auth_password:
            return {}
        token = base64.b64encode(
            f"{self._auth_user}:{self._auth_password}".encode()
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def _post_sync(
        self,
        query_str: str,
        *,
        timeout: int = 30,
    ) -> dict[str, Any] | None:
        """POST to /query-sync and return the parsed JSON response.

        Uses httpx with connection pooling when available (~50ms saved
        per query vs new-TCP-per-request urllib).  Falls back to urllib.
        """
        if self._base_url is None:
            return None

        url = f"{self._base_url}/query-sync"
        payload = {"query": query_str}

        self._last_post_error = ""
        if _httpx is not None:
            return self._post_httpx(url, payload, timeout)
        return self._post_urllib(url, payload, timeout)

    def _post_httpx(
        self,
        url: str,
        payload: dict,
        timeout: int,
    ) -> dict[str, Any] | None:
        # Fresh client per request.  The Joern REPL is single-threaded;
        # a timed-out query leaves stale state in the connection pool
        # that blocks all subsequent queries on the reused socket.  The
        # ~50ms TCP setup overhead is negligible vs query execution time.
        client = _httpx.Client(
            timeout=_httpx.Timeout(timeout, connect=5.0),
            trust_env=False,
        )
        try:
            resp = client.post(url, json=payload, headers=self._auth_headers())
            return resp.json()
        except Exception as e:  # noqa: BLE001 — classified below by message
            if "timed out" in str(e).lower() or "timeout" in type(e).__name__.lower():
                self._last_post_error = f"query timed out after {timeout}s"
            elif "connect" in str(e).lower() or "refused" in str(e).lower():
                self._last_post_error = f"connection failed: {e}"
            else:
                self._last_post_error = str(e)
            logger.debug("query-sync (httpx) failed: %s", e)
            return None
        finally:
            client.close()

    def _post_urllib(
        self,
        url: str,
        payload: dict,
        timeout: int,
    ) -> dict[str, Any] | None:
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json",
                     **self._auth_headers()},
            method="POST",
        )
        try:
            with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (URLError, OSError, json.JSONDecodeError, TimeoutError) as e:
            if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
                self._last_post_error = f"query timed out after {timeout}s"
            elif "refused" in str(e).lower():
                self._last_post_error = f"connection refused: {e}"
            else:
                self._last_post_error = str(e)
            logger.debug("query-sync (urllib) failed: %s", e)
            return None

    # ── Async query (submit + poll) ──────────────────────────────────

    def _post_async(self, query_str: str) -> str | None:
        """POST to /query (non-blocking). Returns UUID or None."""
        if self._base_url is None:
            return None
        url = f"{self._base_url}/query"
        payload = {"query": query_str}
        try:
            body = json.dumps(payload).encode("utf-8")
            req = Request(url, data=body,
                          headers={"Content-Type": "application/json",
                                   **self._auth_headers()},
                          method="POST")
            with _NO_PROXY_OPENER.open(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("uuid") or data.get("id")
        except Exception as e:  # noqa: BLE001 — submit is best-effort
            logger.debug("async query submit failed: %s", e)
            return None

    def _get_result(self, uuid: str) -> dict[str, Any] | None:
        """GET /result/<uuid>. Returns response dict if ready, None if pending."""
        if self._base_url is None:
            return None
        url = f"{self._base_url}/result/{uuid}"
        try:
            req = Request(url, method="GET",
                          headers=self._auth_headers())
            with _NO_PROXY_OPENER.open(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("success") is not None:
                return data
            return None
        except Exception:  # noqa: BLE001 — poll is best-effort
            return None

    def query_cancellable(
        self,
        cpgql: str,
        *,
        timeout: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
        poll_interval: float = 2.0,
        validate: bool = True,
        check_length: bool = True,
    ) -> JoernResult:
        """Submit a query asynchronously and poll until done or cancelled.

        ``cancel_check`` is called every ``poll_interval`` seconds.
        When it returns True the poll loop exits immediately with an
        error result.  Falls back to the blocking ``query()`` path if
        the async endpoint is unavailable.
        """
        if timeout is None:
            timeout = self._query_timeout_s

        # Same fail-fast as ``query()`` — see comment there.
        if self._restarting.is_set():
            return JoernResult(
                query=cpgql,
                errors=[_RESTARTING_ERROR],
            )

        if self._proc is not None and self._proc.poll() is not None:
            return JoernResult(
                query=cpgql,
                errors=["server process exited"],
            )

        if not self._cpg_loaded:
            return JoernResult(
                query=cpgql,
                errors=["no CPG loaded (call import_cpg first)"],
            )
        if validate:
            err = _validate_query(cpgql, check_length=check_length)
            if err:
                return JoernResult(query=cpgql, errors=[err])

        uuid = self._post_async(cpgql)
        if uuid is None:
            return self.query(cpgql, timeout=timeout, validate=False,
                              check_length=False)

        t0 = time.monotonic()
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            if cancel_check is not None and cancel_check():
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                return JoernResult(
                    query=cpgql, errors=["cancelled"],
                    elapsed_ms=elapsed_ms,
                )

            resp = self._get_result(uuid)
            if resp is not None:
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                stdout = resp.get("stdout", "")
                stderr = resp.get("stderr", "")
                success = resp.get("success", True)

                if not success and not stdout and not stderr:
                    logger.debug(
                        "async query returned empty failure; "
                        "falling back to sync path",
                    )
                    return self.query(
                        cpgql, timeout=max(1, timeout - int(time.monotonic() - t0)),
                        validate=False, check_length=False,
                    )

                errors: list[str] = []
                if not success:
                    detail = stderr[:500] or stdout[:500]
                    errors.append(f"query failed: {detail}")
                elif _has_scala_error(stdout):
                    errors.append(f"query failed: {_strip_ansi(stdout)[:500]}")
                flows, parse_errors = _parse_output(stdout)
                errors.extend(parse_errors)
                dark = _parse_dark_methods(stdout)
                return JoernResult(
                    query=cpgql, flows=flows, raw_output=stdout,
                    errors=errors, elapsed_ms=elapsed_ms,
                    dark_methods=dark,
                )

            time.sleep(poll_interval)

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        # The server is stuck on this query.  Restart so subsequent
        # queries don't queue behind it.
        self.restart()
        return JoernResult(
            query=cpgql, errors=["timeout (async poll)"],
            elapsed_ms=elapsed_ms,
        )

    def set_flow_semantics(self, rows: list[Any]) -> int:
        """Install learned FlowSemantic rows for subsequent taint queries.

        *rows* are ``packages.joern.semantics.SemanticRow`` items (or
        vocabulary-shaped strings/dicts, converted via
        ``rows_from_vocab``). Invalid rows and ``llm_prior``-provenance
        rows are dropped loudly by the semantics module. Returns the
        number of rows retained. Passing an empty list clears the
        installed semantics.
        """
        from .semantics import SemanticRow, filter_valid_rows, rows_from_vocab

        if rows and not isinstance(rows[0], SemanticRow):
            valid = rows_from_vocab(rows)
        else:
            valid, _rejected = filter_valid_rows(rows)
        self._flow_semantics = valid
        if valid:
            logger.info(
                "flow semantics installed: %d row(s) (%s)",
                len(valid),
                ", ".join(r.method for r in valid[:8]),
            )
        return len(valid)

    def close_workspace(self) -> None:
        """Close the active CPG and free memory."""
        resp = self._post_sync("workspace.reset", timeout=30)
        self._cpg_loaded = False
        if resp and not resp.get("success", True):
            logger.warning("workspace.reset failed: %s",
                           resp.get("stderr", "")[:200])

    def run_taint_query(
        self,
        source_method: str,
        sink_call: str,
        *,
        source_param: str | None = None,
        timeout: int | None = None,
        max_call_depth: int = 2,
        errors_out: list | None = None,
    ) -> list[TaintFlow]:
        """Run a source-to-sink taint query via the server.

        ``errors_out``: optional caller-supplied list that receives the
        underlying query errors.  An empty flow list is AMBIGUOUS
        without it — "no taint path exists" and "the query never ran
        (server restarting / timed out)" both return ``[]``, so a
        verdict-bearing caller would book a degraded query as a
        refutation.
        """
        if timeout is None:
            timeout = self._query_timeout_s
        from .runner import (
            _build_taint_query,
            _escape_scala_string,
            _validate_substitution_value,
        )

        if not _validate_substitution_value(source_method):
            return []
        if not _validate_substitution_value(sink_call):
            return []
        if source_param and not _validate_substitution_value(source_param):
            return []

        safe_source = _escape_scala_string(source_method)
        safe_sink = _escape_scala_string(sink_call)
        query = _build_taint_query(safe_source, safe_sink, source_param,
                                   max_call_depth=max_call_depth)

        result = self.query(query, timeout=timeout, validate=True)
        if result.errors:
            logger.warning("server taint query errors: %s", result.errors)
            if errors_out is not None:
                errors_out.extend(result.errors)
        return result.flows

    def run_taint_exists_query(
        self,
        source_method: str,
        sink_call: str,
        *,
        timeout: int | None = None,
        max_call_depth: int = 2,
    ) -> bool:
        """Check if a taint flow exists without full path reconstruction.

        Uses reachableBy (existence) instead of reachableByFlows (path
        reconstruction). Cheaper for callers that only need a yes/no answer.
        """
        if timeout is None:
            timeout = self._query_timeout_s
        from .runner import (
            _build_taint_exists_query,
            _escape_scala_string,
            _validate_substitution_value,
        )

        if not _validate_substitution_value(source_method):
            return False
        if not _validate_substitution_value(sink_call):
            return False

        safe_source = _escape_scala_string(source_method)
        safe_sink = _escape_scala_string(sink_call)
        query = _build_taint_exists_query(safe_source, safe_sink,
                                          max_call_depth=max_call_depth)

        result = self.query(query, timeout=timeout, validate=True)
        if not result.ok:
            return False
        return "JOERN_EXISTS:true" in (result.raw_output or "")

    def run_taint_queries_batch(
        self,
        pairs: list[tuple[str, str]],
        *,
        timeout: int | None = None,
        max_call_depth: int = 2,
    ) -> list[TaintFlow]:
        """Run multiple source→sink taint queries in a single REPL submission.

        Each pair is (source_method, sink_call).  Saves ~3-5s per pair by
        avoiding repeated Scala compilation overhead — imports are already
        in the persistent REPL session from warmup.
        """
        if timeout is None:
            timeout = self._query_timeout_s
        if not pairs:
            return []

        from .runner import _escape_scala_string, _validate_substitution_value

        valid_pairs = []
        for src, sink in pairs:
            if _validate_substitution_value(src) and _validate_substitution_value(sink):
                valid_pairs.append((_escape_scala_string(src), _escape_scala_string(sink)))
            else:
                logger.warning("batch: skipping invalid pair (%r, %r)", src[:40], sink[:40])

        if not valid_pairs:
            return []

        from .semantics import render_context_arg, render_semantics_decl
        sem_decl = render_semantics_decl(self._flow_semantics)
        sem_arg = render_context_arg(self._flow_semantics)
        lines = [
            "import io.joern.dataflowengineoss.queryengine._",
            "import io.joern.dataflowengineoss.language._",
            "import io.shiftleft.semanticcpg.language._",
            "import io.shiftleft.codepropertygraph.generated.nodes.CfgNode",
            "import scala.util.Try",
        ]
        if sem_decl:
            lines.append(sem_decl.rstrip("\n"))
        lines += [
            f"val batchConfig = EngineConfig(maxCallDepth = {max_call_depth})",
            (
                "implicit val batchContext: EngineContext = "
                f"EngineContext({sem_arg}config = batchConfig)"
            ),
        ]

        # Transport and echo discipline (three interacting REPL facts,
        # all observed on the supported joern line):
        # * println output does NOT come back through /query-sync —
        #   flows must ride the FINAL EXPRESSION's string echo, exactly
        #   like tiered_taint.sc / _build_taint_query do.
        # * a bare `val flowsN = ....l` at top level echoes the fully
        #   pretty-printed node list, flooding (and truncating) the
        #   response — each pair runs inside locally{} so intermediate
        #   vals never echo.
        # * interpolator dollars are single ($ln): a doubled $$ is
        #   Scala's ESCAPED literal dollar and would emit the JSON
        #   un-interpolated.
        lines.append(
            "val raptorBatchLines = "
            "scala.collection.mutable.ListBuffer.empty[String]"
        )
        for i, (src, sink) in enumerate(valid_pairs):
            lines.append(
                f'locally {{\n'
                f'val src{i} = cpg.method.name("{src}").parameter\n'
                f'val snk{i} = cpg.call.name("{sink}").argument\n'
                f'val flows{i} = snk{i}.reachableByFlows(src{i}).take(50).l\n'
                f'flows{i}.foreach {{ flow =>\n'
                f'  val steps = flow.elements.map {{ e =>\n'
                f'    val ln = e.lineNumber.getOrElse(0)\n'
                f'    val cd = e.code.take(200).replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", " ").replace("\\r", "")\n'
                f'    val (fn, fl) = e match {{\n'
                f'      case n: CfgNode =>\n'
                f'        (Try(n.method.name).getOrElse(""), Try(n.method.filename).getOrElse(""))\n'
                f'      case _ => ("", "")\n'
                f'    }}\n'
                f'    val fnEsc = fn.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", " ")\n'
                f'    val flEsc = fl.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", " ")\n'
                f'    s"""{{"line":$ln,"code":"$cd","function":"$fnEsc","file":"$flEsc"}}"""\n'
                f'  }}.mkString(",")\n'
                f'  raptorBatchLines += ("JOERN_FLOW:[" + steps + "]")\n'
                f'}}\n'
                f'}}'
            )

        lines.append(
            '"JOERN_FLOWS_START\\n" + raptorBatchLines.mkString("\\n") '
            '+ "\\nJOERN_FLOWS_END"'
        )
        query = "\n".join(lines)

        result = self.query(query, timeout=timeout, validate=True, check_length=False)
        if result.errors:
            logger.warning("batch taint query errors: %s", result.errors)
        return result.flows

    def _submit_query(
        self,
        content: str,
        *,
        timeout: int = 300,
        cancel_check: Callable[[], bool] | None = None,
    ) -> JoernResult:
        if cancel_check is not None:
            return self.query_cancellable(
                content, timeout=timeout, cancel_check=cancel_check,
                validate=True, check_length=False,
            )
        return self.query(
            content, timeout=timeout, validate=True, check_length=False,
        )

    def run_tiered_sweep(
        self,
        *,
        timeout: int | None = None,
        lang_profile: Any | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> JoernResult:
        """Run the tiered taint sweep with per-language tuning.

        Reads tiered_taint.sc, substitutes placeholders from the
        lang_profile (or defaults to Python profile), and submits.
        When *cancel_check* is provided, uses the async submit+poll
        path so the caller can abort mid-query.
        """
        if timeout is None:
            timeout = self._query_timeout_s

        script_path = Path(__file__).parent / "queries" / "tiered_taint.sc"
        if not script_path.exists():
            return JoernResult(
                query="tiered_taint.sc",
                errors=[f"script not found: {script_path}"],
            )

        if lang_profile is None:
            from .lang_config import DEFAULT
            lang_profile = DEFAULT

        content = script_path.read_text(encoding="utf-8")

        sink_items = ", ".join(f'"{s}"' for s in lang_profile.sinks)
        content = content.replace("__DANGEROUS_SINKS__", f"List({sink_items})")
        content = content.replace(
            "__EFFECTIVE_DEPTH__", str(lang_profile.max_call_depth),
        )
        content = content.replace(
            "__MAX_ARGS__", str(lang_profile.max_args_to_allow),
        )
        content = content.replace(
            "__MAX_OUTPUT_ARGS__", str(lang_profile.max_output_args_expansion),
        )

        from .semantics import render_context_arg, render_semantics_decl
        content = content.replace(
            "__SEMANTICS_DECL__\n", render_semantics_decl(self._flow_semantics),
        )
        content = content.replace(
            "__CTX_SEMANTICS__", render_context_arg(self._flow_semantics),
        )

        return self._submit_query(
            content, timeout=timeout, cancel_check=cancel_check,
        )

    def run_summary_batch(
        self,
        method_names: list[str],
        *,
        timeout: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> dict[str, JoernMethodSummary]:
        """Run taint-rule, precondition, and return summaries for multiple methods.

        Composes all three summary scripts into a single REPL submission
        to amortise the Scala compilation cost across all methods.
        Returns a dict keyed by method name.
        """
        if not method_names:
            return {}
        if not self._cpg_loaded:
            logger.warning("run_summary_batch: no CPG loaded")
            return {}
        if timeout is None:
            timeout = self._query_timeout_s

        from .runner import _build_summary_batch_query, parse_summary_output

        query = _build_summary_batch_query(method_names)
        if query is None:
            logger.warning("run_summary_batch: invalid method names")
            return {}

        if cancel_check is not None:
            result = self.query_cancellable(
                query, timeout=timeout, cancel_check=cancel_check,
                validate=True, check_length=False,
            )
        else:
            result = self.query(
                query, timeout=timeout, validate=True, check_length=False,
            )

        if result.errors:
            logger.warning("summary batch errors: %s", result.errors)
            return {}

        return parse_summary_output(result.raw_output)

    @classmethod
    def from_tunables(cls, tunables: JoernTunables | None = None) -> JoernServer:
        """Create a server instance from JoernTunables."""
        if tunables is None:
            tunables = JoernTunables()
        return cls(
            heap_mb=tunables.heap_mb,
            query_timeout_s=tunables.query_timeout_s,
        )

    @property
    def port(self) -> int | None:
        return self._port

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def __del__(self) -> None:
        self.stop()
