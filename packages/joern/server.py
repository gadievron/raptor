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

import json
import logging
import re
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

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

logger = logging.getLogger(__name__)

_BOOT_TIMEOUT_S = 120
_BOOT_POLL_INTERVAL_S = 2
_QUERY_TIMEOUT_S = 300
_HEALTH_QUERY = "1+1"
_SHUTDOWN_GRACE_S = 5
_REPL_BRIDGE_NAME = "repl-bridge"

# Version-adaptive rewrites for Joern API changes.
# Each entry is (old_str, new_str) applied when a query fails compilation.
# Written for v4 (current); rewrites downgrade to v3 patterns.
_V4_TO_V3_REWRITES: list[tuple[str, str]] = [
    # v4 wraps EngineConfig in EngineContext; v3 passes EngineConfig directly
    ("EngineContext(config = tier1Config)", "tier1Config"),
    ("EngineContext(config = tier2Config)", "tier2Config"),
    # v4 moved Path from queryengine to language
    (
        "io.joern.dataflowengineoss.language.Path",
        "io.joern.dataflowengineoss.queryengine.Path",
    ),
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SCALA_ERROR_MARKERS = ("-- [E", "error:", "Error:")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _has_scala_error(stdout: str) -> bool:
    """Detect Scala compilation errors in stdout.

    The Joern REPL returns success=True even when the Scala compiler
    emits errors. The error text appears in stdout with ANSI codes.
    """
    if not stdout:
        return False
    plain = _strip_ansi(stdout[:2000])
    return any(marker in plain for marker in _SCALA_ERROR_MARKERS)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
    bridge = joern_dir / _REPL_BRIDGE_NAME
    if bridge.exists():
        return str(bridge)
    import shutil
    return shutil.which(_REPL_BRIDGE_NAME)


class JoernServer:
    """Manages a persistent ``joern --server`` process.

    The server listens on 127.0.0.1 with a random port.  Queries
    are submitted via ``POST /query-sync`` and return synchronously.

    Sandbox note: the server process runs unsandboxed — same trust
    level as the LLM harness itself.  The CPG build step
    (``joern-parse``) that processes untrusted target code runs
    sandboxed via ``core.sandbox.run``.  The server only receives
    RAPTOR-authored CPGQL queries validated by ``_validate_query``,
    not raw target input.
    """

    def __init__(
        self,
        *,
        heap_mb: int | None = None,
        boot_timeout_s: int = _BOOT_TIMEOUT_S,
        query_timeout_s: int = _QUERY_TIMEOUT_S,
    ):
        self._heap_mb = heap_mb
        self._boot_timeout_s = boot_timeout_s
        self._query_timeout_s = query_timeout_s
        self._port: int | None = None
        self._proc: subprocess.Popen | None = None
        self._base_url: str | None = None
        self._cpg_loaded = False
        self._http_client: Any | None = None
        self._version_downgrade: bool = False
        self._last_post_error: str = ""

    def start(self) -> None:
        """Boot the Joern server and wait for readiness."""
        if self._proc is not None:
            return

        binary = _repl_bridge_path() or _joern_path() or "joern"
        self._port = _find_free_port()
        self._base_url = f"http://127.0.0.1:{self._port}"

        cmd = [binary]
        if self._heap_mb is not None:
            cmd.append(f"-J-Xms{self._heap_mb}m")
            cmd.append(f"-J-Xmx{self._heap_mb}m")
        cmd.extend([
            "-J-XX:+UseZGC",
            "-J-XX:+ZGenerational",
            "-J-XX:+UseStringDeduplication",
            "-J-Djava.util.concurrent.ForkJoinPool.common.parallelism=6",
            "--server",
            "--server-host", "127.0.0.1",
            "--server-port", str(self._port),
        ])

        logger.info("starting Joern server on 127.0.0.1:%d", self._port)

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        if not self._wait_for_ready():
            self.stop()
            raise RuntimeError(
                f"Joern server failed to start within {self._boot_timeout_s}s"
            )

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
            try:
                resp = self._post_sync(_HEALTH_QUERY, timeout=5)
                if resp is not None:
                    return True
            except Exception:
                pass
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
        except Exception:
            pass

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
        except Exception:
            pass

    def stop(self) -> None:
        """Shut down the Joern server."""
        if self._proc is None:
            return

        pid = self._proc.pid
        logger.info("stopping Joern server (pid %d)", pid)

        try:
            self._proc.terminate()
            self._proc.wait(timeout=_SHUTDOWN_GRACE_S)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)
        except OSError:
            pass

        if self._http_client is not None:
            try:
                self._http_client.close()
            except Exception:
                pass
            self._http_client = None
        self._proc = None
        self._port = None
        self._base_url = None
        self._cpg_loaded = False

    def is_alive(self) -> bool:
        if self._proc is None or self._proc.poll() is not None:
            return False
        try:
            resp = self._post_sync(_HEALTH_QUERY, timeout=5)
            return resp is not None
        except Exception:
            return False

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

        logger.info("CPG loaded in %.1fs", elapsed)
        self._cpg_loaded = True

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
        cancel_check: "Callable[[], bool] | None" = None,
    ) -> JoernResult:
        """Execute a .sc script file via the server.

        Reads the script content and submits it as an inline query.
        When *cancel_check* is provided, uses the async submit+poll
        path so the caller can abort mid-query.
        """
        script_path = Path(script_path)
        if not script_path.exists():
            return JoernResult(
                query=str(script_path),
                errors=[f"script not found: {script_path}"],
            )

        content = script_path.read_text(encoding="utf-8")
        if cancel_check is not None:
            return self.query_cancellable(
                content, timeout=timeout, cancel_check=cancel_check,
                validate=True, check_length=False,
            )
        return self.query(content, timeout=timeout, validate=True, check_length=False)

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
        try:
            if self._http_client is None:
                self._http_client = _httpx.Client(
                    timeout=_httpx.Timeout(timeout, connect=5.0),
                )
            resp = self._http_client.post(
                url, json=payload, timeout=timeout,
            )
            return resp.json()
        except Exception as e:
            if "timed out" in str(e).lower() or "timeout" in type(e).__name__.lower():
                self._last_post_error = f"query timed out after {timeout}s"
            elif "connect" in str(e).lower() or "refused" in str(e).lower():
                self._last_post_error = f"connection failed: {e}"
            else:
                self._last_post_error = str(e)
            logger.debug("query-sync (httpx) failed: %s", e)
            return None

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
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
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
            if _httpx is not None and self._http_client is not None:
                resp = self._http_client.post(url, json=payload, timeout=10)
                data = resp.json()
            else:
                body = json.dumps(payload).encode("utf-8")
                req = Request(url, data=body,
                              headers={"Content-Type": "application/json"},
                              method="POST")
                with urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            return data.get("uuid") or data.get("id")
        except Exception as e:
            logger.debug("async query submit failed: %s", e)
            return None

    def _get_result(self, uuid: str) -> dict[str, Any] | None:
        """GET /result/<uuid>. Returns response dict if ready, None if pending."""
        if self._base_url is None:
            return None
        url = f"{self._base_url}/result/{uuid}"
        try:
            if _httpx is not None and self._http_client is not None:
                resp = self._http_client.get(url, timeout=5)
                data = resp.json()
            else:
                req = Request(url, method="GET")
                with urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            if data.get("success") is not None:
                return data
            return None
        except Exception:
            return None

    def query_cancellable(
        self,
        cpgql: str,
        *,
        timeout: int | None = None,
        cancel_check: "Callable[[], bool] | None" = None,
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
        return JoernResult(
            query=cpgql, errors=["timeout (async poll)"],
            elapsed_ms=elapsed_ms,
        )

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
    ) -> list[TaintFlow]:
        """Run a source-to-sink taint query via the server."""
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

        lines = [
            "import io.joern.dataflowengineoss.queryengine._",
            "import io.joern.dataflowengineoss.language._",
            "import io.shiftleft.semanticcpg.language._",
            "import io.shiftleft.codepropertygraph.generated.nodes.CfgNode",
            "import scala.util.Try",
            f"val batchConfig = EngineConfig(maxCallDepth = {max_call_depth})",
            "implicit val batchContext: EngineContext = "
            "EngineContext(config = batchConfig)",
        ]

        for i, (src, sink) in enumerate(valid_pairs):
            lines.append(
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
                f'    s"""{{"line":$$ln,"code":"$$cd","function":"$$fnEsc","file":"$$flEsc"}}"""\n'
                f'  }}.mkString(",")\n'
                f'  println("JOERN_FLOW:[" + steps + "]")\n'
                f'}}'
            )

        lines.append('"batch-done"')
        query = "\n".join(lines)

        result = self.query(query, timeout=timeout, validate=True, check_length=False)
        if result.errors:
            logger.warning("batch taint query errors: %s", result.errors)
        return result.flows

    def _apply_version_rewrites(self, content: str) -> str:
        """Apply cached version rewrites from prior adaptation."""
        if self._version_downgrade:
            for old, new in _V4_TO_V3_REWRITES:
                content = content.replace(old, new)
        return content

    def _try_version_fallback(self, content: str) -> str | None:
        """Apply v4→v3 rewrites and test compilation.

        Returns the rewritten content if it compiles, None otherwise.
        Caches the result so future queries skip the probe.
        """
        candidate = content
        for old, new in _V4_TO_V3_REWRITES:
            candidate = candidate.replace(old, new)
        if candidate == content:
            return None
        result = self._submit_query(candidate, timeout=30)
        if not result.errors:
            self._version_downgrade = True
            logger.info("joern version adaptation: applied v3 API rewrites")
            return candidate
        return None

    def _submit_query(
        self,
        content: str,
        *,
        timeout: int = 300,
        cancel_check: "Callable[[], bool] | None" = None,
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
        cancel_check: "Callable[[], bool] | None" = None,
    ) -> JoernResult:
        """Run the tiered taint sweep with per-language tuning.

        Reads tiered_taint.sc, substitutes placeholders from the
        lang_profile (or defaults to Python profile), and submits.
        When *cancel_check* is provided, uses the async submit+poll
        path so the caller can abort mid-query.

        Version-adaptive: if the query fails with a Scala compilation
        error, known import substitutions are tried automatically
        (e.g. Path moved between packages across Joern versions).
        Successful substitutions are cached for the session.
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

        content = self._apply_version_rewrites(content)

        result = self._submit_query(
            content, timeout=timeout, cancel_check=cancel_check,
        )

        if result.errors and any("query failed:" in e for e in result.errors):
            adapted = self._try_version_fallback(content)
            if adapted is not None:
                result = self._submit_query(
                    adapted, timeout=timeout, cancel_check=cancel_check,
                )

        return result

    def run_summary_batch(
        self,
        method_names: list[str],
        *,
        timeout: int | None = None,
        cancel_check: "Callable[[], bool] | None" = None,
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

    def __enter__(self) -> JoernServer:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def __del__(self) -> None:
        self.stop()
