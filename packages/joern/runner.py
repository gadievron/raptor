"""Joern CPG runner — build graphs, execute queries, parse results.

Follows the packages/coccinelle/runner.py pattern: subprocess-based,
sandbox-first, injectable runner for testing.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path
import threading
from typing import Callable, List, Optional, Set

from .models import FlowStep, JoernCPG, JoernMethodSummary, JoernResult, TaintFlow
from .prereqs import _joern_parse_path, _joern_path

logger = logging.getLogger(__name__)

_JOERN_PARSE_BIN = "joern-parse"

_QUERY_MAX_LEN = 4096

_DANGEROUS_QUERY_PATTERNS = re.compile(
    r"java\.io\b|java\.nio\b|scala\.io\b"
    r"|java\.net\b|scala\.sys\b"
    r"|Runtime\.exec|ProcessBuilder|sys\.process"
    r"|Class\.forName|getDeclaredMethod|getDeclaredField"
    r"|getRuntime",
    re.IGNORECASE,
)

_IDENTIFIER_QUALIFIED_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
)


def _validate_query(query: str, *, check_length: bool = True) -> Optional[str]:
    """Validate a query string. Returns error message or None if clean."""
    if check_length and len(query) > _QUERY_MAX_LEN:
        return f"query exceeds {_QUERY_MAX_LEN}-char cap ({len(query)})"
    m = _DANGEROUS_QUERY_PATTERNS.search(query)
    if m:
        return f"query contains blocked pattern: {m.group()}"
    return None


def _validate_substitution_value(value: str) -> bool:
    """Validate a value to be substituted into a query template.

    Bare identifiers: is_valid_identifier().
    Qualified names (a.b.c): each segment must be a valid identifier.
    """
    if not value:
        return False
    return bool(_IDENTIFIER_QUALIFIED_RE.match(value))


def _escape_scala_string(value: str) -> str:
    """Escape a value for Scala string literal context."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _default_sandbox_runner():
    """Return the default sandbox runner for subprocess calls."""
    try:
        from core.sandbox import run as sandbox_run
        return sandbox_run
    except ImportError:
        return subprocess.run


_STALL_CALIBRATION_FILES = 10
_STALL_MULTIPLIER = 3
_STALL_FLOOR_S = 30


class _StallMonitor:
    """Monitor joern-parse stderr for per-file progress and kill on stall.

    Measures wall clock of the first N files, then sets a stall threshold
    of max(p90 * 3, 30s). If any subsequent file exceeds that threshold
    with no progress, the subprocess is killed.
    """

    def __init__(
        self,
        proc: subprocess.Popen,
        on_progress: Optional[Callable] = None,
    ):
        self._proc = proc
        self._on_progress = on_progress
        self._file_times: List[float] = []
        self._threshold: Optional[float] = None
        self._last_progress = time.monotonic()
        self._total_files = 0
        self._killed = False
        self._stderr_lines: List[str] = []

    def run(self) -> None:
        """Read stderr line by line, track file processing times."""
        for raw_line in self._proc.stderr:
            line = raw_line.strip()
            if not line:
                continue
            self._stderr_lines.append(line)

            if self._is_file_progress(line):
                now = time.monotonic()
                elapsed = now - self._last_progress
                self._total_files += 1

                if self._total_files <= _STALL_CALIBRATION_FILES:
                    self._file_times.append(elapsed)
                    if self._total_files == _STALL_CALIBRATION_FILES:
                        self._calibrate()
                elif self._threshold and elapsed > self._threshold:
                    logger.warning(
                        "Joern CPG build stalled after %d/%s files "
                        "(%.1fs > %.1fs threshold)",
                        self._total_files, "?",
                        elapsed, self._threshold,
                    )
                    self._proc.kill()
                    self._killed = True
                    return

                self._last_progress = now
                if self._on_progress:
                    self._on_progress(
                        f"Joern CPG: {self._total_files} files processed"
                    )

    def _calibrate(self) -> None:
        if len(self._file_times) < 2:
            self._threshold = _STALL_FLOOR_S
            return
        sorted_times = sorted(self._file_times)
        p90_idx = int(len(sorted_times) * 0.9) - 1
        p90 = sorted_times[max(0, min(p90_idx, len(sorted_times) - 1))]
        self._threshold = max(p90 * _STALL_MULTIPLIER, _STALL_FLOOR_S)
        logger.debug(
            "Joern stall threshold calibrated: p90=%.2fs, threshold=%.1fs",
            p90, self._threshold,
        )

    @staticmethod
    def _is_file_progress(line: str) -> bool:
        low = line.lower()
        return (
            "parsing" in low
            or "processing" in low
            or "analyzing" in low
            or line.endswith(".c")
            or line.endswith(".cpp")
            or line.endswith(".h")
            or line.endswith(".py")
            or line.endswith(".java")
            or line.endswith(".js")
        )

    @property
    def was_killed(self) -> bool:
        return self._killed

    @property
    def stderr_output(self) -> str:
        return "\n".join(self._stderr_lines)


def build_cpg(
    target: Path,
    *,
    languages: Optional[Set[str]] = None,
    output_dir: Optional[Path] = None,
    timeout: int = 600,
    subprocess_runner=None,
    on_progress: Optional[Callable] = None,
) -> JoernCPG:
    """Parse target directory into a Code Property Graph.

    Returns a JoernCPG handle. The CPG is written to output_dir
    (default: tempdir) as a binary file.
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise ValueError(f"target must be a directory: {target}")

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="raptor-joern-cpg-"))
    output_dir.mkdir(parents=True, exist_ok=True)

    cpg_path = output_dir / "cpg.bin"

    joern_parse = _joern_parse_path() or _JOERN_PARSE_BIN
    cmd = [joern_parse, "--output", str(cpg_path), str(target)]

    if languages:
        cmd.extend(["--language", ",".join(sorted(languages))])

    runner = subprocess_runner or _default_sandbox_runner()

    start = time.monotonic()

    if on_progress is not None and subprocess_runner is None:
        return _build_cpg_with_stall_monitor(
            cmd, cpg_path, target, languages, timeout, on_progress,
        )

    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            target=str(target),
            output=str(output_dir),
        )
    except TypeError:
        try:
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("joern-parse timed out after %ds", timeout)
            return JoernCPG(path=cpg_path, target=target)
        except OSError as e:
            logger.error("joern-parse failed: %s", e)
            return JoernCPG(path=cpg_path, target=target)
    except subprocess.TimeoutExpired:
        logger.warning("joern-parse timed out after %ds", timeout)
        return JoernCPG(path=cpg_path, target=target)
    except OSError as e:
        logger.error("joern-parse failed: %s", e)
        return JoernCPG(path=cpg_path, target=target)

    elapsed = int((time.monotonic() - start) * 1000)

    if proc.returncode != 0:
        logger.warning(
            "joern-parse returned %d: %s",
            proc.returncode,
            proc.stderr[:500] if proc.stderr else "(no stderr)",
        )

    detected_langs: Set[str] = set()
    if proc.stdout:
        for line in proc.stdout.splitlines():
            if "language:" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    detected_langs.add(parts[1].strip().lower())

    return JoernCPG(
        path=cpg_path,
        target=target,
        languages=languages or detected_langs,
        build_time_ms=elapsed,
    )


def _build_cpg_with_stall_monitor(
    cmd: list,
    cpg_path: Path,
    target: Path,
    languages: Optional[Set[str]],
    timeout: int,
    on_progress: Callable,
) -> JoernCPG:
    """Build CPG with real-time stderr monitoring and adaptive stall detection."""
    try:
        from core.config import RaptorConfig
        safe_env = RaptorConfig.get_safe_env()
    except ImportError:
        safe_env = None

    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=safe_env,
        )
    except OSError as e:
        logger.error("joern-parse failed to start: %s", e)
        return JoernCPG(path=cpg_path, target=target)

    monitor = _StallMonitor(proc, on_progress=on_progress)
    monitor_thread = threading.Thread(
        target=monitor.run, daemon=True, name="joern-stall-monitor",
    )
    monitor_thread.start()

    # Wait for the process without reading its pipes -- the monitor
    # thread owns stderr and stdout is collected after it exits.
    # Using proc.communicate() here would race with the monitor
    # thread on the stderr pipe (two unsynchronised consumers).
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        logger.warning("joern-parse timed out after %ds", timeout)
        return JoernCPG(path=cpg_path, target=target)

    monitor_thread.join(timeout=5)

    stdout = proc.stdout.read() if proc.stdout else ""

    elapsed = int((time.monotonic() - start) * 1000)

    if monitor.was_killed:
        logger.warning("joern-parse was killed by stall monitor")
        return JoernCPG(path=cpg_path, target=target)

    if proc.returncode != 0:
        stderr_text = monitor.stderr_output
        logger.warning(
            "joern-parse returned %d: %s",
            proc.returncode,
            stderr_text[:500] if stderr_text else "(no stderr)",
        )

    detected_langs: Set[str] = set()
    if stdout:
        for line in stdout.splitlines():
            if "language:" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    detected_langs.add(parts[1].strip().lower())

    return JoernCPG(
        path=cpg_path,
        target=target,
        languages=languages or detected_langs,
        build_time_ms=elapsed,
    )


def run_query(
    cpg: JoernCPG,
    query: str,
    *,
    timeout: int = 300,
    subprocess_runner=None,
    validate: bool = True,
) -> JoernResult:
    """Execute a Joern/CPGQL query against a built CPG.

    query: inline CPGQL string OR path to a .sc script file.
    validate: if True, run query validation before execution.
    """
    if not cpg.exists():
        return JoernResult(
            query=query,
            errors=[f"CPG not found: {cpg.path}"],
        )

    if validate:
        err = _validate_query(query)
        if err:
            return JoernResult(query=query, errors=[err])

    joern = _joern_path() or "joern"

    query_path = Path(query)
    try:
        is_script_file = query_path.exists() and query_path.suffix == ".sc"
    except OSError:
        is_script_file = False
    if is_script_file:
        try:
            script_body = query_path.read_text()
        except OSError as e:
            return JoernResult(query=query, errors=[f"cannot read script: {e}"])
    else:
        script_body = query

    # joern's CLI flag surface drifts across releases: `--script-content`
    # does not exist in 4.x, and `--import` there means "compile .sc onto
    # the classpath", not "load this CPG".  The stable interface across
    # versions is `--script` plus the importCpg predef, so wrap every
    # query in a temporary script that loads the CPG itself.  Written
    # next to the CPG so the sandbox read grant covers it.
    wrapper = (
        f'importCpg("{_escape_scala_string(str(cpg.path))}")\n'
        f"{script_body}\n"
    )
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=cpg.path.parent, suffix=".sc",
            prefix="raptor-query-", delete=False,
        ) as f:
            f.write(wrapper)
            wrapper_path = Path(f.name)
    except OSError as e:
        return JoernResult(query=query, errors=[f"cannot write query script: {e}"])

    cmd = [joern, "--script", str(wrapper_path)]

    runner = subprocess_runner or _default_sandbox_runner()

    start = time.monotonic()
    try:
        try:
            # cwd + output grant point at the CPG dir: importCpg copies
            # the CPG into a `workspace/` under the process cwd, which
            # must be writable inside the sandbox.
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                target=str(cpg.target),
                output=str(cpg.path.parent),
                cwd=str(cpg.path.parent),
                block_network=True,
            )
        except TypeError:
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return JoernResult(
            query=query,
            errors=[f"query timed out after {timeout}s"],
        )
    except OSError as e:
        return JoernResult(query=query, errors=[str(e)])
    finally:
        try:
            wrapper_path.unlink()
        except OSError:
            pass

    elapsed = int((time.monotonic() - start) * 1000)

    flows, errors = _parse_output(proc.stdout or "")
    if proc.stderr:
        stderr_errors = _parse_errors(proc.stderr)
        errors.extend(stderr_errors)

    if proc.returncode != 0 and not errors:
        errors.append(f"joern exited with code {proc.returncode}")

    return JoernResult(
        query=query,
        flows=flows,
        raw_output=proc.stdout or "",
        errors=errors,
        elapsed_ms=elapsed,
    )


def run_taint_query(
    cpg: JoernCPG,
    source_method: str,
    sink_call: str,
    *,
    source_param: Optional[str] = None,
    timeout: int = 300,
    subprocess_runner=None,
    max_call_depth: int = 2,
) -> List[TaintFlow]:
    """Run a source-to-sink taint tracking query.

    Returns list of TaintFlow objects. Validates method/sink names
    against the identifier allowlist before substitution.
    """
    if not _validate_substitution_value(source_method):
        logger.warning(
            "rejecting source_method %r: fails identifier validation",
            source_method[:80],
        )
        return []

    if not _validate_substitution_value(sink_call):
        logger.warning(
            "rejecting sink_call %r: fails identifier validation",
            sink_call[:80],
        )
        return []

    if source_param and not _validate_substitution_value(source_param):
        logger.warning(
            "rejecting source_param %r: fails identifier validation",
            source_param[:80],
        )
        return []

    safe_source = _escape_scala_string(source_method)
    safe_sink = _escape_scala_string(sink_call)

    query = _build_taint_query(safe_source, safe_sink, source_param,
                              max_call_depth=max_call_depth)

    err = _validate_query(query)
    if err:
        logger.warning("generated taint query failed validation: %s", err)
        return []

    result = run_query(
        cpg, query,
        timeout=timeout,
        subprocess_runner=subprocess_runner,
        validate=False,
    )

    if result.errors:
        logger.warning("taint query errors: %s", result.errors)

    return result.flows


def _build_taint_query(
    source_method: str,
    sink_call: str,
    source_param: Optional[str] = None,
    *,
    max_call_depth: int = 2,
) -> str:
    """Build an inline CPGQL taint query string."""
    if source_param:
        safe_param = _escape_scala_string(source_param)
        source_filter = (
            f'cpg.method.name("{source_method}")'
            f'.parameter.name("{safe_param}")'
        )
    else:
        source_filter = f'cpg.method.name("{source_method}").parameter'

    query = _TAINT_QUERY_TEMPLATE.replace("__SOURCE_FILTER__", source_filter)
    query = query.replace("__SINK_CALL__", sink_call)
    query = query.replace("__MAX_CALL_DEPTH__", str(int(max_call_depth)))
    return query


_TAINT_QUERY_TEMPLATE = r'''import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import scala.util.Try

implicit val engineContext: EngineContext = EngineContext(config = EngineConfig(maxCallDepth = __MAX_CALL_DEPTH__))
val source = __SOURCE_FILTER__
val sink = cpg.call.name("__SINK_CALL__").argument
val flows = sink.reachableByFlows(source).l
val flowLines = flows.map { flow =>
  val steps = flow.elements.map { e =>
    val ln = e.lineNumber.getOrElse(0)
    val cd = e.code.take(200).replace("\\", "\\\\").replace("\"", "\\\"")
    val (fn, fl) = e match {
      case n: CfgNode =>
        (Try(n.method.name).getOrElse(""), Try(n.method.filename).getOrElse(""))
      case _ => ("", "")
    }
    val fnEsc = fn.replace("\\", "\\\\").replace("\"", "\\\"")
    val flEsc = fl.replace("\\", "\\\\").replace("\"", "\\\"")
    s"""{"line":${ln},"code":"${cd}","function":"${fnEsc}","file":"${flEsc}"}"""
  }.mkString(",")
  "JOERN_FLOW:[" + steps + "]"
}
flowLines.foreach(println)
"JOERN_FLOWS_START\n" + flowLines.mkString("\n") + "\nJOERN_FLOWS_END"
'''


def _build_taint_exists_query(
    source_method: str,
    sink_call: str,
    *,
    max_call_depth: int = 2,
) -> str:
    """Build a cheap existence-only taint query.

    Uses ``reachableBy`` + ``.take(1).l.nonEmpty`` instead of
    ``reachableByFlows`` (full path reconstruction).  Returns a query
    whose output contains ``JOERN_EXISTS:true`` or ``JOERN_EXISTS:false``.
    """
    source_filter = f'cpg.method.name("{source_method}").parameter'
    return (
        "import io.joern.dataflowengineoss.queryengine._\n"
        "import io.joern.dataflowengineoss.language._\n"
        "import io.shiftleft.semanticcpg.language._\n"
        "\n"
        "implicit val engineContext: EngineContext = EngineContext("
        f"config = EngineConfig(maxCallDepth = {int(max_call_depth)}))\n"
        f"val source = {source_filter}\n"
        f'val sink = cpg.call.name("{sink_call}").argument\n'
        "val exists = sink.reachableBy(source).take(1).l.nonEmpty\n"
        's"JOERN_EXISTS:${exists}"'
    )


def _target_content_hash(target: Path) -> str:
    """Fast content hash: sorted file listing with mtimes."""
    import hashlib
    h = hashlib.sha256()
    source_exts = {
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
        ".py", ".java", ".js", ".ts", ".go", ".rs",
    }
    entries = []
    for p in sorted(target.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in source_exts:
            continue
        try:
            st = p.stat()
            entries.append(f"{p.relative_to(target)}:{st.st_size}:{int(st.st_mtime)}")
        except OSError:
            continue
    h.update("\n".join(entries).encode())
    return h.hexdigest()[:16]


def _write_cpg_manifest(
    cpg_dir: Path, target: Path, content_hash: str,
    languages: Optional[Set[str]] = None, build_time_ms: int = 0,
) -> None:
    """Write manifest.json alongside the cached CPG."""
    manifest = {
        "target_path": str(target),
        "content_hash": content_hash,
        "build_time_ms": build_time_ms,
        "languages": sorted(languages or []),
    }
    manifest_path = cpg_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))


def _read_cpg_manifest(cpg_dir: Path) -> Optional[dict]:
    """Read manifest.json, returning None if missing or corrupt."""
    manifest_path = cpg_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def load_cached_cpg(
    target: Path,
    cache_dir: Path,
) -> Optional[JoernCPG]:
    """Return a cached CPG if fresh, None if stale or missing."""
    cpg_dir = cache_dir / "joern-cpg"
    cpg_path = cpg_dir / "cpg.bin"
    if not cpg_path.exists():
        return None

    manifest = _read_cpg_manifest(cpg_dir)
    if manifest is None:
        return None

    current_hash = _target_content_hash(target)
    if manifest.get("content_hash") != current_hash:
        logger.info(
            "CPG cache stale (hash %s → %s), will rebuild",
            manifest.get("content_hash", "?")[:8], current_hash[:8],
        )
        return None

    langs = set(manifest.get("languages", []))
    logger.info("CPG cache hit for %s", target)
    return JoernCPG(
        path=cpg_path,
        target=target,
        languages=langs,
        build_time_ms=manifest.get("build_time_ms", 0),
    )


def build_cpg_cached(
    target: Path,
    cache_dir: Path,
    *,
    languages: Optional[Set[str]] = None,
    timeout: int = 600,
    subprocess_runner=None,
    on_progress: Optional[Callable] = None,
) -> JoernCPG:
    """Build or reuse a cached CPG for the target.

    cache_dir is typically the project directory. The CPG is stored
    in cache_dir/joern-cpg/cpg.bin with a manifest for freshness.
    """
    cached = load_cached_cpg(target, cache_dir)
    if cached is not None:
        return cached

    cpg_dir = cache_dir / "joern-cpg"
    cpg = build_cpg(
        target,
        languages=languages,
        output_dir=cpg_dir,
        timeout=timeout,
        subprocess_runner=subprocess_runner,
        on_progress=on_progress,
    )

    if cpg.exists():
        content_hash = _target_content_hash(target)
        _write_cpg_manifest(
            cpg_dir, target, content_hash,
            languages=cpg.languages,
            build_time_ms=cpg.build_time_ms,
        )

    return cpg


def cleanup_cpg(cpg: JoernCPG) -> None:
    """Remove the CPG binary from disk."""
    try:
        cpg.path.unlink(missing_ok=True)
        parent = cpg.path.parent
        try:
            parent.rmdir()
        except OSError:
            pass
    except OSError as e:
        logger.warning("cleanup_cpg failed: %s", e)


_CALL_RE = re.compile(r"(\w+)\s*\(")


def _infer_function(code: str) -> str:
    m = _CALL_RE.search(code)
    return m.group(1) if m else code.strip()


def _infer_call(code: str) -> str:
    m = _CALL_RE.search(code)
    return m.group(1) if m else ""


def _try_parse_flow_json(json_str: str) -> tuple:
    try:
        data = json.loads(json_str)
        return data, None
    except (json.JSONDecodeError, ValueError) as exc:
        return None, str(exc)


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _parse_output(stdout: str) -> tuple:
    """Parse Joern stdout for JOERN_FLOW: lines.

    Returns (flows, errors).

    REPL output format drifts across joern versions: the Scala 3 REPL
    (joern 4.x) wraps values in ANSI colour codes and echoes the final
    string as ``val resN: String = \"\"\"JOERN_FLOWS_START...``, and
    each flow may appear multiple times (println + value echoes, the
    latter with escaped quotes).  So: strip ANSI, match sentinels by
    prefix/suffix rather than exact line, accept any line whose payload
    parses as JSON, and dedupe.
    """
    flows: List[TaintFlow] = []
    errors: List[str] = []
    seen_flows: Set[str] = set()
    in_flows = False

    for raw_line in stdout.splitlines():
        line = _ANSI_ESCAPE_RE.sub("", raw_line).strip()
        if line.endswith("JOERN_FLOWS_START"):
            in_flows = True
            continue
        if line.startswith("JOERN_FLOWS_END") or line.endswith("JOERN_FLOWS_END"):
            in_flows = False
            continue

        marker_idx = line.find("JOERN_FLOW:")
        if marker_idx < 0:
            continue

        json_str = line[marker_idx + len("JOERN_FLOW:"):]
        steps_data, parse_err = _try_parse_flow_json(json_str)
        if parse_err:
            # Value echoes re-print flows with escaped quotes; only
            # report unparseable lines inside the sentinel block that
            # aren't such echoes.
            if in_flows and '\\"' not in json_str:
                errors.append(f"failed to parse flow: {parse_err}")
            continue
        dedupe_key = json.dumps(steps_data, sort_keys=True)
        if dedupe_key in seen_flows:
            continue
        seen_flows.add(dedupe_key)
        if isinstance(steps_data, list) and steps_data:
            steps = [FlowStep.from_dict(s) for s in steps_data if isinstance(s, dict)]
            if steps:
                src_fn = steps[0].function or _infer_function(steps[0].code)
                sink_fn = _infer_call(steps[-1].code) if len(steps) > 1 else ""
                funcs = {s.function for s in steps if s.function}
                flow = TaintFlow(
                    source_method=src_fn,
                    source_param=steps[0].variable or steps[0].code,
                    sink_call=sink_fn,
                    sink_arg_idx=-1,
                    steps=steps,
                    is_inter_procedural=len(funcs) > 1,
                )
                flows.append(flow)

    return flows, errors


def _parse_dark_methods(stdout: str) -> List[str]:
    """Extract JOERN_DARK: markers — methods with uncertain reachability."""
    dark: List[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("JOERN_DARK:"):
            name = line[len("JOERN_DARK:"):].strip()
            if name:
                dark.append(name)
    return dark


def _parse_errors(stderr: str) -> List[str]:
    """Extract error messages from Joern stderr."""
    errors: List[str] = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(kw in low for kw in ("error", "exception", "failed", "fatal")):
            if "deprecated" not in low and "warning" not in low:
                errors.append(line)
    return errors


def _build_summary_batch_query(method_names: list[str]) -> Optional[str]:
    """Build a Joern query that fetches summaries for multiple methods."""
    if not method_names:
        return None
    safe = [n for n in method_names if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", n)]
    if not safe:
        return None
    names_list = ", ".join(f'"{n}"' for n in safe)
    return (
        f"val names = List({names_list})\n"
        "names.map { n =>\n"
        '  val m = cpg.method.nameExact(n).headOption.getOrElse(null)\n'
        '  if (m != null) {\n'
        '    val taints = m.parameter.reachableBy(cpg.method.nameExact(n).parameter).code.l\n'
        '    val pre = m.ast.isCall.name(".*check.*|.*assert.*|.*validate.*").code.l\n'
        '    val ret = m.methodReturn.typ.name.l\n'
        '    s"METHOD:${n}|TAINTS:${taints.mkString(",")}|PRE:${pre.mkString(",")}|RET:${ret.mkString(",")}"\n'
        '  } else s"METHOD:${n}|NOTFOUND"\n'
        "}.mkString(\"\\n\")"
    )


def parse_summary_output(raw: str) -> dict[str, JoernMethodSummary]:
    """Parse the batch summary output into JoernMethodSummary objects."""
    results: dict[str, JoernMethodSummary] = {}
    for line in raw.splitlines():
        line = line.strip().strip('"')
        if not line.startswith("METHOD:"):
            continue
        parts = line.split("|")
        name = parts[0].removeprefix("METHOD:")
        if len(parts) < 2 or "NOTFOUND" in parts[1]:
            continue
        taints: list[str] = []
        pre: list[str] = []
        ret: list[str] = []
        for part in parts[1:]:
            if part.startswith("TAINTS:"):
                val = part.removeprefix("TAINTS:")
                taints = [v for v in val.split(",") if v]
            elif part.startswith("PRE:"):
                val = part.removeprefix("PRE:")
                pre = [v for v in val.split(",") if v]
            elif part.startswith("RET:"):
                val = part.removeprefix("RET:")
                ret = [v for v in val.split(",") if v]
        results[name] = JoernMethodSummary(
            method=name,
            taint_rules=taints,
            preconditions=pre,
            returns=ret,
        )
    return results
