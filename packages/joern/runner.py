"""Joern CPG runner — build graphs, execute queries, parse results.

Follows the packages/coccinelle/runner.py pattern: subprocess-based,
sandbox-first, injectable runner for testing.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import stat
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .models import FlowStep, JoernCPG, JoernMethodSummary, JoernResult, TaintFlow
from .prereqs import _joern_parse_path, _joern_path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

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


def _validate_query(query: str, *, check_length: bool = True) -> str | None:
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
    fullmatch, not match — a ``$`` anchor alone admits a trailing
    newline.
    """
    if not value:
        return False
    return bool(_IDENTIFIER_QUALIFIED_RE.fullmatch(value))


def _escape_scala_string(value: str) -> str:
    """Escape a value for Scala string literal context."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _default_sandbox_runner():
    """Return the default sandbox runner for subprocess calls.

    Fail-closed: when ``core.sandbox`` cannot be imported this raises
    ``core.run.sandbox_policy.SandboxUnavailableError`` instead of
    silently degrading to bare ``subprocess.run`` (joern parses
    untrusted source; its CPG frontends are a code-execution surface).
    Operators on hosts without sandbox support can explicitly opt in
    via ``RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1`` (loud warning +
    security-event emission).
    """
    try:
        from core.sandbox import run as sandbox_run
        return sandbox_run
    except ImportError as exc:
        from core.run.sandbox_policy import require_sandbox_or_optout
        require_sandbox_or_optout("joern (CPG build / query runner)", exc)
        return subprocess.run


_STALL_CALIBRATION_FILES = 10
_STALL_MULTIPLIER = 3
_STALL_FLOOR_S = 30


def _drain_stream(stream, chunks: list[str]) -> None:
    """Incrementally read a child's pipe so it can never block on a
    full OS pipe buffer; keeps partial output if the child is killed."""
    if stream is None:
        return
    try:
        for line in stream:
            chunks.append(line)  # noqa: PERF402 — incremental drain, not a copy
    except (OSError, ValueError):
        pass


class _StallMonitor:
    """Monitor joern-parse stderr for per-file progress and kill on stall.

    Measures wall clock of the first N files, then sets a stall threshold
    of max(p90 * 3, 30s). If any subsequent file exceeds that threshold
    with no progress, the subprocess is killed.
    """

    def __init__(
        self,
        proc: subprocess.Popen,
        on_progress: Callable | None = None,
    ) -> None:
        self._proc = proc
        self._on_progress = on_progress
        self._file_times: list[float] = []
        self._threshold: float | None = None
        self._last_progress = time.monotonic()
        self._total_files = 0
        self._killed = False
        self._stderr_lines: list[str] = []

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
            or line.endswith((".c", ".cpp", ".h", ".py", ".java", ".js"))
        )

    @property
    def was_killed(self) -> bool:
        return self._killed

    @property
    def stderr_output(self) -> str:
        return "\n".join(self._stderr_lines)


# ─── compile_commands.json → c2cpg frontend args ─────────────────────
#
# The c2cpg frontend resolves #include and macros from what it is told
# on the command line; without the build's -I/-D flags it silently
# misses build-configured code. A target's compile_commands.json (when
# the operator built the target) carries those flags — but the file
# ships with the SCANNED REPO, so its contents are untrusted: only
# -D/-U and -I tokens are extracted, values are charset-allowlisted,
# include dirs must resolve to existing directories inside the target
# root, and counts are capped. c2cpg's own --compilation-database mode
# is deliberately not used — it would hand the untrusted file to the
# frontend wholesale (file lists, arbitrary flags).
#
# c2cpg exposes only --define and --include (no -U / -std equivalents,
# verified against c2cpg --help), so -U participates in the
# config-dependent conflict rule (a name both defined and undefined
# across TUs is dropped, mirroring core/build/macro_config.py) but is
# never emitted.

_CC_DB_NAME = "compile_commands.json"
# Search order mirrors the binary-oracle auto-detect build dirs that
# plausibly hold a cmake/bear-generated database. First match wins.
_CC_SEARCH_SUBDIRS = ("", "build", "builddir", "out", "Debug", "Release")
_CC_MAX_BYTES = 32 * 1024 * 1024
_CC_MAX_ENTRIES = 2000
_CC_MAX_TOKENS_PER_ENTRY = 512
_CC_MAX_DEFINES = 64
_CC_MAX_INCLUDES = 32

_CC_DEFINE_NAME_RE = re.compile(r"^\w{1,128}$")
# No quotes, spaces, or shell metacharacters — argv is list-based so
# nothing is shell-evaluated, but a hostile value must not be able to
# smuggle option-shaped or log-forging content into the frontend argv.
_CC_DEFINE_VALUE_RE = re.compile(r"^[\w.\-+/:@,]{1,128}$")


@dataclass(frozen=True)
class FrontendArgs:
    """Sanitized c2cpg frontend flags recovered from compile_commands.json.

    ``defines`` holds ``NAME`` / ``NAME=VALUE`` strings, ``includes``
    absolute directory paths inside the target root. Both are emitted
    verbatim after joern-parse's ``--frontend-args`` separator.
    """

    defines: tuple = ()
    includes: tuple = ()

    def __bool__(self) -> bool:
        return bool(self.defines or self.includes)

    def to_argv(self) -> list:
        """joern-parse argv tail (empty when there is nothing to pass)."""
        if not self:
            return []
        argv = ["--frontend-args"]
        for d in self.defines:
            argv.extend(["--define", d])
        for i in self.includes:
            argv.extend(["--include", i])
        return argv

    def fingerprint(self) -> str:
        """Deterministic short hash for cache keying; empty when empty."""
        if not self:
            return ""
        payload = repr((self.defines, self.includes))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


_EMPTY_FRONTEND_ARGS = FrontendArgs()


def find_compile_commands(target: Path) -> Path | None:
    """First compile_commands.json under the target's build dirs, or None."""
    target = Path(target)
    candidates = [target / sub / _CC_DB_NAME if sub else target / _CC_DB_NAME
                  for sub in _CC_SEARCH_SUBDIRS]
    candidates.extend(sorted(target.glob(f"cmake-build-*/{_CC_DB_NAME}")))
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def _cc_entry_tokens(entry: dict) -> list:
    """Command tokens for one entry (``arguments`` array preferred,
    ``command`` string shlex-split) — mirrors core/build/macro_config."""
    if isinstance(entry.get("arguments"), list):
        toks = [str(a) for a in entry["arguments"]]
    else:
        cmd = entry.get("command")
        if not isinstance(cmd, str):
            return []
        try:
            toks = shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
    return toks[:_CC_MAX_TOKENS_PER_ENTRY]


def _cc_resolve_include(raw: str, entry_dir: str | None,
                        target_root: Path) -> str | None:
    """Resolve one -I operand to an existing directory inside the target
    root (realpath containment — symlink escapes rejected), else None."""
    if not raw or "\x00" in raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        base = None
        if isinstance(entry_dir, str) and entry_dir:
            base = Path(entry_dir)
            if not base.is_absolute():
                base = target_root / base
        p = (base or target_root) / p
    try:
        resolved = p.resolve()
        root = target_root.resolve()
        if not resolved.is_dir():
            return None
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return str(resolved)


def discover_frontend_args(target: Path) -> FrontendArgs:
    """Extract sanitized -D/-I flags from the target's compile_commands.json.

    Returns empty FrontendArgs when the database is absent, malformed,
    oversized, or yields nothing that survives sanitization. Never raises.
    """
    target = Path(target)
    db = find_compile_commands(target)
    if db is None:
        return _EMPTY_FRONTEND_ARGS
    try:
        if db.stat().st_size > _CC_MAX_BYTES:
            logger.warning("%s exceeds %d bytes — ignored for frontend args",
                           db, _CC_MAX_BYTES)
            return _EMPTY_FRONTEND_ARGS
        entries = json.loads(db.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.debug("compile_commands parse failed at %s: %s", db, exc)
        return _EMPTY_FRONTEND_ARGS
    if not isinstance(entries, list):
        return _EMPTY_FRONTEND_ARGS
    if len(entries) > _CC_MAX_ENTRIES:
        logger.info("compile_commands at %s has %d entries; scanning first %d",
                    db, len(entries), _CC_MAX_ENTRIES)
        entries = entries[:_CC_MAX_ENTRIES]

    defines: dict = {}
    undefined: set = set()
    conflict: set = set()
    includes: list = []
    seen_includes: set = set()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_dir = entry.get("directory")
        tokens = _cc_entry_tokens(entry)
        i = 0
        n = len(tokens)
        while i < n:
            tok = tokens[i]
            name = val = inc = None
            is_undef = False
            if tok in ("-D", "-U", "-I", "-isystem") and i + 1 < n:
                i += 1
                operand = tokens[i]
                if tok == "-D":
                    name, _, val = operand.partition("=")
                elif tok == "-U":
                    name, is_undef = operand, True
                else:
                    inc = operand
            elif tok.startswith("-D") and len(tok) > 2:
                name, _, val = tok[2:].partition("=")
            elif tok.startswith("-U") and len(tok) > 2:
                name, is_undef = tok[2:], True
            elif tok.startswith("-I") and len(tok) > 2:
                inc = tok[2:]
            elif tok.startswith("-isystem") and len(tok) > 8:
                inc = tok[8:]
            i += 1

            if inc is not None:
                resolved = _cc_resolve_include(inc, entry_dir, target)
                if resolved and resolved not in seen_includes:
                    seen_includes.add(resolved)
                    includes.append(resolved)
                continue
            if name is None or not _CC_DEFINE_NAME_RE.match(name):
                continue
            if is_undef:
                if name in defines:
                    conflict.add(name)
                undefined.add(name)
                continue
            if val and not _CC_DEFINE_VALUE_RE.match(val):
                continue
            if name in undefined:
                conflict.add(name)
            defines[name] = val or ""

    # A name both defined and undefined across TUs is config-dependent
    # project-wide — drop it rather than pick a side.
    for name in conflict:
        defines.pop(name, None)

    define_strs = sorted(
        name if not val else f"{name}={val}"
        for name, val in defines.items()
    )
    if len(define_strs) > _CC_MAX_DEFINES:
        logger.info("compile_commands at %s: capping defines %d → %d",
                    db, len(define_strs), _CC_MAX_DEFINES)
        define_strs = define_strs[:_CC_MAX_DEFINES]
    if len(includes) > _CC_MAX_INCLUDES:
        logger.info("compile_commands at %s: capping includes %d → %d",
                    db, len(includes), _CC_MAX_INCLUDES)
        includes = includes[:_CC_MAX_INCLUDES]

    fa = FrontendArgs(defines=tuple(define_strs), includes=tuple(includes))
    if fa:
        logger.info(
            "joern c2cpg frontend args from %s: %d defines, %d includes",
            db, len(fa.defines), len(fa.includes),
        )
    return fa


def build_cpg(
    target: Path,
    *,
    languages: set[str] | None = None,
    output_dir: Path | None = None,
    timeout: int = 600,
    subprocess_runner=None,
    on_progress: Callable | None = None,
    heap_mb: int | None = None,
    frontend_args: FrontendArgs | None = None,
    exclude_dirs=(),
) -> JoernCPG:
    """Parse target directory into a Code Property Graph.

    Returns a JoernCPG handle. The CPG is written to output_dir
    (default: tempdir) as a binary file. ``heap_mb`` sets the JVM
    ``-Xms``/``-Xmx`` via the launcher's ``-J`` passthrough, matching
    JoernServer's heap flags; ``None`` keeps the JVM default.

    ``frontend_args``: sanitized c2cpg flags. ``None`` auto-discovers
    from the target's compile_commands.json when the pinned language
    set includes the C frontend; pass ``FrontendArgs()`` to disable.

    ``exclude_dirs``: caller-declared directories (e.g. a run's
    configured output root inside the target) passed to the frontend
    as ``--exclude``. The shared directory-name rule
    (:data:`CPG_EXCLUDE_REGEX`) is always passed as
    ``--exclude-regex`` so the graph's coverage matches the content
    key's file set exactly (key/analysis parity).
    """
    target = Path(target).resolve()
    if not target.is_dir():
        msg = f"target must be a directory: {target}"
        raise ValueError(msg)

    if output_dir is None:
        # Reaper-visible scratch: register the prefix so a dir
        # orphaned by a crashed run (build succeeded, caller never
        # reached cleanup_cpg) is reclaimed by a later run's sweep in
        # the same process family, instead of accumulating under
        # /tmp forever.
        from core.run import tmp_reaper
        tmp_reaper.register_dir_prefix("raptor-joern-cpg-")
        output_dir = Path(tempfile.mkdtemp(prefix="raptor-joern-cpg-"))
    output_dir.mkdir(parents=True, exist_ok=True)

    cpg_path = output_dir / "cpg.bin"

    joern_parse = _joern_parse_path() or _JOERN_PARSE_BIN
    heap_flags: list = []
    if heap_mb is not None:
        # Ceiling only — no -Xms pin. Measured: equal Xms/Xmx bought
        # nothing (lazy commit keeps RSS at working-set size), it is
        # boot-fragile at very large values, and the c2cpg frontend
        # child (which inherits this Xmx via the driver's
        # maxMemoryParameter forwarding) never receives Xms anyway.
        heap_flags = [f"-J-Xmx{heap_mb}m"]
    # JEP 519 compact object headers (product in JDK 25): per-object
    # savings compound on the node-dense CPG the parse builds. Guarded
    # JVM-side rather than by probing `java -version` — build_cpg must
    # not spawn raw subprocesses (sandbox-purity contract), and
    # IgnoreUnrecognizedVMOptions makes pre-25 JDKs skip the unknown
    # flag instead of aborting startup. The Ignore flag only applies
    # to flags AFTER it; our own flags are static and test-pinned, so
    # its typo-masking cost is nil here.
    heap_flags.extend([
        "-J-XX:+IgnoreUnrecognizedVMOptions",
        "-J-XX:+UseCompactObjectHeaders",
    ])
    cmd = [joern_parse, *heap_flags, "--output", str(cpg_path), str(target)]

    if languages:
        cmd.extend(["--language", ",".join(sorted(languages))])

    if frontend_args is None and languages and "c" in languages:
        frontend_args = discover_frontend_args(target)
    if frontend_args:
        # Everything after --frontend-args is passed verbatim to the
        # frontend, so this must be the argv tail.
        cmd.extend(frontend_args.to_argv())
    else:
        cmd.append("--frontend-args")
    # Key/analysis parity: the same exclusion rule that prunes the
    # content-key walk is handed to the frontend. Without it, a
    # subtree the key skips (vendor/, dot-dirs, a declared output
    # root) would still be parsed into the graph — an edit there
    # leaves the key unchanged and every joern-backed check silently
    # evaluates stale code.
    cmd.extend(["--exclude-regex", CPG_EXCLUDE_REGEX])
    for d in sorted(_resolved_exclude_dirs(exclude_dirs)):
        cmd.extend(["--exclude", str(d)])

    runner = subprocess_runner or _default_sandbox_runner()

    start = time.monotonic()

    if on_progress is not None and subprocess_runner is None:
        if runner is subprocess.run:
            # core.sandbox is unavailable — the stall-monitor's raw
            # Popen is the same trust level as the subprocess.run
            # fallback the non-monitor branch would use.
            return _build_cpg_with_stall_monitor(
                cmd, cpg_path, target, languages, timeout, on_progress,
            )
        # The sandbox API is subprocess.run-shaped (blocking, output
        # captured after exit), so per-file stderr streaming cannot
        # pass through it. Sandboxing joern-parse on untrusted source
        # outranks stall detection: drop the monitor and fall through
        # to the sandboxed build with a coarse progress note.
        on_progress("Joern CPG build running (sandboxed; per-file progress unavailable)")

    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            target=str(target),
            output=str(output_dir),
            block_network=True,
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

    detected_langs: set[str] = set()
    if proc.stdout:
        for line in proc.stdout.splitlines():
            if "language:" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    detected_langs.add(parts[1].strip().lower())

    _reject_empty_cpg(cpg_path, languages or detected_langs)

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
    languages: set[str] | None,
    timeout: int,
    on_progress: Callable,
) -> JoernCPG:
    """Build CPG with real-time stderr monitoring and adaptive stall detection.

    Only used when ``core.sandbox`` is unavailable: this path spawns
    joern-parse with a raw Popen to stream stderr, which cannot be
    routed through the run()-shaped sandbox API. When the sandbox is
    present, ``build_cpg`` keeps the sandbox and drops the monitor.
    """
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

    # Drain stdout in its own thread. The monitor owns stderr; leaving
    # stdout unread until after exit let a chatty joern-parse fill the
    # ~64KB OS pipe buffer and block in write() — stderr progress then
    # stopped and the stall monitor (or the wait timeout below) killed
    # it, misreported as a joern-parse timeout/stall.
    stdout_chunks: list[str] = []
    stdout_thread = threading.Thread(
        target=_drain_stream,
        args=(proc.stdout, stdout_chunks),
        daemon=True,
        name="joern-stdout-drain",
    )
    stdout_thread.start()

    # Wait for the process without reading its pipes here -- the two
    # drain threads own them. Using proc.communicate() would race with
    # those threads (two unsynchronised consumers per pipe).
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        logger.warning("joern-parse timed out after %ds", timeout)
        return JoernCPG(path=cpg_path, target=target)

    monitor_thread.join(timeout=5)
    stdout_thread.join(timeout=5)

    stdout = "".join(stdout_chunks)

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

    detected_langs: set[str] = set()
    if stdout:
        for line in stdout.splitlines():
            if "language:" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    detected_langs.add(parts[1].strip().lower())

    _reject_empty_cpg(cpg_path, languages or detected_langs)

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
    substitutions: dict[str, str] | None = None,
) -> JoernResult:
    """Execute a Joern/CPGQL query against a built CPG.

    query: inline CPGQL string OR path to a .sc script file.
    validate: if True, run query validation before execution.
    substitutions: template-slot markers (e.g. ``__SINK_NAMES__``)
    mapped to replacement text, applied to the script body.
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
    for marker, replacement in (substitutions or {}).items():
        script_body = script_body.replace(marker, replacement)

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
            # Runner without the sandbox kwargs (injected stubs,
            # bare subprocess.run). Still pass an explicit cwd:
            # importCpg copies the CPG into a `workspace/` under the
            # process cwd — without this the copies landed in
            # whatever directory the CALLER happened to run from
            # (observed: a workspace/ full of CPG copies in the
            # repo root).
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cpg.path.parent),
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


def run_taint_query_result(
    cpg: JoernCPG,
    source_method: str,
    sink_call: str,
    *,
    source_param: str | None = None,
    timeout: int = 300,
    subprocess_runner=None,
    max_call_depth: int = 2,
) -> JoernResult:
    """Run a source-to-sink taint tracking query, errors included.

    Returns the full :class:`JoernResult` so callers can tell "no
    flows" (a genuine negative) apart from "query failed" (timeout,
    server crash, validation reject — says nothing about the code).
    Verdict-bearing callers must check ``result.errors`` before
    reading an empty ``result.flows`` as a refutation.
    """
    if not _validate_substitution_value(source_method):
        logger.warning(
            "rejecting source_method %r: fails identifier validation",
            source_method[:80],
        )
        return JoernResult(query="", errors=[
            f"source_method fails identifier validation: "
            f"{source_method[:80]!r}",
        ])

    if not _validate_substitution_value(sink_call):
        logger.warning(
            "rejecting sink_call %r: fails identifier validation",
            sink_call[:80],
        )
        return JoernResult(query="", errors=[
            f"sink_call fails identifier validation: {sink_call[:80]!r}",
        ])

    if source_param and not _validate_substitution_value(source_param):
        logger.warning(
            "rejecting source_param %r: fails identifier validation",
            source_param[:80],
        )
        return JoernResult(query="", errors=[
            f"source_param fails identifier validation: "
            f"{source_param[:80]!r}",
        ])

    safe_source = _escape_scala_string(source_method)
    safe_sink = _escape_scala_string(sink_call)

    query = _build_taint_query(safe_source, safe_sink, source_param,
                              max_call_depth=max_call_depth)

    err = _validate_query(query)
    if err:
        logger.warning("generated taint query failed validation: %s", err)
        return JoernResult(query=query, errors=[
            f"generated taint query failed validation: {err}",
        ])

    result = run_query(
        cpg, query,
        timeout=timeout,
        subprocess_runner=subprocess_runner,
        validate=False,
    )

    if result.errors:
        logger.warning("taint query errors: %s", result.errors)

    return result


def run_taint_query(
    cpg: JoernCPG,
    source_method: str,
    sink_call: str,
    *,
    source_param: str | None = None,
    timeout: int = 300,
    subprocess_runner=None,
    max_call_depth: int = 2,
) -> list[TaintFlow]:
    """Run a source-to-sink taint tracking query.

    Returns list of TaintFlow objects — empty on no flows AND on query
    failure, so this shape suits positive-evidence callers only.
    Verdict-bearing callers that would read an empty list as a
    refutation must use :func:`run_taint_query_result` and check
    ``errors``.
    """
    return run_taint_query_result(
        cpg, source_method, sink_call,
        source_param=source_param,
        timeout=timeout,
        subprocess_runner=subprocess_runner,
        max_call_depth=max_call_depth,
    ).flows


def _build_taint_query(
    source_method: str,
    sink_call: str,
    source_param: str | None = None,
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
    return query.replace("__MAX_CALL_DEPTH__", str(int(max_call_depth)))


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


#: Directories that never contribute analysed source: VCS/tool state
#: (any dot-dir), dependency trees, and bytecode caches. Mirrors the
#: walk-skip conventions elsewhere in the repo (compiler_sweep,
#: inventory.library_detection). This single rule drives BOTH the
#: content-key walk and the CPG build's ``--exclude-regex``
#: (:data:`CPG_EXCLUDE_REGEX`) — key and analysis coverage are
#: identical by construction, so an edit the key ignores is an edit
#: joern never analysed, and vice versa. A subtree the key skips but
#: the build parses would serve a silently stale CPG to every
#: joern-backed check.
_SKIP_DIR_NAMES = frozenset({
    "node_modules", "vendor", "third_party", "__pycache__",
})


def _dir_name_excluded(name: str) -> bool:
    """The shared directory-exclusion rule (dot-dirs + _SKIP_DIR_NAMES)."""
    return name.startswith(".") or name in _SKIP_DIR_NAMES


#: Frontend ``--exclude-regex`` equivalent of :func:`_dir_name_excluded`
#: (X2Cpg matches it against paths relative to the input dir). The
#: excluded segment must be a DIRECTORY component (trailing ``/``):
#: dot-FILES are source and stay in both the key and the graph.
CPG_EXCLUDE_REGEX = (
    r"(?:^|.*/)(?:\.[^/]+|"
    + "|".join(sorted(_SKIP_DIR_NAMES))
    + r")/.*$"
)


def _resolved_exclude_dirs(exclude_dirs) -> set:
    """Resolve caller-declared exclusion roots for prune comparison."""
    resolved = set()
    for d in exclude_dirs or ():
        try:
            resolved.add(Path(d).resolve())
        except OSError:
            continue
    return resolved


def run_output_exclude_dirs(
    out_dir: str | Path | None,
    target: str | Path | None,
) -> tuple[str, ...]:
    """Caller-declared exclusion roots for a run writing into *out_dir*.

    Returns the resolved run-output directory when it lives strictly
    inside *target* (e.g. a self-analysis run with ``out/`` under the
    analysed repo), else ``()``. Run artifacts change while the run
    executes, so an in-target output dir left in the content key flaps
    the key at every resumed segment and re-buys a full CPG rebuild —
    churn, never staleness. Only the run's OWN output dir is declared:
    a broader ancestor could swallow real source when the operator
    points the output somewhere unusual inside the tree, and exclusions
    silently remove code from every joern-backed check (key/analysis
    parity cuts both ways).
    """
    if not out_dir or not target:
        return ()
    try:
        out = Path(out_dir).resolve()
        root = Path(target).resolve()
    except OSError:
        return ()
    if root not in out.parents:
        return ()
    return (str(out),)


def _target_content_hash(target: Path, *, exclude_dirs=()) -> str:
    """Content-only cache key for the target tree.

    A function of the source file SET and each file's CONTENT and
    nothing else: entries are ``relpath:sha256(content)``, sorted by
    path, so the key is invariant under mtime churn (builds,
    checkouts, tooling touches) and directory iteration order. The
    previous mtime-based key flapped at every resumed-audit segment
    start on an unchanged, git-clean tree, forcing a full CPG rebuild
    per segment.

    Exclusions are never derived from repo content: a hostile tree
    must not be able to carve itself a blind spot. Two sources only,
    both mirrored into the CPG build for key/analysis parity:

    * the shared directory-name rule (:func:`_dir_name_excluded` /
      :data:`CPG_EXCLUDE_REGEX`): dot-dirs, dependency trees,
      bytecode caches;
    * ``exclude_dirs`` — directories the CALLER declares (a run's
      configured output root living inside the target), passed to the
      build as ``--exclude``.

    Only regular files are hashed: a symlink to a character device
    (``zero.c -> /dev/zero``) or a FIFO named like source must be
    skipped, not opened — reading either blocks the orchestrator
    indefinitely.
    """
    source_exts = {
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
        ".py", ".java", ".js", ".ts", ".go", ".rs",
    }
    excluded_roots = _resolved_exclude_dirs(exclude_dirs)
    entries = []
    for root, dirs, files in os.walk(target):
        root_path = Path(root)
        dirs[:] = [
            d for d in dirs
            if not _dir_name_excluded(d)
            and (not excluded_roots
                 or (root_path / d).resolve() not in excluded_roots)
        ]
        for name in files:
            p = root_path / name
            if p.suffix.lower() not in source_exts:
                continue
            try:
                st = os.stat(p)  # follows symlinks
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                # FIFOs block open(); device files read forever.
                continue
            digest = hashlib.sha256()
            try:
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        digest.update(chunk)
            except OSError:
                continue
            entries.append(
                f"{p.relative_to(target)}:{digest.hexdigest()}")
    entries.sort()
    h = hashlib.sha256()
    h.update("\n".join(entries).encode())
    return h.hexdigest()[:16]


# Flatgraph serialises a JSON manifest as the final bytes of cpg.bin,
# opening with {"version" and carrying a per-kind node count table.
# Reading that tail is the cheapest possible method-count probe — no
# JVM boot. The string pool precedes the manifest, so even a source
# file containing the literal anchor cannot shadow it: rfind always
# lands on the real manifest.
_CPG_MANIFEST_ANCHOR = b'{"version"'
_CPG_MANIFEST_TAIL_BYTES = 8 * 1024 * 1024


def cpg_method_count(cpg_path: Path) -> int | None:
    """METHOD node count from the flatgraph tail manifest.

    Returns None when the file or its manifest cannot be read — the
    caller must treat None as "unknown", never as "empty": only a
    positively-parsed zero may reject a CPG.
    """
    try:
        size = cpg_path.stat().st_size
        with Path(cpg_path).open("rb") as f:
            if size > _CPG_MANIFEST_TAIL_BYTES:
                f.seek(size - _CPG_MANIFEST_TAIL_BYTES)
            data = f.read()
    except OSError:
        return None
    start = data.rfind(_CPG_MANIFEST_ANCHOR)
    if start < 0:
        return None
    try:
        manifest = json.loads(data[start:].decode("utf-8"))
        for node in manifest.get("nodes", []):
            if node.get("nodeLabel") == "METHOD":
                return int(node.get("nnodes", 0))
    except (ValueError, UnicodeDecodeError, TypeError):
        return None
    # Schema table present but no METHOD row: unexpected shape —
    # unknown, not empty.
    return None


def _reject_empty_cpg(cpg_path: Path, languages: set[str] | None) -> bool:
    """Delete a structurally-empty CPG so callers see a parse failure.

    joern-parse can exit 0 while writing a CPG with zero METHOD nodes
    (observed: rubysrc's embedded parser gem failing to load — the
    frontend dies after the writer opened the file). Exit codes cannot
    catch this class; the manifest probe can. Only a parsed zero
    rejects; an unreadable manifest passes through.
    """
    if not cpg_path.exists():
        return False
    count = cpg_method_count(cpg_path)
    if count == 0:
        logger.error(
            "joern-parse exited successfully but the CPG at %s contains "
            "zero METHOD nodes — the %s frontend produced an empty "
            "graph (broken frontend helper, unsupported dialect, or "
            "partial write). Treating as a parse failure.",
            cpg_path,
            ",".join(sorted(languages)) if languages else "auto-detected",
        )
        with contextlib.suppress(OSError):
            cpg_path.unlink()
        return True
    if count is None:
        logger.debug("CPG manifest at %s unreadable; skipping empty check", cpg_path)
    return False


def _write_cpg_manifest(
    cpg_dir: Path, target: Path, content_hash: str,
    languages: set[str] | None = None, build_time_ms: int = 0,
    frontend_args_fingerprint: str = "",
    method_count: int | None = None,
    exclude_dirs=(),
) -> None:
    """Write manifest.json alongside the cached CPG."""
    manifest = {
        "target_path": str(target),
        "content_hash": content_hash,
        "build_time_ms": build_time_ms,
        "languages": sorted(languages or []),
        "frontend_args_fingerprint": frontend_args_fingerprint,
        "method_count": method_count,
        # The exclusion contract this graph was built under. The regex
        # joins the freshness check: a graph built under a different
        # rule has different coverage, and serving it would break
        # key/analysis parity.
        "exclude_regex": CPG_EXCLUDE_REGEX,
        "exclude_dirs": sorted(str(d) for d in exclude_dirs or ()),
    }
    manifest_path = cpg_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))


def _read_cpg_manifest(cpg_dir: Path) -> dict | None:
    """Read manifest.json, returning None if missing or corrupt."""
    manifest_path = cpg_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    from core.json import load_json
    return load_json(manifest_path, max_bytes=8 * 1024 * 1024)


def load_cached_cpg(
    target: Path,
    cache_dir: Path,
    *,
    expected_frontend_fingerprint: str | None = None,
    current_content_hash: str | None = None,
    exclude_dirs=(),
) -> JoernCPG | None:
    """Return a cached CPG if fresh, None if stale or missing.

    ``expected_frontend_fingerprint``: when given, the manifest's
    recorded c2cpg frontend-args fingerprint must match it — a
    compile_commands.json change then invalidates the cache. ``None``
    (read-only consumers that never rebuild) skips the check.

    ``current_content_hash``: precomputed :func:`_target_content_hash`
    of the target tree; ``None`` computes it here (with
    ``exclude_dirs``). Callers that go on to rebuild pass it so the
    freshness check and the rebuilt cache's manifest describe the
    SAME tree state.

    Read-only consumers that pass neither hash nor ``exclude_dirs``
    reproduce the manifest's recorded exclusion contract: a graph
    built under caller-declared exclusions would otherwise hash the
    excluded run artifacts back into the key and read as permanently
    stale. Trusting the recorded list adds nothing an attacker did not
    already have — the manifest carries ``content_hash`` itself.
    """
    cpg_dir = cache_dir / "joern-cpg"
    cpg_path = cpg_dir / "cpg.bin"
    if not cpg_path.exists():
        return None

    manifest = _read_cpg_manifest(cpg_dir)
    if manifest is None:
        return None

    recorded_regex = manifest.get("exclude_regex")
    if recorded_regex is not None and recorded_regex != CPG_EXCLUDE_REGEX:
        # Built under a different exclusion rule: its coverage no
        # longer matches the content key's file set (parity).
        logger.info(
            "CPG cache at %s stale (exclusion rule changed) — this "
            "cache will be rebuilt",
            cpg_dir,
        )
        return None

    if expected_frontend_fingerprint is not None:
        recorded = manifest.get("frontend_args_fingerprint", "")
        if recorded != expected_frontend_fingerprint:
            logger.info(
                "CPG cache at %s stale (frontend args %s → %s) — this "
                "cache will be rebuilt",
                cpg_dir, recorded or "(none)",
                expected_frontend_fingerprint or "(none)",
            )
            return None

    if current_content_hash:
        current_hash = current_content_hash
    else:
        effective_exclude = (
            exclude_dirs or manifest.get("exclude_dirs") or ()
        )
        current_hash = _target_content_hash(
            target, exclude_dirs=effective_exclude)
    if manifest.get("content_hash") != current_hash:
        # Name the cache path: several consumers keep separate CPG
        # caches, and a bare "will rebuild" printed next to another
        # consumer's fast cache load reads as a contradiction.
        logger.info(
            "CPG cache at %s stale (hash %s → %s) — this cache will "
            "be rebuilt",
            cpg_dir,
            manifest.get("content_hash", "?")[:8], current_hash[:8],
        )
        return None

    # Refuse structurally-empty cached CPGs (including ones written
    # before the empty check existed — the probe reads the file, not
    # the manifest field, so legacy caches are covered).
    if cpg_method_count(cpg_path) == 0:
        logger.info(
            "CPG cache at %s contains zero METHOD nodes — refusing the "
            "cached graph; this cache will be rebuilt",
            cpg_dir,
        )
        return None

    langs = set(manifest.get("languages", []))
    logger.info("CPG cache hit for %s (cache: %s)", target, cpg_dir)
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
    languages: set[str] | None = None,
    timeout: int = 600,
    subprocess_runner=None,
    on_progress: Callable | None = None,
    heap_mb: int | None = None,
    exclude_dirs=(),
) -> JoernCPG:
    """Build or reuse a cached CPG for the target.

    cache_dir is typically the project directory. The CPG is stored
    in cache_dir/joern-cpg/cpg.bin with a manifest for freshness.
    Frontend args discovered from compile_commands.json join the
    freshness contract: a flags change rebuilds even when source
    contents are unchanged.

    ``exclude_dirs``: caller-declared exclusion roots (a run's
    configured output directory inside the target). They are pruned
    from the content key AND passed to the build as ``--exclude`` —
    the two must always travel together (key/analysis parity).
    """
    frontend_args = _EMPTY_FRONTEND_ARGS
    if languages and "c" in languages:
        frontend_args = discover_frontend_args(Path(target))

    # Hash the tree ONCE, before the (potentially minutes-long) build.
    # The manifest then records the tree state the CPG was built FROM;
    # re-walking after the build used to pick up transient files
    # written while it ran, producing a recorded hash that never
    # matched the at-rest tree — a guaranteed rebuild at the next
    # consumer.
    content_hash = _target_content_hash(target, exclude_dirs=exclude_dirs)

    cached = load_cached_cpg(
        target, cache_dir,
        expected_frontend_fingerprint=frontend_args.fingerprint(),
        current_content_hash=content_hash,
    )
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
        heap_mb=heap_mb,
        frontend_args=frontend_args,
        exclude_dirs=exclude_dirs,
    )

    if cpg.exists():
        _write_cpg_manifest(
            cpg_dir, target, content_hash,
            languages=cpg.languages,
            build_time_ms=cpg.build_time_ms,
            frontend_args_fingerprint=frontend_args.fingerprint(),
            method_count=cpg_method_count(cpg.path),
            exclude_dirs=exclude_dirs,
        )

    return cpg


def cleanup_cpg(cpg: JoernCPG) -> None:
    """Remove the CPG binary from disk, plus the ``workspace/`` copy
    ``importCpg`` leaves next to it.

    ``run_query`` executes joern with cwd = the CPG's directory, and
    importCpg copies the CPG into ``<cwd>/workspace/``. Pre-fix the
    cleanup unlinked only ``cpg.bin`` — the workspace copy survived,
    the ``rmdir`` below always failed on the non-empty dir, and the
    duplicated CPGs accumulated for the life of the host."""
    try:
        cpg.path.unlink(missing_ok=True)
        parent = cpg.path.parent
        workspace = parent / "workspace"
        # rmtree only a real directory we own the layout of — never
        # follow a symlink planted at that name.
        if workspace.is_dir() and not workspace.is_symlink():
            shutil.rmtree(workspace, ignore_errors=True)
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
    flows: list[TaintFlow] = []
    errors: list[str] = []
    seen_flows: set[str] = set()
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


def _parse_dark_methods(stdout: str) -> list[str]:
    """Extract dark-method markers — methods invisible to taint analysis.

    Two marker shapes:

    * ``JOERN_DARK:<name>`` — one method per line.
    * ``JOERN_DIAG:dark_methods:<count>:<name,name,...>`` — the tiered
      taint script's diagnostic line (sample capped at 10 names, so
      the parsed list may undercount the emitted total).
    """
    dark: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("JOERN_DARK:"):
            name = line[len("JOERN_DARK:"):].strip()
            if name:
                dark.append(name)
        elif line.startswith("JOERN_DIAG:dark_methods:"):
            payload = line[len("JOERN_DIAG:dark_methods:"):]
            _count, _, sample = payload.partition(":")
            dark.extend(
                n for n in (s.strip() for s in sample.split(",")) if n
            )
    return dark


def _parse_errors(stderr: str) -> list[str]:
    """Extract error messages from Joern stderr."""
    errors: list[str] = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if (
            any(kw in low for kw in ("error", "exception", "failed", "fatal"))
            and "deprecated" not in low
            and "warning" not in low
        ):
            errors.append(line)
    return errors


def _build_summary_batch_query(method_names: list[str]) -> str | None:
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
