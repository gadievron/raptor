#!/usr/bin/env python3
"""
CodeQL Query Runner

Executes CodeQL queries and suites against databases,
producing SARIF output for vulnerability analysis.
"""

import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path
from typing import Any, ClassVar

# `os.environ["RAPTOR_DIR"]` (no fallback) is the canonical project
# root marker — see CLAUDE.md "Python path safety"; a KeyError surfaces
# the configuration problem at startup instead of a positional walk
# silently breaking under relocation.
if __name__ == "__main__":
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.analysis.rule_versions import VersionProbeCache, rule_version_refusal, version_tuple as _release_version
from core.security.capped_read import read_capped_text
from core.config import RaptorConfig
from core.logging import get_logger
from core.sandbox import SandboxSetupError
from packages.codeql.temp_env import temporary_command
from packages.codeql.tunables import CodeQLTunables

logger = get_logger()

_SARIF_DATA_UNSET = object()

# Tightened from `[\w/.-]+\S*` which accepted any path-like
# blob (path-traversal `../../etc/passwd`, multi-segment
# `a/b/c/d`, leading-dot `..foo`). Pack names follow CodeQL's
# canonical `<scope>/<name>` format: each segment starts and
# ends with alphanumeric, contains only alphanumeric + dash +
# (for the `<name>` half) dot/underscore. The downloaded pack
# name flows into a CLI-arg execve here (`codeql pack download
# <pack>`); even though codeql validates internally, accepting
# operator-controlled strings into ANOTHER subprocess invocation
# is a surface we don't need.
_PACK_NOT_FOUND_RE = re.compile(
    r"[Qq]uery pack "
    r"([a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?/"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9])?)"
    # Optional version (`@1.2.3`) or suite-path (`:suite/x.qls`)
    # suffix that codeql appends — discarded, not captured.
    r"(?:[@:][^\s]*)?"
    r" cannot be found"
)


def _iris_pack_deps_already_resolved(pack_dir: Path) -> bool:
    """True when every dep pinned in `pack_dir/codeql-pack.lock.yml`
    has matching package metadata at its pinned cache version.

    Used by `analyze_iris_packs` to skip the network-permitted
    `codeql pack install` call when the dep cache is already warm —
    avoids both the subprocess and the sandbox network round-trip on
    every IRIS analysis. Common case in normal RAPTOR setups (where
    the user already has `codeql/<lang>-all` cached from prior
    /codeql or /agentic runs).

    Returns False (i.e. defer to full install) on any parse error,
    missing lockfile, or incomplete/mismatched cached dep. Metadata reads
    are bounded; malformed cache hints defer to CodeQL installation.
    """
    try:
        import yaml  # transitively available via codeql packs
    except ImportError:
        return False

    def metadata(path: Path) -> dict | None:
        text = read_capped_text(path, 1024 * 1024, errors="strict")
        if text is None:
            return None
        try:
            data = yaml.safe_load(text)
        except (ValueError, RecursionError, yaml.YAMLError):
            return None
        return data if isinstance(data, dict) else None

    def component(value: object) -> bool:
        return (isinstance(value, str) and value not in ("", ".", "..")
                and not any(char in value for char in ("/", "\\", "\x00")))

    data = metadata(pack_dir / "codeql-pack.lock.yml")
    deps = data.get("dependencies") if data is not None else None
    if not isinstance(deps, dict) or not deps:
        return False
    try:
        cache = (Path.home() / ".codeql" / "packages").resolve(strict=True)
        for dep_name, info in deps.items():
            if not isinstance(dep_name, str) or not isinstance(info, dict):
                return False
            parts = dep_name.split("/")
            version = info.get("version")
            if (len(parts) != 2 or not all(component(part) for part in parts)
                    or not isinstance(version, str) or not component(version)):
                return False
            package = (cache / dep_name / version).resolve(strict=True)
            package.relative_to(cache)
            manifest = package / "qlpack.yml"
            if not manifest.is_file():
                manifest = package / "codeql-pack.yml"
            installed = metadata(manifest)
            if (installed is None or installed.get("name") != dep_name
                    or installed.get("version") != version):
                return False
    except (OSError, ValueError, RuntimeError):
        return False
    return True


def _bundled_stdlib_roots(lang: str, *, codeql_cli: str | None = None) -> list[Path]:
    """Find the ``<lang>-all`` library pack bundled with the CodeQL CLI.

    Standard CodeQL installations place the CLI at ``<prefix>/codeql/``
    with queries at ``<prefix>/codeql-queries/<lang>/ql/lib/``.  The
    library pack there contains ``qlpack.yml`` naming ``codeql/<lang>-all``
    and is already known to ``codeql resolve qlpacks``, but invisible to
    the package cache that ``_iris_pack_deps_already_resolved`` checks.
    """
    import shutil
    cli = codeql_cli or os.environ.get("CODEQL_CLI") or shutil.which("codeql")
    if not cli:
        return []
    try:
        dist_dir = Path(cli).resolve().parent          # <prefix>/codeql/
        workspace = dist_dir.parent / "codeql-queries"
        lib_root = workspace / lang / "ql" / "lib"
        if (lib_root / "qlpack.yml").is_file():
            # The language library imports sibling shared packs. Under
            # scoped filesystem access CodeQL cannot discover this workspace
            # by enumerating the CLI's parent; select it explicitly.
            if (workspace / "codeql-workspace.yml").is_file():
                return [workspace]
            return [lib_root]
    except (OSError, ValueError):
        pass
    return []


def _vendored_stdlib_roots(lang: str, *, codeql_cli: str | None = None) -> list[Path]:
    """Library-pack roots usable as ``--additional-packs`` for offline
    stdlib resolution.

    Checked in order:

    1. **Cached query pack** — ``~/.codeql/packages/codeql/<lang>-queries/
       <version>/.codeql/libraries/codeql/``.  This is the vendored
       ``<lang>-all`` library pack inside a previously downloaded standard
       query pack.

    2. **Bundled distribution pack** — the ``<lang>-all`` library pack
       shipped alongside the CodeQL CLI (``<dist>/../codeql-queries/
       <lang>/ql/lib/``).  Present in every standard CodeQL installation
       but invisible to the package cache.

    The bundled fallback returns the workspace root, including shared
    dependencies, rather than only its language library. Returns a
    one-element list on the first hit, or ``[]`` when nothing is found.
    """
    # --- path 1: cached query pack ---
    base = Path.home() / ".codeql" / "packages" / "codeql" / f"{lang}-queries"
    if base.is_dir():

        def _version_key(p: Path) -> tuple:
            try:
                return tuple(int(part) for part in p.name.split("."))
            except ValueError:
                return (0,)

        try:
            versions = sorted(
                (d for d in base.iterdir() if d.is_dir()),
                key=_version_key, reverse=True,
            )
        except OSError:
            versions = []
        for version_dir in versions:
            cand = version_dir / ".codeql" / "libraries" / "codeql"
            if cand.is_dir():
                return [cand]

    # --- path 2: bundled distribution pack ---
    return _bundled_stdlib_roots(lang, codeql_cli=codeql_cli)


def vendored_stdlib_roots(lang: str) -> list[Path]:
    """Public seam over ``_vendored_stdlib_roots`` for out-of-package
    consumers (``core.iris.codeql_runner``): returns an
    ``--additional-packs``-compatible root that resolves the
    ``<lang>-all`` stdlib dependency without registry egress."""
    return _vendored_stdlib_roots(lang)


_STDERR_LENGTH_CAP = 256 * 1024  # 256 KB; codeql stderr is typically <16 KB


def _extract_missing_pack(stderr: str) -> str | None:
    """Extract the missing pack name from a CodeQL 'cannot be found' error.

    Matches: "Query pack codeql/cpp-queries:suites/foo.qls cannot be found."
    Does NOT match: "Could not read /path/to/suite.qls" (different error).

    Caps stderr length before the regex match to bound wallclock.
    Pre-fix the regex ran against unbounded stderr — codeql stderr
    is typically <16 KB, but a misbehaving build that streamed
    multi-MB output (build-mode=manual with verbose logging,
    java-kotlin builds dumping JVM stack traces from a crash)
    could feed pathological input to the regex. The pattern
    contains nested quantifiers that, while not catastrophic-
    backtracking, scan O(N) per failed match attempt — multi-MB
    input → measurable wallclock per stderr scan.

    Also: the captured pack name flows into a CLI-arg execve
    (`codeql pack download <pack>`), so a too-long match could
    trigger E2BIG from the kernel. The regex itself bounds the
    pack-name shape to small strings, but the WHOLE-STDERR scan
    is still proportional to input size.

    256 KB cap covers any realistic codeql stderr while refusing
    pathological input. Above the cap we return None — the same
    behaviour as a non-matching stderr; caller falls through to
    the normal "no pack to retry" path.
    """
    if len(stderr) > _STDERR_LENGTH_CAP:
        return None
    m = _PACK_NOT_FOUND_RE.search(stderr)
    if m:
        # Strip trailing colon or version: "codeql/cpp-queries:" → "codeql/cpp-queries"
        return m.group(1).rstrip(":").split("@")[0]
    return None


@dataclass
class QueryResult:
    """Result of query execution."""
    success: bool
    language: str
    database_path: Path
    sarif_path: Path | None
    findings_count: int
    duration_seconds: float
    errors: list[str]
    suite_name: str
    queries_executed: int = 0
    skipped_rules: list[str] = field(default_factory=list)


# `codeql database analyze --threat-model` first shipped in CLI 2.15.3.
# Older CLIs reject the flag as unknown, so the runner version-gates it
# (skip entirely below this) rather than risking a failed analyze.
THREAT_MODEL_MIN_VERSION = (2, 15, 3)


class QueryRunner:
    """
    Execute CodeQL queries and suites against databases.

    Supports:
    - Official CodeQL security suites
    - Custom query packs
    - Parallel execution for multiple databases
    - SARIF output generation
    """

    # Official CodeQL security suites (from GitHub)
    SECURITY_SUITES: ClassVar[dict] = {
        "java": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-and-quality.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls",
        "swift": "codeql/swift-queries:codeql-suites/swift-security-and-quality.qls",
        "kotlin": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",  # Kotlin uses Java queries
        "rust": "codeql/rust-queries:codeql-suites/rust-security-and-quality.qls",
    }

    # Alternative: security-extended suites (more comprehensive)
    SECURITY_EXTENDED_SUITES: ClassVar[dict] = {
        "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
        "swift": "codeql/swift-queries:codeql-suites/swift-security-extended.qls",
        "kotlin": "codeql/java-queries:codeql-suites/java-security-extended.qls",
        "rust": "codeql/rust-queries:codeql-suites/rust-security-extended.qls",
    }

    def __init__(self, codeql_cli: str | None = None) -> None:
        """
        Initialize query runner.

        Args:
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        # Same resolution ladder as the package's _resolve_cli /
        # DatabaseManager._detect_codeql_cli: explicit arg, then the
        # CODEQL_CLI environment variable, then PATH. This runner used
        # to skip the env var — on hosts where codeql is reachable
        # ONLY via CODEQL_CLI (the configuration DatabaseManager's own
        # error message tells operators to use), construction raised
        # AFTER database creation succeeded, and availability probes
        # (env-aware) disagreed with the constructor.
        from packages.codeql import _resolve_cli
        _cli = codeql_cli or _resolve_cli()
        # Realpath for the same reason as DatabaseManager: the sandbox
        # binds the resolved install root; a ~/.local/bin symlink as
        # cmd[0] would push every query run onto the Landlock-only
        # fallback path.
        from packages.codeql._bootstrap import resolve_bootstrap
        _cli = resolve_bootstrap(_cli)
        resolved_cli = os.path.realpath(_cli) if _cli else _cli
        if not resolved_cli:
            msg = (
                "CodeQL CLI not found (set the CODEQL_CLI environment "
                "variable or add codeql to PATH)"
            )
            raise RuntimeError(msg)

        self.codeql_cli: str = resolved_cli
        self._version_cache = VersionProbeCache()
        logger.info("Query runner initialized with CodeQL: %s", self.codeql_cli)

    def _sandbox_tool_paths(self) -> list:
        """Mount-ns bind dirs needed for codeql to run.

        Returns the codeql binary's containing dir. The codeql install
        layout typically places the binary at `<install_root>/codeql`
        with lib/java/packs siblings — bind-mounting the parent directory
        exposes the whole install root. Without this, mount-ns mode
        would fall back to Landlock-only (per context.py's
        `_cmd_visible_in_mount_tree` check) because codeql is rarely
        in /usr/bin.
        """
        from .tool_paths import codeql_tool_paths
        return codeql_tool_paths(self.codeql_cli)

    def _filesystem_scope(self, out_dir: Path, *, writable=(), readonly=()) -> dict:
        """Limit tool I/O while retaining the operator's CodeQL pack/cache layout."""
        from core.sandbox.python_paths import _home_roots, python_runtime_tool_paths

        def dedicated(path: Path) -> Path:
            path = path.absolute()
            resolved = path.resolve()
            if any(candidate == home or candidate in home.parents
                   for candidate in (path, resolved) for home in _home_roots()):
                raise ValueError("CodeQL filesystem grants require dedicated directories, not HOME or its ancestors")
            return path

        output = dedicated(Path(out_dir))
        cache = dedicated(Path.home() / ".codeql")
        cache.mkdir(parents=True, exist_ok=True)
        reads = []
        for entry in readonly:
            path = Path(entry)
            if not path.exists():
                continue
            # A selected suite file imports helpers from its owning pack.
            # Walk at most 32 parents, never promoting a loose file to HOME.
            root = path if path.is_dir() else path.parent
            if path.is_file():
                cursor = root
                for _ in range(32):
                    if (cursor / "qlpack.yml").is_file() or (cursor / "codeql-pack.yml").is_file():
                        root = cursor
                        break
                    if cursor.parent == cursor:
                        break
                    cursor = cursor.parent
            value = str(dedicated(root))
            if value not in reads:
                reads.append(value)
        return dict(output=str(output), restrict_reads=True,
                    writable_paths=[str(cache), *(str(dedicated(Path(p))) for p in writable)],
                    readable_paths=reads or None,
                    tool_paths=list(dict.fromkeys(self._sandbox_tool_paths() + python_runtime_tool_paths())))

    def _analysis_scope(self, command: list, database: Path, out_dir: Path, query=None) -> dict:
        """Include selected suites and model-pack roots, without general HOME access."""
        roots = [query] if query is not None else []
        configured = os.environ.get("CODEQL_QUERIES")
        if configured:
            roots.append(configured)
        bundled = Path(self.codeql_cli).resolve().parent.parent / "codeql-queries"
        if bundled.is_dir():
            roots.append(bundled)
        for index, arg in enumerate(command):
            if str(arg) == "--additional-packs" and index + 1 < len(command):
                roots.extend(str(command[index + 1]).split(os.pathsep))
            elif str(arg).startswith("--additional-packs="):
                roots.extend(str(arg).split("=", 1)[1].split(os.pathsep))
        # Database analysis writes logs/results beside the dataset. It is a
        # writable bind, not target= (which would make the database read-only).
        return self._filesystem_scope(out_dir, writable=[database], readonly=roots)

    def _local_dependency_roots(self, language: str, query_path: Path) -> list[Path]:
        """Resolve an unpinned stdlib-only pack without changing its dependencies.

        A lockfile or any other dependency contract belongs to the package
        manager. Additional source roots take precedence over its pins, so
        never introduce them for those packs. No network access is added.
        """
        import yaml

        pack = Path(query_path).absolute()
        if not pack.is_dir():
            pack = pack.parent
        for _ in range(32):
            manifest = pack / "qlpack.yml"
            if not manifest.is_file():
                manifest = pack / "codeql-pack.yml"
            if manifest.is_file():
                break
            if pack.parent == pack:
                return []
            pack = pack.parent
        else:
            return []
        if os.path.lexists(pack / "codeql-pack.lock.yml"):
            return []
        try:
            metadata = yaml.safe_load(read_capped_text(manifest, max_bytes=64 * 1024, raise_on_refusal=True))
        except (OSError, ValueError, RecursionError, yaml.YAMLError):
            return []
        if (not isinstance(metadata, dict)
                or metadata.get("dependencies") != {f"codeql/{language}-all": "*"}):
            return []
        return _vendored_stdlib_roots(language, codeql_cli=self.codeql_cli)

    def _codeql_version(self) -> str | None:
        """Reuse successful facts only while this runner's CLI is unchanged."""
        from .version_probe import read_codeql_version

        cache = getattr(self, "_version_cache", None)
        if cache is None:
            cache = VersionProbeCache()
            self._version_cache = cache
        return cache.get(lambda: read_codeql_version(self.codeql_cli), lambda: self.codeql_cli)

    #: language → [(search_dir, pack_name)] for learned/derived model
    #: packs. Set by the agent BEFORE the parallel analysis phase and
    #: read-only afterwards, so the ThreadPoolExecutor sees a frozen
    #: map. BOTH halves are required: --additional-packs only makes a
    #: pack resolvable; --model-packs applies its data extensions
    #: (verified live — without it the augmented analysis is
    #: byte-identical to the baseline).
    additional_model_packs: dict[str, list[tuple[str, str]]] | None = None

    def _model_pack_args(self, language: str) -> list[str]:
        packs = (self.additional_model_packs or {}).get(language, [])
        out: list[str] = []
        for search_dir, pack_name in packs:
            out.extend([
                "--additional-packs", str(search_dir),
                "--model-packs", pack_name,
            ])
        return out

    def _has_model_packs(self, language: str) -> bool:
        return bool((self.additional_model_packs or {}).get(language))


    def active_threat_models(self) -> tuple:
        """Threat models the standard-suite pass will request.

        Empty when the kill-switch is off, the configured set is empty,
        or the CLI predates ``--threat-model``
        (:data:`THREAT_MODEL_MIN_VERSION`). Version facts are cached by CLI
        identity; the comparison and config reads stay fresh so recovery,
        executable changes and per-run overrides take effect immediately.
        """
        if not RaptorConfig.CODEQL_THREAT_MODELS_ENABLED:
            return ()
        models = tuple(RaptorConfig.CODEQL_THREAT_MODELS or ())
        if not models:
            return ()
        version = self._codeql_version()
        parts = _release_version(version)
        gate = parts is not None and parts >= THREAT_MODEL_MIN_VERSION
        previous_notice = getattr(self, "_threat_model_notice", ())
        self._threat_model_notice = version
        if not gate and previous_notice != version:
            if version is None:
                logger.info("threat models skipped: CodeQL version unknown")
            elif parts is None:
                logger.info("threat models skipped: unparseable CodeQL version %r", version)
            else:
                logger.info("threat models skipped: CodeQL %s < %s", version,
                            ".".join(map(str, THREAT_MODEL_MIN_VERSION)))
        return models if gate else ()

    def _threat_model_args(self) -> list:
        """``--threat-model=<name>`` flags for the analyze command."""
        return [f"--threat-model={m}" for m in self.active_threat_models()]

    def run_suite(
        self,
        database_path: Path,
        language: str,
        out_dir: Path,
        suite: str | None = None,
        use_extended: bool = False,
        concurrent_workers: int = 1,
    ) -> QueryResult:
        """
        Execute CodeQL suite against database.

        Args:
            database_path: Path to CodeQL database
            language: Programming language
            out_dir: Output directory for SARIF
            suite: Custom suite identifier (uses default if None)
            use_extended: Use security-extended suite instead of standard
            concurrent_workers: How many CodeQL invocations run at the
                same time as this one (parallel multi-language analyses).
                Passed to ``CodeQLTunables.from_tuning`` so the auto
                (``-j 0``) thread count is divided between the concurrent
                processes; explicit thread settings are respected as-is

        Returns:
            QueryResult with execution status
        """
        start_time = time.time()
        errors = []
        database_path = Path(database_path).absolute()
        out_dir = Path(out_dir).absolute()

        logger.info("%s", '=' * 70)
        logger.info("Running CodeQL analysis for %s", language)
        logger.info("%s", '=' * 70)

        # Determine suite to use
        if suite:
            suite_name = suite
            logger.info("Using custom suite: %s", suite)
        else:
            # Use standard or extended suite
            suites = self.SECURITY_EXTENDED_SUITES if use_extended else self.SECURITY_SUITES
            suite_name = suites.get(language)  # type: ignore[assignment]

            if not suite_name:
                error = f"No default suite for language: {language}"
                logger.error(error)
                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=[error],
                    suite_name="unknown",
                )

            suite_type = "security-extended" if use_extended else "security-and-quality"
            logger.info("Using %s suite: %s", suite_type, suite_name)

        # Prepare output path
        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}.sarif"

        # If CODEQL_QUERIES is set, ALWAYS use absolute paths to avoid pack conflicts
        import os
        codeql_queries = os.environ.get("CODEQL_QUERIES")
        if not codeql_queries:
            sibling = Path(self.codeql_cli).resolve().parent.parent / "codeql-queries"
            if sibling.is_dir():
                codeql_queries = str(sibling)
        actual_suite_path = suite_name
        resolved_to_absolute = False

        if codeql_queries and Path(codeql_queries).exists():
            # Try to resolve the suite to an absolute path to avoid pack conflicts
            # Convert pack reference like "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
            # to absolute path like "/path/to/codeql-queries/java/ql/src/codeql-suites/java-security-and-quality.qls"
            if ":" in suite_name:
                pack_name, suite_path = suite_name.split(":", 1)
                # Map pack names to directories
                lang_map = {
                    "codeql/java-queries": "java",
                    "codeql/python-queries": "python",
                    "codeql/javascript-queries": "javascript",
                    "codeql/cpp-queries": "cpp",
                    "codeql/csharp-queries": "csharp",
                    "codeql/go-queries": "go",
                    "codeql/ruby-queries": "ruby",
                    "codeql/swift-queries": "swift",
                    "codeql/rust-queries": "rust",
                }

                lang_dir = lang_map.get(pack_name)
                if lang_dir:
                    # Try to find the suite file
                    potential_path = Path(codeql_queries) / lang_dir / "ql" / "src" / suite_path
                    if potential_path.exists():
                        actual_suite_path = str(potential_path)
                        resolved_to_absolute = True
                        logger.info("✓ Resolved suite to absolute path: %s", actual_suite_path)
                    else:
                        logger.warning("Could not find suite at %s", potential_path)
                        # Try without the "ql/src" part (for different CodeQL repo structures)
                        alt_path = Path(codeql_queries) / lang_dir / suite_path
                        if alt_path.exists():
                            actual_suite_path = str(alt_path)
                            resolved_to_absolute = True
                            logger.info(
                                "✓ Resolved suite to absolute path (alt): %s", actual_suite_path
                            )
                        else:
                            logger.error("✗ Cannot resolve suite path - will attempt pack reference (may cause conflicts)")
            # Already an absolute path or simple name
            elif Path(suite_name).exists():
                actual_suite_path = str(Path(suite_name).resolve())
                resolved_to_absolute = True

        # Build command
        cmd = [
            self.codeql_cli,
            "database",
            "analyze",
            str(database_path),
            actual_suite_path,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            # Cached query results MASK model-pack rows — force
            # re-evaluation when learned models are staged.
            ("--rerun" if self._has_model_packs(language)
             else "--no-rerun"),
            # Additive source models (e.g. `local` = environment /
            # commandargs / stdin / file / database) on stock queries.
            # Empty on old CLIs / kill-switch; CLI-documented no-op for
            # packs without threat-model support.
            *self._threat_model_args(),
            *self._model_pack_args(language),
            f"--max-paths={RaptorConfig.CODEQL_MAX_PATHS}",
        ]
        # Central CodeQL resource tunables (-j / -M, tuning.json-backed).
        # ``include_disk_cache=False`` because ``database analyze``
        # rejects ``--max-disk-cache`` as an unknown flag.
        CodeQLTunables.from_tuning(
            concurrent_workers=concurrent_workers,
        ).append_to(cmd, include_disk_cache=False)

        # DO NOT add search-path - it causes pack conflicts when multiple copies exist
        # Instead, we always use absolute paths (resolved above) to avoid ambiguity
        if not resolved_to_absolute and codeql_queries:
            logger.warning("⚠️  Using pack reference without resolved absolute path")
            logger.warning("   This may cause conflicts if multiple pack copies exist")
            logger.warning("   Pack: %s", actual_suite_path)

        logger.info("Executing: %s", ' '.join(cmd))
        logger.info("Timeout: %ss", RaptorConfig.CODEQL_ANALYZE_TIMEOUT)

        # Execute analysis in sandbox (network blocked — packs pre-fetched)
        try:
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                temporary_command(cmd, scoped=True),
                block_network=True,
                **self._analysis_scope(cmd, database_path, out_dir, actual_suite_path),
                audit_run_dir=str(out_dir),
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            # Auto-download missing query packs (needs network) and retry in sandbox
            if (not success and "cannot be found" in (result.stderr or "").lower()
                    and not RaptorConfig.CODEQL_OFFLINE):
                pack_name = _extract_missing_pack(result.stderr)  # type: ignore[assignment]
                if pack_name:
                    logger.info("Query pack '%s' not found — downloading...", pack_name)
                    # Route codeql through the RAPTOR egress proxy.
                    # CodeQL's Java stack respects the lowercase
                    # `https_proxy` env var (set automatically by
                    # use_egress_proxy=True). Hostname allowlist pins
                    # the download to the CodeQL registry / GitHub
                    # container registry; seccomp blocks UDP (no DNS
                    # exfil — the proxy resolves on behalf). Landlock
                    # pins writes to the codeql pack cache dir.
                    codeql_cache = Path.home() / ".codeql"
                    codeql_cache.mkdir(parents=True, exist_ok=True)
                    # Retry the download up to 3x with exponential
                    # backoff (1s, 2s) via core.run.retry. Pre-fix a
                    # single attempt — if the registry was
                    # momentarily slow / a transient 503 from
                    # ghcr.io / network blip, the whole analysis
                    # dispatch failed and the operator had to re-run
                    # the entire scan. Retries are cheap (at most 3
                    # sub-2-minute calls) and cover the common
                    # transient failure modes.
                    from core.run.retry import RetryPolicy, retry_call
                    from packages.codeql.codeql_proxy_hosts import (
                        proxy_hosts_for_codeql,
                    )

                    def _download():
                        return sandbox_run(
                            temporary_command([self.codeql_cli, "pack", "download", pack_name], scoped=True),
                            use_egress_proxy=True,
                            # The pack name is parsed out of `codeql
                            # analyze` stderr over a database built
                            # from the UNTRUSTED repo (in-repo query
                            # packs included), so the child's argv is
                            # repo-influenced. Require the netns
                            # egress tier: on a host where only the
                            # port-scoped Landlock fallback is
                            # available, a direct connect on the
                            # proxy port would bypass the hostname
                            # allowlist (00015 doctrine — untrusted
                            # egress must use the netns tier).
                            # SandboxSetupError is caught by this
                            # method's handler; the analysis then
                            # fails with a clear reason instead of
                            # downloading through the weaker tier.
                            require_proxy_netns=True,
                            # Hostname allowlist auto-discovered from
                            # the calibrated profile when present
                            # (catches enterprise GHE redirect to
                            # `ghe.<corp>.example`-style hosts);
                            # falls back to the documented vanilla
                            # GitHub Container Registry set otherwise.
                            # Operator override at
                            # ~/.config/raptor/codeql-proxy-hosts.json
                            # short-circuits both.
                            proxy_hosts=proxy_hosts_for_codeql(
                                self.codeql_cli,
                            ),
                            caller_label="codeql-pack-download",
                            **self._filesystem_scope(codeql_cache),
                            capture_output=True, text=True, timeout=120,
                        )

                    dl = retry_call(
                        _download,
                        policy=RetryPolicy(
                            attempts=3,
                            # Result-based retry only: sandbox_run
                            # returns a CompletedProcess; a raised
                            # exception is a hard failure, not a
                            # registry blip.
                            retryable=lambda _exc: False,
                            base_delay=1.0, multiplier=2.0,
                        ),
                        retry_result=lambda r: r.returncode != 0,
                        on_retry=lambda i, _exc, delay: logger.info(
                            "Pack download attempt %d failed; "
                            "retrying in %ds", i + 1, int(delay),
                        ),
                    )
                    if dl.returncode == 0:
                        logger.info("✓ Downloaded %s — retrying analysis", pack_name)
                        result = sandbox_run(
                            temporary_command(cmd, scoped=True), block_network=True,
                            **self._analysis_scope(cmd, database_path, out_dir, actual_suite_path),
                            audit_run_dir=str(out_dir),
                            capture_output=True, text=True,
                            timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
                        )
                        success = result.returncode == 0
                    else:
                        # `or ""` — sandbox_run can return None for
                        # stderr when the captured stream was closed
                        # before any output was written; pre-fix the
                        # `[:200]` slice raised TypeError on None,
                        # masking the original "download failed" with
                        # an unrelated traceback.
                        dl_stderr = (dl.stderr or "")[:200]
                        errors.append(f"Pack download failed: {dl_stderr}")
                        logger.error("✗ Failed to download %s: %s", pack_name, dl_stderr)

            if not success:
                errors.append(f"Analysis failed with exit code {result.returncode}")
                if RaptorConfig.CODEQL_OFFLINE:
                    errors.append('Offline CodeQL: run engine/codeql/tools/offline.py check for the selected language and modes')
                if result.stderr:
                    errors.append(result.stderr[:1000])
                logger.error("✗ Analysis failed for %s", language)
                # `or ""` for the same reason as above — `result.stderr`
                # may be None on some sandbox failure modes (timeout
                # mid-stream, killed before write). Escaped because
                # analyze stderr can quote hostile source from the
                # scanned repo (extractor diagnostics) — control/bidi
                # bytes must not reach the operator's terminal raw.
                from core.security.log_sanitisation import (
                    escape_nonprintable,
                )
                logger.error(
                    "%s",
                    escape_nonprintable(
                        (result.stderr or "")[:500],
                        preserve_newlines=True,
                    ),
                )

                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=errors,
                    suite_name=suite_name,
                )

            # Parse SARIF to count findings
            findings_count = 0
            queries_executed = 0

            from core.sarif.parser import load_sarif
            sarif_data = load_sarif(sarif_path) if sarif_path.exists() else None
            runs = (
                sarif_data.get("runs")
                if isinstance(sarif_data, dict) else None
            )
            if not isinstance(runs, list):
                # rc==0 but no readable SARIF: a missing / oversized /
                # unparseable output is an analysis failure, never a
                # successful zero-finding run — success=True here reads
                # downstream as a clean scan. Schema leg: a 0-byte
                # file parses to {} and any valid-JSON dict passes
                # load_sarif — without a `runs` list it is not a
                # SARIF document, same failure.
                reason = self._unreadable_sarif_reason(sarif_path)
                errors.append(reason)
                logger.error("✗ %s", reason)
                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=errors,
                    suite_name=suite_name,
                )
            for run in runs:
                findings_count += len(run.get("results", []))
                queries_executed += len(run.get("tool", {}).get("driver", {}).get("rules", []))

            logger.info("✓ Analysis completed for %s", language)
            logger.info("  Findings: %s", findings_count)
            logger.info("  Queries executed: %s", queries_executed)
            logger.info("  Duration: %.1fs", time.time() - start_time)
            logger.info("  SARIF: %s", sarif_path)

            return QueryResult(
                success=True,
                language=language,
                database_path=database_path,
                sarif_path=sarif_path,
                findings_count=findings_count,
                duration_seconds=time.time() - start_time,
                errors=[],
                suite_name=suite_name,
                queries_executed=queries_executed,
            )

        except subprocess.TimeoutExpired:
            error = f"Analysis timed out after {RaptorConfig.CODEQL_ANALYZE_TIMEOUT}s"
            errors.append(error)
            logger.error("✗ %s", error)

            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=errors,
                suite_name=suite_name,
            )

        except SandboxSetupError:
            raise  # sandbox isolation could not engage — fail loud, never mask as a benign result

        except Exception as e:  # noqa: BLE001
            error = f"Unexpected error: {e!s}"
            errors.append(error)
            logger.error("✗ Analysis failed with exception: %s", e)

            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=errors,
                suite_name=suite_name,
            )

    def _compatible_query_args(
        self, query_path: Path, *, excluded_queries: tuple[Path, ...] = (),
    ) -> tuple[list[str], list[str]]:
        """Retain native suite membership, excluding explicit utility paths."""
        import json

        from core.sandbox import run as sandbox_run

        candidates = (sorted(query_path.rglob("*.ql")) if query_path.is_dir()
                      else [query_path] if query_path.suffix == ".ql" else [])

        # Keep one version answer and one metadata decision per selection.
        # Unknown versions are retried by the next invocation, rather than
        # potentially paying a probe timeout for every declared query here.
        version_checked = False
        installed_version: str | None = None
        decisions: dict[Path, str | None] = {}

        def installed() -> str | None:
            nonlocal version_checked, installed_version
            if not version_checked:
                installed_version = self._codeql_version()
                version_checked = True
            return installed_version

        def refusal(path: Path) -> str | None:
            key = path.resolve()
            if key not in decisions:
                text = read_capped_text(path, 1024 * 1024, errors="strict")
                decisions[key] = ("rule skipped: requirement metadata unreadable"
                                  if text is None else rule_version_refusal(text, installed))
            return decisions[key]

        excluded = {path.resolve() for path in excluded_queries}
        refused = {str(path.resolve()): reason for path in candidates
                   if (not excluded or path.resolve() not in excluded)
                   and (reason := refusal(path)) is not None}
        has_excluded = bool(excluded) and any(path.resolve() in excluded for path in candidates)
        if not refused and not has_excluded and query_path.suffix != ".qls":
            return [str(query_path)], []
        try:
            resolved = sandbox_run(
                temporary_command([self.codeql_cli, "resolve", "queries",
                                   str(query_path), "--format=json"]),
                block_network=True, tool_paths=self._sandbox_tool_paths(),
                readable_paths=[str(query_path.resolve())],
                capture_output=True, text=True, timeout=60,
            )
            # Resolver output is tool output; cap it before parsing.
            if resolved.returncode or len(resolved.stdout) > 1024 * 1024:
                raise ValueError("query resolution failed")
            selected = json.loads(resolved.stdout)
            if not isinstance(selected, list) or not all(isinstance(p, str) for p in selected):
                raise ValueError("invalid query resolution")
            selected = list(dict.fromkeys(selected))
        except SandboxSetupError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError, RecursionError):
            return [], ["custom rules skipped: compatibility query selection unavailable"]
        eligible, skipped = [], []
        for name in selected:
            path = Path(name)
            if path.resolve() in excluded:
                logger.debug("Excluded internal utility query from security selection")
                continue
            reason = refusal(path)
            if reason:
                skipped.append(f"{name}: {reason}")
            else:
                eligible.append(f"path:{name}")
        return eligible, skipped

    def run_custom_queries(
        self, database_path: Path, query_path: Path, out_dir: Path, language: str,
    ) -> QueryResult:
        args, skipped = self._compatible_query_args(Path(query_path))
        if not args:
            self._log_rule_skips(skipped)
            return QueryResult(
                success=False, language=language, database_path=database_path,
                sarif_path=None, findings_count=0, duration_seconds=0,
                errors=["No compatible custom queries selected"],
                suite_name="custom", skipped_rules=skipped,
            )
        result = self._run_compatible_custom_queries(
            database_path, query_path, out_dir, language, query_args=args,
        )
        result.skipped_rules = skipped
        self._log_rule_skips(skipped)
        return result

    @staticmethod
    def _log_rule_skips(skipped: list[str]) -> None:
        from core.security.log_sanitisation import escape_nonprintable

        for reason in skipped:
            logger.warning("%s", escape_nonprintable(reason))

    def _run_compatible_custom_queries(
        self,
        database_path: Path,
        query_path: Path,
        out_dir: Path,
        language: str,
        *, query_args: list[str],
    ) -> QueryResult:
        """
        Run custom query pack against database.

        Args:
            database_path: Path to CodeQL database
            query_path: Path to query pack or directory
            out_dir: Output directory
            language: Programming language

        Returns:
            QueryResult
        """
        start_time = time.time()
        database_path = Path(database_path).absolute()
        query_path = Path(query_path).absolute()
        out_dir = Path(out_dir).absolute()

        logger.info("Running custom queries from: %s", query_path)

        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}_custom.sarif"

        cmd = [
            self.codeql_cli,
            "database",
            "analyze",
            str(database_path),
            *query_args,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            *(f"--additional-packs={root}" for root in
              self._local_dependency_roots(language, query_path)),
        ]
        CodeQLTunables.from_tuning().append_to(cmd, include_disk_cache=False)

        try:
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                temporary_command(cmd, scoped=True),  # type: ignore[arg-type]
                block_network=True,
                **self._analysis_scope(cmd, database_path, out_dir, query_path),
                audit_run_dir=str(out_dir),
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            if success:
                findings_count = (
                    self._count_sarif_findings(sarif_path)
                    if sarif_path.exists() else None
                )
                if findings_count is None:
                    # rc==0 but no readable SARIF is an analysis
                    # failure, never a clean zero-finding scan —
                    # run_suite's guard, applied to this sibling.
                    reason = self._unreadable_sarif_reason(sarif_path)
                    logger.error("✗ %s", reason)
                    return QueryResult(
                        success=False,
                        language=language,
                        database_path=database_path,
                        sarif_path=None,
                        findings_count=0,
                        duration_seconds=time.time() - start_time,
                        errors=[reason],
                        suite_name="custom",
                    )
                logger.info("✓ Custom queries completed: %s findings", findings_count)

                return QueryResult(
                    success=True,
                    language=language,
                    database_path=database_path,
                    sarif_path=sarif_path,
                    findings_count=findings_count,
                    duration_seconds=time.time() - start_time,
                    errors=[],
                    suite_name="custom",
                )
            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                # Same cap as run_suite's stderr capture: this rides
                # uncapped into the report JSON otherwise, and
                # analyze stderr can carry megabytes of extractor
                # diagnostics quoting hostile source.
                errors=[result.stderr[:1000]] if result.stderr else [],
                suite_name="custom",
            )

        except SandboxSetupError:
            raise  # sandbox isolation could not engage — fail loud, never mask as a benign result

        except Exception as e:  # noqa: BLE001
            logger.error("✗ Custom query execution failed: %s", e)
            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=[str(e)],
                suite_name="custom",
            )

    def analyze_all_databases(
        self,
        databases: dict[str, Path],
        out_dir: Path,
        use_extended: bool = False,
        max_workers: int | None = None
    ) -> dict[str, QueryResult]:
        """
        Analyze multiple databases in parallel.

        Args:
            databases: Dict mapping language -> database path
            out_dir: Output directory
            use_extended: Use extended security suites
            max_workers: Max parallel workers

        Returns:
            Dict mapping language -> QueryResult
        """
        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results = {}

        logger.info(
            "Analyzing %d databases in parallel (max workers: %s)", len(databases), max_workers
        )

        # Core-share for each child: N concurrent -j0 analyses would
        # each claim every core; divide instead (explicit numeric
        # codeql_threads is respected inside from_tuning).
        _share = min(max_workers, len(databases)) or 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_lang = {
                executor.submit(
                    self.run_suite,
                    db_path,
                    lang,
                    out_dir,
                    None,
                    use_extended,
                    _share,
                ): lang
                for lang, db_path in databases.items()
            }

            # Collect results
            for future in as_completed(future_to_lang):
                lang = future_to_lang[future]
                try:
                    result = future.result()
                    results[lang] = result
                    if result.success:
                        logger.info(
                            "✓ %s analysis completed: %s findings", lang, result.findings_count
                        )
                    else:
                        logger.error("✗ %s analysis failed", lang)
                except Exception as e:  # noqa: BLE001
                    logger.error("✗ %s analysis raised exception: %s", lang, e)
                    results[lang] = QueryResult(
                        success=False,
                        language=lang,
                        database_path=databases[lang],
                        sarif_path=None,
                        findings_count=0,
                        duration_seconds=0.0,
                        errors=[str(e)],
                        suite_name="unknown",
                    )

        return results

    def analyze_iris_packs(
        self,
        databases: dict[str, Path],
        out_dir: Path,
        max_workers: int | None = None,
    ) -> dict[str, "QueryResult"]:
        """Run RAPTOR's in-repo IRIS LocalFlowSource packs against each
        database. Same DBs the standard suite uses; complementary
        queries that catch CLI / env / stdin source flows the stdlib
        `RemoteFlowSource`-based queries miss.

        Standalone consumers: `/codeql` calls this after the standard
        suite so operators running CodeQL outside `/agentic` get
        LocalFlowSource coverage too. The pack lives at
        `packages/llm_analysis/codeql_packs/<lang>-queries/`; lockfile
        is committed, so `codeql pack install` is a fast idempotent
        no-op on subsequent runs.

        Returns one `QueryResult` per language whose pack exists. Langs
        without an in-repo pack (e.g. cpp — stdlib already covers it
        via parent `FlowSource`) are silently skipped.

        Per-language analyses run in parallel via the same
        ThreadPoolExecutor pattern `analyze_all_databases` uses.

        Caveat: first install on a fresh checkout needs network to
        fetch dependency packs (codeql/<lang>-all etc.). Subsequent
        runs are offline-cacheable via the committed lockfile. CI
        environments without egress should pre-warm the dep cache;
        otherwise IRIS analyses surface a `success=False` QueryResult
        with the resolution error captured in `errors`.
        """
        from core.config import RaptorConfig

        if not RaptorConfig.CODEQL_ENABLED:
            logger.info("IRIS pack analysis skipped: CODEQL_ENABLED is False")
            return {}

        if not RaptorConfig.IRIS_TIER1_ENABLED:
            logger.info("IRIS pack analysis skipped: IRIS_TIER1_ENABLED is False")
            return {}

        extras = list(RaptorConfig.EXTRA_CODEQL_PACK_ROOTS or [])
        if not extras:
            return {}
        # First entry is the canonical RAPTOR-shipped pack root.
        pack_root = extras[0]
        if not pack_root.is_dir():
            return {}

        # Filter to languages that actually have an in-repo pack.
        analyzable: dict[str, tuple[Path, Path]] = {}
        for lang, db in databases.items():
            pack_dir = pack_root / f"{lang}-queries"
            if pack_dir.is_dir():
                analyzable[lang] = (db, pack_dir)
        if not analyzable:
            return {}

        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results: dict[str, QueryResult] = {}

        def _run_one(lang: str, db: Path, pack_dir: Path) -> "QueryResult":
            return self._run_iris_pack(lang, db, pack_dir, out_dir)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_lang = {
                executor.submit(_run_one, lang, db, pack_dir): lang
                for lang, (db, pack_dir) in analyzable.items()
            }
            for future in as_completed(future_to_lang):
                lang = future_to_lang[future]
                try:
                    results[lang] = future.result()
                except Exception as e:  # noqa: BLE001
                    logger.warning("IRIS LocalFlowSource (%s) raised: %s", lang, e)
                    db, _ = analyzable[lang]
                    results[lang] = QueryResult(
                        success=False, language=lang,
                        database_path=db, sarif_path=None, findings_count=0,
                        duration_seconds=0.0, errors=[str(e)],
                        suite_name="raptor-iris-local",
                    )
        return results

    def analyze_curated_packs(
        self,
        databases: dict[str, Path],
        out_dir: Path,
        max_workers: int | None = None,
    ) -> dict[str, "QueryResult"]:
        """Run RAPTOR's curated in-repo query packs
        (`engine/codeql/queries/<lang>/`) against each database.

        Hand-written queries complementing the standard suites (e.g.
        cpp use-after-move / iterator invalidation, java XXE / SSRF
        annotation sources). Same DBs the standard suite uses; output
        `codeql_<lang>_curated.sarif` joins the report's `sarif_files`
        exactly like the IRIS pass, so downstream consumers pick it up
        without changes.

        Returns one `QueryResult` per language whose curated pack
        exists (a directory with a `qlpack.yml` and at least one
        `.ql`). Languages without one are silently skipped.

        Dependency resolution: the curated packs pin their stdlib dep
        with `*` and may not carry a committed lockfile. `codeql pack
        install` is attempted lazily (warning on failure, mirroring
        the IRIS pass), but when the standard suite has already cached
        `codeql/<lang>-queries`, the `<lang>-all` library vendored
        inside that cache is passed via `--additional-packs` — so on
        hosts without registry egress the curated queries still
        resolve their imports.
        """
        from core.config import RaptorConfig

        if not RaptorConfig.CODEQL_ENABLED:
            logger.info("Curated query analysis skipped: CODEQL_ENABLED is False")
            return {}

        if not RaptorConfig.CODEQL_CURATED_ENABLED:
            logger.info(
                "Curated query analysis skipped: CODEQL_CURATED_ENABLED is False"
            )
            return {}

        pack_root = RaptorConfig.CODEQL_QUERIES_DIR
        if not pack_root.is_dir():
            return {}

        analyzable: dict[str, tuple[Path, Path]] = {}
        for lang, db in databases.items():
            pack_dir = pack_root / lang
            if (
                pack_dir.is_dir()
                and (pack_dir / "qlpack.yml").is_file()
                and any(pack_dir.glob("*.ql"))
            ):
                analyzable[lang] = (db, pack_dir)
        if not analyzable:
            return {}

        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results: dict[str, QueryResult] = {}

        def _run_one(lang: str, db: Path, pack_dir: Path) -> "QueryResult":
            return self._run_local_pack(
                lang, db, pack_dir, out_dir,
                suite_name="raptor-curated",
                sarif_name=f"codeql_{lang}_curated.sarif",
                label="curated queries",
            )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_lang = {
                executor.submit(_run_one, lang, db, pack_dir): lang
                for lang, (db, pack_dir) in analyzable.items()
            }
            for future in as_completed(future_to_lang):
                lang = future_to_lang[future]
                try:
                    results[lang] = future.result()
                except Exception as e:  # noqa: BLE001
                    logger.warning("curated queries (%s) raised: %s", lang, e)
                    db, _ = analyzable[lang]
                    results[lang] = QueryResult(
                        success=False, language=lang,
                        database_path=db, sarif_path=None, findings_count=0,
                        duration_seconds=0.0, errors=[str(e)],
                        suite_name="raptor-curated",
                    )
        return results

    def _run_iris_pack(
        self, lang: str, db: Path, pack_dir: Path, out_dir: Path,
    ) -> "QueryResult":
        """Per-language worker for `analyze_iris_packs` — pack install
        followed by analyze."""
        probe = pack_dir / "Raptor" / "CallableInventory.ql"
        return self._run_local_pack(
            lang, db, pack_dir, out_dir,
            suite_name="raptor-iris-local",
            sarif_name=f"codeql_{lang}_iris.sarif",
            label="IRIS LocalFlowSource",
            excluded_queries=(probe,) if probe.is_file() else (),
        )

    def _run_local_pack(
        self, lang: str, db: Path, pack_dir: Path, out_dir: Path,
        *, suite_name: str, sarif_name: str, label: str,
        extra_analyze_args: tuple[str, ...] = (), skip_install: bool = False,
        excluded_queries: tuple[Path, ...] = (),
    ) -> QueryResult:
        # Share offline stdlib discovery with the custom-query entry point.
        # Explicit caller resolution settings retain their existing contract.
        if not extra_analyze_args and not skip_install:
            roots = self._local_dependency_roots(lang, pack_dir)
            extra_analyze_args = tuple(f"--additional-packs={root}" for root in roots)
            skip_install = bool(roots)
        if excluded_queries:
            args, skipped = self._compatible_query_args(
                Path(pack_dir), excluded_queries=excluded_queries)
        else:
            args, skipped = self._compatible_query_args(Path(pack_dir))
        if not args:
            self._log_rule_skips(skipped)
            return QueryResult(
                success=False, language=lang, database_path=db, sarif_path=None,
                findings_count=0, duration_seconds=0,
                errors=["No compatible custom queries selected"],
                suite_name=suite_name, skipped_rules=skipped,
            )
        result = self._run_selected_local_pack(
            lang, db, pack_dir, out_dir, suite_name=suite_name,
            sarif_name=sarif_name, label=label, extra_analyze_args=extra_analyze_args,
            skip_install=skip_install, query_args=args,
        )
        result.skipped_rules = skipped
        self._log_rule_skips(skipped)
        return result

    def _run_selected_local_pack(
        self, lang: str, db: Path, pack_dir: Path, out_dir: Path,
        *, suite_name: str, sarif_name: str, label: str,
        extra_analyze_args: tuple[str, ...] = (),
        skip_install: bool = False,
        query_args: list[str],
    ) -> "QueryResult":
        """Per-language worker shared by `analyze_iris_packs` and
        `analyze_curated_packs` — lazy pack install followed by a
        sandboxed `database analyze`. Extracted so the parallel
        orchestrators above are just dispatch + result aggregation."""
        from core.config import RaptorConfig
        from core.sandbox import run as sandbox_run
        db, pack_dir, out_dir = (Path(path).absolute() for path in (db, pack_dir, out_dir))

        # Skip the install entirely when every dep pinned in the
        # in-repo lockfile is already present in the standard pack
        # cache. In normal RAPTOR setups (where `~/.codeql/packages/
        # codeql/<lang>-all/...` is populated by the user's existing
        # CodeQL install) this is the common case, and skipping
        # avoids both the subprocess and the sandbox network-permit
        # round-trip. Sandboxed CI environments without a populated
        # pack cache fall through to the install attempt as before.
        if (skip_install or _iris_pack_deps_already_resolved(pack_dir)
                or RaptorConfig.CODEQL_OFFLINE):
            logger.debug(
                "%s pack (%s): deps already resolvable, skipping install",
                label, lang,
            )
        else:
            # Lazy `codeql pack install` — populates dependency cache
            # from the committed lockfile. Idempotent and fast on
            # subsequent runs; needed once on fresh checkouts before
            # the in-repo queries can resolve their imports.
            try:
                # Route the first-run dep fetch through the egress
                # proxy, mirroring the `pack download` site above.
                # Pre-fix this passed only block_network=False: the
                # child ran with a proxy-stripped safe env and dialed
                # ghcr.io directly, which mandatory-egress-proxy
                # hosts block — the IRIS pack install failed on every
                # fresh checkout there. use_egress_proxy sets the
                # lowercase https_proxy CodeQL's Java stack honours,
                # and the proxy chains to the operator's upstream.
                from packages.codeql.codeql_proxy_hosts import (
                    proxy_hosts_for_codeql,
                )
                # require_proxy_netns is deliberately NOT set here:
                # the child is the trusted codeql binary and its argv
                # / fetch set are RAPTOR-pinned (pack_dir is the
                # RAPTOR-shipped pack root; the dependency list comes
                # from our committed codeql-pack.lock.yml, not from
                # the scanned repo). Nothing the target repo controls
                # reaches this execution, so the port-scoped Landlock
                # fallback tier is an acceptable degradation for the
                # first-run dep fetch (00015 requires the netns tier
                # only for repo-influenced egress).
                install_proc = sandbox_run(
                    temporary_command([self.codeql_cli, "pack", "install", str(pack_dir)], scoped=True),  # type: ignore[list-item]
                    use_egress_proxy=True,
                    proxy_hosts=proxy_hosts_for_codeql(self.codeql_cli),
                    caller_label="codeql-pack-install",
                    **self._filesystem_scope(Path.home() / ".codeql", writable=[pack_dir]),
                    audit_run_dir=str(out_dir),
                    capture_output=True, text=True,
                    timeout=180,
                )
                if install_proc.returncode != 0:
                    # Surface install failure at warning level so
                    # operators see *why* a subsequent analyze
                    # failure is happening. Common failure mode:
                    # sandboxed CI without network on a fresh
                    # checkout (lockfile committed but dep packs not
                    # cached locally).
                    install_err = (
                        install_proc.stderr or install_proc.stdout or ""
                    ).strip()[:300]
                    # Escaped at the echo: install stderr relays
                    # registry-influenced content — control/bidi
                    # bytes must not reach the operator terminal raw
                    # (same contract as the analyze stderr echoes).
                    from core.security.log_sanitisation import (
                        escape_nonprintable,
                    )
                    logger.warning(
                        "%s pack install (%s) returned %s: %s",
                        label,
                        lang,
                        install_proc.returncode,
                        escape_nonprintable(
                            install_err, preserve_newlines=True,
                        ),
                    )
            except Exception as e:  # noqa: BLE001
                logger.warning("%s pack install (%s) raised: %s", label, lang, e)

        sarif_path = out_dir / sarif_name
        cmd = [
            self.codeql_cli, "database", "analyze",
            str(db), *query_args,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            *extra_analyze_args,
        ]
        CodeQLTunables.from_tuning().append_to(cmd, include_disk_cache=False)
        analysis_start = time.time()
        try:
            proc = sandbox_run(
                temporary_command(cmd, scoped=True), block_network=True,  # type: ignore[arg-type]
                **self._analysis_scope(cmd, db, out_dir, pack_dir),
                audit_run_dir=str(out_dir),
                capture_output=True, text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )
        except SandboxSetupError:
            raise  # sandbox isolation could not engage — fail loud, never mask as a benign result

        except Exception as e:  # noqa: BLE001
            logger.warning("%s (%s) analyze raised: %s", label, lang, e)
            return QueryResult(
                success=False, language=lang,
                database_path=db, sarif_path=None, findings_count=0,
                duration_seconds=time.time() - analysis_start,
                errors=[str(e)], suite_name=suite_name,
            )

        if proc.returncode == 0:
            n = (
                self._count_sarif_findings(sarif_path)
                if sarif_path.exists() else None
            )
            if n is None:
                # rc==0 but no readable SARIF: analysis failure, never
                # a clean zero-finding scan (run_suite's guard, applied
                # to the IRIS + curated sibling).
                reason = self._unreadable_sarif_reason(sarif_path)
                logger.warning("%s (%s) failed: %s", label, lang, reason)
                return QueryResult(
                    success=False, language=lang,
                    database_path=db, sarif_path=None, findings_count=0,
                    duration_seconds=time.time() - analysis_start,
                    errors=[reason], suite_name=suite_name,
                )
            logger.info("✓ %s (%s): %s findings", label, lang, n)
            return QueryResult(
                success=True, language=lang,
                database_path=db, sarif_path=sarif_path,
                findings_count=n,
                duration_seconds=time.time() - analysis_start,
                errors=[], suite_name=suite_name,
            )

        err = (proc.stderr or proc.stdout or "").strip()[:300]
        # Escaped at the echo only: analyze stderr quotes hostile
        # source from the scanned repo (extractor diagnostics), so
        # control/bidi bytes must not reach the operator terminal raw.
        # The stored error list keeps the raw string — it is the data
        # plane consumers (RefinementFeedback.tool_errors, reports)
        # sanitise at their own render sites.
        from core.security.log_sanitisation import escape_nonprintable
        logger.warning(
            "%s (%s) failed: %s", label, lang,
            escape_nonprintable(err, preserve_newlines=True),
        )
        return QueryResult(
            success=False, language=lang,
            database_path=db, sarif_path=None, findings_count=0,
            duration_seconds=time.time() - analysis_start,
            errors=[err] if err else [],
            suite_name=suite_name,
        )

    def run_local_pack(
        self, lang: str, db: Path, pack_dir: Path, out_dir: Path,
        *, suite_name: str, sarif_name: str, label: str,
        extra_analyze_args: tuple[str, ...] = (),
        skip_install: bool = False,
    ) -> "QueryResult":
        """Public seam over ``_run_local_pack`` for out-of-package
        consumers (``core.iris.codeql_runner``): lazy proxy-routed pack
        install (unless *skip_install* / deps already cached) followed
        by a sandboxed network-blocked ``database analyze``."""
        return self._run_local_pack(
            lang, db, pack_dir, out_dir,
            suite_name=suite_name, sarif_name=sarif_name, label=label,
            extra_analyze_args=extra_analyze_args,
            skip_install=skip_install,
        )

    def _count_sarif_findings(self, sarif_path: Path) -> int | None:
        """Count findings in a SARIF file — ``None`` when unreadable.

        ``load_sarif`` refuses missing / oversized (past the
        corpus-tuned ``SARIF_MAX_BYTES``; see the trade-off note at
        the constant) / malformed files by returning None. Mapping
        that refusal to 0 here used
        to let an rc==0 analyze with an unreadable output read
        downstream as a successful zero-finding scan; callers must
        treat None as an analysis failure, mirroring run_suite's
        explicit guard.

        A document ``load_sarif`` accepts is not necessarily SARIF: a
        0-byte file parses to ``{}`` and any valid-JSON dict passes.
        Without a ``runs`` list (or with malformed run entries) this
        is not a SARIF document, so it lands on the same None path —
        never a countable zero."""
        from core.sarif.parser import load_sarif
        sarif_data = load_sarif(sarif_path)
        if sarif_data is None:
            return None
        runs = sarif_data.get("runs")
        if not isinstance(runs, list):
            return None
        total = 0
        for run in runs:
            if not isinstance(run, dict):
                return None
            results = run.get("results", [])
            if not isinstance(results, list):
                return None
            total += len(results)
        return total

    def _unreadable_sarif_reason(self, sarif_path: Path) -> str:
        """Failure reason for an rc==0 analyze without readable SARIF.

        The oversized case is diagnosed with the mechanical facts
        (actual size vs the parser cap) so an operator whose
        completed multi-hour analyze was discarded over the size cap
        can see exactly which limit fired and that the artifact
        itself is intact — instead of the undifferentiated
        "parse/size/schema failure" that hid the cheapest recovery
        (re-running with a raised cap, per SARIF_MAX_BYTES's own
        move-only-against-a-corpus note).
        """
        if not sarif_path.exists():
            return f"SARIF output missing after successful analyze: {sarif_path}"
        from core.sarif.parser import SARIF_MAX_BYTES
        try:
            size = sarif_path.stat().st_size
        except OSError:
            size = -1
        if size > SARIF_MAX_BYTES:
            return (
                f"SARIF output exceeds the parser cap "
                f"({size} bytes > SARIF_MAX_BYTES={SARIF_MAX_BYTES}): "
                f"{sarif_path} — the analyze completed and the "
                f"artifact is intact; the lane failed on the "
                f"post-parse size refusal"
            )
        return (
            f"SARIF output unreadable (parse/schema failure): {sarif_path}"
        )

    def get_sarif_summary(self, sarif_path: Path,
                          *, sarif_data: object = _SARIF_DATA_UNSET) -> dict:
        """Summarize usable rows without discarding neighboring valid data.

        Omit ``sarif_data`` to load through the shared bounded reader. An
        explicit dict reuses a prior decode; explicit None records a failed
        prior load and never reopens that input. Query counts describe unique
        named descriptors per tool component, not proof of query execution.
        """
        from core.sarif.parser import (
            ResultRuleResolver, _as_dict, _normalise_tool_name, _result_rule_id,
            get_run_execution_diagnostics, get_tool_name, load_sarif, rule_default_level,
        )

        if sarif_data is _SARIF_DATA_UNSET:
            sarif_data = load_sarif(sarif_path)
        if not isinstance(sarif_data, dict):
            return {}
        if not isinstance(sarif_data.get("runs"), list):
            logger.warning("CodeQL SARIF summary unavailable: report has no runs array")
            return {}

        summary: dict[str, Any] = {
            "total_findings": 0,
            "by_severity": {"error": 0, "warning": 0, "note": 0},
            "by_rule": {},
            "queries_executed": 0,
            "dataflow_paths": 0,
            "total_dataflow_steps": 0,
            "sarif_input_errors": 0,
            "tool_execution_failures": {},
            "tool_coverage_limitations": {},
        }

        def rows(container, key):
            value = container.get(key, [])
            if not isinstance(value, list):
                summary["sarif_input_errors"] += 1
                return
            for row in value:
                if isinstance(row, dict):
                    yield row
                else:
                    summary["sarif_input_errors"] += 1

        for run in rows(sarif_data, "runs"):
            diagnostics = get_run_execution_diagnostics(run)
            summary["sarif_input_errors"] += diagnostics["sarif_input_errors"]
            tool_key = _normalise_tool_name(get_tool_name(run))
            for key in ("tool_execution_failures", "tool_coverage_limitations"):
                if diagnostics[key]:
                    counts = summary[key]
                    counts[tool_key] = counts.get(tool_key, 0) + diagnostics[key]
            resolver = None
            for result in rows(run, "results"):
                summary["total_findings"] += 1
                level, rule_id = result.get("level"), result.get("ruleId")
                needs_level = not isinstance(level, str) or not level
                needs_id = not isinstance(rule_id, str) or not rule_id
                rule = {}
                if needs_level or needs_id:
                    if resolver is None:
                        resolver = ResultRuleResolver(run)
                    rule = resolver.resolve(result)
                    if not rule and ("ruleIndex" in result or "rule" in result):
                        summary["sarif_input_errors"] += 1
                for key in ("level", "ruleId"):
                    value = result.get(key)
                    if value is not None and not isinstance(value, str):
                        summary["sarif_input_errors"] += 1
                if needs_level:
                    level = rule_default_level(rule) or "warning"
                if needs_id:
                    rule_id = _result_rule_id(result, rule) or "unknown"
                summary["by_severity"][level] = summary["by_severity"].get(level, 0) + 1
                summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1
                for flow in rows(result, "codeFlows"):
                    summary["dataflow_paths"] += 1
                    for thread in rows(flow, "threadFlows"):
                        for _ in rows(thread, "locations"):
                            summary["total_dataflow_steps"] += 1

            raw_tool = run.get("tool", {})
            if not isinstance(raw_tool, dict):
                summary["sarif_input_errors"] += 1
            tool = _as_dict(raw_tool)
            driver = tool.get("driver", {})
            components = chain((driver,), rows(tool, "extensions"))
            for component in components:
                if not isinstance(component, dict):
                    summary["sarif_input_errors"] += 1
                    continue
                names = set()
                for descriptor in rows(component, "rules"):
                    name = descriptor.get("id")
                    if isinstance(name, str) and name:
                        names.add(name)
                    else:
                        summary["sarif_input_errors"] += 1
                summary["queries_executed"] += len(names)

        if summary["sarif_input_errors"]:
            logger.warning("CodeQL SARIF summary retained usable data with %s malformed metadata item(s)",
                           summary["sarif_input_errors"])
        if summary["tool_execution_failures"] or summary["tool_coverage_limitations"]:
            logger.warning("CodeQL SARIF reports %s failed invocation(s) and %s coverage limitation(s)",
                           sum(summary["tool_execution_failures"].values()),
                           sum(summary["tool_coverage_limitations"].values()))
        return summary


def iris_overlap_summary(out_dir: Path, languages) -> dict:
    """Per-(language, CWE) finding counts: standard suite vs IRIS pass.

    Cheap, mechanical data for the standing question of whether the
    in-repo IRIS packs are subsumed once the standard suite runs with
    `--threat-model=local` — nothing here changes verdicts. Only
    languages where BOTH `codeql_<lang>.sarif` and
    `codeql_<lang>_iris.sarif` exist appear in the result.
    """
    from core.sarif.parser import parse_sarif_findings

    def _counts(path: Path) -> dict:
        counts: dict = {}
        for finding in parse_sarif_findings(path):
            cwe = finding.get("cwe_id") or "unknown"
            counts[cwe] = counts.get(cwe, 0) + 1
        return counts

    summary: dict = {}
    for lang in languages:
        std = out_dir / f"codeql_{lang}.sarif"
        iris = out_dir / f"codeql_{lang}_iris.sarif"
        if not (std.is_file() and iris.is_file()):
            continue
        try:
            summary[lang] = {
                "standard": _counts(std),
                "iris": _counts(iris),
            }
        except Exception as e:  # noqa: BLE001 — diagnostics only, never fatal
            logger.debug("iris overlap summary skipped for %s: %s", lang, e)
    return summary


def main() -> None:
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeQL Query Runner")
    parser.add_argument("--database", required=True, help="Database path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--extended", action="store_true", help="Use extended security suite")
    parser.add_argument("--custom-queries", help="Path to custom query pack")
    args = parser.parse_args()

    runner = QueryRunner()

    if args.custom_queries:
        result = runner.run_custom_queries(
            Path(args.database),
            Path(args.custom_queries),
            Path(args.out),
            args.language
        )
    else:
        result = runner.run_suite(
            Path(args.database),
            args.language,
            Path(args.out),
            use_extended=args.extended
        )

    if result.success:
        print("\n✓ Analysis completed")
        print(f"  Findings: {result.findings_count}")
        print(f"  SARIF: {result.sarif_path}")
        print(f"  Duration: {result.duration_seconds:.1f}s")
    else:
        print("\n✗ Analysis failed", file=sys.stderr)
        for error in result.errors:
            print(f"  {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
