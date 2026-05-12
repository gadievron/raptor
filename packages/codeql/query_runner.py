#!/usr/bin/env python3
"""
CodeQL Query Runner

Executes CodeQL queries and suites against databases,
producing SARIF output for vulnerability analysis.
"""

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
# packages/codeql/query_runner.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


import re

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
    exists at its pinned version under `~/.codeql/packages/`.

    Used by `analyze_iris_packs` to skip the network-permitted
    `codeql pack install` call when the dep cache is already warm —
    avoids both the subprocess and the sandbox network round-trip on
    every IRIS analysis. Common case in normal RAPTOR setups (where
    the user already has `codeql/<lang>-all` cached from prior
    /codeql or /agentic runs).

    Returns False (i.e. defer to full install) on any parse error,
    missing lockfile, or missing dep — never raises.
    """
    lock = pack_dir / "codeql-pack.lock.yml"
    if not lock.is_file():
        return False
    try:
        import yaml  # transitively available via codeql packs
    except ImportError:
        return False
    try:
        data = yaml.safe_load(lock.read_text()) or {}
    except Exception:
        return False
    deps = (data.get("dependencies") or {})
    if not deps:
        return False
    cache = Path.home() / ".codeql" / "packages"
    for dep_name, info in deps.items():
        version = (info or {}).get("version")
        if not version or not (cache / dep_name / version).is_dir():
            return False
    return True


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
    sarif_path: Optional[Path]
    findings_count: int
    duration_seconds: float
    errors: List[str]
    suite_name: str
    queries_executed: int = 0


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
    SECURITY_SUITES = {
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
    SECURITY_EXTENDED_SUITES = {
        "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
        "rust": "codeql/rust-queries:codeql-suites/rust-security-extended.qls",
    }

    def __init__(self, codeql_cli: Optional[str] = None):
        """
        Initialize query runner.

        Args:
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        import shutil
        self.codeql_cli = codeql_cli or shutil.which("codeql")
        if not self.codeql_cli:
            raise RuntimeError("CodeQL CLI not found")

        logger.info(f"Query runner initialized with CodeQL: {self.codeql_cli}")

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
        from pathlib import Path
        return [str(Path(self.codeql_cli).resolve().parent)]

    def run_suite(
        self,
        database_path: Path,
        language: str,
        out_dir: Path,
        suite: Optional[str] = None,
        use_extended: bool = False
    ) -> QueryResult:
        """
        Execute CodeQL suite against database.

        Args:
            database_path: Path to CodeQL database
            language: Programming language
            out_dir: Output directory for SARIF
            suite: Custom suite identifier (uses default if None)
            use_extended: Use security-extended suite instead of standard

        Returns:
            QueryResult with execution status
        """
        start_time = time.time()
        errors = []

        logger.info(f"{'=' * 70}")
        logger.info(f"Running CodeQL analysis for {language}")
        logger.info(f"{'=' * 70}")

        # Determine suite to use
        if suite:
            suite_name = suite
            logger.info(f"Using custom suite: {suite}")
        else:
            # Use standard or extended suite
            suites = self.SECURITY_EXTENDED_SUITES if use_extended else self.SECURITY_SUITES
            suite_name = suites.get(language)

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
            logger.info(f"Using {suite_type} suite: {suite_name}")

        # Prepare output path
        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}.sarif"

        # If CODEQL_QUERIES is set, ALWAYS use absolute paths to avoid pack conflicts
        import os
        codeql_queries = os.environ.get("CODEQL_QUERIES")
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
                        logger.info(f"✓ Resolved suite to absolute path: {actual_suite_path}")
                    else:
                        logger.warning(f"Could not find suite at {potential_path}")
                        # Try without the "ql/src" part (for different CodeQL repo structures)
                        alt_path = Path(codeql_queries) / lang_dir / suite_path
                        if alt_path.exists():
                            actual_suite_path = str(alt_path)
                            resolved_to_absolute = True
                            logger.info(f"✓ Resolved suite to absolute path (alt): {actual_suite_path}")
                        else:
                            logger.error(f"❌ Cannot resolve suite path - will attempt pack reference (may cause conflicts)")
            else:
                # Already an absolute path or simple name
                if Path(suite_name).exists():
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
            f"--threads={RaptorConfig.CODEQL_THREADS}",
            f"--ram={RaptorConfig.CODEQL_RAM_MB}",
            "--no-rerun",  # Don't rerun queries if results exist
        ]

        # DO NOT add search-path - it causes pack conflicts when multiple copies exist
        # Instead, we always use absolute paths (resolved above) to avoid ambiguity
        if not resolved_to_absolute and codeql_queries:
            logger.warning("⚠️  Using pack reference without resolved absolute path")
            logger.warning("   This may cause conflicts if multiple pack copies exist")
            logger.warning(f"   Pack: {actual_suite_path}")

        logger.info(f"Executing: {' '.join(cmd)}")
        logger.info(f"Timeout: {RaptorConfig.CODEQL_ANALYZE_TIMEOUT}s")

        # Execute analysis in sandbox (network blocked — packs pre-fetched)
        try:
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                cmd,
                block_network=True,
                tool_paths=self._sandbox_tool_paths(),
                # audit_run_dir = where audit JSONL lands when --audit
                # is set. Decoupled from output= so Landlock writable_
                # paths isn't restricted (codeql analyze writes to
                # ~/.codeql cache, the database dir, etc. — paths we
                # can't safely enumerate as writable).
                audit_run_dir=str(out_dir),
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            # Auto-download missing query packs (needs network) and retry in sandbox
            if not success and "cannot be found" in (result.stderr or "").lower():
                pack_name = _extract_missing_pack(result.stderr)
                if pack_name:
                    logger.info(f"Query pack '{pack_name}' not found — downloading...")
                    # Route codeql through the RAPTOR egress proxy.
                    # CodeQL's Java stack respects the lowercase
                    # `https_proxy` env var (set automatically by
                    # use_egress_proxy=True). Hostname allowlist pins
                    # the download to the CodeQL registry / GitHub
                    # container registry; seccomp blocks UDP (no DNS
                    # exfil — the proxy resolves on behalf). Landlock
                    # pins writes to the codeql pack cache dir.
                    from pathlib import Path
                    codeql_cache = Path.home() / ".codeql"
                    codeql_cache.mkdir(parents=True, exist_ok=True)
                    # Retry the download up to 3x with exponential
                    # backoff. Pre-fix a single attempt — if the
                    # registry was momentarily slow / a transient
                    # 503 from ghcr.io / network blip, the whole
                    # analysis dispatch failed and the operator
                    # had to re-run the entire scan. Retries are
                    # cheap (at most 3 sub-2-minute calls) and
                    # cover the common transient failure modes.
                    import time as _time
                    dl = None
                    from packages.codeql.codeql_proxy_hosts import (
                        proxy_hosts_for_codeql,
                    )
                    for attempt in range(3):
                        dl = sandbox_run(
                            [self.codeql_cli, "pack", "download", pack_name],
                            use_egress_proxy=True,
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
                            target=str(codeql_cache),
                            output=str(codeql_cache),
                            tool_paths=self._sandbox_tool_paths(),
                            capture_output=True, text=True, timeout=120,
                        )
                        if dl.returncode == 0:
                            break
                        if attempt < 2:
                            backoff = 2 ** attempt  # 1s, 2s
                            logger.info(
                                "Pack download attempt %d failed (rc=%d); "
                                "retrying in %ds", attempt + 1, dl.returncode, backoff,
                            )
                            _time.sleep(backoff)
                    if dl.returncode == 0:
                        logger.info(f"✓ Downloaded {pack_name} — retrying analysis")
                        result = sandbox_run(
                            cmd, block_network=True,
                            tool_paths=self._sandbox_tool_paths(),
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
                        logger.error(f"✗ Failed to download {pack_name}: {dl_stderr}")

            if not success:
                errors.append(f"Analysis failed with exit code {result.returncode}")
                if result.stderr:
                    errors.append(result.stderr[:1000])
                logger.error(f"✗ Analysis failed for {language}")
                # `or ""` for the same reason as above — `result.stderr`
                # may be None on some sandbox failure modes (timeout
                # mid-stream, killed before write).
                logger.error((result.stderr or "")[:500])

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
            if sarif_data:
                for run in sarif_data.get("runs", []):
                    findings_count += len(run.get("results", []))
                    queries_executed += len(run.get("tool", {}).get("driver", {}).get("rules", []))

            logger.info(f"✓ Analysis completed for {language}")
            logger.info(f"  Findings: {findings_count}")
            logger.info(f"  Queries executed: {queries_executed}")
            logger.info(f"  Duration: {time.time() - start_time:.1f}s")
            logger.info(f"  SARIF: {sarif_path}")

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
            logger.error(f"✗ {error}")

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

        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            errors.append(error)
            logger.error(f"✗ Analysis failed with exception: {e}")

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

    def run_custom_queries(
        self,
        database_path: Path,
        query_path: Path,
        out_dir: Path,
        language: str
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

        logger.info(f"Running custom queries from: {query_path}")

        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}_custom.sarif"

        cmd = [
            self.codeql_cli,
            "database",
            "analyze",
            str(database_path),
            str(query_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={RaptorConfig.CODEQL_THREADS}",
        ]

        try:
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                cmd,
                block_network=True,
                tool_paths=self._sandbox_tool_paths(),
                audit_run_dir=str(out_dir),
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            if success and sarif_path.exists():
                findings_count = self._count_sarif_findings(sarif_path)
                logger.info(f"✓ Custom queries completed: {findings_count} findings")

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
            else:
                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=[result.stderr] if result.stderr else [],
                    suite_name="custom",
                )

        except Exception as e:
            logger.error(f"✗ Custom query execution failed: {e}")
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
        databases: Dict[str, Path],
        out_dir: Path,
        use_extended: bool = False,
        max_workers: Optional[int] = None
    ) -> Dict[str, QueryResult]:
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

        logger.info(f"Analyzing {len(databases)} databases in parallel (max workers: {max_workers})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_lang = {
                executor.submit(
                    self.run_suite,
                    db_path,
                    lang,
                    out_dir,
                    None,
                    use_extended
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
                        logger.info(f"✓ {lang} analysis completed: {result.findings_count} findings")
                    else:
                        logger.error(f"✗ {lang} analysis failed")
                except Exception as e:
                    logger.error(f"✗ {lang} analysis raised exception: {e}")
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
        databases: Dict[str, Path],
        out_dir: Path,
        max_workers: Optional[int] = None,
    ) -> Dict[str, "QueryResult"]:
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

        # Master kill-switch — operators can disable IRIS Tier 1
        # globally via `RaptorConfig.IRIS_TIER1_ENABLED = False`. /codeql
        # CLI's `--no-iris-tier1` flag flips this for a single invocation.
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
        analyzable: Dict[str, Tuple[Path, Path]] = {}
        for lang, db in databases.items():
            pack_dir = pack_root / f"{lang}-queries"
            if pack_dir.is_dir():
                analyzable[lang] = (db, pack_dir)
        if not analyzable:
            return {}

        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results: Dict[str, "QueryResult"] = {}

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
                except Exception as e:
                    logger.warning(f"IRIS LocalFlowSource ({lang}) raised: {e}")
                    db, _ = analyzable[lang]
                    results[lang] = QueryResult(
                        success=False, language=lang,
                        database_path=db, sarif_path=None, findings_count=0,
                        duration_seconds=0.0, errors=[str(e)],
                        suite_name="raptor-iris-local",
                    )
        return results

    def _run_iris_pack(
        self, lang: str, db: Path, pack_dir: Path, out_dir: Path,
    ) -> "QueryResult":
        """Per-language worker for `analyze_iris_packs` — pack install
        followed by analyze. Extracted so the parallel orchestrator
        above is just dispatch + result aggregation."""
        from core.config import RaptorConfig
        from core.sandbox import run as sandbox_run

        # Skip the install entirely when every dep pinned in the
        # in-repo lockfile is already present in the standard pack
        # cache. In normal RAPTOR setups (where `~/.codeql/packages/
        # codeql/<lang>-all/...` is populated by the user's existing
        # CodeQL install) this is the common case, and skipping
        # avoids both the subprocess and the sandbox network-permit
        # round-trip. Sandboxed CI environments without a populated
        # pack cache fall through to the install attempt as before.
        if _iris_pack_deps_already_resolved(pack_dir):
            logger.debug(
                f"IRIS pack ({lang}): deps satisfied from pack cache, skipping install"
            )
        else:
            # Lazy `codeql pack install` — populates dependency cache
            # from the committed lockfile. Idempotent and fast on
            # subsequent runs; needed once on fresh checkouts before
            # the in-repo queries can resolve their imports.
            try:
                install_proc = sandbox_run(
                    [self.codeql_cli, "pack", "install", str(pack_dir)],
                    block_network=False,  # may need to fetch dep packs first time
                    tool_paths=self._sandbox_tool_paths(),
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
                    logger.warning(
                        f"IRIS pack install ({lang}) returned "
                        f"{install_proc.returncode}: {install_err}"
                    )
            except Exception as e:
                logger.warning(f"IRIS pack install ({lang}) raised: {e}")

        sarif_path = out_dir / f"codeql_{lang}_iris.sarif"
        cmd = [
            self.codeql_cli, "database", "analyze",
            str(db), str(pack_dir),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={RaptorConfig.CODEQL_THREADS}",
        ]
        analysis_start = time.time()
        try:
            proc = sandbox_run(
                cmd, block_network=True,
                tool_paths=self._sandbox_tool_paths(),
                audit_run_dir=str(out_dir),
                capture_output=True, text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )
        except Exception as e:
            logger.warning(f"IRIS LocalFlowSource ({lang}) analyze raised: {e}")
            return QueryResult(
                success=False, language=lang,
                database_path=db, sarif_path=None, findings_count=0,
                duration_seconds=time.time() - analysis_start,
                errors=[str(e)], suite_name="raptor-iris-local",
            )

        if proc.returncode == 0 and sarif_path.exists():
            n = self._count_sarif_findings(sarif_path)
            logger.info(f"✓ IRIS LocalFlowSource ({lang}): {n} findings")
            return QueryResult(
                success=True, language=lang,
                database_path=db, sarif_path=sarif_path,
                findings_count=n,
                duration_seconds=time.time() - analysis_start,
                errors=[], suite_name="raptor-iris-local",
            )

        err = (proc.stderr or proc.stdout or "").strip()[:300]
        logger.warning(f"IRIS LocalFlowSource ({lang}) failed: {err}")
        return QueryResult(
            success=False, language=lang,
            database_path=db, sarif_path=None, findings_count=0,
            duration_seconds=time.time() - analysis_start,
            errors=[err] if err else [],
            suite_name="raptor-iris-local",
        )

    def _count_sarif_findings(self, sarif_path: Path) -> int:
        """Count findings in SARIF file."""
        from core.sarif.parser import load_sarif
        sarif_data = load_sarif(sarif_path)
        if not sarif_data:
            return 0
        return sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))

    def get_sarif_summary(self, sarif_path: Path,
                          *, sarif_data: Optional[Dict] = None) -> Dict:
        """
        Extract summary information from SARIF file.

        `sarif_data` (optional) is a pre-parsed SARIF dict. When the
        caller has already loaded the file (e.g. agent.print_summary
        loading it once and sharing across summary + example
        extraction), pass it here to avoid the redundant parse.
        Defaults to None → load the file ourselves (preserves the
        standalone-call API).

        Returns:
            Dict with summary statistics
        """
        try:
            if sarif_data is None:
                from core.sarif.parser import load_sarif
                sarif_data = load_sarif(sarif_path)
            if not sarif_data:
                return {}

            summary = {
                "total_findings": 0,
                "by_severity": {"error": 0, "warning": 0, "note": 0},
                "by_rule": {},
                "queries_executed": 0,
                "dataflow_paths": 0,
                "total_dataflow_steps": 0,
            }

            for run in sarif_data.get("runs", []):
                # Count findings by severity
                for result in run.get("results", []):
                    summary["total_findings"] += 1

                    # Coerce to str — SARIF spec says `level` is a
                    # string enum, but malformed emitters
                    # occasionally produce ints (numeric severity)
                    # or None. Pre-fix `summary["by_severity"][level]`
                    # used the value as a dict key, so a dict-typed
                    # tag (some custom queries return rich objects)
                    # raised TypeError. None merged into one bucket
                    # with the literal string "None" — confusing
                    # later report consumers. Coerce defensively.
                    raw_level = result.get("level", "warning")
                    level = str(raw_level) if raw_level is not None else "warning"
                    summary["by_severity"][level] = summary["by_severity"].get(level, 0) + 1

                    # Count by rule
                    rule_id = result.get("ruleId", "unknown")
                    summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1

                    # Count dataflow paths. Pre-fix `+= 1` per
                    # result conflated "findings WITH dataflow"
                    # with "number of actual dataflow paths" —
                    # a single finding often has multiple
                    # codeFlows (alternative paths reaching the
                    # same sink), each of which is a distinct
                    # exploitable path. Operators reading the
                    # summary saw "dataflow_paths: 12" and
                    # assumed 12 distinct paths to triage; in
                    # reality there could be 12 findings with
                    # 30+ paths between them. Count one per
                    # codeFlow so the metric matches the name.
                    code_flows = result.get("codeFlows", [])
                    summary["dataflow_paths"] += len(code_flows)
                    for flow in code_flows:
                        for thread_flow in flow.get("threadFlows", []):
                            locations = thread_flow.get("locations", [])
                            summary["total_dataflow_steps"] += len(locations)

                # Count queries
                tool = run.get("tool", {})
                driver = tool.get("driver", {})
                rules = driver.get("rules", [])
                summary["queries_executed"] += len(rules)

            return summary

        except Exception as e:
            logger.warning(f"Failed to generate SARIF summary: {e}")
            return {}


def main():
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
        print(f"\n✓ Analysis completed")
        print(f"  Findings: {result.findings_count}")
        print(f"  SARIF: {result.sarif_path}")
        print(f"  Duration: {result.duration_seconds:.1f}s")
    else:
        print(f"\n✗ Analysis failed")
        for error in result.errors:
            print(f"  {error}")


if __name__ == "__main__":
    main()
