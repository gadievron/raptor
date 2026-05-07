#!/usr/bin/env python3
"""
CodeQL Database Manager

Manages CodeQL database lifecycle including creation, caching,
validation, and cleanup.
"""

import errno
import hashlib
import os
import re
import shutil
import stat
import subprocess

import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
# packages/codeql/database_manager.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.json import load_json, save_json
from core.config import RaptorConfig
from core.hash import sha256_string
from core.logging import get_logger
from packages.codeql.build_detector import BuildSystem

logger = get_logger()


@dataclass
class DatabaseMetadata:
    """Metadata for CodeQL database."""
    repo_hash: str
    repo_path: str
    language: str
    created_at: str
    codeql_version: str
    build_command: str
    build_system: str
    file_count: int
    success: bool
    duration_seconds: float
    errors: List[str]
    database_path: str

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(data: dict):
        return DatabaseMetadata(**data)


@dataclass
class DatabaseResult:
    """Result of database creation."""
    success: bool
    language: str
    database_path: Optional[Path]
    metadata: Optional[DatabaseMetadata]
    errors: List[str]
    duration_seconds: float
    cached: bool = False  # Was this from cache?


class DatabaseManager:
    """
    Manages CodeQL database lifecycle.

    Features:
    - Database creation with build command support
    - SHA256-based caching (reuse databases for unchanged repos)
    - Parallel database creation for multi-language repos
    - Database validation and integrity checking
    - Automatic cleanup of old databases
    """

    def __init__(self, db_root: Optional[Path] = None, codeql_cli: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            db_root: Root directory for databases (defaults to RaptorConfig.CODEQL_DB_DIR)
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        self.db_root = db_root or RaptorConfig.CODEQL_DB_DIR
        self.db_root.mkdir(parents=True, exist_ok=True)

        # Detect CodeQL CLI
        self.codeql_cli = codeql_cli or self._detect_codeql_cli()
        if not self.codeql_cli:
            raise RuntimeError("CodeQL CLI not found. Set CODEQL_CLI environment variable or install CodeQL.")

        logger.info(f"Database manager initialized: {self.db_root}")
        logger.info(f"CodeQL CLI: {self.codeql_cli}")

    def _sandbox_tool_paths(self) -> list:
        """Mount-ns bind dirs needed for codeql to run. See QueryRunner
        equivalent — same rationale (codeql install root rarely lives
        in /usr/bin)."""
        return [str(Path(self.codeql_cli).resolve().parent)]

    def _detect_codeql_cli(self) -> Optional[str]:
        """Detect CodeQL CLI path."""
        import os

        # Check environment variable
        env_cli = os.environ.get("CODEQL_CLI")
        if env_cli and Path(env_cli).exists():
            return env_cli

        # Check PATH
        cli_path = shutil.which("codeql")
        if cli_path:
            return cli_path

        return None

    def get_codeql_version(self) -> Optional[str]:
        """Get CodeQL version."""
        try:
            result = subprocess.run(
                [self.codeql_cli, "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Parse version from output (first line usually contains version)
                version = result.stdout.strip().split('\n')[0]
                return version
            return None
        except Exception as e:
            logger.warning(f"Failed to get CodeQL version: {e}")
            return None

    def compute_repo_hash(self, repo_path: Path) -> str:
        """
        Compute SHA256 hash of repository for caching.

        Uses git commit hash if available, otherwise hashes file contents.

        Args:
            repo_path: Path to repository

        Returns:
            SHA256 hash string
        """
        repo_path = Path(repo_path).resolve()

        # Try to use git commit hash (fast)
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                git_hash = result.stdout.strip()
                # Combine with repo path to ensure uniqueness
                combined = f"{repo_path}:{git_hash}"
                return sha256_string(combined)[:16]
        except Exception:
            pass

        # Fallback: hash directory structure and file sizes (no
        # mtime). Iterative accumulator (mixing many inputs into
        # one digest) so this stays on hashlib.sha256() —
        # core.hash exposes only closed-form one-shot helpers.
        # Filename .encode() calls below use surrogateescape to
        # match core.hash's non-UTF-8 safety.
        #
        # Pre-fix issues addressed here:
        #   * `list(rglob("*"))` walked the ENTIRE tree first
        #     then `[:1000]` sliced. For big repos with
        #     node_modules / .venv / .git this enumerated
        #     millions of files before discarding most. Use
        #     os.walk with early-exit so we stop after collecting
        #     1000 candidates.
        #   * mtime in the hash invalidated the cache on any
        #     `touch`-style write that didn't change content
        #     (`make` rebuilds, editor saves with same content,
        #     git checkout updates mtimes wholesale). Drop mtime;
        #     keep (name, size) — same files at same sizes
        #     produce the same hash regardless of touch noise.
        #   * No filtering of known noise directories. Skip
        #     .git / node_modules / .venv / __pycache__ / .tox /
        #     dist / build / target — none are source-of-truth
        #     for the database identity.
        _SKIP_DIRS = {
            ".git", "node_modules", ".venv", "venv", "__pycache__",
            ".tox", "dist", "build", "target", ".idea", ".vscode",
            ".gradle", ".mvn", ".cache", "coverage",
        }
        hasher = hashlib.sha256()
        hasher.update(str(repo_path).encode("utf-8", errors="surrogateescape"))

        try:
            collected: List[Path] = []
            for dirpath, dirnames, filenames in os.walk(
                repo_path, followlinks=False,
            ):
                # In-place prune skipped dirs from the walk to
                # avoid even descending into them.
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for name in filenames:
                    collected.append(Path(dirpath) / name)
                    if len(collected) >= 1000:
                        break
                if len(collected) >= 1000:
                    break

            for file_path in sorted(collected):
                if file_path.is_file():
                    hasher.update(
                        str(file_path.relative_to(repo_path))
                        .encode("utf-8", errors="surrogateescape"),
                    )
                    try:
                        hasher.update(str(file_path.stat().st_size).encode())
                    except OSError:
                        pass
        except Exception as e:
            logger.debug(f"Error hashing repository: {e}")

        return hasher.hexdigest()[:16]

    def get_database_dir(self, repo_hash: str, language: str) -> Path:
        """Get database directory path."""
        return self.db_root / repo_hash / f"{language}-db"

    def get_metadata_path(self, repo_hash: str, language: str) -> Path:
        """Get metadata file path."""
        return self.db_root / repo_hash / f"{language}-metadata.json"

    def load_metadata(self, repo_hash: str, language: str) -> Optional[DatabaseMetadata]:
        """Load database metadata from disk."""
        metadata_path = self.get_metadata_path(repo_hash, language)
        if not metadata_path.exists():
            return None

        data = load_json(metadata_path)
        if data is None:
            return None
        try:
            return DatabaseMetadata.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load metadata: {e}")
            return None

    def save_metadata(self, metadata: DatabaseMetadata):
        """Save database metadata to disk."""
        metadata_path = Path(metadata.database_path).parent / f"{metadata.language}-metadata.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            save_json(metadata_path, metadata.to_dict())
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")

    def get_cached_database(
        self,
        repo_path: Path,
        language: str,
        max_age_days: int = 7
    ) -> Optional[Path]:
        """
        Check if valid cached database exists.

        Args:
            repo_path: Repository path
            language: Programming language
            max_age_days: Maximum age of cached database in days

        Returns:
            Path to cached database or None
        """
        repo_hash = self.compute_repo_hash(repo_path)
        db_path = self.get_database_dir(repo_hash, language)
        metadata = self.load_metadata(repo_hash, language)

        if not db_path.exists() or not metadata:
            return None

        # Check if database is valid
        if not metadata.success:
            logger.debug(f"Cached database marked as failed: {language}")
            return None

        # Check age
        try:
            created_at = datetime.fromisoformat(metadata.created_at)
            # Promote naive timestamps from pre-batch-396 metadata
            # to UTC so the comparison below doesn't TypeError.
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - created_at
            if age > timedelta(days=max_age_days):
                logger.debug(f"Cached database too old: {age.days} days")
                return None
        except Exception as e:
            logger.debug(f"Failed to parse database age: {e}")
            return None

        # Validate database integrity
        if not self.validate_database(db_path):
            logger.warning(f"Cached database failed validation: {language}")
            return None

        logger.info(f"✓ Using cached database for {language}: {db_path}")
        return db_path

    # Concurrent-write safety: build-in-staging + atomic-promote pattern.
    # Two parallel /codeql runs against the same target+language used to
    # race on direct in-place writes to <db_root>/<repo_hash>/<language>-db,
    # corrupting whichever finished second. Each writer now builds in its
    # own staging dir on the same filesystem as canonical, then attempts
    # atomic os.rename to canonical. First to finish wins the cache slot;
    # losers cleanup their staging and use the winner's canonical. No lock,
    # no warning, no corruption — readers never see a partial DB because
    # the canonical slot is only ever replaced atomically by a complete one.

    def _staging_path(self, repo_hash: str, language: str) -> Path:
        """Return per-process staging path on the same filesystem as canonical.

        Same-parent-dir is required so os.rename is atomic — cross-fs rename
        falls back to copy-then-delete which is non-atomic and would let
        readers see partial state.

        **Process-safe, NOT thread-safe.** Two threads in the same process
        share PID and thus get the same staging path; concurrent writes
        within the staging dir would race. RAPTOR's parallelism model uses
        processes (not threads) so this is fine in practice; a future
        thread-based caller would need a different staging key (e.g.,
        include thread.get_ident()).
        """
        canonical = self.get_database_dir(repo_hash, language)
        return canonical.parent / f".staging-{language}-{os.getpid()}"

    def _stale_marker_name(self, canonical: Path) -> str:
        """Build a unique stale-marker name for an evicted canonical.

        Uses time.time_ns() (nanoseconds since epoch, UTC) so two
        evictions from the same process within the same wall-clock
        second get distinct names — int(time.time()) would collide and
        the second os.rename would fail with ENOTEMPTY, leaving the
        (now-twice-detected-as-stale) canonical in place.

        Note: timestamp here is UTC nanoseconds since epoch; unique_run_suffix
        in core/run/output.py uses local-time strftime. Inconsistent but
        intentional — both serve uniqueness, not timezone consistency.
        """
        return f"{canonical.name}.stale.{time.time_ns()}.{os.getpid()}"

    def _gc_stale_markers(self, repo_dir: Path, max_age_seconds: int = 3600) -> None:
        """Best-effort cleanup of `.stale.*` and `.staging-*` markers older
        than `max_age_seconds`. Called on cache miss so the cache is
        self-healing without depending on the manual `--cleanup` CLI being
        run on a schedule.

        1 hour TTL is generous: any active reader will have finished using
        an evicted DB by then; any abandoned staging from a crashed writer
        is genuinely orphaned by then.
        """
        if not repo_dir.is_dir():
            return
        cutoff = time.time() - max_age_seconds
        for entry in repo_dir.iterdir():
            name = entry.name
            if not (name.startswith(".staging-") or ".stale." in name):
                continue
            try:
                if entry.stat().st_mtime < cutoff:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        entry.unlink(missing_ok=True)
            except OSError:
                pass  # best-effort

    def _evict_stale_canonical(
        self, repo_hash: str, language: str, max_age_days: int,
    ) -> None:
        """Atomically rename the canonical DB out of the way if it's
        stale (older than `max_age_days`), missing metadata for longer
        than the grace period, or has malformed metadata — so future
        cache lookups see a miss and trigger rebuild.

        Reader-safety caveat: files a reader had OPEN before the rename
        keep working — POSIX rename moves the directory entry, not the
        underlying inode, and existing FDs reference the inode. But
        readers doing NEW opens through the canonical path after the
        rename will fail (path no longer points to the dir). CodeQL
        queries open dataset chunks lazily during execution, so a query
        in flight when we evict can break mid-run. Eviction only fires
        on canonicals that are stale-by-age, missing metadata for >60s
        (a plausibly-orphaned writer), or malformed — so the impact is
        bounded to operators who chose to query already-broken data.

        In-flight writer protection: the missing-metadata case applies
        a grace period (`RaptorConfig.CODEQL_DB_MISSING_METADATA_GRACE`)
        so a sibling in the post-promote / pre-save-metadata window
        doesn't get its fresh canonical evicted.
        """
        canonical = self.get_database_dir(repo_hash, language)
        if not canonical.exists():
            return  # nothing to evict; short-circuit before load_metadata
        metadata = self.load_metadata(repo_hash, language)
        # Evict if metadata is malformed, stale-by-age, or missing-for-long-
        # enough-to-rule-out-an-in-flight-writer. The grace period on the
        # missing-metadata case is the critical one — without it, this
        # function would race in-flight writers (see the config docstring
        # on CODEQL_DB_MISSING_METADATA_GRACE for the timing analysis).
        evict = False
        if metadata is None:
            try:
                age = time.time() - canonical.stat().st_mtime
            except OSError:
                return  # canonical disappeared mid-check; harmless
            if age >= RaptorConfig.CODEQL_DB_MISSING_METADATA_GRACE:
                evict = True
        else:
            try:
                created_at = datetime.fromisoformat(metadata.created_at)
                # Promote naive timestamps from pre-batch-396 metadata
                # to UTC so the comparison below doesn't TypeError.
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) - created_at > timedelta(days=max_age_days):
                    evict = True
            except (ValueError, AttributeError):
                # Malformed metadata can't come from an in-flight writer
                # because save_metadata uses atomic temp-rename — readers
                # see either the old or the new metadata, never partial.
                # So malformed = on-disk corruption / hand-edit / bug; no
                # grace period needed (no in-flight case to race).
                evict = True
        if not evict:
            return
        marker = canonical.with_name(self._stale_marker_name(canonical))
        try:
            os.rename(canonical, marker)
        except OSError:
            pass  # raced with another evictor; harmless

    def create_database(
        self,
        repo_path: Path,
        language: str,
        build_system: Optional[BuildSystem] = None,
        force: bool = False,
        audit_run_dir: Optional[Path] = None,
    ) -> DatabaseResult:
        """
        Create CodeQL database.

        Args:
            repo_path: Path to source code
            language: Programming language
            build_system: Build system info (None for no-build mode)
            audit_run_dir: When --audit is engaged, where the tracer
                should drop the audit JSONL. Decoupled from output= so
                Landlock writable_paths isn't restricted (codeql
                database create runs build subprocesses that write to
                ~/.codeql, the database dir, and working_dir — none
                of which can be safely listed as writable).
            force: Force recreation even if cached DB exists. Skips both
                the initial cache check AND the race-absorbing re-check
                — a sibling who promoted between our entry and our force
                eviction will have their canonical evicted and rebuilt.
                That's the "user asked for fresh" semantics; if you want
                to coalesce concurrent force=True invocations, do it at
                the orchestrator layer.

        Returns:
            DatabaseResult with creation status
        """
        start_time = time.time()
        repo_path = Path(repo_path).resolve()
        errors = []

        logger.info(f"{'=' * 70}")
        logger.info(f"Creating CodeQL database for {language}")
        logger.info(f"{'=' * 70}")

        # Check for cached database
        if not force:
            cached_db = self.get_cached_database(repo_path, language)
            if cached_db:
                duration = time.time() - start_time
                metadata = self.load_metadata(
                    self.compute_repo_hash(repo_path),
                    language
                )
                return DatabaseResult(
                    success=True,
                    language=language,
                    database_path=cached_db,
                    metadata=metadata,
                    errors=[],
                    duration_seconds=duration,
                    cached=True,
                )

        # Compute repo hash and paths. canonical is the cache slot;
        # staging is per-process, on the same filesystem so atomic rename
        # works. See _staging_path docstring for the same-fs requirement.
        repo_hash = self.compute_repo_hash(repo_path)
        canonical_path = self.get_database_dir(repo_hash, language)
        staging_path = self._staging_path(repo_hash, language)

        # Ensure parent directory exists (db_root/<repo_hash>/)
        canonical_path.parent.mkdir(parents=True, exist_ok=True)

        # Self-healing GC of orphaned .staging-*/.stale.* markers from
        # crashed writers or evicted stale DBs. Cheap (one iterdir).
        self._gc_stale_markers(canonical_path.parent)

        # Force=True: evict canonical so the cache miss flow rebuilds.
        # Use rename-out-of-the-way rather than rmtree so any concurrent
        # reader keeps its inode references intact (see _evict_stale_canonical
        # docstring for the POSIX semantics).
        if force and canonical_path.exists():
            logger.info(f"Force rebuild: evicting cached database for {language}")
            try:
                marker = canonical_path.with_name(self._stale_marker_name(canonical_path))
                os.rename(canonical_path, marker)
            except OSError:
                pass  # someone else evicted in parallel; harmless

        # Race-absorbing re-check: another concurrent writer may have
        # promoted their staging to canonical between our initial cache
        # miss (line 304) and now. If so, use theirs and skip the build.
        if not force:
            cached = self.get_cached_database(repo_path, language)
            if cached:
                duration = time.time() - start_time
                metadata = self.load_metadata(repo_hash, language)
                return DatabaseResult(
                    success=True, language=language,
                    database_path=cached, metadata=metadata,
                    errors=[], duration_seconds=duration, cached=True,
                )

        # Stale eviction independent of force — handles the case where
        # canonical exists but is older than the TTL.
        self._evict_stale_canonical(repo_hash, language, max_age_days=7)

        # Cleanup any prior leftover staging from this same process (e.g.,
        # from a previous crashed run with the same PID after PID reuse).
        if staging_path.exists():
            shutil.rmtree(staging_path, ignore_errors=True)

        # Build the codeql command — point at staging, not canonical, so
        # readers of canonical never see a partial DB.
        cmd = [
            self.codeql_cli,
            "database",
            "create",
            str(staging_path),
            f"--language={language}",
            f"--source-root={repo_path}",
        ]

        # Set working directory and environment
        working_dir = build_system.working_dir if build_system else repo_path
        env = RaptorConfig.get_safe_env()
        if build_system and build_system.env_vars:
            # Filter build env vars through the same blocklist — a malicious
            # repo's build config could try to re-inject LD_PRELOAD, BASH_ENV, etc.
            blocked = set(RaptorConfig.DANGEROUS_ENV_VARS + RaptorConfig.PROXY_ENV_VARS)
            for k, v in build_system.env_vars.items():
                if k not in blocked:
                    env[k] = v
        # Auto-detect toolchain-home env vars (JAVA_HOME, GOROOT, etc.)
        # per build system's env_detect list. Per-subprocess scope —
        # these land only in this build invocation, not in other sandbox
        # calls. See ~/design/env-handling.md and core/build/toolchain.py.
        if build_system and build_system.env_detect:
            from core.build.toolchain import apply_toolchain_env
            apply_toolchain_env(env, build_system.env_detect)

        # Add build command if provided.
        # CodeQL splits --command on whitespace without shell interpretation,
        # so shell operators (&&, ||, ;, |) break. Wrap in a script unless
        # the command is already a path to an executable (e.g. synthesised builds).
        build_script = None
        if build_system and build_system.command:
            build_cmd = build_system.command
            if Path(build_cmd).is_file() or re.fullmatch(r'[a-zA-Z0-9._-]+', build_cmd):
                cmd.extend(["--command", build_cmd])
            else:
                # mkstemp creates the stub on disk BEFORE write_text/chmod run.
                # The existing finally at the bottom of this method only fires
                # if we reach the outer try — so guard create+write+chmod
                # atomically here: clean up our own mess if any of the three
                # raises, then re-raise so the caller still sees the error.
                #
                # `dir=` is `self.db_root / "tmp"`, NOT `working_dir`. Pre-fix
                # the build script was written into the operator's REPO
                # directory (`dir=working_dir`). On cleanup-failure paths
                # (cleanup at line ~831 unlinks but only if exists; sandbox
                # crashes mid-build skip it) the user found
                # `.raptor_codeql_build_*.sh` files in their git checkout —
                # `git status` noise, accidental `git add -A` commits,
                # confused operators. Keep our scratch under our managed
                # area where we control cleanup.
                tmp_dir = self.db_root / "tmp"
                tmp_dir.mkdir(parents=True, exist_ok=True)
                fd, script_name = tempfile.mkstemp(
                    prefix=".raptor_codeql_build_", suffix=".sh", dir=str(tmp_dir),
                )
                os.close(fd)
                build_script = Path(script_name)
                try:
                    build_script.write_text(f"#!/bin/bash\n{build_cmd}\n")
                    build_script.chmod(build_script.stat().st_mode | stat.S_IEXEC)
                except BaseException:
                    build_script.unlink(missing_ok=True)
                    build_script = None
                    raise
                cmd.extend(["--command", str(build_script)])
            logger.info(f"Build command: {build_system.command}")
            logger.info(f"Working directory: {working_dir}")
        else:
            logger.info("No build command (interpreted language or no-build mode)")

        logger.info(f"Executing: {' '.join(cmd)}")
        logger.info(f"Timeout: {RaptorConfig.CODEQL_TIMEOUT}s")

        # Execute database creation in sandbox (network blocked — packs pre-fetched)
        try:
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                cmd,
                block_network=True,
                cwd=working_dir,
                env=env,
                tool_paths=self._sandbox_tool_paths(),
                # Audit JSONL home (only used when --audit is engaged).
                # Decoupled from output= because the build subprocess
                # writes to working_dir / db_path / ~/.codeql, none of
                # which can safely be enumerated as Landlock writable_
                # paths without breaking real codeql workflows.
                audit_run_dir=str(audit_run_dir) if audit_run_dir else None,
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_TIMEOUT,
            )

            success = result.returncode == 0

            if not success:
                errors.append(f"Database creation failed with exit code {result.returncode}")
                if result.stderr:
                    errors.append(result.stderr[:1000])  # Truncate long errors
                logger.error(f"✗ Database creation failed for {language}")
                logger.error(result.stderr[:500])
                # Cleanup partial staging on build failure — no point keeping
                # broken DBs around to confuse future cache lookups (they
                # never reach canonical anyway since promote is gated on
                # success, but the staging dir would otherwise linger
                # until _gc_stale_markers picks it up).
                shutil.rmtree(staging_path, ignore_errors=True)
                final_path = None
                did_promote = False
                used_cached = False
            else:
                # Atomic-promote: try to install our staging as canonical.
                # Four post-build outcomes:
                #   A. Won the rename → did_promote=True, used_cached=False
                #   B. Lost rename, sibling's canonical valid → use theirs;
                #      did_promote=False, used_cached=True
                #   C. Lost rename, sibling's canonical invalid → evict it,
                #      retry-promote our staging:
                #      C1. Retry succeeds → did_promote=True (filled empty slot)
                #      C2. Retry fails (third writer) → use our staging;
                #          did_promote=False, used_cached=False
                #   D. Other I/O error (perms, disk full) → fall back to our
                #      staging; did_promote=False, used_cached=False
                # Note: did_promote=True is set in two places (A and C1) and
                # both gate save_metadata identically — kept inline rather
                # than refactored because the surrounding control flow makes
                # a unified flag harder to read.
                final_path = canonical_path
                did_promote = False
                used_cached = False
                try:
                    os.rename(staging_path, canonical_path)
                    logger.info(f"✓ Database promoted to canonical: {canonical_path}")
                    did_promote = True
                except OSError as e:
                    if e.errno in (errno.ENOTEMPTY, errno.EEXIST):
                        # Lost the promotion race. Validate the sibling's
                        # canonical before trusting it — without this check,
                        # a sibling who promoted broken content would propagate
                        # to us as success=True pointing at garbage.
                        if self.validate_database(canonical_path):
                            logger.info(
                                f"✓ Database promoted by sibling; using cached "
                                f"{canonical_path}"
                            )
                            shutil.rmtree(staging_path, ignore_errors=True)
                            used_cached = True
                        else:
                            # Sibling's canonical is broken. Best-effort:
                            # evict it and try to install our (valid)
                            # staging in its place — fills the cache slot
                            # so the next run hits cache instead of
                            # redundantly rebuilding. Both steps can fail
                            # benignly: if eviction fails, retry-promote
                            # falls into ENOTEMPTY again and we use staging.
                            # If eviction succeeds but retry-promote loses
                            # (third writer slipped in), we use staging.
                            # Either way the broken canonical eventually
                            # gets evicted (this run's lost-race branch on
                            # the next attempt, or _gc_stale_markers).
                            logger.warning(
                                f"Canonical {canonical_path} exists but failed "
                                f"validation; evicting and retrying promote"
                            )
                            try:
                                marker = canonical_path.with_name(
                                    self._stale_marker_name(canonical_path)
                                )
                                os.rename(canonical_path, marker)
                            except OSError:
                                pass  # eviction failed; retry-promote will see ENOTEMPTY
                            try:
                                os.rename(staging_path, canonical_path)
                                logger.info(
                                    f"✓ Database promoted to canonical "
                                    f"(after evicting broken sibling copy): "
                                    f"{canonical_path}"
                                )
                                did_promote = True
                            except OSError:
                                # Eviction may have failed, OR succeeded but
                                # a third writer slipped into the empty slot.
                                # Don't validate-and-cascade; keep staging.
                                final_path = staging_path
                    else:
                        # Genuine I/O error (permissions, disk full); fall back
                        # to using staging directly so the caller's analysis
                        # can still proceed. Future runs will rebuild.
                        logger.warning(
                            f"Could not promote staging to canonical "
                            f"({e}); using staging path"
                        )
                        final_path = staging_path

            # Count files in database (use whatever path won out above).
            # Cosmetic-only: a force=True writer in another window could
            # evict canonical between our os.rename above and this call,
            # leaving file_count=0 in the metadata we eventually save.
            # Not a correctness issue — the DB content the caller uses
            # via FDs is unaffected (POSIX inode survives rename).
            file_count = self._count_database_files(final_path) if success and final_path else 0

            # Create metadata; database_path reflects where the DB actually
            # lives (canonical if promote succeeded, staging on fallback,
            # None on build failure)
            metadata = DatabaseMetadata(
                repo_hash=repo_hash,
                repo_path=str(repo_path),
                language=language,
                # Tz-aware UTC timestamp. Pre-fix `datetime.now()`
                # was tz-naive — when serialised to ISO and later
                # parsed by another runner in a different
                # timezone, the comparison against `datetime.now()`
                # (which would be a different tz-naive local time)
                # produced silently-wrong age calculations.
                created_at=datetime.now(timezone.utc).isoformat(),
                codeql_version=self.get_codeql_version() or "unknown",
                build_command=build_system.command if build_system else "",
                build_system=build_system.type if build_system else "no-build",
                file_count=file_count,
                success=success,
                duration_seconds=time.time() - start_time,
                errors=errors,
                database_path=str(final_path) if final_path else "",
            )

            # Save metadata only when WE promoted to canonical. If we used
            # the sibling's canonical (used_cached) the winner's metadata
            # is already there. If we used our own staging (validation
            # failure or I/O error fallback) the metadata file at canonical
            # path doesn't apply — saving it would mislead future cache
            # lookups about what's at canonical.
            if did_promote:
                self.save_metadata(metadata)

            return DatabaseResult(
                success=success,
                language=language,
                database_path=final_path if success else None,
                metadata=metadata,
                errors=errors,
                duration_seconds=time.time() - start_time,
                cached=used_cached,
            )

        except subprocess.TimeoutExpired:
            errors.append(f"Database creation timed out after {RaptorConfig.CODEQL_TIMEOUT}s")
            logger.error(f"✗ Database creation timed out for {language}")

            return DatabaseResult(
                success=False,
                language=language,
                database_path=None,
                metadata=None,
                errors=errors,
                duration_seconds=time.time() - start_time,
                cached=False,
            )

        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")
            logger.error(f"✗ Database creation failed with exception: {e}")

            return DatabaseResult(
                success=False,
                language=language,
                database_path=None,
                metadata=None,
                errors=errors,
                duration_seconds=time.time() - start_time,
                cached=False,
            )

        finally:
            if build_script and build_script.exists():
                build_script.unlink()
            # Belt-and-braces staging cleanup for timeout / unhandled exception
            # paths that bypass the success/failure cleanup branches above.
            # Skip if we ended up using staging as final_path (the fallback
            # cases where promote failed but we kept staging as a usable DB)
            # — otherwise we'd delete the very DB we're returning to the
            # caller. Use locals().get to handle the case where we never
            # reached the assignment (early exception before final_path set).
            _final = locals().get('final_path')
            if staging_path.exists() and _final != staging_path:
                shutil.rmtree(staging_path, ignore_errors=True)

    def create_databases_parallel(
        self,
        repo_path: Path,
        language_build_map: Dict[str, Optional[BuildSystem]],
        force: bool = False,
        max_workers: Optional[int] = None,
        audit_run_dir: Optional[Path] = None,
    ) -> Dict[str, DatabaseResult]:
        """
        Create multiple databases in parallel.

        Args:
            repo_path: Repository path
            language_build_map: Dict mapping language -> BuildSystem
            force: Force recreation
            max_workers: Max parallel workers (default: RaptorConfig.MAX_CODEQL_WORKERS)
            audit_run_dir: Forwarded to per-language create_database for
                audit JSONL targeting (no Landlock impact).

        Returns:
            Dict mapping language -> DatabaseResult
        """
        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results = {}

        logger.info(f"Creating {len(language_build_map)} databases in parallel (max workers: {max_workers})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_lang = {
                executor.submit(
                    self.create_database,
                    repo_path,
                    lang,
                    build_system,
                    force,
                    audit_run_dir,
                ): lang
                for lang, build_system in language_build_map.items()
            }

            # Collect results as they complete
            for future in as_completed(future_to_lang):
                lang = future_to_lang[future]
                try:
                    result = future.result()
                    results[lang] = result
                    if result.success:
                        logger.info(f"✓ {lang} database completed")
                    else:
                        logger.error(f"✗ {lang} database failed")
                except Exception as e:
                    logger.error(f"✗ {lang} database raised exception: {e}")
                    results[lang] = DatabaseResult(
                        success=False,
                        language=lang,
                        database_path=None,
                        metadata=None,
                        errors=[str(e)],
                        duration_seconds=0.0,
                        cached=False,
                    )

        return results

    def validate_database(self, db_path: Path) -> bool:
        """
        Validate database integrity.

        Args:
            db_path: Path to database

        Returns:
            True if database is valid
        """
        if not db_path.exists():
            return False

        # Check for essential database files
        essential_files = ["codeql-database.yml"]
        for file_name in essential_files:
            if not (db_path / file_name).exists():
                logger.debug(f"Missing essential file: {file_name}")
                return False

        # Pre-fix `codeql-database.yml` existence was the only
        # check — easy for a half-built / corrupted database to
        # pass (the yml is the FIRST thing CodeQL writes during
        # build, so an aborted build leaves the yml in place
        # but no actual DB content). Add a minimal-substance
        # check: the database must have a `db-*` subdirectory
        # (CodeQL writes per-language dbs as db-cpp, db-java,
        # etc.) AND that subdir must be non-empty / non-trivial
        # in size. Half-built databases typically have a few KB
        # of yml/header but the multi-MB db-*/default/* trie
        # files only land on successful build completion.
        try:
            db_subdirs = [d for d in db_path.iterdir()
                          if d.is_dir() and d.name.startswith("db-")]
            if not db_subdirs:
                logger.debug(f"No db-* subdir in {db_path}")
                return False
            # At least one db-* subdir must hold > 100KB of data
            # (the smallest realistic codeql DB observed in
            # practice). Empty / kilobyte-sized = aborted build.
            for sub in db_subdirs:
                total_size = sum(
                    f.stat().st_size for f in sub.rglob("*") if f.is_file()
                )
                if total_size > 100 * 1024:
                    return True
            logger.debug(
                f"db-* subdirs present but trivially small in {db_path} "
                f"(likely aborted build)",
            )
            return False
        except OSError as e:
            logger.debug(f"validate_database couldn't stat {db_path}: {e}")
            return False

    def _count_database_files(self, db_path: Path) -> int:
        """Count files in database (for statistics)."""
        try:
            # Count files in src.zip if it exists
            src_zip = db_path / "src.zip"
            if src_zip.exists():
                import zipfile
                with zipfile.ZipFile(src_zip) as zf:
                    return len(zf.namelist())
            return 0
        except Exception:
            return 0

    def cleanup_old_databases(self, days: int = 7, dry_run: bool = False) -> List[str]:
        """
        Clean up databases older than specified days.

        Args:
            days: Age threshold in days
            dry_run: If True, only report what would be deleted

        Returns:
            List of deleted database paths
        """
        logger.info(f"Cleaning up databases older than {days} days...")
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = []

        for repo_dir in self.db_root.iterdir():
            if not repo_dir.is_dir():
                continue

            # Check all metadata files in this repo
            for metadata_file in repo_dir.glob("*-metadata.json"):
                try:
                    data = load_json(metadata_file)
                    if data is None:
                        continue
                    created_at = datetime.fromisoformat(data["created_at"])
                    # Promote naive timestamps from pre-batch-396
                    # metadata to UTC so the cutoff comparison
                    # doesn't TypeError.
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    if created_at < cutoff:
                        db_path = Path(data["database_path"])
                        if db_path.exists():
                            if not dry_run:
                                shutil.rmtree(db_path)
                                metadata_file.unlink()
                                logger.info(f"Deleted old database: {db_path}")
                            else:
                                logger.info(f"Would delete: {db_path}")
                            deleted.append(str(db_path))
                except Exception as e:
                    logger.warning(f"Error processing {metadata_file}: {e}")

        logger.info(f"Cleaned up {len(deleted)} databases")
        return deleted


def main():
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeQL Database Manager")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--build-command", help="Build command")
    parser.add_argument("--force", action="store_true", help="Force recreation")
    parser.add_argument("--cleanup", type=int, help="Cleanup databases older than N days")
    args = parser.parse_args()

    manager = DatabaseManager()

    if args.cleanup:
        deleted = manager.cleanup_old_databases(days=args.cleanup, dry_run=False)
        print(f"Deleted {len(deleted)} databases")
        return

    # Create build system object if command provided
    build_system = None
    if args.build_command:
        from packages.codeql.build_detector import BuildSystem
        build_system = BuildSystem(
            type="custom",
            command=args.build_command,
            working_dir=Path(args.repo),
            env_vars={},
            confidence=1.0,
            detected_files=[],
        )

    # Create database
    result = manager.create_database(
        Path(args.repo),
        args.language,
        build_system,
        force=args.force
    )

    if result.success:
        print(f"\n✓ Database created: {result.database_path}")
        print(f"Duration: {result.duration_seconds:.1f}s")
        if result.cached:
            print("(from cache)")
    else:
        print("\n✗ Database creation failed")
        for error in result.errors:
            print(f"  {error}")


if __name__ == "__main__":
    main()
