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
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Path setup for direct CLI invocation. `os.environ["RAPTOR_DIR"]`
# (no fallback) is the canonical project root marker — see CLAUDE.md
# "Python path safety"; a KeyError surfaces the configuration problem
# at startup instead of a positional walk silently breaking.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.build.build_detector import BuildSystem
from core.config import RaptorConfig
from core.git import get_safe_git_env

# Per-invocation git overrides for target-repo invocations.
# See `core.git.clone.safe_git_command` for the threat model
# (CVE-2024-32002 family: hostile per-repo .git/config).
from core.git.clone import safe_git_command
from core.hash import sha256_string
from core.json import load_json, save_json
from core.logging import get_logger
from core.sandbox import SandboxSetupError
from packages.codeql.tunables import CodeQLTunables

logger = get_logger()

# Languages whose databases are created with ``--build-mode=none``
# (buildless extraction) BY DEFAULT.  A traced build (and the
# autobuilder) runs the target repo's build system —
# attacker-controlled code — so untrusted repos must never trigger it
# implicitly.  Buildless extraction parses the source without
# executing anything from the repo, removing the repo-code-execution
# vector entirely.
# For Java there is a second forcing constraint: ``database create``
# runs with the sandbox network blocked, so an autobuild that needs to
# fetch dependencies fails by construction; buildless extraction is
# documented to proceed with unresolved dependencies (reduced type
# fidelity, verified offline in a no-network namespace).  Operators
# opt back into traced builds explicitly (``--traced-build`` on the
# CLI, an explicit ``--build-command``,
# ``create_database(traced_build=True)``, or the project's ``build``
# trust marker).
#
# Decision record: the buildless-by-default posture originally covered
# only cpp and java; csharp got NO gate — ``database create`` without
# ``--build-mode=none`` runs the CodeQL AUTOBUILDER for it, which
# executes repo-controlled build entry points (msbuild targets), i.e.
# the exact vector the cpp/java gate closes.  It now shares the gate.
# Languages CodeQL has no buildless mode for (go, swift, ...) keep
# their traced/autobuild behaviour but a loud banner discloses the
# execution and the run metadata records it (see
# ``CodeQLWorkflowResult.untrusted_build_languages``).
BUILDLESS_DEFAULT_LANGUAGES = frozenset({"cpp", "java", "csharp"})

# Minimum CLI version for ``--build-mode=none`` per language.  Older
# CLIs degrade loudly (cpp: clear skip; java/csharp: pre-existing
# traced behaviour + banner) — never a crash and never a SILENT
# fallback to a traced build.  Java's buildless extractor stabilised
# later than C/C++'s; csharp buildless is gated at 2.17.1 (earlier
# CLIs carried it only as beta).
BUILDLESS_MIN_VERSIONS = {
    "cpp": (2, 16),
    "java": (2, 16, 4),
    "csharp": (2, 17, 1),
}

# Back-compat alias — external callers referenced the cpp constant.
BUILDLESS_CPP_MIN_VERSION = BUILDLESS_MIN_VERSIONS["cpp"]

# Languages where ``codeql database create`` WITHOUT
# ``--build-mode=none`` executes repo build logic — either the
# explicit ``--command`` or CodeQL's autobuilder probing the repo's
# build entry points.  Used to decide when the untrusted-traced-build
# banner must fire.
AUTOBUILD_LANGUAGES = frozenset(
    {"cpp", "java", "csharp", "go", "swift", "kotlin"},
)

# Diagnostic messages the extractor emits when an #include could not
# be resolved.  Matched loosely across CLI versions.
_UNRESOLVED_INCLUDE_RE = re.compile(
    r"(could not find|cannot open|could not open|missing|not found)"
    r".{0,60}include"
    r"|include.{0,60}"
    r"(could not find|cannot open|could not open|missing|not found)",
    re.IGNORECASE,
)


def buildless_degradation_summary(db_path: Path) -> tuple:
    """(hit_count, one-line summary) for a buildless C/C++ database.

    Buildless extraction never sees build-generated headers
    (config.h, yacc/protobuf output), so TUs that include them parse
    partially and dataflow through those regions is silently lost —
    which reads as "covered" unless surfaced.  Count the extractor
    diagnostics in the created database that mention unresolved
    includes.  Fail-safe: any parse trouble degrades to the generic
    notice (count 0), never an exception.
    """
    hits = 0
    try:
        diag_root = db_path / "diagnostic"
        if diag_root.is_dir():
            for f in sorted(diag_root.rglob("*")):
                if not f.is_file() or f.suffix.lower() not in (".json", ".jsonl"):
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                hits += sum(
                    1 for line in text.splitlines()
                    if _UNRESOLVED_INCLUDE_RE.search(line)
                )
    except OSError:
        hits = 0
    if hits:
        return hits, (
            f"buildless mode: {hits} extractor diagnostic(s) mention "
            f"unresolved includes — build-generated headers are invisible "
            f"without a traced build (opt in via --traced-build)"
        )
    return 0, (
        "buildless mode: database created without executing the build; "
        "TUs needing build-generated headers may be partially analysed"
    )


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
    errors: list[str]
    database_path: str

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(data: dict):
        fields = {f.name for f in __import__('dataclasses').fields(DatabaseMetadata)}
        return DatabaseMetadata(**{k: v for k, v in data.items() if k in fields})


@dataclass
class DatabaseResult:
    """Result of database creation."""
    success: bool
    language: str
    database_path: Path | None
    metadata: DatabaseMetadata | None
    errors: list[str]
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

    # Auto-cleanup runs at most once per process (the tree walk is
    # pointless to repeat for every manager a run constructs).
    _auto_cleanup_done = False

    def __init__(self, db_root: Path | None = None, codeql_cli: str | None = None) -> None:
        """
        Initialize database manager.

        Args:
            db_root: Root directory for databases (defaults to RaptorConfig.CODEQL_DB_DIR)
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        self.db_root = db_root or RaptorConfig.CODEQL_DB_DIR
        self.db_root.mkdir(parents=True, exist_ok=True)

        # Detect CodeQL CLI
        _cli = codeql_cli or self._detect_codeql_cli()
        # Resolve symlinks (pip/user installs land a ~/.local/bin
        # symlink pointing at the real distribution). The sandbox
        # bind-mounts the RESOLVED parent dir (_sandbox_tool_paths),
        # so invoking via the symlink path would fail the mount-ns
        # visibility check and silently degrade the whole DB build
        # to the Landlock-only fallback.
        self.codeql_cli = os.path.realpath(_cli) if _cli else _cli
        if not self.codeql_cli:
            msg = "CodeQL CLI not found. Set CODEQL_CLI environment variable or install CodeQL."
            raise RuntimeError(msg)

        logger.info("Database manager initialized: %s", self.db_root)
        logger.info("CodeQL CLI: %s", self.codeql_cli)

        # CODEQL_DB_AUTO_CLEANUP: the read side (get_cached_database)
        # already refuses databases older than CODEQL_DB_CACHE_DAYS, so
        # everything past the threshold is disk the cache will never
        # serve again — reclaim it here. Only for the DEFAULT root: a
        # caller-supplied db_root (tests, ad-hoc tooling) manages its
        # own lifecycle. Best-effort — a cleanup failure must never
        # block the run.
        if (db_root is None
                and getattr(RaptorConfig, "CODEQL_DB_AUTO_CLEANUP", False)
                and not DatabaseManager._auto_cleanup_done):
            DatabaseManager._auto_cleanup_done = True
            try:
                self.cleanup_old_databases(
                    days=getattr(RaptorConfig, "CODEQL_DB_CACHE_DAYS", 7),
                )
            except Exception as exc:  # noqa: BLE001 — reclaim is optional
                logger.debug("auto-cleanup of old databases failed: %s", exc)

    def _sandbox_tool_paths(self) -> list:
        """Mount-ns bind dirs needed for codeql to run. See QueryRunner
        equivalent — same rationale (codeql install root rarely lives
        in /usr/bin)."""
        return [str(Path(self.codeql_cli).resolve().parent)]

    def _detect_codeql_cli(self) -> str | None:
        """Detect CodeQL CLI path.

        `os.path.isfile` + `os.access(path, X_OK)` — the same validation
        as the sibling `packages/codeql._resolve_cli`. Pre-fix the
        env-var path was accepted on `X_OK` alone: `CODEQL_CLI=/etc/passwd`
        would have us shell out to a non-executable file (OSError at
        subprocess.run with a confusing stderr), and `CODEQL_CLI=/usr/bin`
        — a directory, which carries the x bit — slipped straight through
        to the same fate. An invalid explicit setting warns loudly rather
        than being silently ignored: the operator set it on purpose, so a
        quiet fall-through to a different PATH binary masks the typo.
        """
        import os

        # Check environment variable
        env_cli = os.environ.get("CODEQL_CLI")
        if env_cli:
            if os.path.isfile(env_cli) and os.access(env_cli, os.X_OK):
                return env_cli
            logger.warning(
                "CODEQL_CLI=%r is not an executable file; "
                "falling back to PATH lookup for 'codeql'",
                env_cli,
            )

        # Check PATH (shutil.which already requires X_OK)
        cli_path = shutil.which("codeql")
        if cli_path:
            return cli_path

        return None

    def get_codeql_version(self) -> str | None:
        r"""Get CodeQL version.

        Returns the dotted-version number (e.g. ``"2.16.4"``) extracted
        from `codeql version` output, or None on failure. Pre-fix the
        function returned the WHOLE first line, which on modern CodeQL
        looks like::

            CodeQL command-line toolchain release 2.16.4.

        Callers comparing against version strings (semver, regex
        `\d+\.\d+`) then matched against the trailing prose, not the
        version number, and either crashed or silently mismatched.
        """
        try:
            # `env=RaptorConfig.get_safe_env()` so the version probe
            # doesn't inherit the parent's env. Pre-fix the bare
            # `subprocess.run` carried LD_PRELOAD / LD_LIBRARY_PATH /
            # PYTHONPATH / etc. through to the codeql binary —
            # codeql is a JVM launcher that respects JAVA_TOOL_OPTIONS
            # and other JVM env vars (which can attach a Java agent
            # at startup, equivalent to LD_PRELOAD for Java). Same
            # env-hygiene posture as the database-creation Popen
            # below.
            result = subprocess.run(
                [self.codeql_cli, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=RaptorConfig.get_safe_env(),
            )
            if result.returncode == 0:
                # Parse first dotted-version-shaped token from stdout.
                # `re.ASCII` so Unicode digits don't sneak in (see
                # packages/exploit_feasibility/profiles.py for the same
                # rationale applied to glibc parsing).
                m = re.search(r'\d+(?:\.\d+){1,3}', result.stdout, re.ASCII)
                if m:
                    return m.group(0)
                # Fallback for unexpected output: return first line so
                # operators still see SOMETHING in logs/banners.
                return result.stdout.strip().split('\n')[0] or None
            return None
        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            logger.warning("Failed to get CodeQL version: %s", e)
            return None

    def supports_buildless(self, language: str) -> tuple:
        """Probe whether the CLI supports ``--build-mode=none`` for *language*.

        Returns ``(supported, detail)`` — ``detail`` is the version on
        success, a human-readable reason on failure.  Version floors
        come from :data:`BUILDLESS_MIN_VERSIONS`; a language absent
        from that table has no buildless mode and reads as
        unsupported.  Never raises; an absent/unparseable CLI reads as
        unsupported so callers can degrade with a clear skip (cpp) or
        a disclosed traced build (java/csharp) instead of a crash.
        Cached per manager instance and language (the CLI doesn't
        change mid-run).
        """
        cache = getattr(self, "_buildless_probes", None)
        if cache is None:
            cache = self._buildless_probes = {}
        if language in cache:
            return cache[language]
        min_version = BUILDLESS_MIN_VERSIONS.get(language)
        if min_version is None:
            result = (
                False,
                f"--build-mode=none has no supported version floor for "
                f"language {language!r}",
            )
            cache[language] = result
            return result
        version = self.get_codeql_version()
        if not version:
            result = (False, "CodeQL CLI version could not be determined")
        else:
            try:
                parts = tuple(int(p) for p in version.split(".")[:3])
            except ValueError:
                result = (False, f"unparseable CodeQL version {version!r}")
            else:
                if parts < min_version:
                    result = (
                        False,
                        (
                            f"CodeQL {version} < "
                            f"{'.'.join(map(str, min_version))} "
                            f"— {language} --build-mode=none unsupported"
                        ),
                    )
                else:
                    result = (True, version)
        cache[language] = result
        return result

    def supports_buildless_cpp(self) -> tuple:
        """Back-compat wrapper: :meth:`supports_buildless` for cpp."""
        return self.supports_buildless("cpp")

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

        # Try to use git commit hash (fast).
        # `safe_git_command` prepends -c overrides that defend
        # against hostile per-repo `.git/config` (core.fsmonitor
        # RCE family). `env=get_safe_git_env()` strips the
        # ambient process env (HOME pinning, GIT_CONFIG_GLOBAL=
        # /dev/null). Both apply — defence in depth.
        try:
            result = subprocess.run(
                safe_git_command("rev-parse", "HEAD"),
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env=get_safe_git_env(),
            )
            if result.returncode == 0:
                git_hash = result.stdout.strip()
                # Combine with repo path to ensure uniqueness.
                #
                # HEAD alone ignores the WORKING TREE: uncommitted
                # edits produced the same cache key as the pristine
                # checkout, so an operator iterating on a fix kept
                # getting the stale database (for up to the 7-day
                # TTL). Fold in a digest of the dirty state — the
                # porcelain listing plus size/mtime of each dirty
                # path, so re-editing an already-dirty file also
                # invalidates. Clean tree → digest is None → key is
                # unchanged from before (cache continuity).
                combined = f"{repo_path}:{git_hash}"
                dirty_digest = self._dirty_tree_digest(repo_path)
                if dirty_digest:
                    combined = f"{combined}:dirty:{dirty_digest}"
                return sha256_string(combined)[:16]
        except (subprocess.SubprocessError, OSError) as exc:
            # Narrowed from bare Exception. ``subprocess.run`` raises
            # SubprocessError subclasses (TimeoutExpired,
            # CalledProcessError) and OSError on exec failure.
            # Programming bugs (TypeError on a renamed kwarg) should
            # still propagate so they surface in tests. Falls through
            # to the directory-structure hash below either way.
            logger.debug(
                "codeql DM: git rev-parse failed for %s: %s; "
                "falling back to directory hash",
                repo_path, exc,
            )

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
        #     keep (name, size) plus a bounded content sample —
        #     touch noise doesn't change the hash, real edits
        #     (including size-preserving ones) do.
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
            collected: list[Path] = []
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
                        # Bounded content sample: (name, size) alone
                        # missed size-preserving edits, so the cache
                        # served a stale database after e.g. flipping
                        # a constant. 4 KiB per file keeps the walk
                        # cheap (<= 4 MiB total at the 1000-file cap)
                        # and stays touch-noise-immune (unlike mtime).
                        with file_path.open("rb") as fh:
                            hasher.update(fh.read(4096))
                    except OSError:
                        pass
        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            logger.debug("Error hashing repository: %s", e)

        return hasher.hexdigest()[:16]

    def _dirty_tree_digest(self, repo_path: Path) -> str | None:
        """Short digest of the working tree's uncommitted state, or
        None when the tree is clean / the probe fails.

        Mixes the ``git status --porcelain`` listing (which files are
        dirty and how) with each dirty path's size and mtime_ns (so a
        further edit to an ALREADY-dirty file still changes the
        digest — the porcelain line alone would not). mtime noise is
        confined to the dirty set: a clean tree keeps the pure
        HEAD-based key.
        """
        try:
            status = subprocess.run(
                safe_git_command("status", "--porcelain"),
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env=get_safe_git_env(),
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.debug(
                "codeql DM: git status failed for %s: %s", repo_path, exc,
            )
            return None
        if status.returncode != 0 or not status.stdout.strip():
            return None
        hasher = hashlib.sha256()
        hasher.update(
            status.stdout.encode("utf-8", errors="surrogateescape"),
        )
        for line in status.stdout.splitlines():
            if len(line) < 4:
                continue
            path_part = line[3:]
            # Rename lines read "old -> new"; the new path is live.
            if " -> " in path_part:
                path_part = path_part.split(" -> ", 1)[1]
            path_part = path_part.strip().strip('"')
            try:
                st = (repo_path / path_part).stat()
            except (OSError, ValueError):
                # Deleted / unstat-able path — the porcelain line
                # above already reflects its state.
                continue
            hasher.update(
                f"{path_part}:{st.st_size}:{st.st_mtime_ns}".encode(
                    "utf-8", errors="surrogateescape",
                ),
            )
        return hasher.hexdigest()[:16]

    def get_database_dir(self, repo_hash: str, language: str) -> Path:
        """Get database directory path."""
        return self.db_root / repo_hash / f"{language}-db"

    def get_metadata_path(self, repo_hash: str, language: str) -> Path:
        """Get metadata file path."""
        return self.db_root / repo_hash / f"{language}-metadata.json"

    def load_metadata(self, repo_hash: str, language: str) -> DatabaseMetadata | None:
        """Load database metadata from disk."""
        metadata_path = self.get_metadata_path(repo_hash, language)
        if not metadata_path.exists():
            return None

        data = load_json(metadata_path)
        if data is None:
            return None
        try:
            return DatabaseMetadata.from_dict(data)
        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            logger.warning("Failed to load metadata: %s", e)
            return None

    def save_metadata(self, metadata: DatabaseMetadata) -> None:
        """Save database metadata to disk."""
        metadata_path = Path(metadata.database_path).parent / f"{metadata.language}-metadata.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            save_json(metadata_path, metadata.to_dict())
        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            logger.error("Failed to save metadata: %s", e)

    def get_cached_database(
        self,
        repo_path: Path,
        language: str,
        max_age_days: int = 7
    ) -> Path | None:
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
            logger.debug("Cached database marked as failed: %s", language)
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
                logger.debug("Cached database too old: %s days", age.days)
                return None
        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            logger.debug("Failed to parse database age: %s", e)
            return None

        # Validate database integrity
        if not self.validate_database(db_path):
            logger.warning("Cached database failed validation: %s", language)
            return None

        logger.info("✓ Using cached database for %s: %s", language, db_path)
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

        Uniqueness suffix: PID alone is NOT sufficient when two writers
        live in DIFFERENT PID namespaces (containers) but share a
        bind-mounted db_root. Two containers can both report
        `os.getpid() == 1` (their per-ns init) and silently collide on
        `.staging-<language>-1`. Append a 4-byte random uniquifier so
        cross-namespace writers stay isolated even if their PID
        coincides. The `_gc_stale_markers` path globs `.staging-*` so
        the trailing uniquifier doesn't break orphan cleanup.
        """
        import secrets
        canonical = self.get_database_dir(repo_hash, language)
        return (
            canonical.parent
            / f".staging-{language}-{os.getpid()}-{secrets.token_hex(4)}"
        )

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

    @staticmethod
    def _salvage_creation_log(staging_path: Path, tail_bytes: int = 8192) -> str:
        """Return the tail of the newest CodeQL creation log, or "".

        ``codeql database create`` writes ``log/database-create-*.log``
        inside the (staging) database dir; on failure that file holds
        the extractor's real error while the CLI stderr only names the
        failing build step.
        """
        try:
            logs = sorted((staging_path / "log").glob("database-create-*.log"))
            if not logs:
                return ""
            data = logs[-1].read_bytes()
            return data[-tail_bytes:].decode("utf-8", errors="replace")
        except OSError:
            return ""

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
            except (ValueError, AttributeError, TypeError):
                # Malformed metadata can't come from an in-flight writer
                # because save_metadata uses atomic temp-rename — readers
                # see either the old or the new metadata, never partial.
                # So malformed = on-disk corruption / hand-edit / bug; no
                # grace period needed (no in-flight case to race).
                evict = True
        if not evict:
            return
        # Pre-check the canonical path right before rename so a race
        # with another evictor / cleanup process surfaces as a fast
        # short-circuit rather than as a silenced OSError. Without
        # this guard, the missing-canonical case fell through into
        # the `os.rename` at the bottom which raised ENOENT, which
        # the bare `except OSError` swallowed — so we couldn't
        # distinguish "harmless race" from "logic bug".
        try:
            real_canonical = canonical.resolve()
        except OSError:
            return  # canonical disappeared between metadata check and rename
        if not real_canonical.exists():
            return
        # Generate a unique marker — if a previous eviction crashed
        # mid-rename and left a marker behind, or two evictors raced
        # to the same `_stale_marker_name`, the second rename would
        # fail with ENOTEMPTY (POSIX rename refuses to clobber a
        # non-empty target directory). Append a short uniquifier so
        # the eviction always succeeds for the canonical-path case
        # we actually care about.
        marker = canonical.with_name(self._stale_marker_name(canonical))
        if marker.exists():
            marker = canonical.with_name(
                f"{self._stale_marker_name(canonical)}.{os.getpid()}.{int(time.monotonic_ns() % 1_000_000)}"
            )
        try:
            os.rename(canonical, marker)
        except OSError:
            pass  # raced with another evictor; harmless

    def _buildless_fallback(
        self,
        repo_path: Path,
        language: str,
        traced_build: bool,
        *,
        force: bool,
        audit_run_dir: Path | None,
        failed_errors: list,
    ) -> "DatabaseResult | None":
        """Retry a failed traced/autobuild create with ``--build-mode=none``.

        Fires only when the failed attempt was an explicit traced build
        for a language with buildless support — the buildless-default
        path can never recurse (its attempts carry
        ``traced_build=False``).  Returns the fallback's DatabaseResult,
        or None when no fallback applies (caller returns its own
        failure).  The fallback result carries a provenance note in
        ``errors`` and the loud degradation warning in the run log —
        a traced build the operator asked for silently downgrading
        would misrepresent extraction fidelity.
        """
        if not traced_build or language not in BUILDLESS_DEFAULT_LANGUAGES:
            return None
        supported, detail = self.supports_buildless(language)
        if not supported:
            logger.warning(
                "traced %s build failed and buildless fallback is "
                "unavailable: %s", language, detail,
            )
            return None
        logger.warning(
            "traced %s build failed — falling back to buildless "
            "extraction (--build-mode=none): build-generated code is "
            "invisible and dependency types resolve best-effort. "
            "Traced failure: %s",
            language,
            "; ".join(failed_errors[:2]) or "see extractor log",
        )
        result = self.create_database(
            repo_path, language,
            build_system=None,
            force=force,
            audit_run_dir=audit_run_dir,
            traced_build=False,
        )
        result.errors.append(
            f"buildless fallback: the traced {language} build failed "
            "and extraction proceeded with --build-mode=none "
            "(reduced fidelity)"
        )
        return result

    def create_database(
        self,
        repo_path: Path,
        language: str,
        build_system: BuildSystem | None = None,
        force: bool = False,
        audit_run_dir: Path | None = None,
        traced_build: bool = False,
        concurrent_workers: int = 1,
    ) -> DatabaseResult:
        """
        Create CodeQL database.

        Args:
            repo_path: Path to source code
            language: Programming language
            build_system: Build system info (None for no-build mode)
            traced_build: Opt into traced-build extraction for
                languages in :data:`BUILDLESS_DEFAULT_LANGUAGES`.
                Default False: C/C++ and Java databases are created
                with ``--build-mode=none`` so an untrusted repo's
                build scripts NEVER execute (any ``build_system``
                command is ignored with a log line).  Buildless needs
                the per-language CLI floor in
                :data:`BUILDLESS_MIN_VERSIONS` — older CLIs return a
                clear failed DatabaseResult (graceful skip, no crash,
                no silent traced fallback).  ``traced_build=True``
                restores the traced path, which runs the repo build
                under the sandbox — the operator asserts trust; when a
                traced attempt for a buildless-capable language fails,
                one buildless retry runs with a loud degradation
                warning and provenance note (see
                :meth:`_buildless_fallback`).
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
            concurrent_workers: How many CodeQL invocations run at the
                same time as this one (parallel multi-language builds).
                Passed to :meth:`CodeQLTunables.from_tuning` so the
                auto (``-j 0``) thread count is divided between the
                concurrent processes; explicit thread settings are
                respected as-is (default: 1).

        Returns:
            DatabaseResult with creation status
        """
        start_time = time.time()
        repo_path = Path(repo_path).resolve()
        errors = []

        logger.info("%s", '=' * 70)
        logger.info("Creating CodeQL database for %s", language)
        logger.info("%s", '=' * 70)

        # Trust check: target-repo codeql-pack.yml / qlpack.yml /
        # codeql-config.yml can declare custom extractors, build hooks
        # and external pack dependencies that codeql exec's during
        # `database create`. Refuse on findings unless --trust-repo
        # has been parsed at the entry point. Distinct surface from
        # the cc_trust check (which guards .claude/settings.json).
        from core.security.codeql_trust import check_repo_codeql_trust
        if check_repo_codeql_trust(str(repo_path)):
            return DatabaseResult(
                success=False,
                language=language,
                database_path=None,
                metadata=None,
                errors=[
                    ("target repo has unsafe CodeQL pack config — refusing "
                     "to invoke `codeql database create`. Re-run with "
                     "--trust-repo to override after auditing the printed "
                     "findings.")
                ],
                duration_seconds=time.time() - start_time,
                cached=False,
            )

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
            logger.info("Force rebuild: evicting cached database for %s", language)
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

        # Buildless default for C/C++: never execute an untrusted
        # repo's build system unless the operator explicitly opted in.
        # Gate AFTER the cache checks (a cached DB is safe to serve
        # regardless of how the CLI was probed) and BEFORE command
        # construction.
        buildless = (
            language in BUILDLESS_DEFAULT_LANGUAGES and not traced_build
        )
        if buildless:
            supported, detail = self.supports_buildless(language)
            if not supported and language == "cpp":
                # C/C++ has no safe alternative on an old CLI:
                # hard-skip rather than silently running the repo's
                # build.
                logger.error(
                    "✗ Buildless %s extraction unavailable: %s", language, detail,
                )
                _floor = BUILDLESS_MIN_VERSIONS.get(language)
                _floor_txt = (
                    '.'.join(map(str, _floor)) if _floor else "a newer release"
                )
                return DatabaseResult(
                    success=False,
                    language=language,
                    database_path=None,
                    metadata=None,
                    errors=[
                        (
                            f"buildless {language} extraction unavailable: "
                            f"{detail}. Upgrade the CodeQL CLI (>= "
                            f"{_floor_txt}) "
                            "or explicitly opt into traced-build mode "
                            "(--traced-build / --build-command) if the repo "
                            "is trusted — traced builds EXECUTE the repo's "
                            "build scripts."
                        )
                    ],
                    duration_seconds=time.time() - start_time,
                    cached=False,
                )
            if not supported:
                # java/csharp on a CLI without buildless: keep the
                # pre-existing traced/autobuild behaviour, disclosed
                # by the untrusted-traced-build banner below.
                logger.warning(
                    "%s: buildless extraction unavailable (%s) — "
                    "falling back to the traced/autobuild path",
                    language, detail,
                )
                buildless = False

        # Untrusted traced-build disclosure. When this create is about
        # to execute repo build logic (an explicit --command, or the
        # CodeQL autobuilder for a compiled language) WITHOUT the
        # operator's trust assertion (traced_build / --build-command /
        # the project's `build` trust marker), say so loudly — the
        # repo's build scripts are attacker-controlled code.
        if not buildless and not traced_build and (
            (build_system is not None and build_system.command)
            or language in AUTOBUILD_LANGUAGES
        ):
            _vector = (
                f"build command {build_system.command!r}"
                if build_system is not None and build_system.command
                else "the CodeQL autobuilder"
            )
            logger.warning("%s", "=" * 70)
            logger.warning(
                "⚠️  %s: traced build without the build trust marker — "
                "`codeql database create` will execute the repository's "
                "build logic via %s (sandboxed, network blocked). If you "
                "trust this repo, acknowledge with --traced-build or "
                "`/project trust build`.",
                language, _vector,
            )
            logger.warning("%s", "=" * 70)

        # Cleanup any prior leftover staging from this same process (e.g.,
        # from a previous crashed run with the same PID after PID reuse).
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
        if buildless:
            # Buildless extraction: codeql parses the source without
            # invoking any build system, so no repo-controlled code
            # runs during `database create`.  (The sandbox below is
            # kept anyway — the extractor still parses hostile input.)
            cmd.append("--build-mode=none")
        # Central CodeQL resource tunables (-j / -M / --max-disk-cache,
        # tuning.json-backed).  ``include_disk_cache=True`` because
        # ``database create`` accepts the flag; ``database analyze``
        # would reject it.
        CodeQLTunables.from_tuning(
            concurrent_workers=concurrent_workers,
        ).append_to(cmd, include_disk_cache=True)

        # Set working directory and environment.
        #
        # `os.access(working_dir, os.X_OK)` check before passing to
        # subprocess. A directory must have execute permission for a
        # process to chdir into it; without it, subprocess.run with
        # `cwd=working_dir` fails with PermissionError that the caller
        # sees only as "build failed". The common cause is a noexec
        # mount: shared CI runners that mount the build area noexec for
        # security, or `/tmp` mounted noexec on hardened hosts. Surface
        # the issue with an actionable message instead of a generic
        # subprocess error. Skip on platforms without POSIX
        # permission semantics (Windows: os.access semantics differ
        # but the noexec hazard doesn't apply the same way).
        working_dir = build_system.working_dir if build_system else repo_path
        if (
            os.name == "posix"
            and not os.access(working_dir, os.X_OK)
        ):
            return DatabaseResult(
                success=False,
                language=language,
                database_path=None,
                metadata=None,
                errors=[
                    (f"working_dir {working_dir!r} lacks execute permission "
                     f"(POSIX dir-exec). Common cause: noexec mount on the "
                     f"build area. Re-mount with exec, or move the build "
                     f"into a directory that has it (e.g. $HOME).")
                ],
                duration_seconds=time.time() - start_time,
                cached=False,
            )
        env = RaptorConfig.get_safe_env()
        if build_system and build_system.env_vars:
            # Filter build env vars through the same blocklist — a malicious
            # repo's build config could try to re-inject LD_PRELOAD, BASH_ENV, etc.
            blocked = set(RaptorConfig.DANGEROUS_ENV_VARS) | set(RaptorConfig.PROXY_ENV_VARS)
            for k, v in build_system.env_vars.items():
                if k not in blocked:
                    env[k] = v
        # Auto-detect toolchain-home env vars (JAVA_HOME, GOROOT, etc.)
        # per build system's env_detect list. Per-subprocess scope —
        # these land only in this build invocation, not in other sandbox
        # calls. See the design memo and core/build/toolchain.py.
        if build_system and build_system.env_detect:
            from core.build.toolchain import apply_toolchain_env
            apply_toolchain_env(env, build_system.env_detect)

        # Add build command if provided.
        # CodeQL splits --command on whitespace without shell interpretation,
        # so shell operators (&&, ||, ;, |) break. Wrap in a script unless
        # the command is already a path to an executable (e.g. synthesised builds).
        build_script = None
        if buildless and build_system and build_system.command:
            logger.info(
                "Buildless mode (--build-mode=none): ignoring detected "
                "build command %r — pass traced_build=True to use it",
                build_system.command,
            )
        elif build_system and build_system.command:
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
                    build_script.write_text(f"#!/bin/bash\n{build_cmd}\n", encoding="utf-8")
                    # 0o500 (read+execute, no write) for parity with
                    # `build_detector.py:871`'s synthesised-script mode
                    # — TOCTOU mitigation: a separate process can't
                    # modify the script between our write and CodeQL's
                    # exec. Pre-fix the chmod was
                    # `st_mode | S_IEXEC` which kept the write bit
                    # from mkstemp's 0o600 default, leaving the script
                    # writable for the lifetime of the build invocation.
                    build_script.chmod(0o500)
                except BaseException:
                    build_script.unlink(missing_ok=True)
                    build_script = None
                    raise
                cmd.extend(["--command", str(build_script)])
            logger.info("Build command: %s", build_system.command)
            logger.info("Working directory: %s", working_dir)
        else:
            logger.info("No build command (interpreted language or no-build mode)")

        logger.info("Executing: %s", ' '.join(cmd))
        logger.info("Timeout: %ss", RaptorConfig.CODEQL_TIMEOUT)

        # Execute database creation in sandbox (network blocked — packs pre-fetched)
        try:
            from core.sandbox import run as sandbox_run
            from core.sandbox.fingerprint import HOST_CPU_COUNT
            result = sandbox_run(
                cmd,
                block_network=True,
                cwd=working_dir,
                env=env,
                env_caller_filtered=True,
                # target/output engage the mount namespace: without them
                # sanitise_host_fingerprint silently no-ops (identity
                # surfaces stay host-real) and the seccomp filter keeps
                # AF_UNIX blocked, which kills Python >= 3.14 extractors
                # (multiprocessing forkserver needs a unix socket).
                # target = source tree (read), output = staging DB (rw);
                # the DB parent dir rides along so codeql's lock files
                # next to the staging dir stay writable.
                target=str(repo_path),
                output=str(staging_path.parent),
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
                # `codeql database create` invokes the target repo's
                # autobuild / --command build, which is where target-
                # supplied build scripts execute. Sanitise identity
                # surfaces so anti-analysis-aware build tooling can't
                # detect the analysis environment.
                #
                # cpu_count=HOST_CPU_COUNT preserves real parallelism
                # for Make/Maven/Gradle — the default cpu_count=4 would
                # serialise to 4 threads regardless of host count and
                # cause ~8x build slowdown on 32-core CI hosts,
                # pushing long builds past CODEQL_TIMEOUT.
                sanitise_host_fingerprint=True,
                cpu_count=HOST_CPU_COUNT,
            )

            success = result.returncode == 0

            if success and buildless:
                # Degradation visibility: silently reduced coverage
                # must not read as full coverage in the run log.
                if language == "cpp":
                    _hits, _summary = buildless_degradation_summary(staging_path)
                    (logger.warning if _hits else logger.info)("%s", _summary)
                else:
                    # The include-diagnostic census is cpp-specific;
                    # for other buildless languages state the generic
                    # fidelity caveat instead of a misleading
                    # "no degradation detected".
                    logger.info(
                        "Buildless %s extraction: build-generated code is "
                        "invisible and dependency types resolve best-effort "
                        "(no dependency fetch under the network-blocked "
                        "sandbox)", language,
                    )

            if not success:
                errors.append(f"Database creation failed with exit code {result.returncode}")
                if result.stderr:
                    errors.append(result.stderr[:1000])  # Truncate long errors
                logger.error("✗ Database creation failed for %s", language)
                logger.error((result.stderr or "")[:500])
                # Surface the extractor's own log before cleanup: the
                # CLI's stderr carries only "autobuild failed" while the
                # actual traceback (missing interpreter, denied syscall,
                # build-tool error) lands in the staging DB's log dir.
                # Losing it turned every creation failure into a manual
                # re-run under a debugger.
                _diag = self._salvage_creation_log(staging_path)
                if _diag:
                    errors.append(_diag[:2000])
                    logger.error("extractor log tail:\n%s", _diag[:2000])
                # Preserve the full staging dir for inspection under a
                # name the stale-marker GC already reaps (1h TTL), so
                # diagnostics survive without accumulating: keep only
                # the newest failed dir per cache slot.
                _failed = staging_path.parent / (
                    f".staging-failed-{language}"
                )
                shutil.rmtree(_failed, ignore_errors=True)
                try:
                    staging_path.rename(_failed)
                    logger.error(
                        "failed staging preserved for inspection at %s "
                        "(auto-cleaned after 1h)", _failed,
                    )
                except OSError:
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
                    # Pre-flight existence check. `os.rename` on Linux
                    # silently SUCCEEDS when the target is an empty
                    # directory — it replaces the empty dir without
                    # raising ENOTEMPTY. A sibling that created
                    # `canonical_path` as a placeholder (e.g. via
                    # `mkdir`-as-lock pattern in some other tool, or a
                    # half-initialised promote-in-progress state) would
                    # have its empty dir silently overwritten by our
                    # staging — the lost-race branch never fires and we
                    # don't validate the sibling's intent. Raise
                    # FileExistsError manually so the existing
                    # ENOTEMPTY/EEXIST handler treats this case the
                    # same as a populated-target collision.
                    if canonical_path.exists():
                        raise FileExistsError(
                            errno.EEXIST,
                            "canonical_path exists pre-rename "
                            "(possibly empty placeholder); routing "
                            "through lost-race handler",
                            str(canonical_path),
                        )
                    os.rename(staging_path, canonical_path)
                    logger.info("✓ Database promoted to canonical: %s", canonical_path)
                    did_promote = True
                except OSError as e:
                    if e.errno in (errno.ENOTEMPTY, errno.EEXIST):
                        # Lost the promotion race. Validate the sibling's
                        # canonical before trusting it — without this check,
                        # a sibling who promoted broken content would propagate
                        # to us as success=True pointing at garbage.
                        if self.validate_database(canonical_path):
                            logger.info(
                                "✓ Database promoted by sibling; using cached %s", canonical_path
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
                                "Canonical %s exists but failed validation; evicting and retrying promote",
                                canonical_path
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
                                    "✓ Database promoted to canonical (after evicting broken sibling copy): %s",
                                    canonical_path
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
                            "Could not promote staging to canonical (%s); using staging path", e
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
                build_command=(
                    "" if buildless
                    else build_system.command if build_system else ""
                ),
                build_system=(
                    "buildless" if buildless
                    else build_system.type if build_system else "no-build"
                ),
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

            if not success:
                fallback = self._buildless_fallback(
                    repo_path, language, traced_build,
                    force=force, audit_run_dir=audit_run_dir,
                    failed_errors=errors,
                )
                if fallback is not None:
                    return fallback

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
            logger.error("✗ Database creation timed out for %s", language)

            fallback = self._buildless_fallback(
                repo_path, language, traced_build,
                force=force, audit_run_dir=audit_run_dir,
                failed_errors=errors,
            )
            if fallback is not None:
                return fallback

            return DatabaseResult(
                success=False,
                language=language,
                database_path=None,
                metadata=None,
                errors=errors,
                duration_seconds=time.time() - start_time,
                cached=False,
            )

        except SandboxSetupError:
            raise  # sandbox isolation could not engage — fail loud, never mask as a benign result

        except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
            errors.append(f"Unexpected error: {e!s}")
            logger.error("✗ Database creation failed with exception: %s", e)

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
            # build_script unlink: missing_ok=True so a script that
            # was already cleaned up by an earlier branch (or that
            # never landed on disk because mkstemp succeeded but
            # write_text raised) doesn't crash the cleanup. Pre-fix
            # `build_script.unlink()` raised FileNotFoundError when
            # the success path had already deleted the script, AND
            # raised PermissionError if the script's parent dir got
            # mounted noexec/readonly mid-build (rare but observed
            # on some CI runners). Either case took the cleanup
            # exception out of `finally:` and skipped the staging
            # rmtree below.
            if build_script:
                try:
                    build_script.unlink(missing_ok=True)
                except OSError as _bs_err:
                    logger.debug("build_script unlink failed: %s", _bs_err)
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
        language_build_map: dict[str, BuildSystem | None],
        force: bool = False,
        max_workers: int | None = None,
        audit_run_dir: Path | None = None,
        traced_languages: "set | None" = None,
    ) -> dict[str, DatabaseResult]:
        """
        Create multiple databases in parallel.

        Args:
            repo_path: Repository path
            language_build_map: Dict mapping language -> BuildSystem
            force: Force recreation
            max_workers: Max parallel workers (default: RaptorConfig.MAX_CODEQL_WORKERS)
            audit_run_dir: Forwarded to per-language create_database for
                audit JSONL targeting (no Landlock impact).
            traced_languages: Languages the operator explicitly opted
                into traced-build extraction for (see
                ``create_database(traced_build=...)``).  Languages not
                in the set keep the buildless default for C/C++.

        Returns:
            Dict mapping language -> DatabaseResult
        """
        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results = {}

        logger.info(
            "Creating %d databases in parallel (max workers: %s)",
            len(language_build_map),
            max_workers
        )

        # Core-share per child build: N concurrent -j0 extractions
        # would each claim every core; divide instead (an explicit
        # numeric codeql_threads is respected inside from_tuning).
        _share = min(max_workers, len(language_build_map)) or 1
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
                    lang in (traced_languages or ()),
                    _share,
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
                        logger.info("✓ %s database completed", lang)
                    else:
                        logger.error("✗ %s database failed", lang)
                except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
                    logger.error("✗ %s database raised exception: %s", lang, e)
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
                logger.debug("Missing essential file: %s", file_name)
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
                logger.debug("No db-* subdir in %s", db_path)
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
                "db-* subdirs present but trivially small in %s (likely aborted build)", db_path
            )
            return False
        except OSError as e:
            logger.debug("validate_database couldn't stat %s: %s", db_path, e)
            return False

    def _count_database_files(self, db_path: Path) -> int:
        """Count files in database (for statistics)."""
        try:
            # Count files in src.zip if it exists. Use the substrate's
            # EOCD pre-flight rather than opening the archive — for a
            # typical CodeQL DB the result is the same as
            # ``len(zf.namelist())`` but we avoid the central-directory
            # materialisation cost and the implicit bomb-shape risk.
            src_zip = db_path / "src.zip"
            if src_zip.exists():
                from core.zip import peek_total_entries
                count = peek_total_entries(src_zip)
                return count if count is not None else 0
            return 0
        except Exception:  # noqa: BLE001 — best-effort; never fail the run
            return 0

    def cleanup_old_databases(self, days: int = 7, dry_run: bool = False) -> list[str]:
        """
        Clean up databases older than specified days.

        Args:
            days: Age threshold in days
            dry_run: If True, only report what would be deleted

        Returns:
            List of deleted database paths
        """
        # Debug, not info: the auto-cleanup path runs this on every
        # process start and it's usually a no-op — the per-deletion
        # lines below surface actual reclaims at INFO.
        logger.debug("Cleaning up databases older than %s days...", days)
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
                        # Containment guard: db_path comes from the
                        # JSON metadata file. Pre-fix `shutil.rmtree
                        # (db_path)` blindly trusted that path. A
                        # tampered or copy-pasted metadata file
                        # naming `database_path: "/etc"` would have
                        # had cleanup obliterate /etc.
                        # Restrict to paths INSIDE self.db_root so
                        # only databases this manager could have
                        # created are eligible for deletion.
                        try:
                            db_resolved = db_path.resolve(strict=False)
                            db_root_resolved = self.db_root.resolve(strict=False)
                            db_resolved.relative_to(db_root_resolved)
                        except (ValueError, OSError):
                            logger.warning(
                                "cleanup_old_databases: refusing to delete "
                                "%r — outside db_root %r",
                                db_path, self.db_root,
                            )
                            continue
                        if db_path.exists():
                            if not dry_run:
                                shutil.rmtree(db_path)
                                metadata_file.unlink()
                                logger.info("Deleted old database: %s", db_path)
                            else:
                                logger.info("Would delete: %s", db_path)
                            deleted.append(str(db_path))
                except Exception as e:  # noqa: BLE001 — best-effort; never fail the run
                    logger.warning("Error processing %s: %s", metadata_file, e)

        if deleted:
            logger.info("Cleaned up %d databases", len(deleted))
        else:
            logger.debug("Cleaned up 0 databases")
        return deleted


def main() -> None:
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeQL Database Manager")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--build-command", help="Build command")
    parser.add_argument(
        "--traced-build", action="store_true",
        help="Opt into traced-build extraction for C/C++ (default is "
             "--build-mode=none, which never executes the repo's build "
             "scripts). Traced builds run repo-controlled code — only "
             "use on trusted repos. Implied by --build-command.",
    )
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
        from core.build.build_detector import BuildSystem
        build_system = BuildSystem(
            type="custom",
            command=args.build_command,
            working_dir=Path(args.repo),
            env_vars={},
            confidence=1.0,
            detected_files=[],
        )

    # Create database.  An explicit --build-command is an operator
    # assertion of trust — it implies traced-build mode.
    result = manager.create_database(
        Path(args.repo),
        args.language,
        build_system,
        force=args.force,
        traced_build=args.traced_build or bool(args.build_command),
    )

    if result.success:
        print(f"\n✓ Database created: {result.database_path}")
        print(f"Duration: {result.duration_seconds:.1f}s")
        if result.cached:
            print("(from cache)")
    else:
        print("\n✗ Database creation failed", file=sys.stderr)
        for error in result.errors:
            print(f"  {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
