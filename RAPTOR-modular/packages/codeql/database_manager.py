#!/usr/bin/env python3
"""
CodeQL Database Manager

Manages CodeQL database lifecycle including creation, caching,
validation, and cleanup.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig
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
                return hashlib.sha256(combined.encode()).hexdigest()[:16]
        except Exception:
            pass

        # Fallback: hash directory structure and modification times
        hasher = hashlib.sha256()
        hasher.update(str(repo_path).encode())

        # Hash a sample of files (for performance)
        try:
            files = list(repo_path.rglob("*"))[:1000]  # Sample first 1000 files
            for file_path in sorted(files):
                if file_path.is_file():
                    hasher.update(str(file_path.relative_to(repo_path)).encode())
                    try:
                        stat = file_path.stat()
                        hasher.update(str(stat.st_mtime).encode())
                        hasher.update(str(stat.st_size).encode())
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

        try:
            with open(metadata_path) as f:
                data = json.load(f)
                return DatabaseMetadata.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load metadata: {e}")
            return None

    def save_metadata(self, metadata: DatabaseMetadata):
        """Save database metadata to disk."""
        metadata_path = Path(metadata.database_path).parent / f"{metadata.language}-metadata.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(metadata_path, 'w') as f:
                json.dump(metadata.to_dict(), f, indent=2)
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
            age = datetime.now() - created_at
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

    def create_database(
        self,
        repo_path: Path,
        language: str,
        build_system: Optional[BuildSystem] = None,
        force: bool = False
    ) -> DatabaseResult:
        """
        Create CodeQL database.

        Args:
            repo_path: Path to source code
            language: Programming language
            build_system: Build system info (None for no-build mode)
            force: Force recreation even if cached DB exists

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

        # Compute repo hash and database path
        repo_hash = self.compute_repo_hash(repo_path)
        db_path = self.get_database_dir(repo_hash, language)

        # Ensure parent directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove existing database if forcing
        if db_path.exists():
            logger.info(f"Removing existing database: {db_path}")
            shutil.rmtree(db_path)

        # Build the codeql command
        cmd = [
            self.codeql_cli,
            "database",
            "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={repo_path}",
        ]

        # Add build command if provided
        if build_system and build_system.command:
            cmd.append(f"--command={build_system.command}")
            logger.info(f"Build command: {build_system.command}")
            logger.info(f"Working directory: {build_system.working_dir}")
        else:
            logger.info("No build command (interpreted language or no-build mode)")

        # Set up environment
        env = RaptorConfig.get_safe_env()
        if build_system and build_system.env_vars:
            env.update(build_system.env_vars)

        # Set working directory
        working_dir = build_system.working_dir if build_system else repo_path

        logger.info(f"Executing: {' '.join(cmd)}")
        logger.info(f"Timeout: {RaptorConfig.CODEQL_TIMEOUT}s")

        # Execute database creation
        try:
            result = subprocess.run(
                cmd,
                cwd=working_dir,
                env=env,
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
            else:
                logger.info(f"✓ Database created successfully: {db_path}")

            # Count files in database
            file_count = self._count_database_files(db_path) if success else 0

            # Create metadata
            metadata = DatabaseMetadata(
                repo_hash=repo_hash,
                repo_path=str(repo_path),
                language=language,
                created_at=datetime.now().isoformat(),
                codeql_version=self.get_codeql_version() or "unknown",
                build_command=build_system.command if build_system else "",
                build_system=build_system.type if build_system else "no-build",
                file_count=file_count,
                success=success,
                duration_seconds=time.time() - start_time,
                errors=errors,
                database_path=str(db_path),
            )

            # Save metadata
            self.save_metadata(metadata)

            return DatabaseResult(
                success=success,
                language=language,
                database_path=db_path if success else None,
                metadata=metadata,
                errors=errors,
                duration_seconds=time.time() - start_time,
                cached=False,
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

    def create_databases_parallel(
        self,
        repo_path: Path,
        language_build_map: Dict[str, Optional[BuildSystem]],
        force: bool = False,
        max_workers: Optional[int] = None
    ) -> Dict[str, DatabaseResult]:
        """
        Create multiple databases in parallel.

        Args:
            repo_path: Repository path
            language_build_map: Dict mapping language -> BuildSystem
            force: Force recreation
            max_workers: Max parallel workers (default: RaptorConfig.MAX_CODEQL_WORKERS)

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
                    force
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

        # Run codeql database check (optional, can be slow)
        # Disabled by default for performance
        # try:
        #     result = subprocess.run(
        #         [self.codeql_cli, "database", "check", str(db_path)],
        #         capture_output=True,
        #         timeout=30,
        #     )
        #     return result.returncode == 0
        # except Exception:
        #     return False

        return True

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
        cutoff = datetime.now() - timedelta(days=days)
        deleted = []

        for repo_dir in self.db_root.iterdir():
            if not repo_dir.is_dir():
                continue

            # Check all metadata files in this repo
            for metadata_file in repo_dir.glob("*-metadata.json"):
                try:
                    with open(metadata_file) as f:
                        data = json.load(f)
                        created_at = datetime.fromisoformat(data["created_at"])

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
        print(f"\n✗ Database creation failed")
        for error in result.errors:
            print(f"  {error}")


if __name__ == "__main__":
    main()
