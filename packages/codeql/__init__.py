"""
CodeQL package for RAPTOR

Autonomous CodeQL analysis with database management, query execution,
and intelligent caching.
"""

import os
import shutil
import subprocess
from typing import Optional

from .language_detector import LanguageDetector, LanguageInfo
from core.build.build_detector import BuildDetector, BuildSystem
from .database_manager import DatabaseManager, DatabaseResult, DatabaseMetadata
from .query_runner import QueryRunner, QueryResult
from .tunables import CodeQLTunables


def _resolve_cli() -> Optional[str]:
    env = os.environ.get("CODEQL_CLI")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("codeql")


def is_available() -> bool:
    return _resolve_cli() is not None


def version() -> Optional[str]:
    cli = _resolve_cli()
    if not cli:
        return None
    try:
        out = subprocess.run(
            [cli, "version", "--format=terse"],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


__all__ = [
    "LanguageDetector",
    "LanguageInfo",
    "BuildDetector",
    "BuildSystem",
    "DatabaseManager",
    "DatabaseResult",
    "DatabaseMetadata",
    "QueryRunner",
    "QueryResult",
    "CodeQLTunables",
    "is_available",
    "version",
]
