"""
CodeQL package for RAPTOR

Autonomous CodeQL analysis with database management, query execution,
and intelligent caching.
"""

import os
import shutil

from .language_detector import LanguageDetector, LanguageInfo
from core.build.build_detector import BuildDetector, BuildSystem
from .database_manager import DatabaseManager, DatabaseResult, DatabaseMetadata
from .query_runner import QueryRunner, QueryResult
from .tunables import CodeQLTunables


def _resolve_cli() -> str | None:
    env = os.environ.get("CODEQL_CLI")
    if env:
        if os.path.isfile(env) and os.access(env, os.X_OK):
            return os.path.realpath(env)
        # Loud, like DatabaseManager._detect_codeql_cli on the same
        # condition: a typo'd operator override silently probed
        # whichever codeql was on PATH here while the DM path warned —
        # the QueryRunner masked exactly the mistake the DM surfaced.
        import logging
        logging.getLogger(__name__).warning(
            "CODEQL_CLI=%r is not an executable file — ignoring the "
            "override and falling back to PATH lookup", env,
        )
    found = shutil.which("codeql")
    return os.path.realpath(found) if found else None


def is_available() -> bool:
    return _resolve_cli() is not None


def version() -> str | None:
    from ._bootstrap import resolve_bootstrap
    cli = resolve_bootstrap(_resolve_cli(), install=False)
    if not cli:
        return None
    from .version_probe import read_codeql_version
    return read_codeql_version(cli)



__all__ = [
    "BuildDetector",
    "BuildSystem",
    "CodeQLTunables",
    "DatabaseManager",
    "DatabaseMetadata",
    "DatabaseResult",
    "LanguageDetector",
    "LanguageInfo",
    "QueryResult",
    "QueryRunner",
    "is_available",
    "version",
]
