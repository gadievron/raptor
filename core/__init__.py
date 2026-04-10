"""
RAPTOR Core Utilities

Re-exports key components for easy importing.
"""

from core.config import RaptorConfig
from core.logging import get_logger
from core.sarif.parser import (
    deduplicate_findings,
    parse_sarif_findings,
    validate_sarif,
    generate_scan_metrics,
    sanitize_finding_for_display,
)

from core.git import clone_repository
from core.semgrep import run_semgrep
from core.exec import run
from core.hash import sha256_tree

__all__ = [
    "RaptorConfig",
    "get_logger",
    "deduplicate_findings",
    "parse_sarif_findings",
    "validate_sarif",
    "generate_scan_metrics",
    "sanitize_finding_for_display",
    "clone_repository",
    "run_semgrep",
    "run",
    "sha256_tree",
]
