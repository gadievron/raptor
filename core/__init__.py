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

# Git utilities (extracted in refactoring)
from core.git import (
    clone_repository,
)

# Semgrep utilities (extracted in refactoring)
from core.semgrep import run_semgrep

# LLM utilities (moved in refactoring)
from core.llm import LLMClient, LLMConfig

# Execution utilities (consolidated in refactoring)
from core.exec import run

# Hash utilities (consolidated in refactoring)
from core.hash import sha256_tree

__all__ = [
    "RaptorConfig",
    "get_logger",
    "deduplicate_findings",
    "parse_sarif_findings",
    "validate_sarif",
    "generate_scan_metrics",
    "sanitize_finding_for_display",
    # Git utilities
    "clone_repository",
    # Semgrep utilities
    "run_semgrep",
    # LLM utilities
    "LLMClient",
    "LLMConfig",
    # Execution utilities
    "run",
    # Hash utilities
    "sha256_tree",
]
