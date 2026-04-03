"""Shared source inventory for RAPTOR analysis skills.

Provides language-aware file enumeration, function extraction,
SHA-256 checksumming, and cumulative coverage tracking.

Usage:
    from core.inventory import build_inventory, get_coverage_stats

    inventory = build_inventory("/path/to/repo", "/path/to/output")
    stats = get_coverage_stats(inventory)
"""

from .builder import build_inventory
from .languages import LANGUAGE_MAP, detect_language
from .exclusions import (
    DEFAULT_EXCLUDES,
    GENERATED_MARKERS,
    is_binary_file,
    is_generated_file,
    should_exclude,
    match_exclusion_reason,
)
from .extractors import (
    FunctionInfo,
    FunctionMetadata,
    extract_functions,
    PythonExtractor,
    JavaScriptExtractor,
    CExtractor,
    JavaExtractor,
    GoExtractor,
    GenericExtractor,
    _REGEX_EXTRACTORS as EXTRACTORS,  # Backward compat
    _get_ts_languages,
)
from .diff import compare_inventories
from .coverage import update_coverage, get_coverage_stats, format_coverage_summary
