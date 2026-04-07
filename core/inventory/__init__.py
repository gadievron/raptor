"""Shared source inventory for RAPTOR analysis skills.

Provides language-aware file enumeration, code item extraction (functions,
globals, macros, classes), SHA-256 checksumming, SLOC counting, and
cumulative coverage tracking.

Usage:
    from core.inventory import build_inventory, get_coverage_stats, get_items

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
    CodeItem,
    FunctionInfo,
    FunctionMetadata,
    KIND_FUNCTION,
    KIND_GLOBAL,
    KIND_MACRO,
    KIND_CLASS,
    extract_functions,
    extract_items,
    count_sloc,
    PythonExtractor,
    JavaScriptExtractor,
    CExtractor,
    JavaExtractor,
    GoExtractor,
    GenericExtractor,
    _REGEX_EXTRACTORS as EXTRACTORS,  # Backward compat
    _get_ts_languages,
)
from .lookup import lookup_function, normalise_path
from .diff import compare_inventories
from .coverage import update_coverage, get_coverage_stats, format_coverage_summary


def get_items(file_entry):
    """Read code items from a file entry. Handles both old and new format.

    Old format: file_entry["functions"] (list of function dicts)
    New format: file_entry["items"] (list of CodeItem dicts with "kind" field)
    """
    return file_entry.get("items", file_entry.get("functions", []))
