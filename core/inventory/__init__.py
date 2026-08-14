"""Shared source inventory for RAPTOR analysis skills.

Provides language-aware file enumeration, code item extraction (functions,
globals, macros, classes), SHA-256 checksumming, SLOC counting, and
cumulative coverage tracking.

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

# Public re-export surface. Each name below is imported above purely
# to make `from core.inventory import X` work for downstream callers
# (packages/exploitability_validation, the validation tests, the
# CodeQL prefilter). Without `__all__`, ruff F401 flags them all as
# "unused import"; with it, ruff recognises the re-export intent and
# `from core.inventory import *` exposes exactly this list.
# Order follows the import statements above (grouped by submodule)
# rather than strict alphabetical, to keep the audit trail between
# import-site and re-export-list trivial. `save_checklist` /
# `get_items` are module-level functions defined below — included
# here because they're part of the public surface too.
__all__ = [
    # .builder
    "build_inventory",
    # .languages
    "LANGUAGE_MAP",
    "detect_language",
    # .exclusions
    "DEFAULT_EXCLUDES",
    "GENERATED_MARKERS",
    "is_binary_file",
    "is_generated_file",
    "should_exclude",
    "match_exclusion_reason",
    # .extractors
    "CodeItem",
    "FunctionInfo",
    "FunctionMetadata",
    "KIND_FUNCTION",
    "KIND_GLOBAL",
    "KIND_MACRO",
    "KIND_CLASS",
    "extract_functions",
    "extract_items",
    "count_sloc",
    "PythonExtractor",
    "JavaScriptExtractor",
    "CExtractor",
    "JavaExtractor",
    "GoExtractor",
    "GenericExtractor",
    "EXTRACTORS",
    "_get_ts_languages",
    # .lookup
    "lookup_function",
    "normalise_path",
    # .diff
    "compare_inventories",
    # .coverage
    "update_coverage",
    "get_coverage_stats",
    "format_coverage_summary",
    # module-level functions defined below
    "save_checklist",
    "update_checklist",
    "get_items",
]



def get_items(file_entry):
    """Read code items from a file entry. Handles both old and new format.

    Old format: file_entry["functions"] (list of function dicts)
    New format: file_entry["items"] (list of CodeItem dicts with "kind" field)
    """
    return file_entry.get("items", file_entry.get("functions", [])) or []


def _resolve_checklist_path(output_dir):
    """Resolve checklist.json path, following symlinks."""
    from pathlib import Path
    checklist_path = Path(output_dir) / "checklist.json"
    if checklist_path.is_symlink():
        checklist_path = checklist_path.resolve()
    checklist_path.parent.mkdir(parents=True, exist_ok=True)
    return checklist_path


class _checklist_lock:
    """Context manager that holds an exclusive flock on checklist.lock.

    Used by both save_checklist (write-only) and update_checklist
    (read-modify-write) so the lock covers the entire critical section.
    """

    __slots__ = ("_lock_path", "_lock_file")

    def __init__(self, checklist_path):
        self._lock_path = checklist_path.with_suffix(".lock")
        self._lock_file = None

    def __enter__(self):
        import fcntl
        import os
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(self._lock_path, flags, 0o600)
        self._lock_file = os.fdopen(fd, "w", encoding="utf-8")
        try:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX)
        except OSError:
            self._lock_file.close()
            self._lock_file = None
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import fcntl
        import logging as _logging
        _local_logger = _logging.getLogger(__name__)
        if self._lock_file is not None:
            try:
                fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            except OSError:
                _local_logger.warning(
                    "checklist_lock: flock LOCK_UN failed for %s",
                    self._lock_path, exc_info=True,
                )
            try:
                self._lock_file.close()
            except OSError:
                _local_logger.warning(
                    "checklist_lock: lock file close failed for %s",
                    self._lock_path, exc_info=True,
                )
        return False


def save_checklist(output_dir, data):
    """Save checklist.json, resolving symlinks and using file locking.

    In project mode, output_dir/checklist.json is a symlink to the
    project-level checklist. This function resolves the symlink before
    writing so the symlink is preserved. Uses fcntl.flock for safe
    concurrent writes.

    In standalone mode, writes directly to output_dir/checklist.json.
    """
    from core.json import save_json

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        save_json(checklist_path, data)


def update_checklist(output_dir, transform_fn):
    """Atomically read-modify-write checklist.json.

    Holds the flock across the entire read-modify-write cycle so
    concurrent callers cannot interleave (preventing last-writer-wins
    data loss). ``transform_fn`` receives the current checklist dict
    (or empty dict if the file does not exist) and must return the
    updated dict to write.

    Use this instead of separate load + save_checklist when modifying
    an existing checklist.
    """
    import json
    from core.json import save_json

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        current = {}
        if checklist_path.is_file():
            try:
                current = json.loads(
                    checklist_path.read_text(encoding="utf-8"),
                )
            except (json.JSONDecodeError, OSError):
                pass
        updated = transform_fn(current)
        save_json(checklist_path, updated)
