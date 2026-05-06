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


def save_checklist(output_dir, data):
    """Save checklist.json, resolving symlinks and using file locking.

    In project mode, output_dir/checklist.json is a symlink to the
    project-level checklist. This function resolves the symlink before
    writing so the symlink is preserved. Uses fcntl.flock for safe
    concurrent writes.

    In standalone mode, writes directly to output_dir/checklist.json.
    """
    import fcntl
    from pathlib import Path
    from core.json import save_json

    checklist_path = Path(output_dir) / "checklist.json"

    # Resolve symlink to write to the real file
    if checklist_path.is_symlink():
        checklist_path = checklist_path.resolve()

    # Ensure parent exists
    checklist_path.parent.mkdir(parents=True, exist_ok=True)

    # File lock for concurrent write safety.
    #
    # `lock_file` initialised to None BEFORE the try so the finally
    # block doesn't raise NameError when open(lock_path, "w") itself
    # raises (permission denied, parent read-only after the mkdir
    # call but before this open, disk full). Pre-fix the NameError
    # masked the real OSError, so operators saw "name 'lock_file' is
    # not defined" instead of "permission denied" — much harder to
    # diagnose.
    #
    # Lock-then-unlink race: pre-fix the finally also called
    # `lock_path.unlink(missing_ok=True)` AFTER LOCK_UN. Race
    # sequence:
    #   1. Process A holds lock, writes, LOCK_UN.
    #   2. Process B (waiting on flock on the same inode) wakes up,
    #      now holds the lock on the still-existing-but-about-to-be-
    #      unlinked file.
    #   3. A unlinks lock_path. The inode survives because B still
    #      has it open, but the directory entry is gone.
    #   4. Process C arrives, opens lock_path — creates a NEW file
    #      at the same path, gets the lock immediately on the new
    #      inode.
    #   5. B and C both think they hold the (different) lock,
    #      write to checklist.json concurrently → corruption.
    #
    # Standard Unix pattern: NEVER unlink the lock file. Stale lock
    # files at rest are harmless (flock state is in-kernel, not
    # disk), and the cost is one tiny .lock dotfile per checklist —
    # acceptable trade for closing the corruption window.
    lock_path = checklist_path.with_suffix(".lock")
    lock_file = None
    try:
        lock_file = open(lock_path, "w")
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        save_json(checklist_path, data)
    finally:
        if lock_file is not None:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_file.close()
            except Exception:
                pass
