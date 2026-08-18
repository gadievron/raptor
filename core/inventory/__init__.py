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
from .coverage import format_coverage_summary, get_coverage_stats, update_coverage
from .diff import compare_inventories
from .exclusions import (
    DEFAULT_EXCLUDES,
    GENERATED_MARKERS,
    is_binary_file,
    is_generated_file,
    match_exclusion_reason,
    should_exclude,
)
from .extractors import (
    _REGEX_EXTRACTORS as EXTRACTORS,  # Backward compat
)
from .extractors import (
    KIND_CLASS,
    KIND_FUNCTION,
    KIND_GLOBAL,
    KIND_MACRO,
    CExtractor,
    CodeItem,
    FunctionInfo,
    FunctionMetadata,
    GenericExtractor,
    GoExtractor,
    JavaExtractor,
    JavaScriptExtractor,
    PythonExtractor,
    _get_ts_languages,
    count_sloc,
    extract_functions,
    extract_items,
)
from .languages import LANGUAGE_MAP, detect_language
from .lookup import lookup_function, normalise_path

# Public re-export surface. Each name below is imported above purely
# to make `from core.inventory import X` work for downstream callers
# (packages/exploitability_validation, the validation tests, the
# CodeQL prefilter). Without `__all__`, ruff F401 flags them all as
# "unused import"; with it, ruff recognises the re-export intent and
# `from core.inventory import *` exposes exactly this list.
# Sorted (RUF022); the import statements above show which submodule
# each name comes from. `save_checklist` / `read_checklist` /
# `update_checklist` / `get_items` are module-level functions defined
# below — included here because they're part of the public surface too.
__all__ = [
    "DEFAULT_EXCLUDES",
    "EXTRACTORS",
    "GENERATED_MARKERS",
    "KIND_CLASS",
    "KIND_FUNCTION",
    "KIND_GLOBAL",
    "KIND_MACRO",
    "LANGUAGE_MAP",
    "CExtractor",
    "CodeItem",
    "FunctionInfo",
    "FunctionMetadata",
    "GenericExtractor",
    "GoExtractor",
    "JavaExtractor",
    "JavaScriptExtractor",
    "PythonExtractor",
    "_get_ts_languages",
    "build_inventory",
    "compare_inventories",
    "count_sloc",
    "detect_language",
    "extract_functions",
    "extract_items",
    "format_coverage_summary",
    "get_coverage_stats",
    "get_items",
    "is_binary_file",
    "is_generated_file",
    "lookup_function",
    "match_exclusion_reason",
    "normalise_path",
    "read_checklist",
    "save_checklist",
    "should_exclude",
    "update_checklist",
    "update_coverage",
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

    __slots__ = ("_lock_file", "_lock_path")

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
    from core.artifacts.provenance import stamp_provenance
    from core.json import save_json

    # Provenance chokepoint for checklist.json. The mechanical
    # inventory writer path contains no LLM-derived content, so the
    # default stamp is untrusted:false; callers persisting LLM-enriched
    # checklists (e.g. understand_bridge.enrich_checklist) pre-stamp
    # untrusted:true, which stamp_provenance never downgrades.
    if isinstance(data, dict):
        stamp_provenance(data, "core-inventory", untrusted=False,
                         overwrite_generator=False)

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        save_json(checklist_path, data)


def read_checklist(output_dir):
    """Read checklist.json under the writers' flock + symlink resolution.

    Read-side counterpart of :func:`save_checklist` /
    :func:`update_checklist`. A raw ``json.load`` on
    ``output_dir/checklist.json`` bypasses two properties the write
    accessors guarantee:

    - **project-symlink resolution** — in project mode the run-dir
      checklist is a symlink to the project-level file; reading the
      resolved path keeps read and write sides pointed at the same
      inode;
    - **flock over the read** — a concurrent :func:`update_checklist`
      holds the lock across its whole read-modify-write, so taking the
      same lock here prevents torn/mid-write reads.

    Returns ``{}`` when the file is missing, malformed, or not a JSON
    object (a non-dict checklist is corrupt for every consumer that
    calls ``.get`` on it).
    """
    import json
    import logging as _logging
    from pathlib import Path

    # Missing file → {} without side effects (_resolve_checklist_path
    # would mkdir the output dir, which a pure read must not do).
    if not (Path(output_dir) / "checklist.json").exists():
        return {}
    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        try:
            data = json.loads(checklist_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            _logging.getLogger(__name__).error(
                "malformed JSON in %s", checklist_path,
            )
            return {}
    return data if isinstance(data, dict) else {}


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
        if isinstance(updated, dict):
            # Same provenance policy as save_checklist above.
            from core.artifacts.provenance import stamp_provenance
            stamp_provenance(updated, "core-inventory", untrusted=False,
                             overwrite_generator=False)
        save_json(checklist_path, updated)
