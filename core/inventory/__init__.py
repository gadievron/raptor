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
    KIND_CONSTANT_MACRO,
    KIND_DECLARATION,
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
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from pathlib import Path

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
    "KIND_CONSTANT_MACRO",
    "KIND_DECLARATION",
    "KIND_FUNCTION",
    "KIND_GLOBAL",
    "KIND_MACRO",
    "LANGUAGE_MAP",
    "CExtractor",
    "ChecklistBudgetExceededError",
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
    "iter_checklist_items",
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


def iter_checklist_items(checklist):
    """Single authority for walking ``checklist["files"][*]`` items.

    Yields ``(file_path, file_entry, item)`` for every code item in a
    checklist/inventory dict — the shape ``build_inventory`` emits and
    ``read_checklist`` returns (``{"files": [{"path": ..., "items":
    [...]}]}``). File records carry ``path`` with a ``file`` fallback
    for older artifacts; item lists live under ``items`` with a
    ``functions`` fallback (via :func:`get_items`). Non-dict file
    records and items are skipped: every consumer immediately calls
    ``.get`` on both, so yielding junk rows only converts a walk into
    a crash.

    Consumers joining on the checklist shape must walk through this
    function rather than hand-rolling the two-level read — flat
    top-level ``items`` reads silently see nothing on real artifacts.
    """
    if not isinstance(checklist, dict):
        return
    for file_entry in checklist.get("files", []) or []:
        if not isinstance(file_entry, dict):
            continue
        file_path = file_entry.get("path", file_entry.get("file", ""))
        for item in get_items(file_entry):
            if not isinstance(item, dict):
                continue
            yield file_path, file_entry, item


# checklist.json is read-modify-written many times per run and
# tracks target size (measured 11.6-35.9 MB on big targets) — the
# checklist budget class.
_MAX_CHECKLIST_BYTES = 256 * 1024 * 1024


class ChecklistBudgetExceededError(RuntimeError):
    """The serialised checklist would exceed the core-inventory read budget.

    The ``checklist.json`` readers in this module gate their loads on
    :data:`_MAX_CHECKLIST_BYTES` — an artifact written past that budget
    is refused right back at this module's own accessors (and other
    reader lanes gate at their own, sometimes tighter, byte budgets),
    so the writer raises this instead of completing the write.
    """


def _enforce_checklist_budget(data: Any, checklist_path: "Path") -> None:
    """Refuse to serialise a checklist the core-inventory readers refuse.

    Raises :class:`ChecklistBudgetExceededError` when the serialised
    artifact would exceed :data:`_MAX_CHECKLIST_BYTES`. Measurement
    reuses ``dumps_artifact`` — the same serialisation ``save_json``
    performs — so the number compared against the budget is the number
    the readers' ``fstat`` gate will see (+1 for save_json's trailing
    newline). The double serialisation on the passing path is bounded
    by the budget itself and is cheap next to the inventory build.
    """
    from core.json import dumps_artifact

    size = len(dumps_artifact(data).encode("utf-8")) + 1
    # Failing fast here cuts both ways: raising refuses to write an
    # inventory whose serialisation is over budget even though the
    # write itself would succeed (a LOWER budget would start refusing
    # working mid-size inventories); NOT raising writes an artifact
    # the core-inventory readers refuse at their fstat load gate
    # (other reader lanes gate at their own budgets), deferring the
    # same failure to a less actionable place — the write site is
    # where "build a scoped inventory instead" is still cheap advice.
    if size <= _MAX_CHECKLIST_BYTES:
        return
    raise ChecklistBudgetExceededError(
        f"refusing to write {checklist_path}: serialised checklist is "
        f"{size} bytes, over the {_MAX_CHECKLIST_BYTES}-byte budget "
        f"the core-inventory readers enforce at load (other reader "
        f"lanes gate at their own byte budgets) — the artifact would "
        f"be unusable downstream. Build a scoped inventory instead "
        f"(the checklist builder's repeatable --scope flag restricts "
        f"it to named subdirectories), or run scoped analyses over "
        f"subtrees of the target."
    )


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

    def __init__(self, checklist_path: "Path") -> None:
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

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> Literal[False]:
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


def save_checklist(output_dir, data) -> None:
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
    # Budget gate BEFORE the lock/write: an over-budget artifact must
    # never replace a previously usable checklist on disk.
    _enforce_checklist_budget(data, checklist_path)
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
    from pathlib import Path

    from core.json import load_json

    # Missing file → {} without side effects (_resolve_checklist_path
    # would mkdir the output dir, which a pure read must not do).
    if not (Path(output_dir) / "checklist.json").exists():
        return {}
    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        data = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
    return data if isinstance(data, dict) else {}


def update_checklist(output_dir, transform_fn) -> None:
    """Atomically read-modify-write checklist.json.

    Holds the flock across the entire read-modify-write cycle so
    concurrent callers cannot interleave (preventing last-writer-wins
    data loss). ``transform_fn`` receives the current checklist dict
    (or empty dict if the file does not exist) and must return the
    updated dict to write.

    Use this instead of separate load + save_checklist when modifying
    an existing checklist.

    Raises ``ValueError`` when an EXISTING checklist fails to load
    (malformed, oversize, unreadable): proceeding with ``{}`` would
    hand the transform an empty dict and then OVERWRITE the real file
    with a fresh provenance-stamped near-empty checklist — corruption
    must surface, never destroy the data needed to diagnose it. A
    genuinely missing file still starts from ``{}``.
    """
    from core.json import load_json, save_json

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        current = None
        if checklist_path.is_file():
            current = load_json(
                checklist_path, max_bytes=_MAX_CHECKLIST_BYTES,
            )
            if not isinstance(current, dict):
                msg = (
                    f"refusing checklist read-modify-write: existing "
                    f"{checklist_path} failed to load as a JSON object "
                    f"(malformed, oversize, or unreadable) — writing "
                    f"would replace it with a near-empty checklist"
                )
                raise ValueError(msg)
        if current is None:
            current = {}
        updated = transform_fn(current)
        if isinstance(updated, dict):
            # Same provenance policy as save_checklist above.
            from core.artifacts.provenance import stamp_provenance
            stamp_provenance(updated, "core-inventory", untrusted=False,
                             overwrite_generator=False)
        # Same budget gate as save_checklist: refusing keeps the
        # on-disk checklist readable instead of atomically replacing
        # it with one the readers reject at their load gates.
        _enforce_checklist_budget(updated, checklist_path)
        save_json(checklist_path, updated)
