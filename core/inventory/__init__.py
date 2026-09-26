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
import logging
import os
import re
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

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
    "ChecklistIntegrityError",
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
    "checklist_exists",
    "compare_inventories",
    "count_sloc",
    "detect_language",
    "ensure_runlocal_checklist",
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
    "read_checklist_meta",
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


def iter_checklist_items(
    checklist: Any,
) -> "Iterator[tuple[str, dict, dict]]":
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

    *checklist* may also be an output DIRECTORY (str / PathLike): the
    walk then streams the on-disk checklist with at most ONE shard's
    file entries in memory at a time when the directory holds the
    sharded ``checklist/`` layout (single-file checklists load whole,
    exactly like ``read_checklist``). The streaming path holds the
    checklist flock for the duration of the walk — do not read or
    write the same checklist through the accessors from inside the
    loop (flock self-deadlock).

    Consumers joining on the checklist shape must walk through this
    function rather than hand-rolling the two-level read — flat
    top-level ``items`` reads silently see nothing on real artifacts.
    """
    if isinstance(checklist, (str, os.PathLike)):
        yield from _iter_checklist_items_from_dir(checklist)
        return
    yield from _iter_items_of(checklist)


def _iter_items_of(checklist: Any) -> "Iterator[tuple[str, dict, dict]]":
    """The in-memory two-level walk shared by both iterator inputs."""
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

# ── Sharded checklist layout ─────────────────────────────────────────
#
# Inventories whose single-file serialisation exceeds the reader
# budget are stored as a ``checklist/`` DIRECTORY next to the
# ``checklist.json`` slot: an ``index.json`` manifest (schema version,
# top-level metadata, totals, per-shard {path, file_count, item_count,
# sloc, sha256, bytes}) plus one ``shard-*.json`` file per shard, each
# holding ``{"files": [...]}``. The in-memory shape is unchanged —
# ``read_checklist`` returns the same merged dict either way, and the
# single-file form stays valid forever. ``index.json`` presence is the
# ONLY discriminator between the two forms.
#
# Integrity contract: every shard's recorded sha256 is verified on
# load; shard paths from the index are constrained dir-local (name
# charset only — no separators, never ``..``); index and shard opens
# go through ``core.source.open_regular`` (O_NOFOLLOW + regular-file
# check on the opened fd), and the accessors' flock covers sharded
# reads and writes exactly like single-file ones.

CHECKLIST_DIR_NAME = "checklist"
CHECKLIST_INDEX_NAME = "index.json"

# Index schema. Version 1: additive changes keep 1; breaking changes
# bump. Readers refuse unknown versions loudly.
CHECKLIST_INDEX_SCHEMA_VERSION = 1

# The index is per-shard rows plus the checklist's top-level metadata
# (which can carry sizeable enrichment blocks); 64 MiB is orders of
# magnitude above any real index while keeping a planted one bounded.
_MAX_CHECKLIST_INDEX_BYTES = 64 * 1024 * 1024

# Per-shard read cap: one shard is what the streaming iterator holds
# in memory, so it inherits the single-file reader budget.
_MAX_CHECKLIST_SHARD_BYTES = _MAX_CHECKLIST_BYTES

# Aggregate cap across a sharded checklist's declared shard bytes.
# Trade-off, both directions: LOWER re-creates the wall sharding
# exists to remove (a measured kernel-scale full-tree inventory was
# ~2.8 GB); HIGHER hands a hostile index a bigger whole-load OOM
# lever for the consumers that still merge the full dict
# (read_checklist — walk-shaped consumers stream instead). 16x the
# single-file budget (4 GiB) covers the largest observed artifact
# with headroom.
_MAX_CHECKLIST_TOTAL_BYTES = 16 * _MAX_CHECKLIST_BYTES

# Shard-count bound for a loadable index. Real sharded inventories at
# the 64 MiB writer target need ~1 shard per 64 MiB — the total-bytes
# cap above implies at most 64 full shards, so 1024 tolerates very
# uneven packing while bounding a hostile index's fan-out.
_MAX_CHECKLIST_SHARDS = 1024

# Dir-local shard names only: fixed prefix/suffix, conservative
# charset (no path separators, so ``..`` cannot form a traversal),
# bounded length. Same validation class as the annotations store.
_CHECKLIST_SHARD_NAME_RE = re.compile(
    r"^shard-[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.json$"
)


class ChecklistIntegrityError(ValueError):
    """A sharded checklist failed its integrity contract — unreadable
    or unvalidatable index, non-dir-local shard path, shard byte-size
    mismatch, or sha256 mismatch. Read-only consumers degrade to
    ``{}`` (loudly); read-modify-write refuses (a transform over a
    partial or forged view must never replace the stored artifact)."""


def _sharded_dir_for(checklist_path: "Path") -> "Path":
    """The sharded layout directory for a resolved checklist.json slot."""
    return checklist_path.parent / CHECKLIST_DIR_NAME


def _sharded_index_path(checklist_path: "Path") -> "Path":
    return _sharded_dir_for(checklist_path) / CHECKLIST_INDEX_NAME


def _read_file_hardened(
    path: "Path", max_bytes: int, what: str,
) -> bytes:
    """Bounded O_NOFOLLOW read of an index/shard file.

    Raises :class:`ChecklistIntegrityError` on refusal (missing,
    non-regular, symlink, over *max_bytes*) — sharded components are
    referenced by the index, so an unreadable one is an integrity
    failure, not an absent optional file.
    """
    from core.source import read_bytes_capped

    read = read_bytes_capped(path, max_bytes)
    if read is None:
        raise ChecklistIntegrityError(
            f"{what} at {path} is missing or refused the hardened "
            f"read (non-regular file or symlink)"
        )
    data, truncated = read
    if truncated:
        raise ChecklistIntegrityError(
            f"{what} at {path} exceeds its {max_bytes}-byte budget"
        )
    return data


def _load_checklist_index(index_path: "Path") -> dict[str, Any]:
    """Load + validate ``checklist/index.json``.

    Raises :class:`ChecklistIntegrityError` on any violation of the
    index contract (see the layout note above).
    """
    from core.json import loads

    raw = _read_file_hardened(
        index_path, _MAX_CHECKLIST_INDEX_BYTES, "checklist index",
    )
    try:
        index = loads(raw)
    except Exception as exc:  # noqa: BLE001 — intake containment boundary
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} failed to parse: {exc}"
        ) from exc
    if not isinstance(index, dict):
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} is not a JSON object"
        )
    version = index.get("schema_version")
    if (not isinstance(version, int) or isinstance(version, bool)
            or version != CHECKLIST_INDEX_SCHEMA_VERSION):
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} has unknown "
            f"schema_version={version!r}; this reader supports "
            f"{CHECKLIST_INDEX_SCHEMA_VERSION} only"
        )
    shards = index.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} carries no shard list"
        )
    if len(shards) > _MAX_CHECKLIST_SHARDS:
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} declares {len(shards)} "
            f"shards (over the {_MAX_CHECKLIST_SHARDS}-shard bound)"
        )
    if not isinstance(index.get("meta"), dict):
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} has no metadata object"
        )
    seen: set[str] = set()
    total_declared = 0
    for row in shards:
        if not isinstance(row, dict):
            raise ChecklistIntegrityError(
                f"checklist index at {index_path}: non-object shard row"
            )
        name = row.get("path")
        if (not isinstance(name, str)
                or not _CHECKLIST_SHARD_NAME_RE.match(name)):
            raise ChecklistIntegrityError(
                f"checklist index at {index_path}: shard path "
                f"{name!r} is not a dir-local shard name"
            )
        if name in seen:
            raise ChecklistIntegrityError(
                f"checklist index at {index_path}: duplicate shard "
                f"path {name!r}"
            )
        seen.add(name)
        size = row.get("bytes")
        if (not isinstance(size, int) or isinstance(size, bool)
                or not (0 < size <= _MAX_CHECKLIST_SHARD_BYTES)):
            raise ChecklistIntegrityError(
                f"checklist index at {index_path}: shard {name} "
                f"declares invalid byte size {size!r}"
            )
        total_declared += size
        digest = row.get("sha256")
        if not (isinstance(digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ChecklistIntegrityError(
                f"checklist index at {index_path}: shard {name} "
                f"carries no valid sha256"
            )
    if total_declared > _MAX_CHECKLIST_TOTAL_BYTES:
        raise ChecklistIntegrityError(
            f"checklist index at {index_path} declares "
            f"{total_declared} total shard bytes (over the "
            f"{_MAX_CHECKLIST_TOTAL_BYTES}-byte aggregate budget)"
        )
    return index


def _read_shard_files(
    shard_dir: "Path", row: dict[str, Any],
) -> list[Any]:
    """Read + verify one shard, returning its ``files`` list.

    The declared byte size and sha256 are verified against the exact
    bytes read; any mismatch raises :class:`ChecklistIntegrityError`.
    """
    import hashlib

    from core.json import loads

    name = row["path"]
    declared = row["bytes"]
    data = _read_file_hardened(
        shard_dir / name, declared, f"checklist shard {name}",
    )
    if len(data) != declared:
        raise ChecklistIntegrityError(
            f"checklist shard {name}: {len(data)} bytes on disk, "
            f"index declares {declared}"
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest != row["sha256"]:
        raise ChecklistIntegrityError(
            f"checklist shard {name}: sha256 mismatch (index "
            f"{row['sha256'][:12]}…, on-disk {digest[:12]}…)"
        )
    try:
        doc = loads(data)
    except Exception as exc:  # noqa: BLE001 — intake containment boundary
        raise ChecklistIntegrityError(
            f"checklist shard {name} failed to parse: {exc}"
        ) from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
        raise ChecklistIntegrityError(
            f"checklist shard {name} is not a "
            '{"files": [...]}-shaped document'
        )
    return doc["files"]


def _load_sharded_checklist(checklist_path: "Path") -> dict[str, Any]:
    """Merge a sharded checklist back into the single in-memory dict.

    Raises :class:`ChecklistIntegrityError` on any contract violation.
    Callers hold the checklist flock.
    """
    shard_dir = _sharded_dir_for(checklist_path)
    index = _load_checklist_index(shard_dir / CHECKLIST_INDEX_NAME)
    merged: dict[str, Any] = dict(index["meta"])
    files: list[Any] = []
    for row in index["shards"]:
        files.extend(_read_shard_files(shard_dir, row))
    merged["files"] = files
    return merged


# ── Sharded writer ───────────────────────────────────────────────────

def _entry_path_of(entry: Any) -> str:
    if isinstance(entry, dict):
        value = entry.get("path", entry.get("file", ""))
        return value if isinstance(value, str) else ""
    return ""


def _compact_bytes(obj: Any) -> int:
    from core.json import dumps_artifact
    return len(dumps_artifact(obj, indent=None).encode("utf-8"))


def _plan_checklist_shards(
    files: list[Any], budget: int,
) -> list[tuple[str, list[int]]]:
    """Greedy bin-packing of file entries into per-shard index lists.

    Shard key is MEASURED size, not fixed directory depth: units start
    at directory subtrees and split one path level deeper whenever a
    subtree exceeds the budget — as deep as the data demands. A
    degenerate single directory whose DIRECT entries still exceed the
    budget is hash-suffix split. Units are then first-fit-decreasing
    packed so many small subtrees share a shard. Returns
    ``[(label, entry_indices), ...]`` — labels stay path-derived for
    inspectability; the index manifest is the authority.

    Raises :class:`ChecklistBudgetExceededError` for a single entry
    whose own serialisation exceeds the per-shard reader budget: no
    split can make it loadable, so failing fast at the write site
    (where excluding or scoping the offending file is cheap advice)
    beats emitting a shard every reader refuses.
    """
    import hashlib

    sizes = [_compact_bytes(e) + 1 for e in files]  # +1 comma/framing
    for i, size in enumerate(sizes):
        if size > _MAX_CHECKLIST_SHARD_BYTES - 64:
            raise ChecklistBudgetExceededError(
                f"checklist entry for {_entry_path_of(files[i])!r} "
                f"serialises to {size} bytes — over the "
                f"{_MAX_CHECKLIST_SHARD_BYTES}-byte per-shard reader "
                f"budget, so no sharding can store it. Exclude the "
                f"file from the inventory (builder exclude patterns) "
                f"or scope the build past it."
            )

    def _component(path: str, depth: int) -> str:
        parts = [p for p in path.split("/") if p]
        # Entries AT this depth (or path-less rows) fall into the
        # leaf bucket "" — they cannot descend further.
        return parts[depth] if depth < len(parts) - 1 else ""

    def _split(idxs: list[int], depth: int,
               prefix: str) -> list[tuple[str, list[int], int]]:
        total = sum(sizes[i] for i in idxs)
        if total <= budget:
            return [(prefix or "root", idxs, total)]
        groups: dict[str, list[int]] = {}
        for i in idxs:
            groups.setdefault(
                _component(_entry_path_of(files[i]), depth), []
            ).append(i)
        units: list[tuple[str, list[int], int]] = []
        for key in sorted(groups):
            members = groups[key]
            label = f"{prefix}/{key}" if prefix and key else (key or prefix)
            subtotal = sum(sizes[i] for i in members)
            if subtotal <= budget:
                units.append((label or "root", members, subtotal))
            elif key:
                units.extend(_split(members, depth + 1, label))
            else:
                # Degenerate single directory: its direct entries
                # alone exceed the budget — hash-suffix split.
                units.extend(_hash_split(members, label or "root"))
        return units

    def _hash_split(idxs: list[int],
                    label: str) -> list[tuple[str, list[int], int]]:
        ordered = sorted(idxs, key=lambda i: (
            hashlib.sha256(
                _entry_path_of(files[i]).encode(
                    "utf-8", "surrogateescape")).hexdigest(), i))
        out: list[tuple[str, list[int], int]] = []
        bucket: list[int] = []
        bucket_size = 0
        for i in ordered:
            if bucket and bucket_size + sizes[i] > budget:
                out.append((f"{label}-h{len(out):02d}", bucket, bucket_size))
                bucket, bucket_size = [], 0
            bucket.append(i)
            bucket_size += sizes[i]
        if bucket:
            out.append((f"{label}-h{len(out):02d}", bucket, bucket_size))
        return out

    units = _split(list(range(len(files))), 0, "")
    # First-fit-decreasing pack: many small subtrees share a shard.
    bins: list[list[tuple[str, list[int], int]]] = []
    bin_sizes: list[int] = []
    for unit in sorted(units, key=lambda u: (-u[2], u[0])):
        for b, used in enumerate(bin_sizes):
            if used + unit[2] <= budget:
                bins[b].append(unit)
                bin_sizes[b] += unit[2]
                break
        else:
            bins.append([unit])
            bin_sizes.append(unit[2])
    plan: list[tuple[str, list[int]]] = []
    for contents in bins:
        # Largest unit names the bin; entries keep build order.
        label = contents[0][0]
        idxs = sorted(i for _, members, _ in contents for i in members)
        plan.append((label, idxs))
    plan.sort(key=lambda p: (p[1][0] if p[1] else 0))
    return plan


def _shard_file_name(label: str, seq: int) -> str:
    """Path-derived, dir-local shard file name (index is authority)."""
    sanitized = re.sub(r"[^A-Za-z0-9_-]+", "_", label).strip("_")[:48]
    if not sanitized or not sanitized[0].isalnum():
        sanitized = f"x{sanitized}" if sanitized else "root"
    return f"shard-{sanitized}-{seq:03d}.json"


def _sweep_retired_dirs(parent: "Path") -> None:
    """Best-effort removal of orphaned swap directories.

    Safe under the held flock: every sharded write runs locked, so a
    ``.checklist-tmp-*`` / ``.checklist-stale-*`` sibling visible now
    is a crashed writer's leftover, never a live one's workspace.
    """
    import shutil
    import time
    # Age gate: a crash BETWEEN the two swap renames leaves the
    # previous form's ONLY copy under a retired name — sweeping it on
    # the very next write would destroy the recovery evidence while
    # an operator could still rescue it. One hour bounds accumulation
    # without touching a same-incident copy; the dirs are small
    # relative to the artifact they back up and every writer sweeps.
    cutoff = time.time() - 3600
    try:
        leftovers = [
            p for p in parent.iterdir()
            if p.name.startswith((".checklist-tmp-", ".checklist-stale-"))
            and p.is_dir() and not p.is_symlink()
        ]
    except OSError:
        return
    for p in leftovers[:16]:
        try:
            # ctime, not mtime: the rename that retired the dir
            # updates its ctime, so the clock starts at the swap even
            # when the CONTENTS were written long before.
            if p.stat().st_ctime > cutoff:
                continue
        except OSError:
            continue
        shutil.rmtree(p, ignore_errors=True)


def _retired_name(parent: "Path", kind: str) -> "Path":
    import time
    return parent / (
        f".checklist-{kind}-{os.getpid()}-{time.monotonic_ns():x}")


def _write_sharded_checklist(
    checklist_path: "Path", data: dict[str, Any],
) -> None:
    """Emit the sharded ``checklist/`` layout, atomically.

    Shards and index are staged in a temp directory beside the slot,
    then swapped in with directory renames (existing dir renamed
    aside first, staged dir renamed in, single-file form removed —
    ``index.json`` presence flips the discriminator to the NEW data
    the instant the staged dir lands). Callers hold the flock.
    """
    import hashlib
    import shutil
    import tempfile
    from datetime import datetime, timezone
    from pathlib import Path

    from core.artifacts.provenance import stamp_provenance
    from core.atomic_fs import write_text_atomically
    from core.json import dumps_artifact

    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, list):
        raise ChecklistBudgetExceededError(
            f"refusing to write {checklist_path}: the serialised "
            f"checklist exceeds the {_MAX_CHECKLIST_BYTES}-byte "
            f"single-file budget and carries no 'files' list to shard."
        )
    meta = {k: v for k, v in data.items() if k != "files"}
    plan = _plan_checklist_shards(files, _CHECKLIST_SHARD_TARGET_BYTES)

    parent = checklist_path.parent
    tmp_dir = Path(tempfile.mkdtemp(prefix=".checklist-tmp-", dir=parent))
    try:
        rows: list[dict[str, Any]] = []
        for seq, (label, idxs) in enumerate(plan):
            shard_files = [files[i] for i in idxs]
            content = (
                dumps_artifact({"files": shard_files}, indent=None) + "\n"
            ).encode("utf-8")
            name = _shard_file_name(label, seq)
            write_text_atomically(
                tmp_dir / name, content.decode("utf-8"),
                tmp_prefix=".~shard-",
            )
            rows.append({
                "path": name,
                "file_count": len(shard_files),
                "item_count": sum(
                    len(get_items(e)) for e in shard_files
                    if isinstance(e, dict)),
                "sloc": sum(
                    e.get("sloc", 0) for e in shard_files
                    if isinstance(e, dict)
                    and isinstance(e.get("sloc"), int)),
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })
        index_doc: dict[str, Any] = {
            "schema_version": CHECKLIST_INDEX_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "meta": meta,
            "totals": {
                "files": sum(r["file_count"] for r in rows),
                "items": sum(r["item_count"] for r in rows),
                "sloc": sum(r["sloc"] for r in rows),
                "bytes": sum(r["bytes"] for r in rows),
            },
            "shards": rows,
        }
        stamp_provenance(index_doc, "core-inventory", untrusted=False,
                         overwrite_generator=False)
        index_content = dumps_artifact(index_doc) + "\n"
        if len(index_content.encode("utf-8")) > _MAX_CHECKLIST_INDEX_BYTES:
            raise ChecklistBudgetExceededError(
                f"refusing to write {checklist_path}: the checklist's "
                f"top-level metadata alone serialises past the "
                f"{_MAX_CHECKLIST_INDEX_BYTES}-byte index budget — "
                f"shed or shrink the metadata payloads."
            )
        write_text_atomically(
            tmp_dir / CHECKLIST_INDEX_NAME, index_content,
            tmp_prefix=".~shard-",
        )

        final_dir = _sharded_dir_for(checklist_path)
        stale: "Path | None" = None
        if final_dir.exists() or final_dir.is_symlink():
            stale = _retired_name(parent, "stale")
            # Crash window note: between this rename and the next, no
            # sharded dir is visible at the slot. The previous form
            # survives under the stale name (and the checklist is
            # rebuildable from the target); the window is two renames
            # wide and every writer/reader serialises on the flock.
            os.rename(final_dir, stale)
        os.rename(tmp_dir, final_dir)
        # Retire the single-file form AFTER the dir swap: from the
        # moment index.json is visible it wins the discriminator, so
        # a crash here leaves a coherent (sharded) artifact plus a
        # dead file, never two live ones.
        checklist_path.unlink(missing_ok=True)
        if stale is not None:
            shutil.rmtree(stale, ignore_errors=True)
    finally:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
    _sweep_retired_dirs(parent)


def _write_checklist_locked(
    checklist_path: "Path", data: Any,
) -> None:
    """Single write chokepoint under the held flock: measure, then
    store single-file (within the reader budget) or sharded (above
    it). Both forms land atomically; whichever form is superseded is
    retired so ``index.json`` presence stays an unambiguous
    discriminator.
    """
    import shutil

    from core.atomic_fs import write_text_atomically
    from core.json import dumps_artifact

    content = dumps_artifact(data) + "\n"
    size = len(content.encode("utf-8"))
    # Switch-over point is the reader budget itself: lower would
    # shard artifacts every reader loads fine (more moving parts for
    # nothing), higher would write single files the readers refuse at
    # their fstat gate.
    if size > _MAX_CHECKLIST_BYTES:
        _write_sharded_checklist(checklist_path, data)
        return
    # Within budget: the measured serialisation IS save_json's exact
    # output (same encoder arms + newline), so write it directly —
    # no second serialisation pass.
    write_text_atomically(checklist_path, content,
                          tmp_prefix=".~savejson-")
    shard_dir = _sharded_dir_for(checklist_path)
    if shard_dir.exists() or shard_dir.is_symlink():
        # Switch-back: retire the sharded form so its index cannot
        # shadow the fresh single file. Rename first (atomic
        # disappearance of index.json), then remove.
        stale = _retired_name(checklist_path.parent, "stale")
        try:
            os.rename(shard_dir, stale)
        except OSError:
            shutil.rmtree(shard_dir, ignore_errors=True)
        else:
            shutil.rmtree(stale, ignore_errors=True)
    _sweep_retired_dirs(checklist_path.parent)


class ChecklistBudgetExceededError(RuntimeError):
    """The checklist cannot be stored within the reader budgets.

    An over-budget single-file serialisation normally switches the
    writer to the sharded ``checklist/`` layout instead of raising.
    This remains the fail-fast for the cases sharding cannot help: a
    SINGLE file entry whose own serialisation exceeds the per-shard
    reader budget (no split can make it loadable), or an over-budget
    document with no ``files`` list to shard.
    """


# Per-shard packing target for the sharded writer. Trade-off, both
# directions: LOWER means more shards (index overhead, more
# open/verify syscalls per read); HIGHER pushes the one-shard-in-
# memory cost of every streaming consumer back toward the whole-file
# problem sharding exists to remove. 64 MiB matches the tightest
# checklist reader lane in the tree and keeps a kernel-scale
# inventory (~2.8 GB measured) under ~50 shards.
_CHECKLIST_SHARD_TARGET_BYTES = 64 * 1024 * 1024


def _resolve_checklist_path(output_dir: "str | Path") -> "Path":
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

    ``create=False`` is the READ-side mode: a pure read must not
    O_CREAT the lock file — creating an entry in the run dir bumps the
    directory mtime, and mtime consumers (the understand bridge's
    newest-candidate ranking) then read every READ as recency. With no
    lock file present the reader proceeds lockless: no writer has ever
    locked that dir, which is exactly the pre-accessor exposure (a
    FIRST concurrent writer racing the lockless read), in the safe
    direction — the writers' create-mode lock is untouched.
    """

    __slots__ = ("_lock_file", "_lock_path", "_create")

    def __init__(self, checklist_path: "Path", *,
                 create: bool = True) -> None:
        self._lock_path = checklist_path.with_suffix(".lock")
        self._lock_file = None
        self._create = create

    def __enter__(self):
        import fcntl
        import os
        flags = os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if self._create:
            flags |= os.O_CREAT | os.O_TRUNC
        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except FileNotFoundError:
            if self._create:
                raise
            # Reader mode, no lock file: lockless read (see class
            # docstring).
            return self
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


def ensure_runlocal_checklist(output_dir: "str | Path") -> bool:
    """Detach a project-linked checklist slot so writes land run-local.

    Scope-collision rule: a SCOPED (partial) inventory build must
    never overwrite the project-level checklist slot. In project mode
    the run dir's ``checklist.json`` is a symlink to the project-level
    file, so a scoped rebuild through the write accessors would
    replace the shared full-tree inventory with a partial one — every
    sibling run's coverage, gap selection, and reporting would then
    silently run against the reduced file set. Unlinking the symlink
    (under the project slot's flock) makes this run's checklist
    run-local; the project-level slot only ever holds the full-tree
    form.

    Returns True when a project link was detached. Loud when the
    project slot already holds an inventory the scoped build now
    diverges from.
    """
    from pathlib import Path

    base = Path(output_dir) / "checklist.json"
    if not base.is_symlink():
        return False
    resolved = base.resolve()
    project_has_inventory = (
        resolved.is_file() or _sharded_index_path(resolved).is_file()
    )
    with _checklist_lock(resolved):
        try:
            base.unlink()
        except OSError as exc:
            logger.warning(
                "scoped inventory build: failed to detach %s from the "
                "project-level checklist slot (%s) — REFUSE writing a "
                "scoped inventory through the link", base, exc,
            )
            raise
    if project_has_inventory:
        logger.warning(
            "scoped inventory build: %s detached from the project-level "
            "checklist slot %s — the scoped inventory DIVERGES from the "
            "existing project-level inventory and is kept run-local; "
            "the project slot keeps the full-tree form",
            base, resolved,
        )
    else:
        logger.info(
            "scoped inventory build: %s detached from the (empty) "
            "project-level checklist slot %s — scoped inventories are "
            "run-local", base, resolved,
        )
    return True


def save_checklist(output_dir: "str | Path", data: Any) -> None:
    """Save the checklist, resolving symlinks and using file locking.

    In project mode, output_dir/checklist.json is a symlink to the
    project-level checklist. This function resolves the symlink before
    writing so the symlink is preserved. Uses fcntl.flock for safe
    concurrent writes.

    In standalone mode, writes directly to output_dir/checklist.json.

    Inventories whose single-file serialisation exceeds the reader
    budget are stored in the sharded ``checklist/`` layout instead
    (see the layout note above) — same in-memory shape on read.
    """
    from core.artifacts.provenance import stamp_provenance

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
        _write_checklist_locked(checklist_path, data)


def _checklist_slot_present(output_dir: "str | Path") -> bool:
    """True when the output dir's checklist slot holds ANYTHING —
    single-file, run-local sharded dir, or a (possibly dangling, in
    project mode once the project slot went sharded) symlink."""
    from pathlib import Path

    base = Path(output_dir) / "checklist.json"
    if base.exists() or base.is_symlink():
        return True
    return (
        Path(output_dir) / CHECKLIST_DIR_NAME / CHECKLIST_INDEX_NAME
    ).is_file()


def checklist_exists(output_dir: "str | Path") -> bool:
    """True when *output_dir* holds a readable checklist in EITHER
    on-disk form.

    Existence-probe counterpart of :func:`read_checklist` — a bare
    ``(dir / "checklist.json").exists()`` misses the sharded
    ``checklist/`` layout, and it misses the project-mode case where
    the run's symlink dangles because the project slot is sharded.
    """
    from pathlib import Path

    base = Path(output_dir) / "checklist.json"
    if base.is_file():
        return True
    if (Path(output_dir) / CHECKLIST_DIR_NAME
            / CHECKLIST_INDEX_NAME).is_file():
        return True
    if base.is_symlink():
        # Dangling symlink: the target single-file is gone, but the
        # sharded dir beside the TARGET may hold the inventory.
        resolved = base.resolve()
        return _sharded_index_path(resolved).is_file()
    return False


def read_checklist(output_dir: "str | Path") -> dict[str, Any]:
    """Read the checklist under the writers' flock + symlink resolution.

    Read-side counterpart of :func:`save_checklist` /
    :func:`update_checklist`. A raw ``json.load`` on
    ``output_dir/checklist.json`` bypasses three properties the
    accessors guarantee:

    - **project-symlink resolution** — in project mode the run-dir
      checklist is a symlink to the project-level file; reading the
      resolved path keeps read and write sides pointed at the same
      inode;
    - **flock over the read** — a concurrent :func:`update_checklist`
      holds the lock across its whole read-modify-write, so taking the
      same lock here prevents torn/mid-write reads;
    - **sharded-layout support** — an inventory too large for the
      single-file reader budget is stored as a ``checklist/`` dir
      (see the layout note above); this reader merges it back into
      the same in-memory dict, verifying each shard's sha256.

    Returns ``{}`` when the checklist is missing, malformed, not a
    JSON object (a non-dict checklist is corrupt for every consumer
    that calls ``.get`` on it), or a sharded layout that fails its
    integrity contract (loud warning).
    """
    from core.json import load_json

    # Missing slot → {} without side effects (_resolve_checklist_path
    # would mkdir the output dir, which a pure read must not do).
    if not _checklist_slot_present(output_dir):
        return {}
    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path, create=False):
        if _sharded_index_path(checklist_path).is_file():
            try:
                return _load_sharded_checklist(checklist_path)
            except ChecklistIntegrityError as exc:
                logger.warning(
                    "read_checklist: sharded checklist at %s refused "
                    "(%s) — reading as empty",
                    _sharded_dir_for(checklist_path), exc,
                )
                return {}
        data = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
    return data if isinstance(data, dict) else {}


def read_checklist_meta(output_dir: "str | Path") -> dict[str, Any]:
    """The checklist's top-level metadata (every key except ``files``).

    For a sharded checklist this reads ONLY the index manifest — the
    cheap path for consumers that need ``target_path`` /
    ``target_kind`` / summary fields without loading a multi-GB file
    inventory. Single-file checklists load whole (their metadata is
    not separable on disk) and strip ``files``. Returns ``{}`` on
    missing/refused, like :func:`read_checklist`.
    """
    if not _checklist_slot_present(output_dir):
        return {}
    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path, create=False):
        if _sharded_index_path(checklist_path).is_file():
            try:
                index = _load_checklist_index(
                    _sharded_index_path(checklist_path))
            except ChecklistIntegrityError as exc:
                logger.warning(
                    "read_checklist_meta: sharded checklist at %s "
                    "refused (%s) — reading as empty",
                    _sharded_dir_for(checklist_path), exc,
                )
                return {}
            # Strip a crafted ``files`` key: the contract is
            # "every key except files", and a forged index must not
            # make the CHEAP reader hand out an unverified file
            # inventory no other reader would produce.
            return {k: v for k, v in index["meta"].items()
                    if k != "files"}
        from core.json import load_json
        data = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k != "files"}


def _iter_checklist_items_from_dir(
    output_dir: "str | Path",
) -> "Iterator[tuple[str, dict, dict]]":
    """Stream checklist items from an output dir, one shard in memory.

    Sharded layouts yield shard by shard (peak memory = one shard's
    file entries); single-file checklists load whole, exactly like
    :func:`read_checklist`. Holds the checklist flock for the whole
    walk (see :func:`iter_checklist_items`). Integrity failures warn
    and end the walk with whatever was already yielded — the same
    degrade direction as ``read_checklist``'s ``{}``.
    """
    from core.json import load_json

    if not _checklist_slot_present(output_dir):
        return
    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path, create=False):
        if _sharded_index_path(checklist_path).is_file():
            shard_dir = _sharded_dir_for(checklist_path)
            try:
                index = _load_checklist_index(
                    shard_dir / CHECKLIST_INDEX_NAME)
                for row in index["shards"]:
                    files = _read_shard_files(shard_dir, row)
                    yield from _iter_items_of({"files": files})
            except ChecklistIntegrityError as exc:
                logger.warning(
                    "iter_checklist_items: sharded checklist at %s "
                    "refused (%s) — walk truncated",
                    shard_dir, exc,
                )
            return
        data = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
    yield from _iter_items_of(data)


def update_checklist(
    output_dir: "str | Path",
    transform_fn: "Callable[[dict[str, Any]], dict[str, Any]]",
) -> None:
    """Atomically read-modify-write checklist.json.

    Holds the flock across the entire read-modify-write cycle so
    concurrent callers cannot interleave (preventing last-writer-wins
    data loss). ``transform_fn`` receives the current checklist dict
    (or empty dict if the file does not exist) and must return the
    updated dict to write.

    Use this instead of separate load + save_checklist when modifying
    an existing checklist.

    Raises ``ValueError`` when an EXISTING checklist fails to load
    (malformed, oversize, unreadable, or a sharded layout that fails
    its integrity contract): proceeding with ``{}`` would hand the
    transform an empty dict and then OVERWRITE the real artifact with
    a fresh provenance-stamped near-empty checklist — corruption must
    surface, never destroy the data needed to diagnose it. A genuinely
    missing checklist still starts from ``{}``.
    """
    from core.json import load_json

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        current = None
        if _sharded_index_path(checklist_path).is_file():
            try:
                current = _load_sharded_checklist(checklist_path)
            except ChecklistIntegrityError as exc:
                msg = (
                    f"refusing checklist read-modify-write: sharded "
                    f"checklist at {_sharded_dir_for(checklist_path)} "
                    f"failed its integrity contract ({exc}) — writing "
                    f"would replace it with a near-empty checklist"
                )
                raise ValueError(msg) from exc
        elif checklist_path.is_file():
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
        _write_checklist_locked(checklist_path, updated)
