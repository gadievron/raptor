"""Function lookup from inventory checklist.

Given a file path and line number, finds the enclosing function from a
pre-built inventory checklist. Used by the agentic pipeline to attach
function metadata to scanner findings.
"""

import os
import threading
from collections import OrderedDict
from typing import Any

from core.paths import strip_file_uri, to_repo_relative


def normalise_path(path: str, repo_root: str) -> str:
    """Normalise a file path relative to the repo root.

    Handles absolute paths, relative paths, file:// URIs, and ./ prefixes.
    Best-effort semantics: never returns ``None`` — an out-of-root
    absolute path comes back as a ``../..``-style relative (it simply
    fails to match any checklist key). Delegates to
    :func:`core.paths.to_repo_relative`.
    """
    result = to_repo_relative(path, repo_root, outside_root="relative")
    assert result is not None  # "relative" mode never returns None
    return result


# Path index per (checklist "files" list, repo_root): normalised entry
# path → the file entries carrying it, in checklist order (duplicate
# paths are legal — e.g. a follow-on entry splitting generated vs
# handwritten functions — so the value is a list, preserving the
# cross-entry fuzzy-fallback semantics of the original linear scan).
#
# Kept OUTSIDE the checklist dict on purpose: stashing the index on the
# checklist would survive into json.dumps of an enriched checklist and
# silently double every file entry in the serialised output (the index
# holds references to the same entry dicts).
#
# The cache VALUE keeps a strong reference to the exact ``files`` list
# object. That is the identity guarantee: while an entry is cached,
# ``id(files)`` cannot be recycled by a new list, so a key hit plus the
# ``is`` check below can never serve a stale index to a different
# checklist. Appends are caught by the stored length; in-place PATH
# mutation of an already-indexed entry is not detected (nothing in the
# enrichment pipeline rewrites entry paths mid-run) — item/line edits
# are always safe because lookups read the live entry dicts.
# Same limitation, one step wider: SAME-LENGTH in-place ENTRY
# replacement (``files[i] = new_entry_dict``) keeps both identity and
# length, so the index would keep serving the replaced-out dict. No
# pipeline site does this either (swept: builders construct fresh
# lists; fixture_detection's ``d["path"]`` writes to a fresh
# ``to_dict`` copy) and it is not hostile-reachable — but a future
# caller that swaps entries in place must rebuild or drop the list
# object (fresh list = fresh id = fresh index).
#
# Bound trade-off: larger keeps more checklists' indexes (and their
# files lists) pinned in memory — checklists on big targets reach tens
# of MB, so an unbounded map leaks entire inventories in long-lived
# processes; smaller thrashes when callers alternate between
# checklists (rebuild is the old O(files) scan plus dict inserts, paid
# per miss). The enrichment hot path works one checklist at a time —
# a handful of live checklists (project merge views, tests) fits in 8.
_INDEX_CACHE_MAX = 8
_INDEX_CACHE: OrderedDict[
    tuple[int, str], tuple[list, int, dict[str, list[dict[str, Any]]]],
] = OrderedDict()
_INDEX_LOCK = threading.Lock()


def _file_index(checklist: dict[str, Any],
                repo_root: str) -> dict[str, list[dict[str, Any]]]:
    """Return the ``{normalised_path: [file_entry, ...]}`` index for
    *checklist*, building (and LRU-caching) it on first use.

    Replaces the per-lookup linear scan that re-normalised every file
    path in the inventory — O(findings x files) path arithmetic in the
    agentic enrichment hot path; each entry path is now normalised once
    per (checklist, repo_root).
    """
    files = checklist.get("files", [])
    # Only plain lists are cached — anything else (exotic caller-built
    # container) still gets indexed, just per call, preserving the old
    # scan's duck-typing.
    cacheable = isinstance(files, list)
    key = (id(files), repo_root)
    if cacheable:
        with _INDEX_LOCK:
            cached = _INDEX_CACHE.get(key)
            if (cached is not None and cached[0] is files
                    and cached[1] == len(files)):
                _INDEX_CACHE.move_to_end(key)
                return cached[2]

    index: dict[str, list[dict[str, Any]]] = {}
    for file_entry in files:
        entry_path = normalise_path(file_entry.get("path", ""), repo_root)
        index.setdefault(entry_path, []).append(file_entry)

    if cacheable:
        with _INDEX_LOCK:
            _INDEX_CACHE[key] = (files, len(files), index)
            _INDEX_CACHE.move_to_end(key)
            while len(_INDEX_CACHE) > _INDEX_CACHE_MAX:
                _INDEX_CACHE.popitem(last=False)
    return index


def lookup_file_language(checklist: dict[str, Any], file_path: str,
                         repo_root: str = "") -> str | None:
    """The inventory's recorded language for *file_path*, or None.

    Same path normalisation and cached index as
    :func:`lookup_function`. Best-effort by contract (consumers treat
    the answer as a hint, e.g. CodeQL database routing for extensions
    outside the extension table): an absolute path without a
    ``repo_root`` returns None instead of raising — a hint must never
    guess against the caller's cwd. Duplicate entries for one path
    (generated/handwritten splits of the same file) carry the same
    source language, so the first entry with one wins.
    """
    if not checklist or not file_path:
        return None
    if os.path.isabs(strip_file_uri(file_path)) and not repo_root:
        return None
    norm_path = normalise_path(file_path, repo_root)
    for file_entry in _file_index(checklist, repo_root).get(norm_path, ()):
        lang = file_entry.get("language")
        if lang:
            return str(lang)
    return None


def lookup_function(checklist: dict[str, Any], file_path: str, line: int,
                    repo_root: str = "") -> dict[str, Any] | None:
    """Find the function containing a given file:line in the checklist.

    Args:
        checklist: Inventory dict from build_inventory (has "files" key)
        file_path: Path to the file (absolute, relative, or file:// URI)
        line: Line number within the file
        repo_root: Repository root for path normalisation. Optional ONLY
            when ``file_path`` is relative — absolute paths and
            ``file://`` URIs MUST be paired with a non-empty
            ``repo_root`` so `normalise_path` can convert them to a
            checklist-relative form. Pre-fix the silent ``""`` default
            made absolute paths fail to match: `os.path.relpath(
            abs_path, "")` returns a path relative to the current
            working directory, not the inventory's repo root. The
            checklist (built with rel paths) never matched the
            relpath-against-cwd result, and `lookup_function` silently
            returned ``None`` — the agentic enrichment pipeline lost
            function metadata for findings whose source carried abs
            paths (most CodeQL output).

    Returns:
        Function dict from the checklist, or None if no match.
        Prefers exact match (line within line_start..line_end).
        Falls back to closest function starting before the line, but only
        when the candidate has no line_end (can't determine boundaries).

    Raises:
        ValueError: if ``file_path`` is absolute (or a file:// URI) but
            ``repo_root`` is empty.
    """
    if not checklist or not file_path or line is None:
        return None

    after_scheme = strip_file_uri(file_path)
    if os.path.isabs(after_scheme) and not repo_root:
        msg = (
            f"lookup_function: absolute file_path={file_path!r} "
            f"requires non-empty repo_root for normalisation"
        )
        raise ValueError(msg)

    norm_path = normalise_path(file_path, repo_root)

    # Track best_fuzzy ACROSS all matching file_entries. Pre-fix the
    # `return best_fuzzy` was inside the per-entry loop, so the
    # function bailed after the FIRST file_entry whose path matched
    # — even if that entry only contained fuzzy candidates and a
    # later entry (same path, e.g. inventory malformed by a duplicate
    # extractor pass, or a follow-on entry intentionally splitting
    # generated-vs-handwritten functions for the same file) had an
    # EXACT match. The exact-match path still returns immediately
    # (correct — we found what we want); the fuzzy fallback now
    # considers every entry's items before deciding.
    best_fuzzy = None
    for file_entry in _file_index(checklist, repo_root).get(norm_path, ()):
        for func in (file_entry.get("items", file_entry.get("functions", [])) or []):
            # Only FUNCTION items enclose a "function" — globals, macros,
            # classes, top_level and interstitial are not callable units, so a
            # sink landing in one has no enclosing function (callers expect
            # None there, e.g. reachability stays conservative rather than
            # mislabelling import-time / glue code as "not_called").
            if func.get("kind", "function") != "function":
                continue
            func_start = func.get("line_start", 0)
            func_end = func.get("line_end")

            if func_start > line:
                continue

            # Exact match: line within function range
            if func_end is not None and func_end >= line:
                return func

            # Fuzzy match: only for functions without line_end
            if func_end is None and (
                best_fuzzy is None
                or func_start > best_fuzzy.get("line_start", 0)
            ):
                best_fuzzy = func

    return best_fuzzy
