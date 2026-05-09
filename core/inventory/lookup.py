"""Function lookup from inventory checklist.

Given a file path and line number, finds the enclosing function from a
pre-built inventory checklist. Used by the agentic pipeline to attach
function metadata to scanner findings.
"""

import os
from typing import Any, Dict, Optional


def normalise_path(path: str, repo_root: str) -> str:
    """Normalise a file path relative to the repo root.

    Handles absolute paths, relative paths, file:// URIs, and ./ prefixes.
    """
    if path.startswith("file://"):
        path = path[7:]  # len("file://") == 7
    if os.path.isabs(path):
        try:
            path = os.path.relpath(path, repo_root)
        except ValueError:
            pass
    return os.path.normpath(path)


def lookup_function(checklist: Dict[str, Any], file_path: str, line: int,
                    repo_root: str = "") -> Optional[Dict[str, Any]]:
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
    if not checklist or not file_path or not line:
        return None

    after_scheme = file_path[7:] if file_path.startswith("file://") else file_path
    if os.path.isabs(after_scheme) and not repo_root:
        raise ValueError(
            f"lookup_function: absolute file_path={file_path!r} "
            f"requires non-empty repo_root for normalisation"
        )

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
    for file_entry in checklist.get("files", []):
        entry_path = normalise_path(file_entry.get("path", ""), repo_root)
        if entry_path != norm_path:
            continue

        for func in file_entry.get("items", file_entry.get("functions", [])):
            func_start = func.get("line_start", 0)
            func_end = func.get("line_end")

            if func_start > line:
                continue

            # Exact match: line within function range
            if func_end is not None and func_end >= line:
                return func

            # Fuzzy match: only for functions without line_end
            if func_end is None:
                if best_fuzzy is None or func_start > best_fuzzy.get("line_start", 0):
                    best_fuzzy = func

    return best_fuzzy
