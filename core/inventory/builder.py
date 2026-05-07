"""Source inventory builder.

Enumerates source files, extracts functions, computes checksums.
Used by both /validate (Stage 0) and /understand (MAP-0).
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.hash import sha256_bytes
from core.json import load_json, save_json

from .languages import LANGUAGE_MAP, detect_language
from .exclusions import (
    DEFAULT_EXCLUDES,
    is_binary_file,
    is_generated_file,
    should_exclude,
    match_exclusion_reason,
)
from .extractors import extract_functions, extract_items, count_sloc
from .call_graph import (
    extract_call_graph_go,
    extract_call_graph_javascript,
    extract_call_graph_python,
)
from .diff import compare_inventories

logger = logging.getLogger(__name__)

MAX_WORKERS = os.cpu_count() or 4

# Per-file read cap. Bigger than any realistic source file (the
# largest in CPython is ~30K LOC ≈ 1 MB) but small enough that a
# pathological input — vendored binary blob, malformed
# symlink-to-/dev/zero, hostile sample in a test fixture — can't
# OOM the inventory builder. Pre-fix `read_bytes()` loaded the whole
# file into memory before any size check, so a single 10 GB file
# anywhere in the target tree killed the run.
MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB


def build_inventory(
    target_path: str,
    output_dir: str,
    exclude_patterns: Optional[List[str]] = None,
    extensions: Optional[Set[str]] = None,
    skip_generated: bool = True,
    parallel: bool = True,
) -> Dict[str, Any]:
    """Build a source inventory of all files and functions in the target path.

    Enumerates source files, detects languages, extracts functions via
    AST/regex, computes SHA-256 per file, and records exclusions.

    Always rehashes files on disk.  Unchanged files (SHA-256 match with
    a previous checklist) reuse their old parsed entries, including
    coverage marks.  Changed files are re-parsed and their coverage
    marks cleared.

    Args:
        target_path: Directory or file to analyze.
        output_dir: Directory to save checklist.json.
        exclude_patterns: Patterns to exclude (defaults to DEFAULT_EXCLUDES).
        extensions: File extensions to include (defaults to LANGUAGE_MAP keys).
        skip_generated: Skip auto-generated files.
        parallel: Use parallel processing for large codebases.

    Returns:
        Inventory dict (also saved to output_dir/checklist.json).
    """
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDES

    if extensions is None:
        extensions = set(LANGUAGE_MAP.keys())

    target = Path(target_path)

    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    if target.is_file() and detect_language(str(target)) is None:
        raise ValueError(f"Target file has no recognized source extension: {target_path}")

    # Collect files in single pass
    file_list = _collect_source_files(target, extensions)
    logger.info(f"Found {len(file_list)} source files to process")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    checklist_file = output_path / 'checklist.json'
    old_inventory = load_json(checklist_file)

    old_files_by_path = {}
    if old_inventory:
        for f in old_inventory.get('files', []):
            if f.get('path') and f.get('sha256'):
                old_files_by_path[f['path']] = f

    files_info = []
    excluded_files = []
    total_items = 0
    total_sloc = 0
    skipped = 0

    def _collect_result(result):
        nonlocal total_items, total_sloc, skipped
        if result is None:
            skipped += 1
        elif result.get("_excluded"):
            excluded_files.append({
                "path": result["path"],
                "reason": result["_reason"],
                "pattern_matched": result.get("_pattern"),
            })
            skipped += 1
        else:
            files_info.append(result)
            total_items += len(result['items'])
            total_sloc += result.get('sloc', 0)

    if parallel and len(file_list) > 10:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    _process_single_file, fp, target, exclude_patterns,
                    skip_generated, old_files_by_path
                ): fp
                for fp in file_list
            }
            for future in as_completed(futures):
                _collect_result(future.result())
    else:
        for filepath in file_list:
            _collect_result(
                _process_single_file(filepath, target, exclude_patterns,
                                     skip_generated, old_files_by_path)
            )

    # Sort for consistent output
    files_info.sort(key=lambda x: x['path'])
    excluded_files.sort(key=lambda x: x['path'])

    # Count functions specifically for backwards-compatible field
    total_functions = sum(
        1 for f in files_info for item in f.get('items', [])
        if item.get('kind', 'function') == 'function'
    )

    # Record limitations when extraction is incomplete
    limitations = []
    from .extractors import _TS_AVAILABLE
    if not _TS_AVAILABLE:
        limitations.append("globals not extracted (tree-sitter was not available)")
        limitations.append("SLOC counts used regex fallback (less accurate)")

    inventory = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'target_path': str(target_path),
        'total_files': len(files_info),
        'total_items': total_items,
        'total_functions': total_functions,
        'total_sloc': total_sloc,
        'skipped_files': skipped,
        'excluded_patterns': exclude_patterns,
        'excluded_files': excluded_files,
        'files': files_info,
    }
    if limitations:
        inventory['limitations'] = limitations

    # Cumulative coverage: carry forward checked_by from previous inventory
    if old_inventory is not None:
        try:
            diff = compare_inventories(old_inventory, inventory)
            if diff is None:
                logger.info("Source material unchanged (SHA256 match)")
                inventory['source_unchanged'] = True
                # Carry forward all checked_by data from old inventory
                _carry_forward_coverage(old_inventory, inventory)
            else:
                logger.info(
                    "Source material changed: %d added, %d removed, %d modified",
                    len(diff['added']), len(diff['removed']), len(diff['modified']),
                )
                inventory['changes_since_last'] = diff
                # Carry forward checked_by only for unchanged files
                _carry_forward_coverage(old_inventory, inventory, modified=set(diff['modified']))
        except (KeyError, TypeError):
            pass  # Incompatible old inventory

    from core.inventory import save_checklist
    save_checklist(str(output_path), inventory)

    logger.info(f"Built inventory: {len(files_info)} files, {total_items} items "
                f"({total_functions} functions, {total_sloc} SLOC, "
                f"{skipped} skipped, {len(excluded_files)} excluded)")
    logger.info(f"Saved to: {checklist_file}")

    return inventory


def _carry_forward_coverage(
    old: Dict[str, Any],
    new: Dict[str, Any],
    modified: Optional[set] = None,
) -> None:
    """Carry forward checked_by from old inventory to new for unchanged files.

    Args:
        old: Previous inventory dict.
        new: Current inventory dict (mutated in place).
        modified: Set of file paths that changed (checked_by cleared for these).
    """
    if modified is None:
        modified = set()

    def _get_items(fi):
        return fi.get("items", fi.get("functions", []))

    # Build lookup: (path, name, kind) -> checked_by from old inventory
    old_coverage = {}
    for file_info in old.get('files', []):
        path = file_info.get('path')
        if path in modified:
            continue  # Don't carry forward stale coverage
        for item in _get_items(file_info):
            key = (path, item.get('name'), item.get('kind', 'function'))
            checked_by = item.get('checked_by', [])
            if checked_by:
                old_coverage[key] = checked_by

    # Apply to new inventory
    for file_info in new.get('files', []):
        path = file_info.get('path')
        for item in _get_items(file_info):
            key = (path, item.get('name'), item.get('kind', 'function'))
            if key in old_coverage:
                item['checked_by'] = list(old_coverage[key])


def _collect_source_files(target: Path, extensions: Set[str]) -> List[Path]:
    """Collect all source files in a single pass."""
    if target.is_file():
        return [target]

    file_list = []
    for root, dirs, files in os.walk(target):
        # Skip hidden directories and symlinked directories
        dirs[:] = [d for d in dirs
                   if not d.startswith('.') and not (Path(root) / d).is_symlink()]
        for filename in files:
            filepath = Path(root) / filename
            if filepath.is_symlink():
                continue  # Don't follow symlinks into files outside the repo
            ext = Path(filename).suffix.lower()
            if ext in extensions:
                file_list.append(filepath)

    return file_list


def _process_single_file(
    filepath: Path,
    target: Path,
    exclude_patterns: List[str],
    skip_generated: bool = True,
    old_files: Dict[str, Any] = None,
) -> Optional[Dict[str, Any]]:
    """Process a single file for the inventory.

    If old_files contains an entry for this file with a matching SHA-256,
    the old entry is returned as-is (skipping tree-sitter parsing).

    Returns:
        File info dict, exclusion record (with _excluded flag), or None if skipped.
    """
    rel_path = str(filepath.relative_to(target) if target.is_dir() else filepath.name)

    # Check exclusions against relative path (not absolute — avoids false
    # positives when parent directories match patterns like "tests/")
    excluded, reason, pattern = match_exclusion_reason(rel_path, exclude_patterns)
    if excluded:
        return {"path": rel_path, "_excluded": True, "_reason": reason, "_pattern": pattern}

    # Detect language
    language = detect_language(str(filepath))
    if not language:
        return None

    # Skip binary files
    if is_binary_file(filepath):
        return None

    try:
        try:
            st = filepath.stat()
            file_stat = [st.st_mtime_ns, st.st_size]
        except OSError:
            file_stat = None

        # Fast path: if stat (mtime_ns + size) matches old entry, reuse
        # without reading the file at all — skips I/O, hash, and parsing.
        if old_files and rel_path in old_files:
            old_entry = old_files[rel_path]
            old_stat = old_entry.get('_stat')
            if file_stat and old_stat and file_stat == old_stat:
                return old_entry

        # Bounded read. `read_bytes()` loads the whole file into
        # memory before any size check — a 10 GB binary, malformed
        # symlink-to-/dev/zero, or hostile sample in a vendored
        # archive OOM-killed the inventory builder. stat-then-bound
        # caps the in-flight memory at MAX_FILE_BYTES + 1 regardless
        # of file size.
        try:
            file_size = filepath.stat().st_size
        except OSError:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "stat_failed", "_pattern": None}
        if file_size > MAX_FILE_BYTES:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "too_large",
                    "_pattern": f"size>{MAX_FILE_BYTES}"}
        with filepath.open("rb") as fh:
            raw_bytes = fh.read(MAX_FILE_BYTES + 1)
        if len(raw_bytes) > MAX_FILE_BYTES:
            # File grew between stat and read — still reject.
            return {"path": rel_path, "_excluded": True,
                    "_reason": "too_large_during_read",
                    "_pattern": f"size>{MAX_FILE_BYTES}"}
        content = raw_bytes.decode('utf-8', errors='ignore')

        if skip_generated and is_generated_file(content):
            return {"path": rel_path, "_excluded": True, "_reason": "generated_file", "_pattern": None}

        line_count = content.count('\n') + 1
        sha256 = sha256_bytes(raw_bytes)

        # Fall back to SHA-256 comparison when stat changed but content didn't
        if old_files and rel_path in old_files:
            old_entry = old_files[rel_path]
            if old_entry.get('sha256') == sha256:
                old_entry['_stat'] = file_stat
                return old_entry

        tree_cache = {}
        items = extract_items(str(filepath), language, content, _tree_cache=tree_cache)
        sloc = count_sloc(content, language, _tree=tree_cache.get("tree"))

        record: Dict[str, Any] = {
            'path': rel_path,
            'language': language,
            'lines': line_count,
            'sloc': sloc,
            'sha256': sha256,
            '_stat': file_stat,
            'items': [item.to_dict() for item in items],
        }
        # Call-graph extraction. The resolver in
        # core.inventory.reachability is language-agnostic; per-file
        # extractors emit the same FileCallGraph dataclass for
        # whichever languages have a walker.
        if language == 'python':
            record['call_graph'] = extract_call_graph_python(content).to_dict()
        elif language in ('javascript', 'typescript'):
            # Tree-sitter-driven; gracefully empty when the grammar
            # isn't installed.
            record['call_graph'] = extract_call_graph_javascript(
                content,
            ).to_dict()
        elif language == 'go':
            record['call_graph'] = extract_call_graph_go(
                content,
            ).to_dict()
        return record

    except Exception as e:
        logger.warning(f"Failed to process {filepath}: {e}")
        return None
