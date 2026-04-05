"""Source inventory builder.

Enumerates source files, extracts functions, computes checksums.
Used by both /validate (Stage 0) and /understand (MAP-0).
"""

import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.json import load_json, save_json

from .languages import LANGUAGE_MAP, detect_language
from .exclusions import (
    DEFAULT_EXCLUDES,
    is_binary_file,
    is_generated_file,
    should_exclude,
    match_exclusion_reason,
)
from .extractors import extract_functions
from .diff import compare_inventories

logger = logging.getLogger(__name__)

MAX_WORKERS = os.cpu_count() or 4


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

    If an existing checklist.json is found in output_dir, cumulative
    coverage (checked_by) is carried forward for unchanged files.

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

    files_info = []
    excluded_files = []
    total_functions = 0
    skipped = 0

    def _collect_result(result):
        nonlocal total_functions, skipped
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
            total_functions += len(result['functions'])

    if parallel and len(file_list) > 10:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    _process_single_file, fp, target, exclude_patterns, skip_generated
                ): fp
                for fp in file_list
            }
            for future in as_completed(futures):
                _collect_result(future.result())
    else:
        for filepath in file_list:
            _collect_result(
                _process_single_file(filepath, target, exclude_patterns, skip_generated)
            )

    # Sort for consistent output
    files_info.sort(key=lambda x: x['path'])
    excluded_files.sort(key=lambda x: x['path'])

    inventory = {
        'generated_at': datetime.now().isoformat(),
        'target_path': str(target_path),
        'total_files': len(files_info),
        'total_functions': total_functions,
        'skipped_files': skipped,
        'excluded_patterns': exclude_patterns,
        'excluded_files': excluded_files,
        'files': files_info,
    }

    # Cumulative coverage: carry forward checked_by from previous inventory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    checklist_file = output_path / 'checklist.json'

    old_inventory = load_json(checklist_file)
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

    save_json(checklist_file, inventory)

    logger.info(f"Built inventory: {len(files_info)} files, {total_functions} functions "
                f"({skipped} skipped, {len(excluded_files)} excluded)")
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

    # Build lookup: (path, func_name) -> checked_by from old inventory
    old_coverage = {}
    for file_info in old.get('files', []):
        path = file_info.get('path')
        if path in modified:
            continue  # Don't carry forward stale coverage
        for func in file_info.get('functions', []):
            key = (path, func.get('name'))
            checked_by = func.get('checked_by', [])
            if checked_by:
                old_coverage[key] = checked_by

    # Apply to new inventory
    for file_info in new.get('files', []):
        path = file_info.get('path')
        for func in file_info.get('functions', []):
            key = (path, func.get('name'))
            if key in old_coverage:
                func['checked_by'] = list(old_coverage[key])


def _collect_source_files(target: Path, extensions: Set[str]) -> List[Path]:
    """Collect all source files in a single pass."""
    if target.is_file():
        return [target]

    file_list = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext in extensions:
                file_list.append(Path(root) / filename)

    return file_list


def _process_single_file(
    filepath: Path,
    target: Path,
    exclude_patterns: List[str],
    skip_generated: bool = True,
) -> Optional[Dict[str, Any]]:
    """Process a single file for the inventory.

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
        content = filepath.read_text(encoding='utf-8', errors='ignore')

        if skip_generated and is_generated_file(content):
            return {"path": rel_path, "_excluded": True, "_reason": "generated_file", "_pattern": None}

        line_count = content.count('\n') + 1
        sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()

        functions = extract_functions(str(filepath), language, content)

        return {
            'path': rel_path,
            'language': language,
            'lines': line_count,
            'sha256': sha256,
            'functions': [
                f.to_dict()
                for f in functions
            ],
        }

    except Exception as e:
        logger.warning(f"Failed to process {filepath}: {e}")
        return None
