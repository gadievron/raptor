"""Source inventory builder.

Enumerates source files, extracts functions, computes checksums.
Used by /validate (Stage 0), /understand (MAP-0), SCA's
function-level reachability tier, and any other consumer that
needs a cached call-graph view of the project.
"""

import fnmatch
import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.hash import sha256_bytes
from core.json import load_json

from .languages import LANGUAGE_MAP, detect_language
from .exclusions import (
    DEFAULT_EXCLUDES,
    is_binary_file,
    is_generated_file,
    match_exclusion_reason,
)
from .extractors import extract_items, count_sloc
from .call_graph import (
    extract_call_graph_csharp,
    extract_call_graph_go,
    extract_call_graph_java,
    extract_call_graph_javascript,
    extract_call_graph_php,
    extract_call_graph_python,
    extract_call_graph_ruby,
    extract_call_graph_rust,
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

# Default cache root for inventory checklists when callers don't
# supply an explicit ``output_dir``. Lives under ``~/.raptor/cache/
# inventory/<target-hash>/`` — the SHA-256-prefix-of-target-path
# keys distinct projects so two scans of unrelated trees don't
# share state. Operator-purge: ``rm -rf ~/.raptor/cache/inventory/``
# or ``raptor-sca clean-cache``.
_DEFAULT_INVENTORY_CACHE_ROOT = (
    Path.home() / ".raptor" / "cache" / "inventory"
)


def default_cache_dir(target_path: str) -> Path:
    """Return the persistent cache directory for ``target_path``'s
    inventory checklist.

    Keyed on a SHA-256 prefix of the resolved absolute target path so
    distinct projects get distinct cache dirs. Auto-creates the
    parent directory; the cache dir itself is created lazily by
    ``build_inventory`` when needed.

    Used as the default ``output_dir`` for ``build_inventory`` when
    callers don't pass one explicitly. Useful for any consumer that
    wants checklist persistence (incremental SHA-256-keyed re-parse)
    without picking a project-specific path themselves.
    """
    target_abs = str(Path(target_path).resolve())
    target_hash = hashlib.sha256(
        target_abs.encode("utf-8"),
    ).hexdigest()[:16]
    return _DEFAULT_INVENTORY_CACHE_ROOT / target_hash


def build_inventory(
    target_path: str,
    output_dir: Optional[str] = None,
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
        output_dir: Directory to save checklist.json. When ``None``
            (default), uses :func:`default_cache_dir` to derive a
            stable per-target cache dir under
            ``~/.raptor/cache/inventory/<target-hash>/``. Persistence
            across runs is the point — re-scans of an unchanged tree
            collapse the inventory build to a hash-check pass
            (sub-second on most projects, ~1s on large Go codebases
            like istio's ~770 files). Callers wanting ephemeral
            output (tests, one-shot tools) pass an explicit tempdir.
        exclude_patterns: Patterns to exclude (defaults to DEFAULT_EXCLUDES).
        extensions: File extensions to include (defaults to LANGUAGE_MAP keys).
        skip_generated: Skip auto-generated files.
        parallel: Use parallel processing for large codebases.

    Returns:
        Inventory dict (also saved to ``<output_dir>/checklist.json``).
    """
    if output_dir is None:
        output_dir = str(default_cache_dir(target_path))
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
    file_list, pruned_dirs = _collect_source_files(target, extensions)
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
    # Seed `excluded_files` with the directories pruned at walk time so
    # operators still see what was skipped even though we never
    # enumerated each file inside.
    excluded_files = list(pruned_dirs)
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


def _collect_source_files(
    target: Path, extensions: Set[str],
) -> tuple[List[Path], List[Dict[str, Any]]]:
    """Collect all source files in a single pass.

    Returns ``(file_list, pruned_dirs)`` where ``pruned_dirs`` lists
    directory-shaped exclusions skipped at walk time so the caller
    can record them in ``excluded_files`` for operator visibility.

    Prunes the descent at walk time on directory-shaped patterns from
    `DEFAULT_EXCLUDES` (`node_modules/`, `vendor/`, `__pycache__/`,
    `.git/` etc.). Pre-fix `os.walk` descended into them all, then
    `_process_single_file` later marked each enumerated file as
    excluded — but `node_modules` on a real project is hundreds of
    thousands of files. The walk-time stat() of every one of those
    files dominated inventory wallclock for any JS/TS project.
    Pruning the dir name from `dirs[:]` skips the entire subtree, so
    walk time scales with source-tree size rather than source-tree
    + dependency-tree size.
    """
    if target.is_file():
        return [target], []

    # Pre-extract directory-shaped exclusion names from DEFAULT_EXCLUDES.
    # Patterns with `/` suffix and no glob meta-chars are pure directory
    # names that prune cleanly. Patterns with `*` (e.g.
    # `cmake-build-*/`) need fnmatch — handle separately.
    exact_dir_names = set()
    glob_dir_patterns = []
    for pat in DEFAULT_EXCLUDES:
        if not pat.endswith('/'):
            continue
        bare = pat.rstrip('/')
        if '*' in bare or '?' in bare or '[' in bare:
            glob_dir_patterns.append(bare)
        else:
            exact_dir_names.add(bare)

    file_list: List[Path] = []
    pruned_dirs: List[Dict[str, Any]] = []
    # Hidden-dir whitelist: pre-fix the blanket `d.startswith('.')`
    # check pruned EVERY dot-dir, including ones that legitimately
    # carry analysable security-relevant source. Concrete misses:
    #
    #   * `.github/workflows/` — CI definitions (YAML / JSON).
    #     Workflow injection (`pull_request_target` + untrusted
    #     event data) is one of the most common GitHub-hosted
    #     supply-chain bug classes; pruning the directory hid
    #     every workflow file from the inventory and downstream
    #     scanners couldn't find them.
    #   * `.gitlab/` / `.gitlab-ci/` — same story for GitLab CI.
    #
    # Other dot-dirs (`.git/`, `.cache/`, `.venv/`, `.tox/`,
    # `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `.idea/`,
    # `.vscode/`, `.gradle/`, etc.) remain pruned — they're either
    # VCS metadata, tool caches, or editor state with no security
    # value.
    _HIDDEN_DIR_WHITELIST = frozenset({
        ".github",
        ".gitlab",
        ".gitlab-ci",
    })
    for root, dirs, files in os.walk(target):
        # Skip hidden directories, symlinked directories, AND any directory
        # that matches a DEFAULT_EXCLUDES dir-shaped pattern.
        kept_dirs = []
        for d in dirs:
            if d.startswith('.') and d not in _HIDDEN_DIR_WHITELIST:
                continue
            if (Path(root) / d).is_symlink():
                continue
            if d in exact_dir_names:
                rel = str((Path(root) / d).relative_to(target))
                pruned_dirs.append({
                    "path": rel + "/",
                    "reason": "excluded_directory_pruned",
                    "pattern_matched": d + "/",
                })
                continue
            matched_glob = next(
                (p for p in glob_dir_patterns if fnmatch.fnmatch(d, p)),
                None,
            )
            if matched_glob is not None:
                rel = str((Path(root) / d).relative_to(target))
                pruned_dirs.append({
                    "path": rel + "/",
                    "reason": "excluded_directory_pruned",
                    "pattern_matched": matched_glob + "/",
                })
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs
        for filename in files:
            filepath = Path(root) / filename
            if filepath.is_symlink():
                continue  # Don't follow symlinks into files outside the repo
            ext = Path(filename).suffix.lower()
            if ext in extensions:
                file_list.append(filepath)

    return file_list, pruned_dirs


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
        # `O_NOFOLLOW` so a symlink that wasn't caught by the
        # walk-time `is_symlink()` filter (race: file became a
        # symlink between walk and read) doesn't transit us into
        # an unrelated tree. The walk-time check was already
        # there as a fast path; this is the authoritative guard
        # at the read site itself. ELOOP from a symlink → caught
        # under OSError below and the file is recorded excluded.
        try:
            fd = os.open(str(filepath), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "open_failed_or_symlink",
                    "_pattern": None}
        with os.fdopen(fd, "rb") as fh:
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
        elif language == 'java':
            record['call_graph'] = extract_call_graph_java(
                content,
            ).to_dict()
        elif language == 'rust':
            record['call_graph'] = extract_call_graph_rust(
                content,
            ).to_dict()
        elif language == 'ruby':
            record['call_graph'] = extract_call_graph_ruby(
                content,
            ).to_dict()
        elif language in ('csharp', 'c_sharp'):
            record['call_graph'] = extract_call_graph_csharp(
                content,
            ).to_dict()
        elif language == 'php':
            record['call_graph'] = extract_call_graph_php(
                content,
            ).to_dict()
        return record

    except Exception as e:
        logger.warning(f"Failed to process {filepath}: {e}")
        return None
