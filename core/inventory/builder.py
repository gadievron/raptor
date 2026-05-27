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
    ROOT_ANCHORED_EXCLUDE_DIRS,
    is_binary_file,
    is_generated_file,
    match_exclusion_reason,
)
from .extractors import extract_items, count_sloc, compute_interstitial_items
from .call_graph import (
    extract_call_graph_c,
    extract_call_graph_cpp,
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
from core.build.macro_config import extract_build_tus, extract_macro_config
from core.build.rust_modules import extract_rust_crate_modules
from .dead_scope import detect_dead_scopes
from .build_membership import (
    crate_module_excluded,
    detect_build_excluded,
    tu_membership_excluded,
)
from .module_load_abort import detect_module_load_abort
from .translation_view import detect_macro_call_targets, preprocess_view

logger = logging.getLogger(__name__)

# Worker cap for the per-file extractor pool. Tree-sitter Tree
# objects can briefly hold tens of MB per file (large TS / JS
# sources in particular). On a high-core box ``os.cpu_count()``
# returns 16+, and the resulting transient peak — workers × tree
# size — dominated inventory peak RSS on Grafana-scale repos
# (observed 5.7 GB across the reach stage). Sourced from
# ``tuning.json`` (``max_inventory_workers``) so operators tune it
# alongside the other RAPTOR pool sizes; default "auto" resolves to
# half the available CPU count, capped at 8.
def _resolved_max_workers() -> int:
    try:
        from core.tuning import load_tuning
        return max(1, load_tuning().max_inventory_workers)
    except Exception:  # noqa: BLE001
        return min(8, os.cpu_count() or 4)


MAX_WORKERS = _resolved_max_workers()

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


def default_cache_dir(
    target_path: str, *, allow_unreachable: bool = False,
    config_fingerprint: str = "",
) -> Path:
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
    # Fold the parse mode into the key: allow_unreachable changes the
    # C/C++ view (#if 0 kept vs blanked), so the two modes must not share
    # a cached checklist. Default mode keeps the original hash input, so
    # existing cache dirs are unchanged.
    key = target_abs if not allow_unreachable else target_abs + "\0allow_unreachable"
    # Fold the macro config too: config-aware blanking (#ifdef resolved via
    # -D/-U/.config) changes which arms are dead, so a config change must
    # invalidate the cache even when file contents are identical (else a
    # newly-live arm would stay blanked from cache → a false negative). Empty
    # fingerprint (no config / non-C target) leaves the key unchanged.
    if config_fingerprint:
        key += "\0cfg=" + config_fingerprint
    target_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return _DEFAULT_INVENTORY_CACHE_ROOT / target_hash


def build_inventory(
    target_path: str,
    output_dir: Optional[str] = None,
    exclude_patterns: Optional[List[str]] = None,
    extensions: Optional[Set[str]] = None,
    skip_generated: bool = True,
    parallel: bool = True,
    allow_unreachable: bool = False,
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
    # Build macro config once (compile_commands.json / .config). Drives
    # config-aware #ifdef resolution in each file's TranslationView. Empty
    # (and inert) when no build artifacts are present or in isolation mode.
    macro_config = extract_macro_config(target_path)
    if allow_unreachable:
        macro_config = None
    # Translation-unit set (compile_commands membership), built once for the
    # C/C++ build-membership witness. A witness record (not a view transform),
    # so — like the Go //go:build detector — it is NOT disabled under
    # allow_unreachable; the surface-only consumers ignore it in that mode.
    build_tus = extract_build_tus(target_path)
    # Rust crate-module set (mod-tree membership), same role for .rs sources.
    crate_modules = extract_rust_crate_modules(target_path)
    cfg_fp = macro_config.fingerprint() if macro_config else ""
    # Fold the membership sets into the cache key: a compile_commands / mod-tree
    # change (a file added to / removed from the build) must invalidate cached
    # build_excluded marks even when file contents are unchanged.
    if build_tus:
        cfg_fp += "|tu=" + hashlib.sha256(
            "\0".join(sorted(build_tus)).encode("utf-8")).hexdigest()[:16]
    if crate_modules:
        cfg_fp += "|rs=" + hashlib.sha256(
            "\0".join(sorted(crate_modules)).encode("utf-8")).hexdigest()[:16]

    if output_dir is None:
        output_dir = str(default_cache_dir(
            target_path, allow_unreachable=allow_unreachable,
            config_fingerprint=cfg_fp,
        ))
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
                    skip_generated, old_files_by_path, allow_unreachable,
                    macro_config, build_tus, crate_modules,
                ): fp
                for fp in file_list
            }
            for future in as_completed(futures):
                # Per-future exception isolation: pre-fix a single
                # worker raising (tree-sitter parser bug, encoding
                # issue, or any unforeseen extractor error) bubbled
                # up through ``future.result()`` and killed the
                # whole ``as_completed`` loop, abandoning every other
                # in-flight future. The inventory was then partial
                # without the operator seeing why. Now: the failing
                # file is logged at WARNING (file path included so
                # the operator can reproduce), counted as a skip,
                # and the rest of the pool finishes.
                fp = futures[future]
                try:
                    _collect_result(future.result())
                except Exception as exc:
                    logger.warning(
                        "inventory: per-file extractor raised on "
                        "%s — skipping (%s: %s)",
                        fp, exc.__class__.__name__, exc,
                    )
                    skipped += 1
    else:
        for filepath in file_list:
            _collect_result(
                _process_single_file(filepath, target, exclude_patterns,
                                     skip_generated, old_files_by_path,
                                     allow_unreachable, macro_config, build_tus,
                                     crate_modules)
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


def _count_source_files(dirpath: Path, extensions: Set[str], cap: int = 1000) -> int:
    """Count files under ``dirpath`` whose extension is a recognised source
    extension, bounded at ``cap`` (we only need "holds source? roughly how
    many" for an operator warning — not an exact census of a huge tree).
    """
    n = 0
    for _root, _dirs, files in os.walk(dirpath):
        for f in files:
            if Path(f).suffix.lower() in extensions:
                n += 1
                if n >= cap:
                    return n
    return n


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
                # Root-anchored names (examples/ samples/ demo/ docs/ …) also
                # name first-party package/source segments, so pruning them by
                # basename at any depth silently drops first-party source — a
                # scanner-wide false negative. Prune them ONLY at the scan-root
                # top level; keep + analyse nested occurrences.
                if d in ROOT_ANCHORED_EXCLUDE_DIRS and Path(root) != target:
                    kept_dirs.append(d)
                    continue
                rel = str((Path(root) / d).relative_to(target))
                # Never SILENTLY drop source: if a pruned top-level anchored dir
                # holds source files, warn with a count so the exclusion is
                # visible and the operator can scan it directly if first-party.
                if d in ROOT_ANCHORED_EXCLUDE_DIRS:
                    n = _count_source_files(Path(root) / d, extensions)
                    if n:
                        logger.warning(
                            "inventory: pruned top-level '%s/' (matches default "
                            "exclude '%s/') holding %d source file(s); scan it "
                            "directly if it is first-party code",
                            rel, d, n,
                        )
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
    allow_unreachable: bool = False,
    macro_config: Optional[object] = None,
    build_tus: Optional[frozenset] = None,
    crate_modules: Optional[frozenset] = None,
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

        # The parser reads a TranslationView (its parse_text), not raw
        # content, so future preprocessing fidelity (e.g. C/C++ #if 0
        # blanking, real cpp) slots in behind this seam without rewiring
        # consumers. Identity view today ⇒ byte-identical behavior.
        # Metrics (sloc, line_count, sha256) and text scanners
        # (detect_dead_scopes / detect_module_load_abort) keep using the
        # real `content`; only the tree-sitter / AST parse uses parse_text.
        view = preprocess_view(
            str(filepath), language, content,
            allow_unreachable=allow_unreachable,
            config=macro_config,
        )
        parse_text = view.parse_text
        tree_cache = {}
        items = extract_items(str(filepath), language, parse_text, _tree_cache=tree_cache)
        # Safety net: every SLOC-bearing line outside an extracted item becomes
        # an interstitial item, so non-function code (top-level statements,
        # missed globals) is never invisible to coverage (coverage Decision #2).
        items = items + compute_interstitial_items(items, parse_text)
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
        # S3: per-function lexical-dead tagging. Functions whose
        # definition lies inside an always-false guard (``if False:``,
        # ``if (false) {…}``, ``#[cfg(any())]``) never bind — the
        # guard's body never runs / compiles. The reachability prepass
        # demotes such functions regardless of in-scope call edges
        # (two dead-scope functions calling each other otherwise read
        # as mutually CALLED). Tagged here (not in each extractor) so
        # detection lives in one place per language; field is set only
        # when dead so inventory size stays flat.
        dead_ranges = detect_dead_scopes(language, content)
        if dead_ranges:
            for item_dict in record['items']:
                ls = item_dict.get('line_start') or 0
                if ls and any(lo <= ls <= hi for lo, hi in dead_ranges):
                    item_dict['lexical_dead'] = True
        # Call-graph extraction. The resolver in
        # core.inventory.reachability is language-agnostic; per-file
        # extractors emit the same FileCallGraph dataclass for
        # whichever languages have a walker.
        if language == 'python':
            record['call_graph'] = extract_call_graph_python(parse_text).to_dict()
        elif language in ('javascript', 'typescript', 'tsx'):
            # Tree-sitter-driven; gracefully empty when the grammar
            # isn't installed. TS/TSX use the typescript grammar so typed
            # source (annotations, decorators, interfaces) parses.
            record['call_graph'] = extract_call_graph_javascript(
                parse_text, language=language,
            ).to_dict()
        elif language == 'go':
            record['call_graph'] = extract_call_graph_go(
                parse_text,
            ).to_dict()
        elif language == 'java':
            record['call_graph'] = extract_call_graph_java(
                parse_text,
            ).to_dict()
        elif language == 'rust':
            record['call_graph'] = extract_call_graph_rust(
                parse_text,
            ).to_dict()
        elif language == 'ruby':
            record['call_graph'] = extract_call_graph_ruby(
                parse_text,
            ).to_dict()
        elif language in ('csharp', 'c_sharp'):
            record['call_graph'] = extract_call_graph_csharp(
                parse_text,
            ).to_dict()
        elif language == 'php':
            record['call_graph'] = extract_call_graph_php(
                parse_text,
            ).to_dict()
        elif language == 'c':
            # S5: wire the existing extract_call_graph_c into the
            # dispatch. The walker has been present (and tested in
            # core/inventory/tests) for a while but was orphaned —
            # C files were getting empty call_graph records, so
            # function_called returned no useful data for any C
            # finding and the analysis prompt's Reachability: block
            # was absent for every C scan. Closes RAPTOR's largest
            # whole-language reachability blind spot.
            record['call_graph'] = extract_call_graph_c(
                parse_text,
            ).to_dict()
        elif language == 'cpp':
            # S5: same wiring story for C++. _CppCallGraph inherits
            # from _CCallGraph; adds class/namespace/qualified-id
            # handling. Covers .cpp / .cc / .cxx / .hpp (per the
            # languages.py extension map).
            record['call_graph'] = extract_call_graph_cpp(
                parse_text,
            ).to_dict()
        # U4 (macro-masking): record the function names invoked inside
        # function-like macro bodies. tree-sitter sees a macro call as a
        # call to the macro, not its expansion, so a function reachable
        # only via a macro reads NOT_CALLED. The resolver consults this to
        # downgrade such verdicts to UNCERTAIN (FN-safe). C/C++ only;
        # scanned from parse_text so macros inside blanked #if 0 don't
        # count. Stored only when non-empty to keep inventory size flat.
        if language in ('c', 'cpp') and isinstance(record.get('call_graph'), dict):
            macro_targets = detect_macro_call_targets(parse_text)
            if macro_targets:
                record['call_graph']['macro_call_targets'] = sorted(macro_targets)
        # S4: file-level module-load-abort gate. When the file's
        # top-level execution unconditionally aborts (raise
        # ImportError / throw new Error / init() panic /
        # compile_error!), no function it defines is reachable
        # through import / link regardless of in-file call edges.
        # The reachability resolver treats this as a whole-file
        # NOT_REACHED gate. Stored only when detected so the field
        # is absent (not False) on the overwhelming majority of
        # files — keeps inventory size flat.
        abort = detect_module_load_abort(language, content)
        if abort is not None:
            record['module_aborts_on_load'] = {
                'line': abort.line,
                'summary': abort.summary,
            }
        # Whole-file build exclusion (e.g. Go `//go:build ignore`): the file
        # is never compiled, so every function in it is dead regardless of
        # call edges or external linkage. Heuristic (config-dependent) — a
        # surface-only gate, never hard-suppress.
        excluded = detect_build_excluded(language, content)
        if excluded is not None:
            record['build_excluded'] = {
                'line': excluded.line,
                'summary': excluded.summary,
            }
        # C/C++ build-membership: a source TU absent from compile_commands.json
        # is not compiled → dead. Whole-file, heuristic. Only when a
        # content-based detector above didn't already fire. Headers are exempt
        # (tu_membership_excluded checks the extension). Path resolved to match
        # the resolved TU-set entries.
        if 'build_excluded' not in record and build_tus is not None:
            tu_excluded = tu_membership_excluded(
                str(filepath.resolve()), build_tus,
            )
            if tu_excluded is not None:
                record['build_excluded'] = {
                    'line': tu_excluded.line,
                    'summary': tu_excluded.summary,
                }
        # Rust crate-module membership: a .rs not reachable via the mod tree
        # from any crate root is not compiled → dead. Whole-file, heuristic.
        if 'build_excluded' not in record and crate_modules is not None:
            rs_excluded = crate_module_excluded(
                str(filepath.resolve()), crate_modules,
            )
            if rs_excluded is not None:
                record['build_excluded'] = {
                    'line': rs_excluded.line,
                    'summary': rs_excluded.summary,
                }
        return record

    except Exception as e:
        logger.warning(f"Failed to process {filepath}: {e}")
        return None
