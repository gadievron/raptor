"""Detect incomplete dispatch tables.

Several real bugs arise from dispatch tables (dict-literal mappings,
if/elif chains, or enums) that are missing entries.  Examples:

- Bug 4:   ``_CALL_GRAPH_DISPATCH`` maps file extensions to handlers
           but is missing ``'tsx'``.
- Bug 373: GitLab CI parser skips ``default:`` block images.
- Bug 302: ``final_status`` enum omits ``'likely_exploitable'`` that
           the orchestrator produces.

The pattern is always the same: a dispatch table handles a set of keys,
but producers elsewhere in the codebase generate keys that the table
never covers.

Detection strategy (mechanical -- no LLM):
1. Parse source files for dict-literal dispatch tables and if/elif
   chains comparing against string literals.
2. Scan the same files for producer sites that yield string values
   consumed by those tables.
3. Cross-reference to find keys that are produced but never dispatched.
"""

from __future__ import annotations

import ast
import logging
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from ._util import find_enclosing_function as _find_enclosing_function
from pathlib import Path
from core.source.lines import split_lines

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DispatchTable:
    """A table that routes control flow based on string keys."""

    file: str
    function: str  # enclosing function, or "<module>" for top-level
    line: int
    keys: set[str]
    table_type: str  # "dict", "if_elif", "enum", "match"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "keys": sorted(self.keys),
            "table_type": self.table_type,
        }


@dataclass
class DispatchGap:
    """A key that is produced but never dispatched."""

    table: DispatchTable
    missing_key: str
    produced_by: str  # "file:line" or description of production site
    confidence: str  # "high" if from same codebase, "medium" if inferred

    def to_dict(self) -> dict:
        return {
            "table": self.table.to_dict(),
            "missing_key": self.missing_key,
            "produced_by": self.produced_by,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _enclosing_function(node: ast.AST, parents: dict[int, ast.AST]) -> str:
    """Walk up the parent map to find the nearest enclosing function."""
    cur = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = parents.get(id(cur))
    return "<module>"


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _string_keys_from_dict(node: ast.Dict) -> set[str]:
    """Extract string literal keys from an ast.Dict."""
    keys: set[str] = set()
    for k in node.keys:
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
    return keys


def _dict_is_dispatch(
    node: ast.Dict,
    _parents: dict[int, ast.AST],
) -> bool:
    """Heuristic: a dict literal is a dispatch table when it has >= 2
    string keys and all values are callable-shaped (names, attributes,
    lambdas) or it is assigned to a variable and later used in .get()
    or [] access.  We lean permissive and require only >= 2 string keys
    with at least one callable-looking value.
    """
    str_keys = _string_keys_from_dict(node)
    if len(str_keys) < 2:
        return False
    # Check if at least one value looks callable: a bare Name, an
    # Attribute (module.handler), or a Lambda. Call-valued dicts
    # (e.g. {"a": partial(handle_a, ctx)}) are deliberately NOT
    # accepted — widening to ast.Call would classify plain
    # data-construction dicts as dispatch tables.
    for v in node.values:
        if isinstance(v, (ast.Name, ast.Attribute, ast.Lambda)):
            return True
    return False


def _extract_dict_tables(
    tree: ast.Module,
    parents: dict[int, ast.AST],
    file: str,
) -> list[DispatchTable]:
    """Find dict-literal dispatch tables in the AST."""
    tables: list[DispatchTable] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and _dict_is_dispatch(node, parents):
            keys = _string_keys_from_dict(node)
            func = _enclosing_function(node, parents)
            tables.append(
                DispatchTable(
                    file=file,
                    function=func,
                    line=node.lineno,
                    keys=keys,
                    table_type="dict",
                )
            )
    return tables


# ---------------------------------------------------------------------------
# Match statement detection (Python 3.10+)
# ---------------------------------------------------------------------------


def _extract_match_tables(
    tree: ast.Module,
    parents: dict[int, ast.AST],
    file: str,
) -> list[DispatchTable]:
    """Find match/case statements dispatching on string values."""
    tables: list[DispatchTable] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Match):
            continue
        keys: set[str] = set()
        for case in node.cases:
            _collect_match_strings(case.pattern, keys)
        if len(keys) >= 2:
            func = _enclosing_function(node, parents)
            tables.append(DispatchTable(
                file=file,
                function=func,
                line=node.lineno,
                keys=keys,
                table_type="match",
            ))
    return tables


def _collect_match_strings(pattern: ast.pattern, out: set[str]) -> None:
    """Extract string literals from a match pattern (handles MatchOr)."""
    if isinstance(pattern, ast.MatchValue):
        if (isinstance(pattern.value, ast.Constant)
                and isinstance(pattern.value.value, str)):
            out.add(pattern.value.value)
    elif isinstance(pattern, ast.MatchOr):
        for sub in pattern.patterns:
            _collect_match_strings(sub, out)


# ---------------------------------------------------------------------------
# If/elif chain detection
# ---------------------------------------------------------------------------

# Pattern: if x == "foo": ... elif x == "bar": ...
# We detect chains of 2+ branches comparing the same variable to string
# literals.

_IF_ELIF_STR_RE = re.compile(
    r"""
    ^\s*(?:el)?if\s+            # if or elif
    (\w+)                       # variable name
    \s*==\s*                    # ==
    (?:"([^"]+)"|'([^']+)')     # string literal (double or single quoted)
    """,
    re.VERBOSE,
)


_IF_ELIF_STR_IMPL = _IF_ELIF_STR_RE
_DISPATCH_LINES_IMPL = split_lines

def _extract_if_elif_tables_from_source(
    source: str,
    file: str,
) -> list[DispatchTable]:
    """Find if/elif chains comparing a variable to string literals."""
    tables: list[DispatchTable] = []
    native_lines = type(source) is str and split_lines is _DISPATCH_LINES_IMPL
    # Every default-pattern match includes this exact literal. Unknown
    # line providers or patterns retain their full scan operations.
    if native_lines and _IF_ELIF_STR_RE is _IF_ELIF_STR_IMPL and "if" not in source:
        return tables
    lines = split_lines(source)
    i = 0
    while i < len(lines):
        m = _IF_ELIF_STR_RE.match(lines[i])
        if m and not lines[i].lstrip().startswith("elif"):
            var_name = m.group(1)
            keys: set[str] = {m.group(2) or m.group(3)}
            start_line = i + 1  # 1-indexed
            # The native head line is immutable throughout this body scan.
            head_indent = len(lines[i]) - len(lines[i].lstrip()) if native_lines else None
            j = i + 1
            while j < len(lines):
                m2 = _IF_ELIF_STR_RE.match(lines[j])
                if (m2 and lines[j].lstrip().startswith("elif")
                        and m2.group(1) == var_name):
                    keys.add(m2.group(2) or m2.group(3))
                    j += 1
                    continue
                stripped = lines[j].lstrip()
                if stripped.startswith(("elif", "else")):
                    if not (m2 and m2.group(1) == var_name):
                        break
                    j += 1
                    continue
                if_indent = (head_indent if head_indent is not None
                             else len(lines[i]) - len(lines[i].lstrip()))
                cur_indent = len(lines[j]) - len(stripped if native_lines else lines[j].lstrip())
                if cur_indent <= if_indent and stripped:
                    break
                j += 1
            if len(keys) >= 2:
                func = _find_enclosing_function(lines, i)
                tables.append(
                    DispatchTable(
                        file=file,
                        function=func,
                        line=start_line,
                        keys=keys,
                        table_type="if_elif",
                    )
                )
            i = j
        else:
            i += 1
    return tables


# ---------------------------------------------------------------------------
# Producer-site scanning
# ---------------------------------------------------------------------------


def _find_string_producers(
    tree: ast.Module,
    _file: str,
) -> list[tuple[str, int]]:
    """Find string literals produced in the source that might be keys.

    We look for:
    - String constants in return statements.
    - String constants on the RHS of assignments.
    - String constants in list/set/tuple literals assigned to variables.

    Returns (value, line) pairs.
    """
    producers: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                producers.append((node.value.value, node.lineno))
        elif isinstance(node, ast.Assign) or (isinstance(node, ast.AnnAssign) and node.value is not None):
            _collect_string_constants(node.value, producers)  # type: ignore[arg-type]
    return producers


def _collect_string_constants(
    node: ast.AST,
    out: list[tuple[str, int]],
) -> None:
    """Recursively collect string constants from an expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append((node.value, node.lineno))
    elif isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        for elt in node.elts:
            _collect_string_constants(elt, out)
    elif isinstance(node, ast.Dict):
        for k in node.keys:
            if k is not None:
                _collect_string_constants(k, out)
        for v in node.values:
            _collect_string_constants(v, out)


# ---------------------------------------------------------------------------
# Cross-reference: find gaps
# ---------------------------------------------------------------------------


def _find_string_producers_ts(
    file_path: str,
    source: str,
) -> list[tuple[str, int]]:
    """Find string producer sites via tree-sitter for non-Python files."""
    if file_path.endswith(".py"):
        return []
    try:
        from .ts_extract import extract_string_literals
    except ImportError:
        return []

    lits = extract_string_literals(file_path, source)
    if lits is None:
        return []

    return [
        (lit.value, lit.line)
        for lit in lits
        if lit.context in ("return", "assignment", "dict_key")
        and lit.value and not any(c in lit.value for c in " \t\n\r")
    ]


def _extract_dispatch_tables_ts(
    file_path: str,
    source: str,
) -> list[DispatchTable]:
    """Extract dispatch tables via tree-sitter for non-Python files."""
    if file_path.endswith(".py"):
        return []
    try:
        from .ts_extract import extract_dispatch_tables as _ts_tables
    except ImportError:
        return []

    ts_result = _ts_tables(file_path, source)
    if ts_result is None:
        return []

    return [
        DispatchTable(
            file=t.file,
            function=t.function,
            line=t.line,
            keys=set(t.keys),
            table_type=t.table_type,
        )
        for t in ts_result
    ]


def _site_prefixes(
    sites: list[tuple[str, int]], file: str,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Select 3 same-file and 2 other sites from native file-sorted groups.

    Phase 1 visits sorted native paths, so each producer's site list is
    grouped in that same order. Lines within a group retain producer order.
    """
    lower = bisect_left(sites, file, key=lambda site: site[0])
    upper = bisect_right(sites, file, key=lambda site: site[0])
    same = sites[lower:min(lower + 3, upper)]
    other = sites[:min(2, lower)]
    if len(other) < 2:
        other += sites[upper:upper + 2 - len(other)]
    return same, other


def _table_affix_index(table: DispatchTable, native_sites: bool):
    """Build a table-local lookup only across closed native callback seams."""
    if (native_sites
            and type is _AFFIX_TYPE_IMPL and str is _AFFIX_STR_IMPL
            and int is _AFFIX_INT_IMPL and len is _AFFIX_LEN_IMPL
            and all is _AFFIX_ALL_IMPL and set is _AFFIX_SET_IMPL
            and min is _AFFIX_MIN_IMPL
            and type(table) is _AFFIX_TABLE_IMPL
            and _AFFIX_TABLE_IMPL.__bases__ is _AFFIX_TABLE_BASES
            and _AFFIX_TABLE_IMPL.__dict__.get('__getattribute__') is None
            and _AFFIX_TABLE_IMPL.__dict__.get('__getattr__') is None
            and _AFFIX_TABLE_IMPL.__dict__.get('file') is None
            and _AFFIX_TABLE_IMPL.__dict__.get('keys') is None
            and type(table.file) is str and type(table.keys) is set
            and len(table.keys) >= 32
            and _shares_affix is _AFFIX_CHECK_IMPL
            and _shares_affix.__defaults__ is _AFFIX_DEFAULTS
            and _shares_affix.__code__ is _AFFIX_CHECK_CODE
            and _site_prefixes is _AFFIX_SITES_IMPL
            and _site_prefixes.__code__ is _AFFIX_SITES_CODE
            and bisect_left is _AFFIX_BISECT_LEFT
            and bisect_right is _AFFIX_BISECT_RIGHT
            and DispatchGap is _AFFIX_GAP_IMPL
            and DispatchGap.__bases__ is _AFFIX_GAP_BASES
            and DispatchGap.__dict__.get('__init__') is _AFFIX_GAP_INIT
            and _AFFIX_GAP_INIT.__code__ is _AFFIX_GAP_INIT_CODE
            and DispatchGap.__dict__.get('__new__') is _AFFIX_GAP_NEW
            and DispatchGap.__dict__.get('__setattr__') is _AFFIX_GAP_SETATTR
            and all(DispatchGap.__dict__.get(name) is None for name in (
                '__getattribute__', '__getattr__', '__del__',
                'table', 'missing_key', 'produced_by', 'confidence',
            ))
            and all(type(key) is str for key in table.keys)):
        prefixes: set[str] = set()
        suffixes: set[str] = set()
        for key in table.keys:
            if len(key) >= 3:
                prefixes.add(key[:3])
                suffixes.add(key[-3:])
        return prefixes, suffixes
    return None


def find_dispatch_gaps(
    call_graphs: dict[str, object],
    source_texts: dict[str, str] | None = None,
    target_root: Path | str | None = None,
) -> list[DispatchGap]:
    """Find dispatch-table keys that are produced but never handled.

    Args:
        call_graphs: Mapping of file path to call-graph data (currently
            unused beyond identifying which files to scan — the actual
            analysis is AST-based).  Keys are file paths.
        source_texts: Optional mapping of file path to source code.
            When provided, avoids re-reading files from disk.  When
            absent, falls back to reading each file from ``call_graphs``
            keys.
        target_root: The run's source root.  Disk fallback reads are
            confined to it (symlink-aware); without it there is no
            disk fallback at all — a bare relative read would resolve
            against the process CWD, never the scanned target — so
            files absent from ``source_texts`` read as unavailable.

    Returns:
        List of ``DispatchGap`` instances describing produced-but-
        unhandled keys.
    """
    files = set(call_graphs.keys())
    if source_texts:
        files |= set(source_texts.keys())

    # Native path sorting also orders producer-site groups for binary search.
    # Foreign path adapters retain the original equality-based scans.
    native_paths = all(type(path) is str for path in files)

    # Phase 1: collect dispatch tables and producer sites.
    all_tables: list[DispatchTable] = []
    all_producers: dict[str, list[tuple[str, int]]] = {}  # file -> [(val, line)]

    for fpath in sorted(files):
        source = _get_source(fpath, source_texts, target_root)
        if source is None:
            continue

        if fpath.endswith(".py"):
            # Python: stdlib AST is richer (dict literals, match, producers)
            try:
                tree = ast.parse(source, filename=fpath)
            except SyntaxError:
                logger.debug("dispatch_completeness: skipping %s (syntax error)", fpath)
                continue
            parents = _build_parent_map(tree)
            all_tables.extend(_extract_dict_tables(tree, parents, fpath))
            all_tables.extend(_extract_match_tables(tree, parents, fpath))
            all_tables.extend(_extract_if_elif_tables_from_source(source, fpath))
            all_producers[fpath] = _find_string_producers(tree, fpath)
        else:
            # Non-Python: tree-sitter primary for switch/case tables
            all_tables.extend(_extract_dispatch_tables_ts(fpath, source))
            # Regex if/elif detection as fallback
            all_tables.extend(_extract_if_elif_tables_from_source(source, fpath))
            # Tree-sitter string producers for cross-reference
            ts_producers = _find_string_producers_ts(fpath, source)
            if ts_producers:
                all_producers[fpath] = ts_producers

    # Phase 2: cross-reference.  For each table, check whether any
    # producer in the codebase yields a key the table doesn't handle.
    gaps: list[DispatchGap] = []
    all_produced: dict[str, list[tuple[str, int]]] = {}
    native_affix_sites = (
        _AFFIX_TYPE_IMPL(native_paths) is _AFFIX_BOOL_IMPL and native_paths
        and _AFFIX_TYPE_IMPL(files) is _AFFIX_SET_IMPL
        and _AFFIX_ALL_IMPL(_AFFIX_TYPE_IMPL(path) is _AFFIX_STR_IMPL for path in files)
    )
    for fpath, prods in all_producers.items():
        for val, lineno in prods:
            if native_affix_sites and (
                _AFFIX_TYPE_IMPL(val) is not _AFFIX_STR_IMPL
                or _AFFIX_TYPE_IMPL(lineno) is not _AFFIX_INT_IMPL
            ):
                native_affix_sites = False
            all_produced.setdefault(val, []).append((fpath, lineno))

    # Pre-index produced keys by shape for fast intersection.
    produced_by_shape: dict[str, list[str]] = {}
    for key in all_produced:
        if key and not any(c in key for c in " \t\n\r"):
            produced_by_shape.setdefault(_key_shape(key), []).append(key)

    # Per-table gap cap: if a single table generates more gaps than
    # this, the detector is clearly matching noise — discard all of them.
    max_gaps_per_table = 50

    for table in all_tables:
        # Pre-compute acceptable shapes and length bounds for this table.
        table_shapes = {_key_shape(k) for k in table.keys}
        lengths = sorted(len(k) for k in table.keys)
        median_len = lengths[len(lengths) // 2] if lengths else 0
        if median_len == 0:
            continue
        min_len = median_len / 3
        max_len = median_len * 3

        # Only iterate produced keys with matching shapes.
        candidates: set[str] = set()
        for shape in table_shapes:
            for key in produced_by_shape.get(shape, []):
                if min_len <= len(key) <= max_len:
                    candidates.add(key)

        # Fully handled tables never need an affix index.
        affix_index = None
        affix_pending = True

        table_gaps: list[DispatchGap] = []
        for produced_key in candidates:
            if produced_key in table.keys:
                continue
            if affix_pending:
                affix_index = _table_affix_index(table, native_affix_sites)
                affix_pending = False
            sites = all_produced[produced_key]
            # Prefer same-file sites (high confidence), cap total sites
            # to avoid combinatorial explosion on repetitive codebases.
            # Direct scans win on tiny lists; larger native groups pay for
            # binary search without full-list copies or a second site index.
            if len(sites) >= 32 and native_paths and type(table.file) is str:
                same_file, other = _site_prefixes(sites, table.file)
            else:
                same_file = [(f, ln) for f, ln in sites if f == table.file]
                other = [(f, ln) for f, ln in sites if f != table.file]

            # Cross-file relatedness gate: only emit cross-file gaps when
            # the produced key shares a prefix or suffix (>= 3 chars) with
            # at least one existing table key.  This filters unrelated
            # strings from different modules (e.g. 'mysql_query' from
            # cwe_dispatch.py against attacker_synthesis.py:to_dict).
            has_affix = None
            if affix_index is not None:
                has_affix = len(produced_key) >= 3 and (
                    produced_key[:3] in affix_index[0]
                    or produced_key[-3:] in affix_index[1]
                )
            if not same_file and not (
                has_affix if has_affix is not None
                else _shares_affix(produced_key, table.keys)
            ):
                continue

            # For cross-file sites, also require the affix check.
            selected_same = same_file[:3] if same_file else []
            selected_other = other[:2] if (
                has_affix if has_affix is not None
                else _shares_affix(produced_key, table.keys)
            ) else []
            selected = selected_same + selected_other
            if not selected:
                continue

            for site_file, site_line in selected:
                confidence = (
                    "high" if site_file == table.file else "medium"
                )
                table_gaps.append(
                    DispatchGap(
                        table=table,
                        missing_key=produced_key,
                        produced_by=f"{site_file}:{site_line}",
                        confidence=confidence,
                    )
                )

        # If a single table generates too many gaps, it is matching noise.
        if len(table_gaps) <= max_gaps_per_table:
            gaps.extend(table_gaps)
        else:
            logger.debug(
                "dispatch_completeness: dropping %d gaps for table %s:%s "
                "(exceeds per-table cap of %d)",
                len(table_gaps), table.file, table.function,
                max_gaps_per_table,
            )

    return gaps


def _shares_affix(candidate: str, existing_keys: set[str], min_affix: int = 3) -> bool:
    """Does *candidate* share a prefix or suffix with any key in the table?

    Catches legitimate missed enum cases (``'status_pending'`` not handled
    when ``'status_active'`` is) while rejecting unrelated strings from
    different modules (``'mysql_query'`` against an attacker-synthesis table).
    """
    native_candidate = (type(candidate) is str and type(min_affix) is int
                        and min_affix > 0)
    if native_candidate:
        prefix = candidate[:min_affix]
        suffix = candidate[-min_affix:]
        enough_chars = len(candidate) >= min_affix
    for key in existing_keys:
        if native_candidate and type(key) is str:
            # Only the required boundary characters establish an affix;
            # a longer common prefix/suffix cannot change the verdict.
            if (enough_chars and len(key) >= min_affix
                    and (key.startswith(prefix) or key.endswith(suffix))):
                return True
            continue
        # Shared prefix
        prefix_len = 0
        for a, b in zip(candidate, key):
            if a == b:
                prefix_len += 1
            else:
                break
        if prefix_len >= min_affix:
            return True
        # Shared suffix
        suffix_len = 0
        for a, b in zip(reversed(candidate), reversed(key)):
            if a == b:
                suffix_len += 1
            else:
                break
        if suffix_len >= min_affix:
            return True
    return False


_AFFIX_CHECK_IMPL = _shares_affix
_AFFIX_DEFAULTS = _shares_affix.__defaults__
_AFFIX_CHECK_CODE = _shares_affix.__code__
_AFFIX_SITES_IMPL = _site_prefixes
_AFFIX_SITES_CODE = _site_prefixes.__code__
_AFFIX_BISECT_LEFT = bisect_left
_AFFIX_BISECT_RIGHT = bisect_right
_AFFIX_TYPE_IMPL = type
_AFFIX_BOOL_IMPL = bool
_AFFIX_STR_IMPL = str
_AFFIX_INT_IMPL = int
_AFFIX_LEN_IMPL = len
_AFFIX_ALL_IMPL = all
_AFFIX_SET_IMPL = set
_AFFIX_MIN_IMPL = min
_AFFIX_TABLE_IMPL = DispatchTable
_AFFIX_TABLE_BASES = DispatchTable.__bases__
_AFFIX_GAP_IMPL = DispatchGap
_AFFIX_GAP_BASES = DispatchGap.__bases__
_AFFIX_GAP_INIT = DispatchGap.__dict__.get('__init__')
_AFFIX_GAP_INIT_CODE = _AFFIX_GAP_INIT.__code__
_AFFIX_GAP_NEW = DispatchGap.__dict__.get('__new__')
_AFFIX_GAP_SETATTR = DispatchGap.__dict__.get('__setattr__')


def _key_shape(key: str) -> str:
    """Classify a key's shape: 'lower', 'upper', 'title', 'mixed'."""
    if key.islower() or ("_" in key and key.replace("_", "").islower()):
        return "lower"
    if key.isupper() or ("_" in key and key.replace("_", "").isupper()):
        return "upper"
    if len(key) > 1 and key[0].isupper() and key[1:].islower():
        return "title"
    return "mixed"


def _get_source(
    fpath: str,
    source_texts: dict[str, str] | None,
    target_root: Path | str | None = None,
) -> str | None:
    """Get source for a file, preferring the in-memory dict."""
    # Path traversal guard: fpath originates from call_graphs.keys() which
    # is untrusted when scanning adversarial codebases.
    if ".." in fpath.split("/") or fpath.startswith("/"):
        logger.warning("_get_source: path traversal rejected: %r", fpath)
        return None
    if source_texts and fpath in source_texts:
        return source_texts[fpath]
    if target_root is None:
        # No root to confine against: a bare Path(fpath) would resolve
        # relative to the process CWD — the tool's own repo dir, never
        # the scanned target. Source-unavailable, not a CWD read.
        logger.debug(
            "_get_source: no target root — skipping disk fallback "
            "for %r", fpath,
        )
        return None
    # Symlink-aware containment: the lexical guard above cannot
    # catch an in-repo symlink pointing outside the tree.
    from core.paths import confine

    full = confine(target_root, fpath)
    if full is None:
        logger.warning(
            "_get_source: refusing path outside target root: %r",
            fpath,
        )
        return None
    # Capped like every migrated core/audit sibling: unbounded
    # f.read() let a planted multi-hundred-MB file cost its full
    # size in peak memory. Refuse the truncated prefix outright —
    # dispatch-arm analysis over a partial file would mint
    # missing-case hypotheses about arms the cap cut off.
    from core.source import read_text_capped
    got = read_text_capped(full, errors="replace")
    if got is None:
        return None
    text, truncated = got
    if truncated:
        logger.debug(
            "_get_source: %r exceeds the source read cap — "
            "skipping dispatch analysis for it", fpath,
        )
        return None
    return text
