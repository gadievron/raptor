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
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ._util import find_enclosing_function as _find_enclosing_function

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
    keys: Set[str]
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


def _enclosing_function(node: ast.AST, parents: Dict[int, ast.AST]) -> str:
    """Walk up the parent map to find the nearest enclosing function."""
    cur = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = parents.get(id(cur))
    return "<module>"


def _build_parent_map(tree: ast.Module) -> Dict[int, ast.AST]:
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _string_keys_from_dict(node: ast.Dict) -> Set[str]:
    """Extract string literal keys from an ast.Dict."""
    keys: Set[str] = set()
    for k in node.keys:
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
    return keys


def _dict_is_dispatch(
    node: ast.Dict,
    parents: Dict[int, ast.AST],
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
    # Check if at least one value looks callable (Name, Attribute, Lambda,
    # Call, or another non-constant expression).
    for v in node.values:
        if isinstance(v, (ast.Name, ast.Attribute, ast.Lambda)):
            return True
    return False


def _extract_dict_tables(
    tree: ast.Module,
    parents: Dict[int, ast.AST],
    file: str,
) -> List[DispatchTable]:
    """Find dict-literal dispatch tables in the AST."""
    tables: List[DispatchTable] = []
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
    parents: Dict[int, ast.AST],
    file: str,
) -> List[DispatchTable]:
    """Find match/case statements dispatching on string values."""
    tables: List[DispatchTable] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Match):
            continue
        keys: Set[str] = set()
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


def _collect_match_strings(pattern: ast.pattern, out: Set[str]) -> None:
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


def _extract_if_elif_tables_from_source(
    source: str,
    file: str,
) -> List[DispatchTable]:
    """Find if/elif chains comparing a variable to string literals."""
    tables: List[DispatchTable] = []
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = _IF_ELIF_STR_RE.match(lines[i])
        if m and not lines[i].lstrip().startswith("elif"):
            var_name = m.group(1)
            keys: Set[str] = {m.group(2) or m.group(3)}
            start_line = i + 1  # 1-indexed
            j = i + 1
            while j < len(lines):
                m2 = _IF_ELIF_STR_RE.match(lines[j])
                if m2 and lines[j].lstrip().startswith("elif"):
                    if m2.group(1) == var_name:
                        keys.add(m2.group(2) or m2.group(3))
                        j += 1
                        continue
                stripped = lines[j].lstrip()
                if stripped.startswith("elif") or stripped.startswith("else"):
                    if not (m2 and m2.group(1) == var_name):
                        break
                    j += 1
                    continue
                if_indent = len(lines[i]) - len(lines[i].lstrip())
                cur_indent = len(lines[j]) - len(lines[j].lstrip())
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
    file: str,
) -> List[Tuple[str, int]]:
    """Find string literals produced in the source that might be keys.

    We look for:
    - String constants in return statements.
    - String constants on the RHS of assignments.
    - String constants in list/set/tuple literals assigned to variables.

    Returns (value, line) pairs.
    """
    producers: List[Tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                producers.append((node.value.value, node.lineno))
        elif isinstance(node, ast.Assign):
            _collect_string_constants(node.value, producers)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _collect_string_constants(node.value, producers)
    return producers


def _collect_string_constants(
    node: ast.AST,
    out: List[Tuple[str, int]],
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
) -> List[Tuple[str, int]]:
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
) -> List[DispatchTable]:
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


def find_dispatch_gaps(
    call_graphs: Dict[str, object],
    source_texts: Optional[Dict[str, str]] = None,
) -> List[DispatchGap]:
    """Find dispatch-table keys that are produced but never handled.

    Args:
        call_graphs: Mapping of file path to call-graph data (currently
            unused beyond identifying which files to scan — the actual
            analysis is AST-based).  Keys are file paths.
        source_texts: Optional mapping of file path to source code.
            When provided, avoids re-reading files from disk.  When
            absent, falls back to reading each file from ``call_graphs``
            keys.

    Returns:
        List of ``DispatchGap`` instances describing produced-but-
        unhandled keys.
    """
    files = set(call_graphs.keys())
    if source_texts:
        files |= set(source_texts.keys())

    # Phase 1: collect dispatch tables and producer sites.
    all_tables: List[DispatchTable] = []
    all_producers: Dict[str, List[Tuple[str, int]]] = {}  # file -> [(val, line)]

    for fpath in sorted(files):
        source = _get_source(fpath, source_texts)
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
    gaps: List[DispatchGap] = []
    all_produced: Dict[str, List[Tuple[str, int]]] = {}
    for fpath, prods in all_producers.items():
        for val, lineno in prods:
            all_produced.setdefault(val, []).append((fpath, lineno))

    # Pre-index produced keys by shape for fast intersection.
    produced_by_shape: Dict[str, List[str]] = {}
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
        candidates: Set[str] = set()
        for shape in table_shapes:
            for key in produced_by_shape.get(shape, []):
                if min_len <= len(key) <= max_len:
                    candidates.add(key)

        table_gaps: List[DispatchGap] = []
        for produced_key in candidates:
            if produced_key in table.keys:
                continue
            sites = all_produced[produced_key]
            # Prefer same-file sites (high confidence), cap total sites
            # to avoid combinatorial explosion on repetitive codebases.
            same_file = [(f, ln) for f, ln in sites if f == table.file]
            other = [(f, ln) for f, ln in sites if f != table.file]

            # Cross-file relatedness gate: only emit cross-file gaps when
            # the produced key shares a prefix or suffix (>= 3 chars) with
            # at least one existing table key.  This filters unrelated
            # strings from different modules (e.g. 'mysql_query' from
            # cwe_dispatch.py against attacker_synthesis.py:to_dict).
            if not same_file and not _shares_affix(produced_key, table.keys):
                continue

            # For cross-file sites, also require the affix check.
            if same_file:
                selected_same = same_file[:3]
            else:
                selected_same = []
            selected_other = other[:2] if _shares_affix(produced_key, table.keys) else []
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


def _key_looks_related(candidate: str, existing_keys: Set[str]) -> bool:
    """Heuristic: does *candidate* look like it belongs in *existing_keys*?

    We require:
    - Candidate is non-empty and doesn't contain spaces (dispatch keys
      are typically identifiers or short tokens).
    - Candidate length is within 3x of the median existing key length.
    - Candidate shares the same "shape" as at least one existing key
      (all-lowercase, snake_case, etc.).
    """
    if not candidate or " " in candidate:
        return False
    if not existing_keys:
        return False
    lengths = sorted(len(k) for k in existing_keys)
    median_len = lengths[len(lengths) // 2]
    if median_len == 0:
        return False
    if len(candidate) > median_len * 3 or len(candidate) < median_len / 3:
        return False
    # Shape check: does the candidate match the general character
    # pattern of at least one existing key?
    cand_shape = _key_shape(candidate)
    return any(_key_shape(k) == cand_shape for k in existing_keys)


def _shares_affix(candidate: str, existing_keys: Set[str], min_affix: int = 3) -> bool:
    """Does *candidate* share a prefix or suffix with any key in the table?

    Catches legitimate missed enum cases (``'status_pending'`` not handled
    when ``'status_active'`` is) while rejecting unrelated strings from
    different modules (``'mysql_query'`` against an attacker-synthesis table).
    """
    for key in existing_keys:
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


def _key_shape(key: str) -> str:
    """Classify a key's shape: 'lower', 'upper', 'mixed', 'other'."""
    if key.islower() or ("_" in key and key.replace("_", "").islower()):
        return "lower"
    if key.isupper() or ("_" in key and key.replace("_", "").isupper()):
        return "upper"
    if len(key) > 1 and key[0].isupper() and key[1:].islower():
        return "title"
    return "mixed"


def _get_source(
    fpath: str,
    source_texts: Optional[Dict[str, str]],
) -> Optional[str]:
    """Get source for a file, preferring the in-memory dict."""
    # Path traversal guard: fpath originates from call_graphs.keys() which
    # is untrusted when scanning adversarial codebases.
    if ".." in fpath.split("/") or fpath.startswith("/"):
        logger.warning("_get_source: path traversal rejected: %r", fpath)
        return None
    if source_texts and fpath in source_texts:
        return source_texts[fpath]
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None
