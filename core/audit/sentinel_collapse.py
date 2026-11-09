"""Detect sentinel-value confusion bugs in source code.

Finds patterns where two semantically distinct states (e.g. "failed"
vs "empty", "unknown" vs "none") collapse into the same value when
compared or coerced.  Real bugs this catches:

- ``list(cached) if cached else []`` collapses None (fetch-failed)
  into [] (no-deps)
- ``except: return {}`` indistinguishable from a success ``return {}``
- ``cache[key] = None`` for errors, then ``cached or default``
  erases the failure signal
- Cross-function: A returns None on error AND not-found, caller B
  does ``result or []``, downstream treats [] as authoritative

Supports Python (AST + regex), Go (tree-sitter return-semantics with
a regex fallback, plus a regex-only map-miss check) and JS/TS (regex
patterns, with tree-sitter function attribution when available).
"""

from __future__ import annotations

import ast
import logging
import re
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass
from itertools import chain, islice
from typing import Any, Iterator, cast
from core.source.lines import iter_source_lines, split_lines
from core.source.line_index import LineSpanIndex

from .run_memo import BoundedMemo

logger = logging.getLogger(__name__)

_SENTINEL_LINES_IMPL = split_lines
_FORWARD_TYPE_IMPL = type
_FORWARD_LEN_IMPL = len
_FORWARD_MIN_IMPL = min
_FORWARD_RANGE_IMPL = range
_FORWARD_ENUM_IMPL = enumerate
_FORWARD_RE_SEARCH_IMPL = re.search
_FORWARD_RE_ESCAPE_IMPL = re.escape

_SENTINEL_PY_DEF_RE = re.compile(r"\s*(?:async\s+)?def\s+(\w+)\s*\(")
_SENTINEL_GO_DEF_RE = re.compile(r"\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")
_SENTINEL_GO_NIL_PAIR_RE = re.compile(r"return\s+nil\s*,\s*nil\b")
_SENTINEL_PY_INDENT_DEF_RE = re.compile(r"(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
_FORWARD_PY_HEADER_IMPL = _SENTINEL_PY_INDENT_DEF_RE
_FORWARD_GO_HEADER_IMPL = _SENTINEL_GO_DEF_RE


@dataclass
class SentinelCollapse:
    """A location where distinct semantic states merge."""

    file: str
    function: str
    line: int
    write_value: str
    read_coercion: str
    semantic_loss: str
    confidence: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "write_value": self.write_value,
            "read_coercion": self.read_coercion,
            "semantic_loss": self.semantic_loss,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Sub-detector (a): falsy coercion on Optional
# ---------------------------------------------------------------------------

# Patterns where a variable is coerced through a falsy check and
# replaced with an empty container, collapsing None into []/{}/""/0.
# The variable groups are \b-pinned to a word START: an unanchored
# bare `\w+` re-scans a hostile identifier run from every offset
# (quadratic), and the dropped matches are only mid-word suffixes
# (`x1f` inside `0x1f`) — false tokens, never real variables.
_FALSY_COERCION_PATTERNS: list[re.Pattern[str]] = [
    # x if x else []  /  x if x else {}
    re.compile(
        r"""\b(?P<var>\w+)\s+if\s+(?P=var)\s+else\s+(?P<default>\[\]|\{\})""",
    ),
    # x or []  /  x or {}
    re.compile(
        r"""\b(?P<var>\w+)\s+or\s+(?P<default>\[\]|\{\})""",
    ),
    # list(x) if x else []  /  dict(x) if x else {}
    re.compile(
        r"""(?:list|dict)\((?P<var>\w+)\)\s+if\s+(?P=var)\s+else\s+(?P<default>\[\]|\{\})""",
    ),
]

_FALSY_COERCION_IMPLS = tuple(_FALSY_COERCION_PATTERNS)


def _detect_falsy_coercion(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []
    current_func = "<module>"
    streaming = type(source) is str and split_lines is _SENTINEL_LINES_IMPL
    lines = iter_source_lines(source) if streaming else split_lines(source)
    recent: deque[str] | None = deque(maxlen=4) if streaming else None

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        if recent is not None:
            recent.append(line)
        func_match = _SENTINEL_PY_DEF_RE.match(line)
        if func_match:
            current_func = func_match.group(1)
            continue

        if (
            type(line) is str and "or" not in line and "else" not in line
            and type(_FALSY_COERCION_PATTERNS) is list
            and len(_FALSY_COERCION_PATTERNS) == 3
            and _FALSY_COERCION_PATTERNS[0] is _FALSY_COERCION_IMPLS[0]
            and _FALSY_COERCION_PATTERNS[1] is _FALSY_COERCION_IMPLS[1]
            and _FALSY_COERCION_PATTERNS[2] is _FALSY_COERCION_IMPLS[2]
        ):
            continue

        for pat in _FALSY_COERCION_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            var_name = m.group("var")
            # Skip if the SAME variable is guarded by ``is not None``
            # in the preceding 3-line window
            window_start = max(0, lineno_0 - 3)
            window = "\n".join(
                recent if recent is not None else cast(list[str], lines)[window_start:lineno_0 + 1]
            )
            guarded = re.search(
                rf"\bif\s+{re.escape(var_name)}\s+is\s+not\s+None\b",
                window,
            )
            if guarded:
                break
            results.append(SentinelCollapse(
                file=path,
                function=current_func,
                line=lineno,
                write_value="None",
                read_coercion=m.group(0),
                semantic_loss=f"None (error/missing) vs {m.group('default')} (empty)",
                confidence="medium",
            ))
            break

    return results


# ---------------------------------------------------------------------------
# Sub-detector (b): except returning same value as success
# ---------------------------------------------------------------------------
# Delegates to fail_open_detector._detect_error_conflated_with_empty which
# is more comprehensive (covers None, True, False, "", 0 in addition to
# [] and {}). Results are re-wrapped as SentinelCollapse for API consistency.


def _detect_except_same_as_success(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    from .fail_open_detector import _detect_error_conflated_with_empty

    results: list[SentinelCollapse] = [SentinelCollapse(
            file=fop.file,
            function=fop.function,
            line=fop.line,
            write_value="except: return (same literal)",
            read_coercion="success also returns same literal",
            semantic_loss="error vs legitimate-empty both return same value",
            confidence="high",
        ) for fop in _detect_error_conflated_with_empty(path, source)]
    return results


# ---------------------------------------------------------------------------
# Sub-detector (c): cache sentinel patterns
# ---------------------------------------------------------------------------

# cache[key] = None  /  cache.set(key, None)
# The base name must LOOK like a cache: the comment above ("does the
# function both write None to a cache-like name...") was the intent,
# but a bare \w+ matched ANY subscript assignment — results[i] = None,
# row["col"] = None — flagging ordinary dict bookkeeping whenever the
# function also coerced any read.
_CACHE_NAME = r"\w*(?:cache|cached|memo|lru)\w*"
_CACHE_WRITE_NONE = re.compile(
    r"""(?:(?P<cache>{name})\[.+\]\s*=\s*None"""
    r"""|(?P<cache2>{name})\.set\(.+,\s*None\))""".format(name=_CACHE_NAME),
    re.IGNORECASE,
)

# cached or default  /  cached if cached else default
# Both variable groups \b-pinned (see _FALSY_COERCION_PATTERNS).
_CACHE_READ_COERCE = re.compile(
    r"""\b(?P<var>\w+)\s+or\s+(?P<default>\[\]|\{\}|0|""|'')"""
    r"""|\b(?P<var2>\w+)\s+if\s+(?P=var2)\s+else\s+(?P<default2>\[\]|\{\}|0|""|'')""",
)


_CACHE_WRITE_IMPL = _CACHE_WRITE_NONE
_CACHE_READ_IMPL = _CACHE_READ_COERCE


def _detect_cache_sentinel(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []
    lines = (
        iter_source_lines(source)
        if type(source) is str and split_lines is _SENTINEL_LINES_IMPL
        else split_lines(source)
    )
    current_func = "<module>"

    # Collect per-function evidence: does the function both write None
    # to a cache-like name AND later coerce the read?
    func_has_write_none = False
    func_coercion_sites: list[tuple[int, str]] = []

    def _flush() -> None:
        if func_has_write_none and func_coercion_sites:
            lineno, coercion = func_coercion_sites[0]
            results.append(SentinelCollapse(
                file=path,
                function=current_func,
                line=lineno,
                write_value="None (cache write)",
                read_coercion=coercion,
                semantic_loss="cached-failure vs cached-empty",
                confidence="medium",
            ))

    for lineno, line in enumerate(lines, 1):
        func_match = _SENTINEL_PY_DEF_RE.match(line)
        if func_match:
            _flush()
            current_func = func_match.group(1)
            func_has_write_none = False
            func_coercion_sites = []
            continue

        # The case-insensitive write regex needs either a subscript
        # assignment (`[` and `=`) or a setter call (`(`).
        if (
            (type(line) is not str or "(" in line or ("[" in line and "=" in line)
             or _CACHE_WRITE_NONE is not _CACHE_WRITE_IMPL)
            and _CACHE_WRITE_NONE.search(line)
        ):
            func_has_write_none = True

        native_read = type(line) is str and _CACHE_READ_COERCE is _CACHE_READ_IMPL
        if native_read and "or" not in line and "else" not in line:
            continue
        m = _CACHE_READ_COERCE.search(line)
        if m and (not func_coercion_sites or not native_read):
            # Only the first site is reported. Retain all custom-provider
            # matches as before, including their group calls and lifetimes.
            func_coercion_sites.append((lineno, m.group(0)))

    _flush()
    return results


# ---------------------------------------------------------------------------
# Sub-detector (d): Go sentinel confusion
# ---------------------------------------------------------------------------

# func returns (nil, err) but caller only checks err, not nil-vs-not-found
# The block body is bounded: unbounded `[^}]*` re-scans a hostile
# brace-free run from every `if err != nil {` occurrence — quadratic.
# A real error-check block sits far under 4000 chars; beyond the
# bound the block stops matching instead of scanning without bound.
_GO_NIL_RETURN_ON_ERR = re.compile(
    r"\bif\s+err\s*!=\s*nil\s*\{[^}]{0,4000}return\s+nil\b",
    re.DOTALL,
)
# caller ignores ok: val := cache[key]  (no comma-ok)
_GO_MAP_NO_OK = re.compile(
    r"\b(\w+)\s*:=\s*(\w+)\[",
)
# caller coerces nil: if val == nil { val = defaultVal }
_GO_NIL_COERCE = re.compile(
    r"\bif\s+(\w+)\s*==\s*nil\s*\{[^}]*\1\s*=",
    re.DOTALL,
)


_FORWARD_GO_MAP_IMPL = _GO_MAP_NO_OK
_FORWARD_GO_COERCE_IMPL = _GO_NIL_COERCE


def _lines_with_pending(lines, pending):
    """Replay prefetched native rows before advancing the source iterator."""
    for line in lines:
        yield line
        while pending:
            yield pending.popleft()


def _forward_window(line, lines, pending):
    """Prepare five rows only when a candidate needs forward context."""
    pending.extend(islice(lines, 4 - len(pending)))
    return chain((line,), pending)


def _detect_go_sentinel(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []

    # --- tree-sitter path: return-semantics extraction ---
    try:
        from .ts_extract import extract_function_returns
        ts_returns = extract_function_returns(path, source)
    except ImportError:
        ts_returns = None

    if ts_returns is not None:
        results.extend(SentinelCollapse(
                    file=path,
                    function=fr.function,
                    line=fr.returns[0].line if fr.returns else 1,
                    write_value="nil",
                    read_coercion="returns nil on both error and not-found",
                    semantic_loss="error-nil vs not-found-nil are indistinguishable "
                                  "to callers",
                    confidence="high",
                ) for fr in ts_returns if fr.sentinel_ambiguous)

    # --- regex path for map-without-comma-ok (no tree-sitter equivalent) ---
    streaming = (ts_returns is not None and _FORWARD_TYPE_IMPL(source) is str
                 and split_lines is _SENTINEL_LINES_IMPL
                 and len is _FORWARD_LEN_IMPL and min is _FORWARD_MIN_IMPL
                 and enumerate is _FORWARD_ENUM_IMPL
                 and _SENTINEL_GO_DEF_RE is _FORWARD_GO_HEADER_IMPL
                 and _GO_MAP_NO_OK is _FORWARD_GO_MAP_IMPL
                 and _GO_NIL_COERCE is _FORWARD_GO_COERCE_IMPL)
    # The native map/coercion regexes require both literals. Parser
    # findings above are already complete; no line work can add a witness.
    if streaming and ("[" not in source or "nil" not in source):
        return results
    lines = [] if streaming else split_lines(source)
    source_lines = iter_source_lines(source) if streaming else None
    pending: deque[str] = deque()
    rows = _lines_with_pending(source_lines, pending) if streaming else lines
    current_func = "<module>"

    for lineno_0, line in enumerate(rows):
        lineno = lineno_0 + 1
        fm = _SENTINEL_GO_DEF_RE.match(line)
        if fm:
            current_func = fm.group(1)
            continue

        m = _GO_MAP_NO_OK.search(line)
        try:
            bracket_idx = line.index("[")
        except ValueError:
            bracket_idx = len(line)
        if m and "," not in line[:bracket_idx]:
            var_name = m.group(1)
            if streaming:
                window = "\n".join(_forward_window(line, source_lines, pending))
            else:
                window_end = min(lineno_0 + 5, len(lines))
                window = "\n".join(lines[lineno_0:window_end])
            if _GO_NIL_COERCE.search(window):
                results.append(SentinelCollapse(
                    file=path,
                    function=current_func,
                    line=lineno,
                    write_value="nil (zero value from map miss)",
                    read_coercion=f"{var_name} == nil → default",
                    semantic_loss="map-miss zero value vs explicit nil",
                    confidence="medium",
                ))

    # --- regex fallback for nil-nil if tree-sitter unavailable ---
    if ts_returns is None:
        func_starts: list[tuple[str, int]] = []
        for lineno_0, line in enumerate(lines):
            fm = _SENTINEL_GO_DEF_RE.match(line)
            if fm:
                func_starts.append((fm.group(1), lineno_0))

        for i, (fname, start) in enumerate(func_starts):
            end = func_starts[i + 1][1] if i + 1 < len(func_starts) else len(lines)
            body = "\n".join(lines[start:end])

            nil_on_err = bool(_GO_NIL_RETURN_ON_ERR.search(body))
            nil_on_success = bool(_SENTINEL_GO_NIL_PAIR_RE.search(body))
            if nil_on_err and nil_on_success:
                results.append(SentinelCollapse(
                    file=path,
                    function=fname,
                    line=start + 1,
                    write_value="nil",
                    read_coercion="returns nil on both error and not-found",
                    semantic_loss="error-nil vs not-found-nil are indistinguishable "
                                  "to callers",
                    confidence="high",
                ))

    return results


# ---------------------------------------------------------------------------
# Sub-detector (e): JS/TS sentinel confusion
# ---------------------------------------------------------------------------

# Variable group \b-pinned (see _FALSY_COERCION_PATTERNS).
_JS_OPTIONAL_CHAIN_DEFAULT = re.compile(
    r"\b(\w+)\?\.\w+\s*\|\|\s*(\[\]|\{\}|\"\")",
)

_JS_FALSY_COERCION = [
    # Optional-chain access with a falsy default (x?.y || "") — the
    # same collapse shape through a property read; also the only
    # pattern here that catches the string-default variant. Ordered
    # FIRST so the chained expression attributes to the chain root
    # (the bare-identifier patterns below would otherwise match the
    # same line as `y || []` and win with the wrong variable).
    _JS_OPTIONAL_CHAIN_DEFAULT,
    re.compile(r"\b(\w+)\s*\|\|\s*(\[\]|\{\})"),
    re.compile(r"\b(\w+)\s*\?\?\s*(\[\]|\{\})"),
]


_JS_FUNC_RE = re.compile(
    r"\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:"
    # gated generator star ((?:\s*\*)?\s+ — the \s*\*?\s+ chain
    # was quadratic on 'function' + whitespace run)
    r"function(?:\s*\*)?\s+(\w+)"                      # function name(
    r"|(?:const|let|var)\s+(\w+)\s*=\s*"
    r"(?:(?:async\s+)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>|\(?function)"  # arrow / function expr
    r"|(\w+)\s*\([^)]*\)\s*\{"             # name(...) {  (class method)
    r"|(\w+)\s*:\s*(?:async\s+)?function"  # name: function (object method)
    r")",
)


_JS_COERCION_IMPLS = tuple(_JS_FALSY_COERCION)
_JS_HEADER_IMPL = _JS_FUNC_RE
_JS_LINE_RANGE_IMPL = range
_JS_LINE_ENUM_IMPL = enumerate
# As with inventory's regex extractor, bare control-flow words are not
# claimed as method names. Keyword-named shorthand methods need the parser;
# explicit `if: function(...)` properties remain unambiguous in fallback.
_JS_CONTROL_HEADERS = frozenset({"if", "for", "while", "switch", "catch", "with"})


def _detect_js_sentinel(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []

    # Use tree-sitter for function name attribution when available
    func_name_at_line: dict[int, str] = {}
    function_spans: list[tuple[int, int, str]] = []
    # Tiny and single-line sources do not repay span indexing.
    compact_names = (
        range is _JS_LINE_RANGE_IMPL and type(source) is str
        and len(source) >= LineSpanIndex.MIN_COMPACT_LINES and "\n" in source
    )
    try:
        from .ts_extract import _parse_file, _iter_functions
        parsed = _parse_file(path, source)
        if parsed is not None:
            tree, lang, src_bytes = parsed
            for func_node, fname, _body in _iter_functions(tree, lang, src_bytes, path):
                start = func_node.start_point[0] + 1
                end = func_node.end_point[0] + 1
                if (compact_names and range is _JS_LINE_RANGE_IMPL
                        and type(start) is int and type(end) is int and type(fname) is str):
                    function_spans.append((start, end, fname))
                    continue
                if compact_names:
                    # Prior native assignments were pure; preserve their
                    # insertion order before resuming adapter operations.
                    for lo, hi, name in function_spans:
                        for ln in _JS_LINE_RANGE_IMPL(lo, hi + 1):
                            func_name_at_line[ln] = name
                    function_spans.clear()
                    compact_names = False
                for ln in range(start, end + 1):
                    func_name_at_line[ln] = fname
    except ImportError:
        pass
    name_index = None
    if function_spans:
        if LineSpanIndex.worthwhile(function_spans):
            name_index = LineSpanIndex(function_spans)
        else:
            for lo, hi, name in function_spans:
                for ln in _JS_LINE_RANGE_IMPL(lo, hi + 1):
                    func_name_at_line[ln] = name
        function_spans.clear()

    streaming = type(source) is str and split_lines is _SENTINEL_LINES_IMPL
    lines = iter_source_lines(source) if streaming else split_lines(source)
    recent: deque[str] | None = deque(maxlen=4) if streaming else None
    current_func = "<module>"
    delayed_names = name_index is not None and enumerate is _JS_LINE_ENUM_IMPL

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        if recent is not None:
            recent.append(line)

        # Function name: prefer tree-sitter map, fall back to regex
        if name_index is not None:
            # Only the built-in monotone enumeration can defer lookups.
            # Adapters retain per-row updates and their gap-carry behavior.
            if not delayed_names:
                current_func = name_index.get(lineno, current_func)
        elif func_name_at_line:
            current_func = func_name_at_line.get(lineno, current_func)
        else:
            native_header = type(line) is str and _JS_FUNC_RE is _JS_HEADER_IMPL
            fm = _JS_FUNC_RE.match(line)
            if fm and not (native_header and fm.group(3) in _JS_CONTROL_HEADERS):
                current_func = (
                    fm.group(1) or fm.group(2) or fm.group(3)
                    or fm.group(4) or "<module>"
                )
                continue

        if (
            type(line) is str and "||" not in line and "??" not in line
            and type(_JS_FALSY_COERCION) is list and len(_JS_FALSY_COERCION) == 3
            and _JS_FALSY_COERCION[0] is _JS_COERCION_IMPLS[0]
            and _JS_FALSY_COERCION[1] is _JS_COERCION_IMPLS[1]
            and _JS_FALSY_COERCION[2] is _JS_COERCION_IMPLS[2]
        ):
            continue

        for pat in _JS_FALSY_COERCION:
            m = pat.search(line)
            if not m:
                continue
            var_name = m.group(1)
            default = m.group(2)
            window_start = max(0, lineno_0 - 3)
            window = "\n".join(
                recent if recent is not None else cast(list[str], lines)[window_start:lineno_0 + 1]
            )
            if re.search(
                rf"\b{re.escape(var_name)}\s*!==?\s*(?:null|undefined)\b",
                window,
            ):
                break
            if delayed_names and name_index is not None:
                current_func = name_index.preceding(lineno, "<module>")
            results.append(SentinelCollapse(
                file=path,
                function=current_func,
                line=lineno,
                write_value="null/undefined",
                read_coercion=m.group(0),
                semantic_loss=f"null/undefined (error) vs {default} (empty)",
                confidence="medium",
            ))
            break

    return results


# ---------------------------------------------------------------------------
# Sub-detector (f): cross-function sentinel collapse
# ---------------------------------------------------------------------------

@dataclass
class _ReturnSemantics:
    function: str
    file: str
    returns_none_on_error: bool = False
    returns_empty_on_error: bool = False
    returns_none_on_success: bool = False
    returns_empty_on_success: bool = False

    @property
    def sentinel_ambiguous(self) -> bool:
        return (
            (self.returns_none_on_error and self.returns_none_on_success)
            or (self.returns_empty_on_error and self.returns_empty_on_success)
        )

    @property
    def ambiguous_value(self) -> str:
        if self.returns_none_on_error and self.returns_none_on_success:
            return "None"
        if self.returns_empty_on_error and self.returns_empty_on_success:
            return "{} or []"
        return "unknown"


def _walk_skipping_nested_funcs(node: ast.AST):
    """Yield all descendants of *node*, skipping nested function bodies."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield child
        yield from _walk_skipping_nested_funcs(child)


def _classify_returns_python(
    file_path: str, source: str,
) -> dict[str, _ReturnSemantics]:
    """Classify return-path semantics for each function in a Python file."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return {}

    results: dict[str, _ReturnSemantics] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        sem = _ReturnSemantics(function=node.name, file=file_path)
        contexts = None
        prepare_contexts = (type(source) is str and ast is _RETURN_AST_MODULE
                            and re is _RETURN_RE_MODULE
                            and getattr(ast, "parse", None) is _RETURN_PARSE_IMPL
                            and _is_inside_except is _RETURN_EXCEPT_IMPL
                            and _is_inside_error_if is _RETURN_ERROR_IF_IMPL
                            and _error_if_test is _RETURN_TEST_IMPL
                            and _walk_skipping_nested_funcs is _RETURN_WALK_IMPL
                            and getattr(ast, "dump", None) is _RETURN_DUMP_IMPL
                            and getattr(re, "search", None) is _RETURN_SEARCH_IMPL
                            and getattr(re, "escape", None) is _RETURN_ESCAPE_IMPL
                            and getattr(ast, "walk", None) is _RETURN_AST_WALK_IMPL
                            and getattr(ast, "iter_child_nodes", None) is _RETURN_CHILDREN_IMPL
                            and sorted is _RETURN_SORT_IMPL)

        for child in _walk_skipping_nested_funcs(node):
            if not isinstance(child, ast.Return):
                continue

            if prepare_contexts and contexts is None:
                try:
                    contexts = _return_contexts(node)
                except Exception:  # noqa: BLE001 - optional preparation must retain legacy error/short-circuit behavior
                    prepare_contexts = False
            if contexts is None:
                in_except = _is_inside_except(child, node)
                in_error_if = _is_inside_error_if(child, node)
            else:
                starts, ends, error_returns = contexts
                line = getattr(child, "lineno", -1)
                index = bisect_right(starts, line) - 1
                in_except = line >= 0 and index >= 0 and line <= ends[index]
                in_error_if = id(child) in error_returns
            is_error_path = in_except or in_error_if

            val = child.value
            is_none = val is None or (
                isinstance(val, ast.Constant) and val.value is None
            )
            is_empty = (
                isinstance(val, ast.Dict) and not val.keys
            ) or (
                isinstance(val, ast.List) and not val.elts
            )

            if is_error_path:
                if is_none:
                    sem.returns_none_on_error = True
                if is_empty:
                    sem.returns_empty_on_error = True
            else:
                if is_none:
                    sem.returns_none_on_success = True
                if is_empty:
                    sem.returns_empty_on_success = True

        results[node.name] = sem

    return results


def _is_inside_except(
    node: ast.AST, func_node: ast.AST,
) -> bool:
    """Check if a node is inside an except handler within the function."""
    node_line = getattr(node, "lineno", -1)
    if node_line < 0:
        return False
    for handler_node in ast.walk(func_node):
        if isinstance(handler_node, ast.ExceptHandler):
            h_start = getattr(handler_node, "lineno", -1)
            h_end = getattr(handler_node, "end_lineno", -1)
            if h_start <= node_line <= h_end:
                return True
    return False


def _error_if_test(if_node: ast.If) -> bool:
    """The existing AST-dump heuristic, shared by prepared and direct queries."""
    test_src = ast.dump(if_node.test)
    return (
        any(re.search(r'\b' + re.escape(kw) + r'\b', test_src) for kw in (
            "error", "err", "exception", "fail", "status_code",
        ))
        or "attr='ok'" in test_src
        or "Is()" in test_src
        or "IsNot()" in test_src
    )


def _is_inside_error_if(
    return_node: ast.Return, func_node: ast.AST,
) -> bool:
    """Check if a return is inside an if-branch that tests for errors."""
    for if_node in ast.walk(func_node):
        if not isinstance(if_node, ast.If):
            continue
        is_error_test = _error_if_test(if_node)
        if not is_error_test:
            continue
        for child in ast.walk(if_node):
            if child is return_node:
                return True
    return False


def _return_contexts(func_node: ast.AST) -> tuple[list[int], list[int], set[int]]:
    """Prepare the legacy inclusive handler ranges and whole-if descendants.

    Include nested definitions and else branches exactly as the direct
    helpers do; the separate return walker still excludes nested functions.
    """
    handlers = []
    error_ifs: set[int] = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.ExceptHandler):
            start = getattr(node, "lineno", -1)
            end = getattr(node, "end_lineno", -1)
            if start <= end:
                handlers.append((start, end))
        elif isinstance(node, ast.If) and _error_if_test(node):
            error_ifs.add(id(node))
    starts: list[int] = []
    ends: list[int] = []
    for start, end in sorted(handlers):
        if ends and start <= ends[-1]:
            ends[-1] = max(ends[-1], end)
        else:
            starts.append(start)
            ends.append(end)
    error_returns: set[int] = set()
    if error_ifs:
        pending = [(func_node, False)]
        while pending:
            node, inside = pending.pop()
            inside = inside or id(node) in error_ifs
            if inside and isinstance(node, ast.Return):
                error_returns.add(id(node))
            pending.extend((child, inside) for child in ast.iter_child_nodes(node))
    return starts, ends, error_returns


_RETURN_AST_MODULE = ast
_RETURN_RE_MODULE = re
_RETURN_PARSE_IMPL = ast.parse
_RETURN_DUMP_IMPL = ast.dump
_RETURN_SEARCH_IMPL = re.search
_RETURN_ESCAPE_IMPL = re.escape
_RETURN_AST_WALK_IMPL = ast.walk
_RETURN_CHILDREN_IMPL = ast.iter_child_nodes
_RETURN_SORT_IMPL = sorted
_RETURN_EXCEPT_IMPL = _is_inside_except
_RETURN_ERROR_IF_IMPL = _is_inside_error_if
_RETURN_TEST_IMPL = _error_if_test
_RETURN_WALK_IMPL = _walk_skipping_nested_funcs


def _callee_suffix_keys(ambiguous_funcs: dict[str, _ReturnSemantics]) -> tuple[dict[str, str], bool]:
    """Index the first key for short native names, with bounded storage.

    A name without a colon matches exactly the last colon-delimited key
    component. Store keys, retaining first-match order and live semantics.
    An incomplete index cannot prove that an unindexed name is absent.
    """
    keys: dict[str, str] = {}
    for key in ambiguous_funcs:
        if len(keys) >= 512:
            return keys, False
        start = key.rfind(":") + 1
        if len(key) - start <= 512:
            keys.setdefault(key[start:], key)
    return keys, True


def _detect_cross_function_collapse(
    source_text: dict[str, str],
    call_graphs: dict[str, Any],
) -> list[SentinelCollapse]:
    """Detect sentinel collapses across function boundaries."""
    results: list[SentinelCollapse] = []

    all_semantics: dict[str, dict[str, _ReturnSemantics]] = {}
    for path, source in source_text.items():
        if path.endswith(".py"):
            all_semantics[path] = _classify_returns_python(path, source)

    ambiguous_funcs: dict[str, _ReturnSemantics] = {}
    for path, funcs in all_semantics.items():
        for fname, sem in funcs.items():
            if sem.sentinel_ambiguous:
                ambiguous_funcs[f"{path}:{fname}"] = sem

    if not ambiguous_funcs:
        return results

    # Build only when a native cross-file query needs it; same-file lookups
    # keep precedence, and incomplete indexes retain the original scan.
    fallback_keys: dict[str, str] | None = None
    fallback_complete = False

    for caller_file, cg in call_graphs.items():
        if not caller_file.endswith(".py"):
            continue
        source = source_text.get(caller_file, "")
        if not source:
            continue
        calls = getattr(cg, "calls", None) or (
            cg.get("calls", []) if isinstance(cg, dict) else []
        )
        # Only repeated known call sequences can reuse a source scan. This
        # memo owns one immutable snapshot and never survives the file pass.
        coercion_queries: BoundedMemo[int | None] | None = (
            BoundedMemo(256)
            if (type(source) is str and len(source) >= 4096
                and (type(calls) is list or type(calls) is tuple) and len(calls) > 1)
            else None
        )
        for call_info in calls:
            caller_name = (
                getattr(call_info, "caller", None)
                or (call_info.get("caller") if isinstance(call_info, dict) else None)
                or ""
            )
            chain = (
                getattr(call_info, "chain", None)
                or (call_info.get("chain") if isinstance(call_info, dict) else None)
                or []
            )
            if not chain:
                continue

            callee_name = chain[-1] if chain else ""
            callee_key_same = f"{caller_file}:{callee_name}"
            sem = ambiguous_funcs.get(callee_key_same)  # type: ignore[assignment]
            if not sem:
                native_name = (type(callee_name) is str and len(callee_name) <= 512
                               and ":" not in callee_name)
                if native_name and fallback_keys is None:
                    fallback_keys, fallback_complete = _callee_suffix_keys(ambiguous_funcs)
                resolved_key = (fallback_keys.get(callee_name)
                                if native_name and fallback_keys is not None else None)
                if resolved_key is not None:
                    sem = ambiguous_funcs[resolved_key]
                elif not (native_name and fallback_complete):
                    for key, s in ambiguous_funcs.items():
                        if key.endswith(f":{callee_name}"):
                            sem = s
                            break
            if not sem:
                continue

            if (coercion_queries is not None
                    and _find_coercion_of_call is _COERCION_LOOKUP_IMPL
                    and type(caller_name) is str and type(callee_name) is str
                    and len(caller_name) <= 512 and len(callee_name) <= 512):
                coercion_line, _ = coercion_queries.get_or_compute(
                    (caller_name, callee_name),
                    lambda: _find_coercion_of_call(source, caller_name, callee_name),
                )
            else:
                coercion_line = _find_coercion_of_call(
                    source, caller_name, callee_name,
                )
            if coercion_line is None:
                continue

            results.append(SentinelCollapse(
                file=caller_file,
                function=caller_name,
                line=coercion_line,
                write_value=f"{sem.ambiguous_value} "
                            f"(from {sem.file}:{sem.function})",
                read_coercion="caller coerces return value",
                semantic_loss=(
                    f"{sem.function}() returns {sem.ambiguous_value} on both "
                    f"error and success paths; caller {caller_name}() coerces "
                    f"the result, making errors invisible"
                ),
                confidence="high",
            ))

    return results


def _find_coercion_of_call(
    source: str,
    caller_name: str,
    callee_name: str,
) -> int | None:
    """Find a line where the caller coerces the callee's return value."""
    streaming = (_FORWARD_TYPE_IMPL(source) is str
                 and _FORWARD_TYPE_IMPL(caller_name) is str
                 and _FORWARD_TYPE_IMPL(callee_name) is str
                 and split_lines is _SENTINEL_LINES_IMPL
                 and len is _FORWARD_LEN_IMPL and min is _FORWARD_MIN_IMPL
                 and range is _FORWARD_RANGE_IMPL and enumerate is _FORWARD_ENUM_IMPL
                 and _SENTINEL_PY_INDENT_DEF_RE is _FORWARD_PY_HEADER_IMPL
                 and re.search is _FORWARD_RE_SEARCH_IMPL
                 and re.escape is _FORWARD_RE_ESCAPE_IMPL)
    # Exact native identifiers must occur verbatim in any header/call
    # witness. A negative probe cannot hide a matching source line.
    if streaming and (caller_name not in source or callee_name not in source):
        return None
    lines = [] if streaming else split_lines(source)
    source_lines = iter_source_lines(source) if streaming else None
    pending: deque[str] = deque()
    rows = _lines_with_pending(source_lines, pending) if streaming else lines
    in_caller = False
    caller_indent = 0

    for lineno_0, line in enumerate(rows):
        fm = _SENTINEL_PY_INDENT_DEF_RE.match(line)
        if fm:
            if fm.group(2) == caller_name:
                in_caller = True
                caller_indent = len(fm.group(1))
            elif in_caller:
                stripped = line.lstrip()
                if stripped and len(line) - len(stripped) <= caller_indent:
                    in_caller = False
            continue

        if not in_caller:
            continue

        # Look for: result = callee(...)  followed by  result or []
        # (\b-pinned variable group, see _FALSY_COERCION_PATTERNS)
        call_pat = re.search(
            rf"\b(\w+)\s*=\s*(?:\w+\.)?{re.escape(callee_name)}\s*\(",
            line,
        )
        if call_pat:
            var = call_pat.group(1)
            checks: Iterator[tuple[int, str]]
            if streaming:
                checks = enumerate(_forward_window(line, source_lines, pending), lineno_0)
            else:
                window_end = min(lineno_0 + 5, len(lines))
                checks = ((i, lines[i]) for i in range(lineno_0, window_end))
            for check_line_0, check_line in checks:
                coerce = re.search(
                    rf"\b{re.escape(var)}\s+(?:or|if\s+{re.escape(var)}\s+else)\s+"
                    r"(?:\[\]|\{\})",
                    check_line,
                )
                if coerce:
                    return check_line_0 + 1

    return None


# Replaced lookup helpers retain their own per-edge operations.
_COERCION_LOOKUP_IMPL = _find_coercion_of_call


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_sentinel_collapses(
    source_text: dict[str, str],
    call_graphs: dict[str, Any] | None = None,
) -> list[SentinelCollapse]:
    """Run all sub-detectors over the provided sources.

    Parameters
    ----------
    source_text:
        Mapping of ``{file_path: source_code}``.
    call_graphs:
        Optional call-graph data for cross-function analysis.
        Same format as used by ``sibling_analysis`` and
        ``value_space_checker``.

    Returns
    -------
    list[SentinelCollapse]
        All detected sentinel-collapse sites, sorted by file then line.
    """
    findings: list[SentinelCollapse] = []

    for path, source in source_text.items():
        if path.endswith(".py"):
            findings.extend(_detect_falsy_coercion(path, source))
            findings.extend(_detect_except_same_as_success(path, source))
            findings.extend(_detect_cache_sentinel(path, source))
        elif path.endswith(".go"):
            findings.extend(_detect_go_sentinel(path, source))
        elif any(path.endswith(ext) for ext in (".js", ".ts", ".jsx", ".tsx")):
            findings.extend(_detect_js_sentinel(path, source))

    if call_graphs:
        findings.extend(
            _detect_cross_function_collapse(source_text, call_graphs)
        )

    findings.sort(key=lambda f: (f.file, f.line))
    return findings
