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
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


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
_FALSY_COERCION_PATTERNS: list[re.Pattern[str]] = [
    # x if x else []  /  x if x else {}
    re.compile(
        r"""(?P<var>\w+)\s+if\s+(?P=var)\s+else\s+(?P<default>\[\]|\{\})""",
    ),
    # x or []  /  x or {}
    re.compile(
        r"""(?P<var>\w+)\s+or\s+(?P<default>\[\]|\{\})""",
    ),
    # list(x) if x else []  /  dict(x) if x else {}
    re.compile(
        r"""(?:list|dict)\((?P<var>\w+)\)\s+if\s+(?P=var)\s+else\s+(?P<default>\[\]|\{\})""",
    ),
]

def _detect_falsy_coercion(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []
    current_func = "<module>"
    lines = source.splitlines()

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        func_match = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", line)
        if func_match:
            current_func = func_match.group(1)
            continue

        for pat in _FALSY_COERCION_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            var_name = m.group("var")
            # Skip if the SAME variable is guarded by ``is not None``
            # in the preceding 3-line window
            window_start = max(0, lineno_0 - 3)
            window = "\n".join(lines[window_start:lineno_0 + 1])
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
_CACHE_WRITE_NONE = re.compile(
    r"""(?:(?P<cache>\w+)\[.+\]\s*=\s*None"""
    r"""|(?P<cache2>\w+)\.set\(.+,\s*None\))""",
)

# cached or default  /  cached if cached else default
_CACHE_READ_COERCE = re.compile(
    r"""(?P<var>\w+)\s+or\s+(?P<default>\[\]|\{\}|0|""|'')"""
    r"""|(?P<var2>\w+)\s+if\s+(?P=var2)\s+else\s+(?P<default2>\[\]|\{\}|0|""|'')""",
)


def _detect_cache_sentinel(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []
    lines = source.splitlines()
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
        func_match = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", line)
        if func_match:
            _flush()
            current_func = func_match.group(1)
            func_has_write_none = False
            func_coercion_sites = []
            continue

        if _CACHE_WRITE_NONE.search(line):
            func_has_write_none = True

        m = _CACHE_READ_COERCE.search(line)
        if m:
            func_coercion_sites.append((lineno, m.group(0)))

    _flush()
    return results


# ---------------------------------------------------------------------------
# Sub-detector (d): Go sentinel confusion
# ---------------------------------------------------------------------------

# func returns (nil, err) but caller only checks err, not nil-vs-not-found
_GO_NIL_RETURN_ON_ERR = re.compile(
    r"\bif\s+err\s*!=\s*nil\s*\{[^}]*return\s+nil\b",
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
    lines = source.splitlines()
    current_func = "<module>"

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        fm = re.match(r"\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", line)
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
            fm = re.match(r"\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", line)
            if fm:
                func_starts.append((fm.group(1), lineno_0))

        for i, (fname, start) in enumerate(func_starts):
            end = func_starts[i + 1][1] if i + 1 < len(func_starts) else len(lines)
            body = "\n".join(lines[start:end])

            nil_on_err = bool(_GO_NIL_RETURN_ON_ERR.search(body))
            nil_on_success = bool(re.search(
                r"return\s+nil\s*,\s*nil\b", body,
            ))
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

_JS_OPTIONAL_CHAIN_DEFAULT = re.compile(
    r"(\w+)\?\.\w+\s*\|\|\s*(\[\]|\{\}|\"\")",
)

_JS_FALSY_COERCION = [
    # Optional-chain access with a falsy default (x?.y || "") — the
    # same collapse shape through a property read; also the only
    # pattern here that catches the string-default variant. Ordered
    # FIRST so the chained expression attributes to the chain root
    # (the bare-identifier patterns below would otherwise match the
    # same line as `y || []` and win with the wrong variable).
    _JS_OPTIONAL_CHAIN_DEFAULT,
    re.compile(r"(\w+)\s*\|\|\s*(\[\]|\{\})"),
    re.compile(r"(\w+)\s*\?\?\s*(\[\]|\{\})"),
]


_JS_FUNC_RE = re.compile(
    r"\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:"
    r"function\s*\*?\s+(\w+)"                          # function name(
    r"|(?:const|let|var)\s+(\w+)\s*=\s*"
    r"(?:(?:async\s+)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>|\(?function)"  # arrow / function expr
    r"|(\w+)\s*\([^)]*\)\s*\{"             # name(...) {  (class method)
    r"|(\w+)\s*:\s*(?:async\s+)?function"  # name: function (object method)
    r")",
)


def _detect_js_sentinel(
    path: str,
    source: str,
) -> list[SentinelCollapse]:
    results: list[SentinelCollapse] = []

    # Use tree-sitter for function name attribution when available
    func_name_at_line: dict[int, str] = {}
    try:
        from .ts_extract import _parse_file, _iter_functions
        parsed = _parse_file(path, source)
        if parsed is not None:
            tree, lang, src_bytes = parsed
            for func_node, fname, _body in _iter_functions(tree, lang, src_bytes, path):
                start = func_node.start_point[0] + 1
                end = func_node.end_point[0] + 1
                for ln in range(start, end + 1):
                    func_name_at_line[ln] = fname
    except ImportError:
        pass

    lines = source.splitlines()
    current_func = "<module>"

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1

        # Function name: prefer tree-sitter map, fall back to regex
        if func_name_at_line:
            current_func = func_name_at_line.get(lineno, current_func)
        else:
            fm = _JS_FUNC_RE.match(line)
            if fm:
                current_func = (
                    fm.group(1) or fm.group(2) or fm.group(3)
                    or fm.group(4) or "<module>"
                )
                continue

        for pat in _JS_FALSY_COERCION:
            m = pat.search(line)
            if not m:
                continue
            var_name = m.group(1)
            default = m.group(2)
            window_start = max(0, lineno_0 - 3)
            window = "\n".join(lines[window_start:lineno_0 + 1])
            if re.search(
                rf"\b{re.escape(var_name)}\s*!==?\s*(?:null|undefined)\b",
                window,
            ):
                break
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

        for child in _walk_skipping_nested_funcs(node):
            if not isinstance(child, ast.Return):
                continue

            in_except = _is_inside_except(child, node)
            in_error_if = _is_inside_error_if(child, node)
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


def _is_inside_error_if(
    return_node: ast.Return, func_node: ast.AST,
) -> bool:
    """Check if a return is inside an if-branch that tests for errors."""
    for if_node in ast.walk(func_node):
        if not isinstance(if_node, ast.If):
            continue
        test_src = ast.dump(if_node.test)
        is_error_test = (
            any(re.search(r'\b' + re.escape(kw) + r'\b', test_src) for kw in (
                "error", "err", "exception", "fail", "status_code",
            ))
            or "attr='ok'" in test_src
            or "Is()" in test_src
            or "IsNot()" in test_src
        )
        if not is_error_test:
            continue
        for child in ast.walk(if_node):
            if child is return_node:
                return True
    return False


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

    for caller_file, cg in call_graphs.items():
        if not caller_file.endswith(".py"):
            continue
        source = source_text.get(caller_file, "")
        if not source:
            continue

        calls = getattr(cg, "calls", None) or (
            cg.get("calls", []) if isinstance(cg, dict) else []
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
            sem = ambiguous_funcs.get(callee_key_same)
            if not sem:
                for key, s in ambiguous_funcs.items():
                    if key.endswith(f":{callee_name}"):
                        sem = s
                        break
            if not sem:
                continue

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
    lines = source.splitlines()
    in_caller = False
    caller_indent = 0

    for lineno_0, line in enumerate(lines):
        fm = re.match(r"(\s*)(?:async\s+)?def\s+(\w+)\s*\(", line)
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
        call_pat = re.search(
            rf"(\w+)\s*=\s*(?:\w+\.)?{re.escape(callee_name)}\s*\(",
            line,
        )
        if call_pat:
            var = call_pat.group(1)
            window_end = min(lineno_0 + 5, len(lines))
            for check_line_0 in range(lineno_0, window_end):
                check_line = lines[check_line_0]
                coerce = re.search(
                    rf"\b{re.escape(var)}\s+(?:or|if\s+{re.escape(var)}\s+else)\s+"
                    r"(?:\[\]|\{\})",
                    check_line,
                )
                if coerce:
                    return check_line_0 + 1

    return None


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
