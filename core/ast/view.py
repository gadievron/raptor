"""Composition layer: build a :class:`FunctionView` over the inventory
substrate.

The public entry point :func:`view` is the only function callers should
need. Everything else here is per-language helper plumbing.

Implementation notes:

  * Function discovery routes through
    :func:`core.inventory.extractors.extract_functions`, which already
    does language dispatch and tree-sitter/regex/Python-AST fallback.
  * Calls extraction routes through the per-language
    ``core.inventory.call_graph.extract_call_graph_<lang>``; the
    dispatch table is local to this module. Languages absent from the
    table return an empty calls list (the rest of the view still
    works).
  * Returns / inline-asm are extracted here per-language because they
    aren't yet first-class in inventory. Per-language walkers stay
    simple (~20-40 LOC each) and lazy-import their grammar so a
    missing grammar package degrades cleanly to no returns / no asm
    flag rather than crashing.

Language coverage at this revision:

  * Calls + returns + asm: C, C++ (asm is C/C++ only)
  * Calls + returns: Python, JavaScript, Java, Go
  * Calls only (inherited from inventory): Rust, Ruby, C#, PHP,
    TypeScript (TS shares the JS walker)

A function with ``line_end == None`` (extractor couldn't determine
the end) skips line-range filtering for calls — the whole file's
call graph would otherwise be empty for that function. Returns/asm
also bail out cleanly when bounds aren't known.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core.ast.model import FunctionView, Return, SCHEMA_VERSION
from core.inventory.call_graph import (
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
from core.inventory.extractors import extract_functions
from core.inventory.languages import detect_language


# ---------------------------------------------------------------------------
# Call-graph dispatch
# ---------------------------------------------------------------------------
#
# Per-language ``extract_call_graph_<lang>`` indexed by the canonical
# language string from ``core.inventory.languages.LANGUAGE_MAP``.
# Languages not in this table aren't a hard error — they just produce
# an empty ``calls_made`` tuple. Adding a new walker is a one-line
# entry here.
#
# TypeScript maps to the JavaScript walker until tree-sitter-typescript
# wiring lands — the JS walker accepts a subset of TS syntactically;
# TS-specific constructs (type annotations, generics, decorators)
# parse-fail or are ignored, but the call-extraction logic is sound
# for the common JS-shaped subset.

_CALL_GRAPH_DISPATCH: dict[str, Callable] = {
    "python": extract_call_graph_python,
    "javascript": extract_call_graph_javascript,
    "typescript": extract_call_graph_javascript,
    "java": extract_call_graph_java,
    "go": extract_call_graph_go,
    "c": extract_call_graph_c,
    "cpp": extract_call_graph_cpp,
    "rust": extract_call_graph_rust,
    "ruby": extract_call_graph_ruby,
    "csharp": extract_call_graph_csharp,
    "php": extract_call_graph_php,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def view(
    path: Path,
    function: str,
    *,
    at_line: Optional[int] = None,
    language: Optional[str] = None,
) -> Optional[FunctionView]:
    """Return a :class:`FunctionView` for ``function`` in ``path``.

    Returns ``None`` when:
      * The file can't be read.
      * The language can't be detected from extension (pass
        ``language=...`` to override).
      * No function in the file matches ``function`` (and ``at_line``
        when given).

    When multiple functions in the file share the same name (e.g.
    methods of different classes), pass ``at_line`` to disambiguate
    — the first match whose line range contains ``at_line`` is
    returned. Without ``at_line``, the first name match wins; for
    files with name collisions this is deterministic (extractor
    output order) but not necessarily the function the caller meant.
    """
    path = Path(path)
    if language is None:
        language = detect_language(str(path))
        if language is None:
            return None

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Function discovery — inventory handles per-language dispatch.
    functions = extract_functions(str(path), language, content)
    matches = [f for f in functions if f.name == function]
    if at_line is not None:
        # Narrow to functions whose range encloses at_line. line_end
        # may be None for extractors that don't compute it; treat
        # missing end as "unknown" and require an exact start match.
        narrowed = []
        for fi in matches:
            if fi.line_end is not None:
                if fi.line_start <= at_line <= fi.line_end:
                    narrowed.append(fi)
            elif fi.line_start == at_line:
                narrowed.append(fi)
        matches = narrowed
    if not matches:
        return None
    fi = matches[0]

    # Calls — filter file-wide graph by the function's line range.
    calls_made = _filter_calls(content, language, fi.line_start, fi.line_end)

    # Returns + inline asm.
    returns = _walk_returns(content, language, fi.line_start, fi.line_end)
    has_asm = _has_inline_asm(content, language, fi.line_start, fi.line_end)

    return FunctionView(
        function=fi.name,
        file=str(path),
        language=language,
        # If line_end is None, fall back to start so the tuple type
        # stays valid; consumers should treat (n, n) as "unknown end"
        # by checking against the source length. Better than tripping
        # downstream assumptions about line_end being None.
        lines=(fi.line_start, fi.line_end if fi.line_end is not None else fi.line_start),
        signature=fi.signature or "",
        calls_made=calls_made,
        returns=returns,
        has_inline_asm=has_asm,
        schema_version=SCHEMA_VERSION,
    )


# ---------------------------------------------------------------------------
# Calls — line-range filter over the file-wide call graph
# ---------------------------------------------------------------------------


def _filter_calls(
    content: str,
    language: str,
    line_start: int,
    line_end: Optional[int],
) -> Tuple:
    """Return calls inside the function's line range. Empty tuple
    when the language has no call-graph walker or the file is
    unparseable for it."""
    extractor = _CALL_GRAPH_DISPATCH.get(language)
    if extractor is None:
        return ()
    try:
        graph = extractor(content)
    except Exception:                                       # noqa: BLE001
        return ()
    if line_end is None:
        # No upper bound known; return every call (best-effort).
        return tuple(graph.calls)
    return tuple(
        c for c in graph.calls
        if line_start <= c.line <= line_end
    )


# ---------------------------------------------------------------------------
# Returns
# ---------------------------------------------------------------------------


def _walk_returns(
    content: str,
    language: str,
    line_start: int,
    line_end: Optional[int],
) -> Tuple[Return, ...]:
    """Return all explicit ``return`` statements inside the function.

    Implicit returns (end-of-function fall-through in C/Go, etc.) are
    NOT emitted. Callers that want "all exit points" should union
    these with ``lines[1]``.
    """
    if line_end is None:
        return ()
    if language == "python":
        return _walk_returns_python(content, line_start, line_end)
    # Tree-sitter languages: same shape across grammars — a
    # ``return_statement`` node whose first named child (if any) is
    # the returned expression. Lazy-import the grammar so a missing
    # package degrades cleanly.
    grammar = _ts_grammar_module(language)
    if grammar is None:
        return ()
    return _walk_returns_ts(content, grammar, line_start, line_end)


def _walk_returns_python(
    content: str,
    line_start: int,
    line_end: int,
) -> Tuple[Return, ...]:
    """Use stdlib ``ast`` for Python — no third-party grammar needed."""
    import ast as _stdlib_ast  # absolute import: shadowed by core.ast namespace
    try:
        tree = _stdlib_ast.parse(content)
    except SyntaxError:
        return ()
    out: List[Return] = []
    for node in _stdlib_ast.walk(tree):
        if not isinstance(node, _stdlib_ast.Return):
            continue
        line = getattr(node, "lineno", 0)
        if not (line_start <= line <= line_end):
            continue
        value_text = ""
        if node.value is not None:
            try:
                value_text = _stdlib_ast.unparse(node.value)
            except Exception:                               # noqa: BLE001
                value_text = ""
        out.append(Return(line=line, value_text=value_text))
    # ast.walk's traversal order isn't source-order; sort by line so
    # consumers get a stable, predictable sequence.
    out.sort(key=lambda r: r.line)
    return tuple(out)


def _walk_returns_ts(
    content: str,
    grammar_module,
    line_start: int,
    line_end: int,
) -> Tuple[Return, ...]:
    """Generic tree-sitter ``return_statement`` walk.

    The grammar's emitted node type is conventionally
    ``return_statement`` in every grammar this dispatch hands out
    (verified for c / cpp / javascript / java / go); if a future
    grammar uses a different name, add it to the tuple below.
    """
    try:
        from tree_sitter import Language, Parser
        parser = Parser(Language(grammar_module.language()))
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:                                       # noqa: BLE001
        return ()
    out: List[Return] = []
    return_types = ("return_statement",)

    def visit(node) -> None:
        # Cheap line-range prune: skip subtrees entirely outside
        # [line_start, line_end].
        n_start = node.start_point[0] + 1
        n_end = node.end_point[0] + 1
        if n_start > line_end or n_end < line_start:
            return
        if node.type in return_types:
            line = n_start
            if line_start <= line <= line_end:
                value_text = ""
                for c in node.children:
                    if c.is_named:
                        value_text = c.text.decode("utf-8", errors="replace")
                        break
                out.append(Return(line=line, value_text=value_text))
            # Returns don't nest meaningfully; still descend so nested
            # functions / lambdas inside return expressions are seen.
        for c in node.children:
            visit(c)

    visit(tree.root_node)
    return tuple(out)


def _ts_grammar_module(language: str):
    """Lazy-import the tree-sitter grammar for ``language``. Returns
    None if the package isn't installed — the caller falls back to
    "no returns" / "no asm" rather than crashing."""
    try:
        if language == "c":
            import tree_sitter_c as m
            return m
        if language == "cpp":
            import tree_sitter_cpp as m
            return m
        if language in ("javascript", "typescript"):
            import tree_sitter_javascript as m
            return m
        if language == "java":
            import tree_sitter_java as m
            return m
        if language == "go":
            import tree_sitter_go as m
            return m
    except ImportError:
        return None
    return None


# ---------------------------------------------------------------------------
# Inline asm (C/C++ only)
# ---------------------------------------------------------------------------


# Whole-word match for the three GNU-extension asm keywords. ``asm``
# is contextual (only meaningful at statement position) — false
# positives are theoretically possible if a function contains a
# variable / type / macro literally named ``asm``, but C and C++
# discourage that (``asm`` is a reserved word in C++ and a
# conditional keyword in C since C99 via ``<iso646.h>``). For PR1
# minimum the regex is the right precision/cost trade-off; a future
# revision can switch to a tree-sitter ``gnu_asm_statement`` walk if
# false positives surface in real corpora.
_ASM_PATTERN = re.compile(
    r"\b(__asm__|__asm|asm)\b\s*(?:volatile|goto)?\s*[(]",
)


def _has_inline_asm(
    content: str,
    language: str,
    line_start: int,
    line_end: Optional[int],
) -> bool:
    """True iff a GNU-extension inline-asm construct appears in the
    function body. Non-C/C++ always False."""
    if language not in ("c", "cpp"):
        return False
    if line_end is None:
        return False
    # Slice the function body by lines (1-indexed). String slicing
    # is cheap relative to parsing the whole file again.
    lines = content.splitlines()
    body = "\n".join(lines[line_start - 1: line_end])
    return bool(_ASM_PATTERN.search(body))
