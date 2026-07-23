"""Index of function definitions in C/C++ header files.

Scans .h/.hpp files for functions defined with bodies (static inline,
__attribute__((always_inline)), and small non-static functions).
Provides a name→(relative_path, source) lookup for callee enrichment
when the function doesn't appear in the inventory's call graph.

Cached per target path.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_HEADER_EXTENSIONS = frozenset({".h", ".hh", ".hpp", ".hxx"})

# Matches a function definition: optional qualifiers, return type, name,
# params, then opening brace. Captures the function name.
# Handles: static inline int foo(int x) {
#          __attribute__((always_inline)) static void bar(void) {
#          ZEXTERN int ZEXPORT crc32(uLong crc, ...) {
_FUNC_DEF_RE = re.compile(
    r"^[ \t]*"
    r"(?:(?:__attribute__\s*\(\([^)]*\)\)|\w+)\s+)*"
    r"(\w+)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)

_SKIP_NAMES = frozenset({
    "if", "else", "for", "while", "do", "switch", "return",
    "sizeof", "typeof", "defined",
})

_MAX_BODY_LINES = 30

_cache: Dict[str, Dict[str, Tuple[str, str]]] = {}


def _extract_function_body(lines: List[str], open_brace_line: int) -> Optional[str]:
    """Extract function body from opening brace line to closing brace."""
    depth = 0
    start = open_brace_line
    for i in range(start, min(start + _MAX_BODY_LINES + 5, len(lines))):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > start:
            body_lines = lines[start:i + 1]
            if len(body_lines) > _MAX_BODY_LINES:
                return None
            return "\n".join(body_lines)
    if depth > 0:
        return None
    body_lines = lines[start:start + 1]
    return "\n".join(body_lines)


def build_header_function_index(
    target_path: Path,
) -> Dict[str, Tuple[str, str]]:
    """Build name → (relative_path, source) index of header-defined functions.

    Only includes functions with bodies (definitions, not declarations).
    Skips functions longer than 30 lines to avoid bloating context.
    Cached per target path.
    """
    key = str(target_path)
    if key in _cache:
        return _cache[key]

    index: Dict[str, Tuple[str, str]] = {}
    try:
        for p in target_path.rglob("*"):
            if not p.is_file() or p.suffix not in _HEADER_EXTENSIONS:
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue

            lines = text.splitlines()
            for m in _FUNC_DEF_RE.finditer(text):
                name = m.group(1)
                if name in _SKIP_NAMES or name in index:
                    continue
                line_no = text[:m.start()].count("\n")
                body = _extract_function_body(lines, line_no)
                if body:
                    rel = str(p.relative_to(target_path))
                    index[name] = (rel, body)
    except OSError:
        pass

    _cache[key] = index
    return index


def lookup_header_function(
    target_path: Path, name: str,
) -> Optional[Tuple[str, str]]:
    """Look up a function by name, returning (relative_path, source) or None."""
    return build_header_function_index(target_path).get(name)
