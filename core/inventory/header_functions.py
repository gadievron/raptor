"""Index of function definitions in C/C++ header files.

Scans .h/.hpp files for functions defined with bodies (static inline,
__attribute__((always_inline)), and small non-static functions).
Provides a name→(relative_path, source) lookup for callee enrichment
when the function doesn't appear in the inventory's call graph.

Cached per target path.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

from core.inventory._walk import iter_regular_files
from core.inventory.extractors import CExtractor

if TYPE_CHECKING:
    from pathlib import Path

_HEADER_EXTENSIONS = frozenset({".h", ".hh", ".hpp", ".hxx"})

# Matches a function definition: optional qualifiers, return type, name,
# params, then opening brace. Captures the function name.
# Handles: static inline int foo(int x) {
#          __attribute__((always_inline)) static void bar(void) {
#          ZEXTERN int ZEXPORT crc32(uLong crc, ...) {
#          static int each(int n, void (*cb)(int)) {
# The parameter list tolerates one level of nested parentheses (same
# sub-pattern the __attribute__ clause uses) so function-pointer
# parameters don't hide the definition.
# Bounded loops and windows on every unbounded-reach span (same
# discipline as the header_api declaration matcher): unbounded
# attribute chains, type loops and parameter windows let every line
# anchor re-scan the remaining text on planted declaration-shaped
# runs — quadratic. Bounds sit far above real definitions
# (trade-offs as in header_api).
_FUNC_DEF_RE = re.compile(
    r"^[ \t]*"
    r"(?:__attribute__\s*\(\([^()]{0,1024}(?:\([^()]{0,1024}\)[^()]{0,1024}){0,8}\)\)\s+){0,8}"
    r"(?:\w+\s+){0,24}?"
    r"(\w+)\s*\([^()]{0,4096}(?:\([^()]{0,1024}\)[^()]{0,4096}){0,16}\)\s*\{",
    re.MULTILINE,
)

# Same "last word before `(`" capture as the inventory's C regex lane,
# so the same declarator shapes (function-pointer returns) can put a
# TYPE token in the name group — share the extractor's reserved-word
# blocklist. `defined` is preprocessor-only (an ordinary identifier in
# C proper) and stays a local extra for `#if defined(...)` lines.
_SKIP_NAMES = CExtractor.RESERVED_WORDS | frozenset({"defined"})

_MAX_BODY_LINES = 30
_MAX_CACHE_ENTRIES = 16

_cache: OrderedDict[str, dict[str, tuple[str, str]]] = OrderedDict()
# The builder fans out via thread pools; unlocked OrderedDict mutation
# from concurrent lookups raced (worst case duplicate index builds and
# a mid-move_to_end KeyError). The build itself runs outside the lock —
# a rare duplicate build is cheaper than serialising every scan.
_cache_lock = threading.Lock()

# Openers pinned to UNESCAPED delimiters ((?<!\\)): an unterminated
# literal whose interior repeats escaped delimiters (`"` + `\"`*n)
# otherwise makes every embedded delimiter a fresh match attempt that
# re-scans to the end of the line — quadratic on a hostile planted
# line (measured exp 2.43; pinned, exp 1.0). On a well-formed token
# stream no string opens at an escaped delimiter, so the strip is
# unchanged; dropping the pin re-opens the quadratic.
_C_STRING_OR_CHAR_RE = re.compile(
    r'(?<!\\)"(?:[^"\\]|\\.)*"|(?<!\\)\'(?:[^\'\\]|\\.)*\'')


def _extract_function_body(lines: list[str], open_brace_line: int) -> str | None:
    """Extract function body from opening brace line to closing brace.

    ``open_brace_line`` is where the SIGNATURE starts; a multi-line
    signature means the first lines carry no brace, so the depth<=0
    exit must wait until an opening brace has actually been seen
    (otherwise a two-line signature returned a one-line "body").
    """
    depth = 0
    opened = False
    start = open_brace_line
    for i in range(start, min(start + _MAX_BODY_LINES + 5, len(lines))):
        cleaned = _C_STRING_OR_CHAR_RE.sub("", lines[i])
        if "{" in cleaned:
            opened = True
        depth += cleaned.count("{") - cleaned.count("}")
        if opened and depth <= 0:
            body_lines = lines[start:i + 1]
            if len(body_lines) > _MAX_BODY_LINES:
                return None
            return "\n".join(body_lines)
    return None


def build_header_function_index(
    target_path: Path,
) -> dict[str, tuple[str, str]]:
    """Build name → (relative_path, source) index of header-defined functions.

    Only includes functions with bodies (definitions, not declarations).
    Skips functions longer than 30 lines to avoid bloating context.
    Cached per target path.
    """
    key = str(target_path)
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]

    index: dict[str, tuple[str, str]] = {}
    try:
        # Symlink-safe enumeration — a hostile `dir -> /` in the
        # target must not walk the host fs into audit context.
        for p in iter_regular_files(target_path, _HEADER_EXTENSIONS):
            try:
                if p.stat().st_size > 1_048_576:  # 1 MB cap
                    continue
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

    with _cache_lock:
        _cache[key] = index
        while len(_cache) > _MAX_CACHE_ENTRIES:
            _cache.popitem(last=False)
    return index


def lookup_header_function(
    target_path: Path, name: str,
) -> tuple[str, str] | None:
    """Look up a function by name, returning (relative_path, source) or None."""
    return build_header_function_index(target_path).get(name)
