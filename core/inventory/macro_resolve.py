"""Resolve macro definitions from a target directory.

Supports:
- C/C++ #define directives (with transitive resolution)
- Rust macro_rules! definitions

Scans source files, builds a name→(params, body) table, and resolves
transitive references used in a given source fragment.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)

_MACRO_DEF_RE = re.compile(
    r"^\s*#\s*define\s+(\w+)(\([^)]*\))?\s+(.+?)(?:\s*\\)?$",
    re.MULTILINE,
)
_MACRO_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
_C_EXTENSIONS = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
})
_RUST_EXTENSIONS = frozenset({".rs"})

_SKIP_IDENTS_C: FrozenSet[str] = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "return",
    "break", "continue", "goto", "sizeof", "typeof", "void", "int",
    "char", "unsigned", "signed", "long", "short", "float", "double",
    "const", "static", "extern", "struct", "enum", "union", "typedef",
    "NULL", "true", "false", "bool", "size_t", "ssize_t", "uint8_t",
    "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t",
    "int64_t", "uintptr_t", "intptr_t", "ptrdiff_t",
})
_SKIP_IDENTS_RUST: FrozenSet[str] = frozenset({
    "if", "else", "for", "while", "loop", "match", "return", "break",
    "continue", "let", "mut", "fn", "pub", "use", "mod", "struct",
    "enum", "impl", "trait", "where", "type", "const", "static",
    "unsafe", "extern", "crate", "self", "super", "as", "in", "ref",
    "move", "async", "await", "dyn", "true", "false", "Self",
    "str", "bool", "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
    "Option", "Result", "Some", "None", "Ok", "Err", "Vec", "String",
    "Box", "Rc", "Arc", "println", "eprintln", "format", "write",
    "writeln", "panic", "assert", "debug_assert", "todo", "unimplemented",
    "unreachable", "cfg", "derive", "allow", "deny", "warn",
})

_TABLE_CACHE_MAX = 8
_table_cache: OrderedDict[str, Dict[str, Tuple[str, str]]] = OrderedDict()

# Anonymous and named enum enumerator extraction:
#   enum { FOO = 1, BAR = 2 };
#   enum limits { MAX_BUF = 256 };
_ENUM_BLOCK_RE = re.compile(r"\benum\s*(?:\w+\s*)?\{([^}]+)\}", re.DOTALL)
_ENUMERATOR_RE = re.compile(r"(\w+)\s*=\s*([^,}]+)")

# Rust macro_rules! extraction
# Matches: macro_rules! name { ... } — we capture the full body between braces
_RUST_MACRO_RULES_RE = re.compile(
    r"macro_rules!\s+(\w+)\s*\{",
)
# Rust macro invocations in source: name!(...)  name![...]  name!{...}
_RUST_MACRO_CALL_RE = re.compile(r"\b(\w+)\s*!")

_RUST_TABLE_CACHE_MAX = 8
_rust_table_cache: OrderedDict[str, Dict[str, str]] = OrderedDict()


def _extract_braced_body(text: str, open_pos: int) -> Optional[str]:
    """Extract text between matched braces starting at open_pos."""
    if open_pos >= len(text) or text[open_pos] != "{":
        return None
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i].strip()
    return None


def build_rust_macro_table(target_path: Path) -> Dict[str, str]:
    """Build name→body table of all macro_rules! in the target.

    Results are cached per target path.
    """
    key = str(target_path)
    if key in _rust_table_cache:
        _rust_table_cache.move_to_end(key)
        return _rust_table_cache[key]

    table: Dict[str, str] = {}
    try:
        for p in target_path.rglob("*"):
            if not p.is_file() or p.suffix not in _RUST_EXTENSIONS:
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for m in _RUST_MACRO_RULES_RE.finditer(text):
                name = m.group(1)
                if name in table:
                    logger.debug(
                        "macro_rules! %s redefined in %s "
                        "(keeping first definition)",
                        name, p,
                    )
                    continue
                body = _extract_braced_body(text, m.end() - 1)
                if body:
                    table[name] = body
    except OSError:
        pass

    if len(_rust_table_cache) >= _RUST_TABLE_CACHE_MAX:
        _rust_table_cache.popitem(last=False)
    _rust_table_cache[key] = table
    return table


def resolve_rust_macros(
    target_path: Path,
    source: str,
    max_depth: int = 3,
) -> List[Tuple[str, str]]:
    """Find macro_rules! macros invoked in source, resolve transitively.

    Returns list of (name, body) tuples, leaf-first.
    """
    if not source:
        return []

    table = build_rust_macro_table(target_path)
    if not table:
        return []

    called = set(_RUST_MACRO_CALL_RE.findall(source)) - _SKIP_IDENTS_RUST

    resolved: Dict[str, Tuple[str, str, int]] = {}
    worklist = [(name, 0) for name in called if name in table]
    visited: set = set()

    while worklist:
        name, depth = worklist.pop()
        if name in visited:
            continue
        visited.add(name)

        body = table.get(name)
        if not body:
            continue
        resolved[name] = (name, body, depth)

        if depth < max_depth:
            child_calls = set(_RUST_MACRO_CALL_RE.findall(body)) - _SKIP_IDENTS_RUST
            for child in child_calls:
                if child not in visited and child in table:
                    worklist.append((child, depth + 1))

    if not resolved:
        return []

    items = sorted(resolved.values(), key=lambda x: (-x[2], x[0]))
    return [(name, body) for name, body, _ in items]


def build_macro_table(target_path: Path) -> Dict[str, Tuple[str, str]]:
    """Build name→(params, body) table of all #defines in the target.

    Results are cached per target path, evicting LRU when full.
    """
    key = str(target_path)
    if key in _table_cache:
        _table_cache.move_to_end(key)
        return _table_cache[key]

    table: Dict[str, Tuple[str, str]] = {}
    try:
        for p in target_path.rglob("*"):
            if not p.is_file() or p.suffix not in _C_EXTENSIONS:
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            text = text.replace("\\\n", " ")
            for m in _MACRO_DEF_RE.finditer(text):
                name = m.group(1)
                params = m.group(2) or ""
                body = m.group(3).strip()
                if not body:
                    continue
                if name not in table:
                    table[name] = (params, body)
                else:
                    logger.debug(
                        "macro %s redefined in %s (keeping first definition)",
                        name, p,
                    )
            for em in _ENUM_BLOCK_RE.finditer(text):
                for ev in _ENUMERATOR_RE.finditer(em.group(1)):
                    ename = ev.group(1).strip()
                    evalue = ev.group(2).strip().rstrip(",")
                    if ename in _SKIP_IDENTS_C:
                        continue
                    if ename not in table:
                        table[ename] = ("", evalue)
                    else:
                        logger.debug(
                            "enumerator %s redefined in %s "
                            "(keeping first definition)",
                            ename, p,
                        )
    except OSError:
        pass

    if len(_table_cache) >= _TABLE_CACHE_MAX:
        _table_cache.popitem(last=False)
    _table_cache[key] = table
    return table


def resolve_macros(
    target_path: Path,
    source: str,
    max_depth: int = 3,
    table: Optional[Dict[str, Tuple[str, str]]] = None,
) -> List[Tuple[str, str]]:
    """Find macros used in source, resolve transitively.

    Returns list of (display_name, body) tuples, leaf-first so consumers
    read primitives before compositions.
    """
    if not source:
        return []

    if table is None:
        table = build_macro_table(target_path)
    if not table:
        return []

    source_idents = set(_MACRO_IDENT_RE.findall(source)) - _SKIP_IDENTS_C

    resolved: Dict[str, Tuple[str, str, int]] = {}
    worklist = [(name, 0) for name in source_idents if name in table]
    visited: set = set()

    while worklist:
        name, depth = worklist.pop()
        if name in visited:
            continue
        visited.add(name)

        entry = table.get(name)
        if not entry:
            continue
        params, body = entry
        display = f"{name}{params}" if params else name
        resolved[name] = (display, body, depth)

        if depth < max_depth:
            body_idents = set(_MACRO_IDENT_RE.findall(body)) - _SKIP_IDENTS_C
            for child in body_idents:
                if child not in visited and child in table:
                    worklist.append((child, depth + 1))

    if not resolved:
        return []

    items = sorted(resolved.values(), key=lambda x: (-x[2], x[0]))
    return [(display, body) for display, body, _ in items]
