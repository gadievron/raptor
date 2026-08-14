"""Shared low-level helpers for core.audit modules.

Three concerns that recur across constraints, propagation, sweep, gaps,
and priority: path containment, identifier validation, and checklist
lookups.  Consolidated here to avoid drift between copies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_IDENTIFIER_QUALIFIED_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

SAFE_COCCI_RULE_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_\-.]*\.cocci$",
)


def safe_join(base: Path, relative: str) -> Path | None:
    """Join *base* + *relative* and verify the result stays under *base*.

    Returns None when the path contains ``..`` segments or resolves
    outside *base*.  Callers should treat None as "path rejected".
    """
    if ".." in relative.split("/"):
        return None
    full = base / relative
    try:
        resolved = full.resolve()
        base_resolved = base.resolve()
        if not str(resolved).startswith(str(base_resolved) + "/") and \
           resolved != base_resolved:
            return None
    except (OSError, ValueError):
        return None
    return resolved


def is_valid_identifier(name: str) -> bool:
    """True when *name* looks like a C / Python identifier."""
    return bool(IDENTIFIER_RE.match(name))


def safe_joern_name(value: str) -> str | None:
    """Validate and escape a name for Joern/Scala string interpolation.

    Returns the escaped string, or None when the value is unsafe.
    """
    if not value:
        return None
    try:
        from packages.joern.runner import (
            _escape_scala_string,
            _validate_substitution_value,
        )
    except ImportError:
        if not _IDENTIFIER_QUALIFIED_RE.match(value):
            return None
        return (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
        )
    if not _validate_substitution_value(value):
        return None
    return _escape_scala_string(value)


def find_function_in_checklist(
    checklist: dict[str, Any],
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Find a function item in the checklist by file + name.

    Returns the item dict (with ``line_start``, ``line_end``,
    ``metadata``, etc.) or None if not found.
    """
    for file_info in checklist.get("files", []):
        if file_info.get("path") != file_path:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            if item.get("name") == function_name:
                return item
    return None


def find_function_line(
    checklist: dict[str, Any],
    file_path: str,
    function_name: str,
) -> int:
    """Return ``line_start`` for a function, or 0 if not found."""
    item = find_function_in_checklist(checklist, file_path, function_name)
    if item:
        return item.get("line_start", 0) or 0
    return 0


def find_function_lines(
    checklist: dict[str, Any],
    file_path: str,
    function_name: str,
) -> tuple[int, int]:
    """Return ``(line_start, line_end)`` for a function, or ``(0, 0)``."""
    item = find_function_in_checklist(checklist, file_path, function_name)
    if item:
        return (
            item.get("line_start", 0) or 0,
            item.get("line_end", 0) or 0,
        )
    return (0, 0)


def extract_context_map_set(
    context_map: dict[str, Any] | None,
    section: str,
    *,
    nested_key: str = "",
) -> set:
    """Extract ``file:name`` keys from a context-map section.

    Works for flat lists (``entry_points``, ``sinks``) and for nested
    structures (``trust_boundaries`` with a ``functions`` sub-list).

    Args:
        context_map: Parsed context-map.json.
        section: Top-level key (``"entry_points"``, ``"sinks"``,
                 ``"trust_boundaries"``).
        nested_key: When set, each item under *section* is expected
                    to carry a sub-list with this key (e.g.
                    ``"functions"`` for trust boundaries).
    """
    if not context_map:
        return set()
    result = set()
    for item in context_map.get(section, []):
        if nested_key:
            for func in item.get(nested_key, []):
                _add_key(result, func)
        else:
            _add_key(result, item)
    return result


def _add_key(result: set, item: dict[str, Any]) -> None:
    key = f"{item.get('file', '')}:{item.get('name', '')}"
    if key != ":":
        result.add(key)


_SECURITY_SINK_TYPES = frozenset({
    "shell_exec", "shell_execution", "process_execution",
    "file_write", "file_read", "file_delete",
    "code_exec", "code_execution",
    "deserialization",
    "sql_query", "network_request",
    "memory_aliasing",
})


def _is_security_sink(item: dict[str, Any]) -> bool:
    """Check if a sink_detail entry represents a security-relevant sink.

    Uses ``type`` first (LLM-assigned or from ``_classify_sink_type``).
    For ``dangerous_call`` fallback entries, checks ``dangerous_target``
    against ``DANGEROUS_TARGETS`` from sink_discovery (the canonical list).
    """
    if item.get("type", "") in _SECURITY_SINK_TYPES:
        return True
    dt = item.get("dangerous_target", "")
    if dt:
        try:
            from core.inventory.sink_discovery import DANGEROUS_TARGETS
            return dt in DANGEROUS_TARGETS
        except ImportError:
            pass
    return False


def extract_sink_sets(
    context_map: dict[str, Any] | None,
) -> tuple[set, set]:
    """Extract sink keys from ``sink_details``, split by security relevance.

    Returns ``(security_sinks, all_sinks)`` where security_sinks is the
    subset whose ``type`` indicates an OS/process boundary crossing
    (shell exec, file I/O, code loading, etc.) and all_sinks includes
    ``dangerous_call`` entries too.

    Triage should only promote ``security_sinks`` to DEEP_DIVE.
    The full ``all_sinks`` set is used for review context and
    clean-check gating.
    """
    if not context_map:
        return set(), set()
    security = set()
    all_sinks = set()
    for item in context_map.get("sink_details", []):
        key = f"{item.get('file', '')}:{item.get('name', '')}"
        if key == ":":
            continue
        all_sinks.add(key)
        if _is_security_sink(item):
            security.add(key)
    if not all_sinks:
        all_sinks = extract_context_map_set(context_map, "sinks")
        security = all_sinks
    return security, all_sinks


# ---------------------------------------------------------------------------
# Shared function-boundary helpers for mechanical detectors
# ---------------------------------------------------------------------------

_FUNC_DEF_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)


def find_enclosing_function(lines: list, target_line: int) -> str:
    """Walk backwards from *target_line* (0-indexed) to find the enclosing def."""
    for i in range(target_line, -1, -1):
        m = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", lines[i])
        if m:
            return m.group(1)
    return "<module>"


def extract_functions_from_source(source: str) -> list:
    """Extract (name, start_line_1indexed, body_text) for each def in *source*.

    Returns a list of 3-tuples. Used by mechanical detectors that need
    per-function source slices without a full AST parse.
    """
    funcs: list = []
    lines = source.split("\n")
    for m in _FUNC_DEF_RE.finditer(source):
        name = m.group("name")
        indent = len(m.group("indent"))
        start_line = source[:m.start()].count("\n") + 1

        body_start_idx = start_line - 1
        end_idx = body_start_idx + 1
        while end_idx < len(lines):
            ln = lines[end_idx]
            stripped = ln.lstrip()
            if stripped and not stripped.startswith("#"):
                line_indent = len(ln) - len(stripped)
                if line_indent <= indent:
                    break
            end_idx += 1

        body = "\n".join(lines[body_start_idx:end_idx])
        funcs.append((name, start_line, body))
    return funcs
