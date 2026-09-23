"""Automatic discovery of lifecycle-sensitive state fields.

Scans source files for struct/class definitions and their fields,
then scores each field for lifecycle sensitivity based on:
- Whether reads occur inside security-relevant guards
- Whether the field flows to known sinks
- Whether writes occur inside lifecycle-critical functions

This provides mechanical field discovery without an LLM pass.

WIRING STATUS: no pipeline currently calls :func:`discover_state_fields`
or persists its output — the lane is EXPERIMENTAL/UNWIRED. The /audit
orchestrator's ``check_lifecycle_at_function`` consumer stays a no-op
until a producer writes ``state_fields`` into context-map.json (see
``lifecycle_context_map``). A repository test pins this status in both
directions: wiring a producer must update these docstrings.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .lifecycle_collector import collect_field_sites_from_source
from .lifecycle_model import ReadSite, StateField, WriteSite

logger = logging.getLogger(__name__)

# Per-file read cap for the regex extractors (hostile-source guard).
_MAX_SOURCE_BYTES = 1_000_000

# --- Struct/class field extraction (regex-based, multi-language) ---

_C_STRUCT_KEYWORD_RE = re.compile(
    r"(?:struct|union)\s+(\w+)\s*\{",
)
# Bounded type window, gated optional atoms, and a leading \b so an
# unanchored scan cannot restart inside an identifier run: the naive
# ``(\w[\w\s*]*?)\s+\*?\s*(\w+)\s*(?:\[.*?\])?\s*;`` chained
# overlapping whitespace-capable spans around optional atoms — a
# field-shaped token run with no ``;`` cost every split of the run
# between them, cubic in the struct-body length. Bound trade-off,
# both directions: a larger window admits longer multi-token types
# but raises the per-position backtracking ceiling. 256 chars sits
# far above real C field types.
_C_FIELD_RE = re.compile(
    r"\b(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:struct\s+)?"
    r"(\w[\w\s*]{0,256}?)\s{1,256}(?:\*\s*)?(\w+)\s*(?:\[.*?\]\s*)?;",
)

_PY_CLASS_RE = re.compile(
    r"^class\s+(\w+).*?:\s*$",
    re.MULTILINE,
)
# Horizontal-only indent — the MULTILINE ^\s+ idiom is quadratic
# on blank-line runs in scanned source.
_PY_ATTR_ASSIGN_RE = re.compile(
    r"^[^\S\n]+self\.(\w+)\s*=",
    re.MULTILINE,
)

_JAVA_CLASS_RE = re.compile(
    r"(?:class|interface)\s+(\w+)",
)
_JAVA_FIELD_RE = re.compile(
    r"(?:private|public|protected)\s+(?:static\s+)?(?:final\s+)?"
    r"(\w[\w<>,\s]*?)\s+(\w+)\s*[;=]",
)


def _match_braces(source: str) -> dict[int, int]:
    """Open-brace position -> matching close position, one pass.
    Unmatched opens are absent — callers SKIP such structs: malformed
    heads get no body attribution (refusal direction), and running
    each one's body to EOF made the field pass quadratic on hostile
    sources full of unclosed 'struct x {' heads."""
    match: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(source):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            match[stack.pop()] = i
    return match


def _extract_struct_fields_c(source: str) -> dict[str, list[str]]:
    """Extract struct/union definitions and their field names from C/C++ source."""
    result: dict[str, list[str]] = {}
    braces = _match_braces(source)
    for m in _C_STRUCT_KEYWORD_RE.finditer(source):
        struct_name = m.group(1)
        brace_start = m.end() - 1  # position of the '{'
        close = braces.get(brace_start)
        if close is None:
            continue
        body = source[brace_start + 1:close]
        fields = [fm.group(2) for fm in _C_FIELD_RE.finditer(body)]
        if fields:
            result[struct_name] = fields
    return result


def _extract_class_fields_python(source: str) -> dict[str, list[str]]:
    """Extract class definitions and self.x assignments from Python source."""
    import bisect
    result: dict[str, list[str]] = {}
    lines = source.splitlines(True)
    # One cumulative newline-offset table shared by every class match
    # — the per-class source[:pos].count("\n") recount was quadratic
    # in class count on hostile sources.
    nl_offsets = [i for i, ch in enumerate(source) if ch == "\n"]

    def _line_index(pos: int) -> int:
        return bisect.bisect_left(nl_offsets, pos)

    classes = list(_PY_CLASS_RE.finditer(source))
    for i, cm in enumerate(classes):
        class_name = cm.group(1)
        class_line_start = _line_index(cm.start())
        # Determine indent level of this class definition
        cls_line = lines[class_line_start]
        class_indent = len(cls_line) - len(cls_line.lstrip())
        start = cm.end()
        # Find end: next class/def at same or lesser indentation
        end = len(source)
        for j in range(i + 1, len(classes)):
            next_line_start = _line_index(classes[j].start())
            nl = lines[next_line_start]
            next_indent = len(nl) - len(nl.lstrip())
            if next_indent <= class_indent:
                end = classes[j].start()
                break
        body = source[start:end]
        attrs = list(dict.fromkeys(
            am.group(1) for am in _PY_ATTR_ASSIGN_RE.finditer(body)
        ))
        if attrs:
            result[class_name] = attrs
    return result


def _extract_class_fields_java(source: str) -> dict[str, list[str]]:
    """Extract class definitions and field declarations from Java/C# source."""
    result: dict[str, list[str]] = {}
    classes = list(_JAVA_CLASS_RE.finditer(source))
    for i, cm in enumerate(classes):
        class_name = cm.group(1)
        start = cm.end()
        end = classes[i + 1].start() if i + 1 < len(classes) else len(source)
        body = source[start:end]
        fields = [fm.group(2) for fm in _JAVA_FIELD_RE.finditer(body)]
        if fields:
            result[class_name] = fields
    return result


_LANG_EXTRACTORS = {
    "c": _extract_struct_fields_c,
    "cpp": _extract_struct_fields_c,
    "h": _extract_struct_fields_c,
    "py": _extract_class_fields_python,
    "java": _extract_class_fields_java,
    "cs": _extract_class_fields_java,
}

# --- Sensitivity scoring ---

_SECURITY_GUARD_PATTERNS = [
    re.compile(r"\b(?:auth|permission|privilege|access|role)\b", re.IGNORECASE),
    re.compile(r"\b(?:null|nil|none|nullptr)\b", re.IGNORECASE),
    re.compile(r"\b(?:bounds|size|length|count|limit|max|min)\b", re.IGNORECASE),
    re.compile(r"\b(?:lock|mutex|semaphore|atomic)\b", re.IGNORECASE),
]

_LIFECYCLE_FUNCTION_PATTERNS = [
    re.compile(r"\b(?:init|setup|create|alloc|new|open|start)\b", re.IGNORECASE),
    re.compile(r"\b(?:free|destroy|close|cleanup|teardown|release|del)\b", re.IGNORECASE),
    re.compile(r"\b(?:exec|fork|clone|spawn)\b", re.IGNORECASE),
]


def _score_field(
    _field_name: str,
    _struct_type: str,
    sites: dict[str, list[int]],
    _source: str,
    source_lines: list[str],
) -> float:
    """Score a field for lifecycle sensitivity (0.0 - 1.0).

    Higher scores indicate fields more likely to carry security-relevant
    lifecycle invariants.
    """
    score = 0.0
    n_writes = len(sites.get("writes", []))
    n_reads = len(sites.get("reads", []))

    if n_writes == 0 and n_reads == 0:
        return 0.0

    if n_writes > 0 and n_reads > 0:
        score += 0.2

    for line_num in sites.get("reads", []):
        if 0 < line_num <= len(source_lines):
            context_start = max(0, line_num - 6)
            context_end = min(len(source_lines), line_num + 2)
            context = "\n".join(source_lines[context_start:context_end])
            for pat in _SECURITY_GUARD_PATTERNS:
                if pat.search(context):
                    score += 0.15
                    break

    for line_num in sites.get("writes", []):
        if 0 < line_num <= len(source_lines):
            context_start = max(0, line_num - 4)
            context_end = min(len(source_lines), line_num + 1)
            context = "\n".join(source_lines[context_start:context_end])
            for pat in _LIFECYCLE_FUNCTION_PATTERNS:
                if pat.search(context):
                    score += 0.2
                    break

    if n_writes >= 2:
        score += 0.1
    if n_reads >= 3:
        score += 0.1

    return min(score, 1.0)


# --- Main API ---

def discover_state_fields(
    checklist: dict[str, Any],
    target_path: str | Path,
    *,
    top_n: int = 20,
    min_score: float = 0.3,
) -> list[StateField]:
    """Discover lifecycle-sensitive state fields from source files.

    Scans files listed in *checklist* for struct/class definitions,
    extracts their fields, finds write/read sites, and returns the
    top-N scoring fields as ``StateField`` objects.

    Parameters
    ----------
    checklist:
        The project checklist (from ``checklist.json``).
    target_path:
        Root of the target codebase for reading source files.
    top_n:
        Maximum number of fields to return.
    min_score:
        Minimum sensitivity score to include a field.
    """
    target = Path(target_path)
    candidates: list[tuple[float, str, StateField]] = []

    for fi in checklist.get("files", []) or []:
        if not isinstance(fi, dict):
            continue
        # Same path/file fallback as core.inventory.iter_checklist_items
        # (older artifacts carry "file"); the walk stays file-level
        # because extraction is per-source-file.
        file_path = fi.get("path", fi.get("file", ""))
        if not file_path:
            continue

        ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        extractor = _LANG_EXTRACTORS.get(ext)
        if extractor is None:
            continue

        full_path = target / file_path
        if not full_path.is_file():
            continue

        try:
            # Checklist-listed files are hostile input; the regex
            # extractors run over the whole text, so cap the read
            # (skip = fewer discovered fields, the refusal direction).
            if full_path.stat().st_size > _MAX_SOURCE_BYTES:
                logger.debug(
                    "field discovery: skipping %s (> %d bytes)",
                    file_path, _MAX_SOURCE_BYTES)
                continue
            source = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        source_lines = source.splitlines()
        structs = extractor(source)

        for struct_name, fields in structs.items():
            for field_name in fields:
                sites = collect_field_sites_from_source(
                    source, file_path, field_name, struct_type=struct_name,
                )
                score = _score_field(
                    field_name, struct_name, sites, source, source_lines,
                )
                if score < min_score:
                    continue

                # Populate the enclosing function from the checklist's
                # own item spans — consumers join on
                # ``site.function == function_name``, so an empty
                # function makes every downstream lookup vacuous.
                def _fn_at(line: int) -> str:
                    from core.analysis.reachability import (
                        enclosing_function,
                    )
                    host = enclosing_function(checklist, file_path, line)
                    return host.name if host is not None else ""

                write_sites = [
                    WriteSite(
                        file=file_path,
                        line=line,
                        function=_fn_at(line),
                        guards=frozenset(),
                    )
                    for line in sites.get("writes", [])
                ]
                read_sites = [
                    ReadSite(
                        file=file_path,
                        line=line,
                        function=_fn_at(line),
                        guards=frozenset(),
                    )
                    for line in sites.get("reads", [])
                ]

                sf = StateField(
                    name=field_name,
                    struct_type=struct_name,
                    invariant=f"auto-discovered field {struct_name}.{field_name}",
                    write_sites=write_sites,
                    read_sites=read_sites,
                    notes="auto-discovered",
                )
                candidates.append((score, file_path, sf))

    candidates.sort(key=lambda x: x[0], reverse=True)

    # Dedup key includes the FILE: same-named structs in different
    # files are different types and must not collapse.
    seen: set[tuple[str, str, str]] = set()
    result: list[StateField] = []
    for score, fpath, sf in candidates:
        key = (fpath, sf.struct_type, sf.name)
        if key in seen:
            continue
        seen.add(key)
        result.append(sf)
        if len(result) >= top_n:
            break

    if result:
        logger.info(
            "field discovery: %d lifecycle-sensitive fields from %d structs/classes",
            len(result),
            len({sf.struct_type for sf in result}),
        )
    return result
