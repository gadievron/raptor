"""Automatic discovery of lifecycle-sensitive state fields.

Scans source files for struct/class definitions and their fields,
then scores each field for lifecycle sensitivity based on:
- Whether reads occur inside security-relevant guards
- Whether the field flows to known sinks
- Whether writes occur inside lifecycle-critical functions

This provides mechanical field discovery without an LLM pass,
usable as a fallback when /understand --map hasn't been run.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .lifecycle_collector import collect_field_sites_from_source
from .lifecycle_model import ReadSite, StateField, WriteSite

logger = logging.getLogger(__name__)

# --- Struct/class field extraction (regex-based, multi-language) ---

_C_STRUCT_KEYWORD_RE = re.compile(
    r"(?:struct|union)\s+(\w+)\s*\{",
)
_C_FIELD_RE = re.compile(
    r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:struct\s+)?"
    r"(\w[\w\s*]*?)\s+\*?\s*(\w+)\s*(?:\[.*?\])?\s*;",
)

_PY_CLASS_RE = re.compile(
    r"^class\s+(\w+).*?:\s*$",
    re.MULTILINE,
)
_PY_ATTR_ASSIGN_RE = re.compile(
    r"^\s+self\.(\w+)\s*=",
    re.MULTILINE,
)

_JAVA_CLASS_RE = re.compile(
    r"(?:class|interface)\s+(\w+)",
)
_JAVA_FIELD_RE = re.compile(
    r"(?:private|public|protected)\s+(?:static\s+)?(?:final\s+)?"
    r"(\w[\w<>,\s]*?)\s+(\w+)\s*[;=]",
)


def _extract_struct_fields_c(source: str) -> dict[str, list[str]]:
    """Extract struct/union definitions and their field names from C/C++ source."""
    result: dict[str, list[str]] = {}
    for m in _C_STRUCT_KEYWORD_RE.finditer(source):
        struct_name = m.group(1)
        brace_start = m.end() - 1  # position of the '{'
        depth = 1
        pos = brace_start + 1
        while pos < len(source) and depth > 0:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1
        body = source[brace_start + 1:pos - 1]
        fields = [fm.group(2) for fm in _C_FIELD_RE.finditer(body)]
        if fields:
            result[struct_name] = fields
    return result


def _extract_class_fields_python(source: str) -> dict[str, list[str]]:
    """Extract class definitions and self.x assignments from Python source."""
    result: dict[str, list[str]] = {}
    lines = source.splitlines(True)
    classes = list(_PY_CLASS_RE.finditer(source))
    for i, cm in enumerate(classes):
        class_name = cm.group(1)
        class_line_start = source[:cm.start()].count("\n")
        # Determine indent level of this class definition
        cls_line = lines[class_line_start]
        class_indent = len(cls_line) - len(cls_line.lstrip())
        start = cm.end()
        # Find end: next class/def at same or lesser indentation
        end = len(source)
        for j in range(i + 1, len(classes)):
            next_line_start = source[:classes[j].start()].count("\n")
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
    re.compile(r"\b(?:auth|permission|privilege|access|role)\b", re.I),
    re.compile(r"\b(?:null|nil|none|nullptr)\b", re.I),
    re.compile(r"\b(?:bounds|size|length|count|limit|max|min)\b", re.I),
    re.compile(r"\b(?:lock|mutex|semaphore|atomic)\b", re.I),
]

_LIFECYCLE_FUNCTION_PATTERNS = [
    re.compile(r"\b(?:init|setup|create|alloc|new|open|start)\b", re.I),
    re.compile(r"\b(?:free|destroy|close|cleanup|teardown|release|del)\b", re.I),
    re.compile(r"\b(?:exec|fork|clone|spawn)\b", re.I),
]


def _score_field(
    field_name: str,
    struct_type: str,
    sites: dict[str, list[int]],
    source: str,
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
    candidates: list[tuple[float, StateField]] = []

    for fi in checklist.get("files", []):
        file_path = fi.get("path", "")
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

                write_sites = [
                    WriteSite(
                        file=file_path,
                        line=line,
                        function="",
                        guards=frozenset(),
                    )
                    for line in sites.get("writes", [])
                ]
                read_sites = [
                    ReadSite(
                        file=file_path,
                        line=line,
                        function="",
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
                candidates.append((score, sf))

    candidates.sort(key=lambda x: x[0], reverse=True)

    seen: set[tuple[str, str]] = set()
    result: list[StateField] = []
    for score, sf in candidates:
        key = (sf.struct_type, sf.name)
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
