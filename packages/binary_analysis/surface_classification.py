"""Classify native imports without calling every interesting API a sink.

The fuzzing taxonomy is intentionally broad because parsers and file APIs are
useful prioritisation signals. A security report needs a tighter distinction:
`memcpy` and `NSTask` are sink candidates; `JSONDecoder` and
`URL.fileURLWithPath` are surfaces that may matter, but are not consequences
on their own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.function_taxonomy import (
    EXEC_FUNCS,
    FORMAT_STRING_FUNCS,
    MACOS_FILESYSTEM_URL_SUBSTRINGS,
    MACOS_PARSER_SUBSTRINGS,
    MACOS_PROCESS_EXEC_SUBSTRINGS,
    MACOS_SECURITY_BOUNDARY_PREFIXES,
    MEMORY_COPY_FUNCS,
    PARSER_FUNCS,
    SCAN_FAMILY_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
)

from ._symbols import strip_import_prefix


@dataclass(frozen=True)
class SurfaceClassification:
    name: str
    role: str
    category: str
    is_sink: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "category": self.category,
            "is_sink": self.is_sink,
            "rationale": self.rationale,
        }


def classify_security_api(name: str) -> SurfaceClassification | None:
    raw = str(name or "")
    stripped = strip_import_prefix(raw)
    base = stripped.split(".")[-1]

    if base in ("NSLog", "CFLog", "os_log", "os_log_impl"):
        return SurfaceClassification(raw, "surface", "logging", False,
                                     "Logging API worth reviewing, but not a format-string sink until the callsite proves a non-literal format.")
    if base in STRING_OVERFLOW_FUNCS or base in MEMORY_COPY_FUNCS:
        return SurfaceClassification(raw, "sink", "memory_write", True,
                                     "Memory/string copy primitive; only dangerous if attacker-controlled sizes or bytes reach it.")
    if base in FORMAT_STRING_FUNCS:
        return SurfaceClassification(raw, "sink", "format_string", True,
                                     "Formatting primitive; only dangerous if attacker data controls the format string.")
    if base in EXEC_FUNCS:
        return SurfaceClassification(raw, "sink", "process_execution", True,
                                     "Process execution primitive; only dangerous if attacker data controls the command or arguments.")
    if base in {"mktemp", "tempnam"}:
        return SurfaceClassification(raw, "sink", "filesystem_race", True,
                                     "Filesystem race primitive; only dangerous if an attacker can influence the checked path.")
    if base in TOCTOU_FUNCS:
        return SurfaceClassification(raw, "surface", "filesystem_path", False,
                                     "Filesystem path handling surface; a race or traversal claim needs a concrete check/use sequence.")
    if base in SCAN_FAMILY_FUNCS or base in PARSER_FUNCS:
        return SurfaceClassification(raw, "surface", "parser", False,
                                     "Parser/input API worth tracing, but not a consequence by itself.")

    # macOS categories come from the taxonomy's grouped substring sets
    # (this consumer used to re-list a drifting subset of them). Match
    # semantics per the taxonomy contract: substring-in-demangled-name
    # for dotted Swift symbols, token match for bare Obj-C class names.
    _raw_parts = stripped.replace(".", " ").replace(":", " ").split()
    if _matches_macos_group(stripped, _raw_parts, MACOS_PROCESS_EXEC_SUBSTRINGS):
        return SurfaceClassification(raw, "sink", "process_execution", True,
                                     "Foundation process execution API.")
    if (_matches_macos_group(stripped, _raw_parts, MACOS_PARSER_SUBSTRINGS)
            or base in ("inflate", "CFXML")):
        return SurfaceClassification(raw, "surface", "parser", False,
                                     "Structured-data parser surface.")
    if (_matches_macos_group(
            stripped, _raw_parts, MACOS_FILESYSTEM_URL_SUBSTRINGS,
    ) or base == "readlink"):
        return SurfaceClassification(raw, "surface", "filesystem_or_url", False,
                                     "Filesystem/URL handling surface.")
    if any(
        part.startswith(prefix)
        for part in _raw_parts
        for prefix in MACOS_SECURITY_BOUNDARY_PREFIXES
    ):
        return SurfaceClassification(raw, "surface", "security_boundary", False,
                                     "Security-framework boundary API.")
    return None


def _matches_macos_group(
    stripped: str, parts: list[str], group: frozenset,
) -> bool:
    """Substring-match a demangled symbol against a taxonomy group.

    Dotted entries (Swift symbol paths) match as prefixes/substrings of
    the stripped name; bare entries (Obj-C class / CF function names)
    match as whole tokens or name prefixes, mirroring the pre-taxonomy
    branch logic.
    """
    for entry in group:
        if "." in entry:
            if stripped.startswith(entry) or entry in stripped:
                return True
        elif entry in parts or stripped.startswith(entry):
            return True
    return False


__all__ = ["SurfaceClassification", "classify_security_api"]
