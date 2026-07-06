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

from ._symbols import strip_import_prefix
from core.function_taxonomy import (
    EXEC_FUNCS,
    FORMAT_STRING_FUNCS,
    MEMORY_COPY_FUNCS,
    PARSER_FUNCS,
    SCAN_FAMILY_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
)


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

    _raw_parts = stripped.replace(".", " ").replace(":", " ").split()
    if any(token in _raw_parts for token in ("NSTask",)) or stripped.startswith("Foundation.Process"):
        return SurfaceClassification(raw, "sink", "process_execution", True,
                                     "Foundation process execution API.")
    if any(stripped.startswith(prefix) for prefix in (
        "Foundation.JSONDecoder",
        "Foundation.JSONSerialization",
        "Foundation.PropertyList",
        "Foundation.Data.base64Encoded",
    )) or base in ("inflate", "CFXML"):
        return SurfaceClassification(raw, "surface", "parser", False,
                                     "Structured-data parser surface.")
    if any(stripped.startswith(prefix) for prefix in (
        "Foundation.Data.contentsOf",
        "Foundation.URL.fileURLWithPath",
        "Foundation.URL.absoluteString",
    )) or base in ("CFURLCreateWithBytes", "readlink"):
        return SurfaceClassification(raw, "surface", "filesystem_or_url", False,
                                     "Filesystem/URL handling surface.")
    if any(part.startswith(prefix) for part in _raw_parts for prefix in ("SecTrust", "SecPolicy", "SecItem", "SecKeychain")):
        return SurfaceClassification(raw, "surface", "security_boundary", False,
                                     "Security-framework boundary API.")
    return None


__all__ = ["SurfaceClassification", "classify_security_api"]
