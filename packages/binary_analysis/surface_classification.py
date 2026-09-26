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
    MACOS_BYTE_BUFFER_SUBSTRINGS,
    MACOS_FILESYSTEM_URL_SUBSTRINGS,
    MACOS_IOKIT_SUBSTRINGS,
    MACOS_PARSER_SUBSTRINGS,
    MACOS_PROCESS_EXEC_SUBSTRINGS,
    MACOS_SECURITY_BOUNDARY_PREFIXES,
    MACOS_XPC_INGRESS_SUBSTRINGS,
    MEMORY_COPY_FUNCS,
    PARSER_FUNCS,
    SCAN_FAMILY_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
    WIN32_DYNAMIC_LOAD_FUNCS,
    WIN32_REGISTRY_INGEST_FUNCS,
    WIN32_SEH_FUNCS,
)

from ._symbols import strip_import_prefix

# Consumer composition (per the taxonomy's use-site rule): only the
# WINDOWS user-side device-control callers classify as sinks here.
# POSIX ``ioctl`` shares the taxonomy group but is near-ubiquitous
# (every TTY-touching binary imports it), so ranking it would drown
# the queue in zero-signal hits — and the kernel-side dispatch names
# never appear in user-space import tables at all.
_WIN32_DEVICE_CONTROL = frozenset({
    "DeviceIoControl", "NtDeviceIoControlFile",
})


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

    # Win32 arms — exact base-name matches like the C-family arms
    # above (Windows import names are unmangled).
    if base in _WIN32_DEVICE_CONTROL:
        return SurfaceClassification(raw, "sink", "device_control", True,
                                     "User-to-driver control call; only dangerous if attacker data shapes the control code or request buffer crossing into the driver.")
    if base in WIN32_REGISTRY_INGEST_FUNCS:
        return SurfaceClassification(raw, "surface", "registry_input", False,
                                     "Registry read surface; values under less-privileged-writable keys are external input worth tracing.")
    if base in WIN32_DYNAMIC_LOAD_FUNCS:
        return SurfaceClassification(raw, "surface", "dynamic_load", False,
                                     "Dynamic code loading surface; a planting/search-path claim needs an attacker-influenceable path at the callsite.")
    if base in WIN32_SEH_FUNCS:
        return SurfaceClassification(raw, "surface", "exception_handling", False,
                                     "SEH/unwind machinery marker; review surface for handler-state abuse, not a consequence by itself.")

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
    if _matches_macos_group(stripped, _raw_parts, MACOS_IOKIT_SUBSTRINGS):
        # Split at the use site: IOConnectCall* pushes attacker-shaped
        # selectors/buffers into a kext — the macOS sibling of the
        # DeviceIoControl sink above; service discovery only acquires
        # the boundary handle.
        if base.startswith("IOConnectCall"):
            return SurfaceClassification(raw, "sink", "device_control", True,
                                         "IOKit user-client call; only dangerous if attacker data shapes the selector or struct buffer crossing into the kext.")
        return SurfaceClassification(raw, "surface", "iokit_boundary", False,
                                     "IOKit service discovery/registry surface on the kernel boundary.")
    if _matches_macos_group(stripped, _raw_parts,
                            MACOS_XPC_INGRESS_SUBSTRINGS):
        return SurfaceClassification(raw, "surface", "ipc_ingress", False,
                                     "XPC listener/payload-read surface; peer-controlled input arrives here, consequences live downstream.")
    if _matches_macos_group(stripped, _raw_parts,
                            MACOS_BYTE_BUFFER_SUBSTRINGS):
        return SurfaceClassification(raw, "surface", "byte_buffer_bridge", False,
                                     "CF/NS byte-buffer bridge surface; tainted bytes and decode options often cross here.")
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
