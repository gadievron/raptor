"""Detect available analysis tools at audit start.

Probed once before the review loop. Each capability gates a fallback
decision: without Joern, summaries come from tree-sitter + LLM instead
of CPG queries; without Frida, evidence stays at HEURISTIC/XREF_BACKED
instead of upgrading to OBSERVED_RUNTIME; etc.
"""

from __future__ import annotations

import importlib
import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class AuditCapabilities:
    """Snapshot of which analysis tools are usable for this audit run."""

    joern: bool = False
    r2: bool = False
    frida: bool = False
    semgrep: bool = False
    coccinelle: bool = False
    codeql: bool = False
    ghidra: bool = False
    cxxfilt: bool = False
    objdump: bool = False
    readelf: bool = False
    binary_available: bool = False
    dwarf_available: bool = False
    joern_issues: tuple = ()


def _can_import(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def _has_dwarf(binary_path: Path | None) -> bool:
    if binary_path is None or not binary_path.is_file():
        return False
    readelf = shutil.which("readelf")
    if not readelf:
        return False
    try:
        resolved = binary_path.resolve()
    except OSError:
        return False
    # Full sandbox, matching binary_oracle._run's posture for the same
    # tools: readelf is RAPTOR-picked but the BYTES it parses are the
    # operator's --binary of unverified provenance, and binutils'
    # ELF/DWARF parsers have a long CVE history — a malformed ELF must
    # not get parsed by a process holding the user's filesystem and
    # network. The resolved ABSOLUTE path is what defuses argument
    # injection: binutils' expandargv turns any argv element starting
    # with `@` into a response file regardless of `--`, and an
    # absolute path can start with neither `@` nor `-`. The `--` is
    # belt-and-braces for the option case only.
    from core.sandbox import run as _sandbox_run
    try:
        result = _sandbox_run(
            [readelf, "--debug-dump=info", "--dwarf-depth=1",
             "--", str(resolved)],
            block_network=True, target=str(resolved.parent),
            capture_output=True, timeout=30,
        )
        stdout = result.stdout
        if isinstance(stdout, str):
            stdout = stdout.encode(errors="replace")
        return b"DW_TAG_compile_unit" in (stdout or b"")
    except Exception:
        return False


def probe_capabilities(
    binary_path: Path | None = None,
) -> AuditCapabilities:
    """Detect available tools. Called once at audit start."""
    try:
        from packages.joern.prereqs import check_prereqs as _joern_prereqs
        _joern_issues = tuple(_joern_prereqs())
    except ImportError:
        _joern_issues = ("packages.joern not available",)

    return AuditCapabilities(
        joern=len(_joern_issues) == 0,
        joern_issues=_joern_issues,
        r2=shutil.which("r2") is not None,
        frida=_can_import("frida"),
        semgrep=shutil.which("semgrep") is not None,
        coccinelle=shutil.which("spatch") is not None,
        codeql=shutil.which("codeql") is not None,
        ghidra=shutil.which("analyzeHeadless") is not None,
        cxxfilt=shutil.which("c++filt") is not None,
        objdump=shutil.which("objdump") is not None,
        readelf=shutil.which("readelf") is not None,
        binary_available=binary_path is not None and binary_path.is_file(),
        dwarf_available=_has_dwarf(binary_path),
    )


def format_capability_report(caps: AuditCapabilities) -> str:
    """One-line summary for audit start banner."""
    present = []
    absent = []

    tool_names = {
        "joern": "Joern",
        "r2": "r2",
        "frida": "Frida",
        "semgrep": "Semgrep",
        "coccinelle": "Coccinelle",
        "codeql": "CodeQL",
        "ghidra": "Ghidra",
    }

    for attr, label in tool_names.items():
        if getattr(caps, attr):
            present.append(label)
        elif attr == "joern" and caps.joern_issues:
            absent.append(f"Joern ({caps.joern_issues[0]})")
        else:
            absent.append(label)

    parts = []
    if present:
        parts.append(f"Running with {' + '.join(present)}.")
    if absent:
        parts.append(f"{', '.join(absent)} unavailable.")
    if not caps.binary_available:
        parts.append("No binary — Layer 0 and dynamic validation disabled.")
    elif caps.dwarf_available:
        parts.append("Binary with DWARF debug info available.")
    else:
        parts.append("Binary available (no DWARF).")

    return " ".join(parts)
