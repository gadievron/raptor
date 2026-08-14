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
from pathlib import Path
from typing import Optional


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
    nm: bool = False
    binary_available: bool = False
    dwarf_available: bool = False
    joern_issues: tuple = ()


def _can_import(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def _has_dwarf(binary_path: Optional[Path]) -> bool:
    if binary_path is None or not binary_path.is_file():
        return False
    readelf = shutil.which("readelf")
    if not readelf:
        return False
    import subprocess
    try:
        from core.config import RaptorConfig
        result = subprocess.run(
            [readelf, "--debug-dump=info", "--dwarf-depth=1", str(binary_path)],
            capture_output=True, timeout=10,
            env=RaptorConfig.get_safe_env(),
        )
        return b"DW_TAG_compile_unit" in result.stdout
    except Exception:
        return False


def probe_capabilities(
    binary_path: Optional[Path] = None,
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
        nm=shutil.which("nm") is not None,
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
