"""Engine selection for KNighter checker synthesis.

Coccinelle is the right tool for C source — its semantic-patch
language captures kernel-style invariant violations (missing
checks, leaked locks, missed bounds tests) with surgical precision
that Semgrep's structural matching can't match.

Semgrep handles every other language we currently support
(Python, Java, Go, JavaScript, TypeScript, Ruby, Rust, etc.).

Files we can't classify (binary blobs, unrecognised extensions)
return ``None`` — caller should skip rather than guess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Set


# C source / header — Coccinelle's home turf.
_COCCINELLE_EXTS: Set[str] = {".c", ".h"}

# Languages Semgrep handles. Not exhaustive — Semgrep supports more —
# but covers everything RAPTOR's inventory extractors currently know
# about. Unknown extensions fall through to None so the caller can
# skip rather than synthesise a rule that has nowhere to run.
_SEMGREP_EXTS: Set[str] = {
    ".py", ".pyi",
    ".java",
    ".go",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".rb",
    ".rs",
    ".php",
    ".cs",
    ".kt", ".kts",
    ".scala",
    ".swift",
    ".lua",
    ".ex", ".exs",
    # C++: Coccinelle's C++ support is weak; route to Semgrep,
    # which handles C++ better via tree-sitter.
    ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".c++",
}


def detect_engine(file_path: str) -> Optional[str]:
    """Pick the synthesis engine for a source file.

    Returns ``"coccinelle"`` for C/C++ headers + sources, ``"semgrep"``
    for everything else we support, or ``None`` for files we don't
    recognise (binary, unknown extension, no extension).
    """
    if not file_path:
        return None
    suffix = Path(file_path).suffix.lower()
    if not suffix:
        return None
    if suffix in _COCCINELLE_EXTS:
        return "coccinelle"
    if suffix in _SEMGREP_EXTS:
        return "semgrep"
    return None


def supported_engines() -> tuple[str, ...]:
    """The engines this package can synthesise rules for."""
    return ("semgrep", "coccinelle")
