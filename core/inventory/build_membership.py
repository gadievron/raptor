"""Detect translation units excluded from the build.

A source file that the build never compiles contributes no reachable code:
every function in it is dead in any normal build, regardless of in-file call
edges or external linkage. The call-graph and entry-point analyses can't see
this — they treat the file as ordinary source.

This module adds per-language detection of *build exclusion*. A single helper
:func:`detect_build_excluded` returns either ``None`` (no exclusion detected)
or a structured record. Consumers treat a detected exclusion as a whole-file
reachability gate: every function in the file is dead.

Unlike a module-load abort (a runtime event with a line threshold — functions
defined above the abort may already have bound), build exclusion is a
*compile-time, whole-file* property: nothing in the file is ever built, so
there is no line threshold.

Soundness: this is a HEURISTIC signal, never sound. A build constraint is
config-dependent — ``//go:build ignore`` excludes the file from *normal*
builds, but ``go build -tags ignore`` would still compile it; and a build
system may include a file by other means. So a ``build_excluded`` verdict is
surface-only (it demotes / annotates, never hard-suppresses), matching the
``no_path_from_entry`` tier.

Per-language detection currently wired:

  * Go: a build-constraint comment whose expression is exactly ``ignore`` —
    the idiomatic "never built in any normal configuration" marker, used for
    ``go run gen.go`` codegen scripts and standalone tools. Both the modern
    ``//go:build ignore`` and the legacy ``// +build ignore`` forms.

Other languages return ``None``. (C/C++ translation-unit membership against
``compile_commands.json`` and Rust crate-module membership are build-manifest
properties rather than file-content properties — a natural extension of the
same ``build_excluded`` witness, wired at the builder level rather than here.)
"""

from __future__ import annotations

import logging
import os.path
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Source translation-unit extensions — a file the build COMPILES. Headers are
# deliberately excluded: a .h is never a TU (never in compile_commands) but its
# functions are reachable via the .c files that #include it, so header
# membership must never be inferred from compile_commands.
_TU_SOURCE_EXT = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"})


@dataclass(frozen=True)
class BuildExcluded:
    """Describes a detected build exclusion.

    ``line``: 1-indexed line of the constraint (for display only — the gate
    is whole-file, not line-relative).
    ``summary``: short human-readable label for prompts / logs, e.g.
    ``"//go:build ignore"``.
    """
    line: int
    summary: str


def detect_build_excluded(
    language: str, content: str,
) -> Optional[BuildExcluded]:
    """Per-language dispatch. Returns the detected build exclusion, or
    ``None`` when none is detected (or the language has no detector wired).
    Best-effort: any parse failure returns ``None``."""
    if not content:
        return None
    try:
        if language == "go":
            return _detect_go(content)
    except Exception:  # noqa: BLE001
        return None
    return None


# ---------------------------------------------------------------------------
# Go build constraints. The expression must be exactly ``ignore`` — a complex
# expression like ``ignore || linux`` is satisfiable (builds on linux) and is
# NOT flagged. Constraints are only valid in the leading comment block, before
# the ``package`` clause, so we stop scanning at the package declaration.
# ---------------------------------------------------------------------------

_GO_BUILD_LINE = re.compile(r"^//go:build\s+(.+?)\s*$")
_GO_LEGACY_BUILD_LINE = re.compile(r"^//\s*\+build\s+(.+?)\s*$")
_GO_PACKAGE = re.compile(r"^\s*package\s+\w+")


def _detect_go(content: str) -> Optional[BuildExcluded]:
    for i, raw in enumerate(content.split("\n"), 1):
        line = raw.strip()
        if _GO_PACKAGE.match(raw):
            # Build constraints must precede the package clause; once we
            # reach it, no exclusion was found in the header.
            return None
        m = _GO_BUILD_LINE.match(line)
        if m and m.group(1).strip() == "ignore":
            return BuildExcluded(line=i, summary="//go:build ignore")
        m = _GO_LEGACY_BUILD_LINE.match(line)
        # Legacy ``// +build`` args are space-separated OR-terms; only a lone
        # ``ignore`` term means never-built. ``// +build ignore foo`` is
        # ``ignore OR foo`` → satisfiable, so not flagged.
        if m and m.group(1).split() == ["ignore"]:
            return BuildExcluded(line=i, summary="// +build ignore")
    return None


def tu_membership_excluded(
    abs_path: str, tu_files: Optional[frozenset],
) -> Optional[BuildExcluded]:
    """C/C++ build-membership witness: a SOURCE translation unit (``.c`` /
    ``.cpp`` / …) absent from ``compile_commands.json`` is not compiled in this
    build, so every function in it is dead. Heuristic (the manifest may be
    partial) → surface-only, never hard-suppress.

    Returns ``None`` (no exclusion) when:
      * ``tu_files`` is ``None`` — no parseable compile_commands ⇒ membership
        unknown (never fire on absence-of-evidence);
      * ``abs_path`` is not a source-TU extension — headers (``.h`` / ``.hpp``)
        are never TUs but their functions are reachable via includers, so they
        are exempt; non-C/C++ files are irrelevant;
      * ``abs_path`` IS in the build.

    ``abs_path`` must be resolved (realpath) to match the ``tu_files`` entries,
    which :func:`core.build.macro_config.extract_build_tus` resolves.
    """
    if tu_files is None:
        return None
    ext = os.path.splitext(abs_path)[1].lower()
    if ext not in _TU_SOURCE_EXT:
        return None
    if abs_path in tu_files:
        return None
    return BuildExcluded(line=0, summary="not in compile_commands.json")


def crate_module_excluded(
    abs_path: str, crate_modules: Optional[frozenset],
) -> Optional[BuildExcluded]:
    """Rust crate-module-membership witness: a ``.rs`` file not reachable via
    the ``mod`` tree from any crate root is not part of the crate — never
    compiled, so every function in it is dead. Heuristic / surface-only (the
    mod scan is best-effort), so it only demotes / surfaces.

    Returns ``None`` (no exclusion) when:
      * ``crate_modules`` is ``None`` — membership unknown (no Cargo.toml / no
        crate root), so never fire on absence-of-evidence;
      * ``abs_path`` is not a ``.rs`` file;
      * ``abs_path`` IS in the crate.

    ``abs_path`` must be resolved to match the resolved
    :func:`core.build.rust_modules.extract_rust_crate_modules` set.
    """
    if crate_modules is None:
        return None
    if not abs_path.endswith(".rs"):
        return None
    if abs_path in crate_modules:
        return None
    return BuildExcluded(
        line=0, summary="not reachable from any crate root (no mod path)")


__all__ = [
    "BuildExcluded",
    "detect_build_excluded",
    "tu_membership_excluded",
    "crate_module_excluded",
]
