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
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


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


__all__ = ["BuildExcluded", "detect_build_excluded"]
