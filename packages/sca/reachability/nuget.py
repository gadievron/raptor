"""Module-level reachability for NuGet (.NET) deps.

Walks ``*.cs`` / ``*.fs`` / ``*.vb`` files outside test trees, extracts
``using <namespace>;`` (C#), ``open <Module>`` (F#), and ``Imports``
(VB.NET) statements, and matches against the dep's name as a namespace
prefix.

Caveat: package names and namespace names aren't always the same in
.NET (e.g., the ``System.Text.Json`` package matches the
``System.Text.Json`` namespace cleanly, but
``Microsoft.Extensions.DependencyInjection.Abstractions`` vs the
package id of the same name — usually they line up). Mechanical match
is "does any namespace start with the package name?". Confidence is
``medium`` because the heuristic is imperfect.
"""

from __future__ import annotations

import logging
import re

from ..models import Confidence, Reachability
from ._shared import format_evidence as _format_evidence
from ._shared import iter_matches_with_lines as _iter_matches_with_lines
from ..parsers import _safe_read
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

# Lowercase canon — membership checks fold the path segment first.
_TEST_DIR_NAMES = {"tests", "test"}

# Leading indent in all three is HORIZONTAL-only ([^\S\n]): under
# MULTILINE the ``^\s*`` spelling re-scans a run of blank lines from
# every line start inside it — quadratic on attacker-supplied source
# files (the import sweep walks every file of the ecosystem).
# C#: ``using Foo.Bar;`` / ``using Alias = Foo.Bar;``
_CS_USING_RE = re.compile(
    r"^[^\S\n]*(?:global\s+)?using\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?"
    r"([A-Za-z_][A-Za-z0-9_.]*)\s*;",
    re.MULTILINE,
)
# F#: ``open Foo.Bar``. The keyword gap is horizontal ([^\S\n]+):
# an ``open`` directive is one line, and the newline-capable ``\s+``
# let every ``open`` anchor re-scan a shared blank run — quadratic
# over planted keyword lines. The dropped corner is a cross-line
# ``open\nFoo``, which is not F#.
_FS_OPEN_RE = re.compile(
    r"^[^\S\n]*open[^\S\n]+([A-Za-z_][A-Za-z0-9_.]*)",
    re.MULTILINE,
)
# VB: ``Imports Foo.Bar``
_VB_IMPORTS_RE = re.compile(
    r"^[^\S\n]*Imports\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?([A-Za-z_][A-Za-z0-9_.]*)",
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> dict[str, list[tuple[Path, int, bool]]]:
    """Return ``{namespace: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: dict[str, list[tuple[Path, int, bool]]] = {}
    for src in _walk_dotnet_sources(target, max_depth=max_depth):
        is_test = _is_test_file(src, target)
        text = _safe_read.read_bounded(src, follow_symlinks=False)
        if text is None:
            continue
        for ns, line in _imports_in(src.suffix.lower(), text):
            out.setdefault(ns, []).append((src, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: dict[str, list[tuple[Path, int, bool]]],
    *,
    target: Path | None = None,
) -> Reachability:
    """Match ``dep_name`` as a namespace prefix in the scan.

    A namespace ``Foo.Bar.Baz`` matches a dep ``Foo.Bar`` and any
    sub-namespace. NuGet package ids are case-insensitive, so the
    comparison folds case — ``<PackageReference
    Include="newtonsoft.json">`` must still match ``using
    Newtonsoft.Json;``. Confidence is ``medium`` for matches because
    NuGet package id ↔ namespace correspondence isn't guaranteed.
    """
    matches: list[tuple[Path, int, bool]] = []
    dep_lower = dep_name.lower()
    for ns, hits in scan.items():
        ns_lower = ns.lower()
        if ns_lower == dep_lower or ns_lower.startswith(dep_lower + "."):
            matches.extend(hits)

    if not matches:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=(f"no `using {dep_name}` (or sub-namespace) "
                        f"found in non-test source"),
            ),
            evidence=[],
        )
    non_test = [h for h in matches if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "medium",          # heuristic id↔namespace mapping
                reason="namespace prefix matches package id",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="package referenced only by test code",
        ),
        evidence=_format_evidence(matches, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _imports_in(suffix: str, text: str) -> Iterable[tuple[str, int]]:
    if suffix == ".cs":
        regex = _CS_USING_RE
    elif suffix == ".fs":
        regex = _FS_OPEN_RE
    elif suffix == ".vb":
        regex = _VB_IMPORTS_RE
    else:
        return
    # Rolling-cursor line numbers — the naive full-prefix count is
    # quadratic on dense-import files.
    for m, line in _iter_matches_with_lines(text, regex.finditer(text)):
        yield m.group(1), line


def _walk_dotnet_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    # .NET-specific extras: ``bin``/``obj`` (build outputs) and the
    # bare ``packages`` dir (NuGet's per-project install location —
    # shadows the canonical "monorepo packages/ is legitimate" rule
    # only inside .NET tree walks). Applied via the shared walker so
    # other reach scanners still see those subtrees.
    from ._walker import iter_source_files
    return iter_source_files(
        target, {".cs", ".fs", ".vb"}, max_depth=max_depth,
        extra_excluded_dir_names=frozenset({"bin", "obj", "packages"}),
    )


def _is_test_file(path: Path, target: Path) -> bool:
    rel_parts = path.relative_to(target).parts
    if any(p.lower() in _TEST_DIR_NAMES for p in rel_parts):
        return True
    return bool(path.stem.lower().endswith(("tests", "test")))

