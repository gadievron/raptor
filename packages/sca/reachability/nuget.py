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
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

_TEST_DIR_NAMES = {"tests", "test", "Tests", "Test"}

# C#: ``using Foo.Bar;`` / ``using Alias = Foo.Bar;``
_CS_USING_RE = re.compile(
    r"^\s*using\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?"
    r"([A-Za-z_][A-Za-z0-9_.]*)\s*;",
    re.MULTILINE,
)
# F#: ``open Foo.Bar``
_FS_OPEN_RE = re.compile(
    r"^\s*open\s+([A-Za-z_][A-Za-z0-9_.]*)",
    re.MULTILINE,
)
# VB: ``Imports Foo.Bar``
_VB_IMPORTS_RE = re.compile(
    r"^\s*Imports\s+([A-Za-z_][A-Za-z0-9_.]*)",
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{namespace: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for src in _walk_dotnet_sources(target, max_depth=max_depth):
        is_test = _is_test_file(src, target)
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.nuget: skip %s (%s)", src, e)
            continue
        for ns, line in _imports_in(src.suffix.lower(), text):
            out.setdefault(ns, []).append((src, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Match ``dep_name`` as a namespace prefix in the scan.

    A namespace ``Foo.Bar.Baz`` matches a dep ``Foo.Bar`` and any
    sub-namespace. Confidence is ``medium`` for matches because
    NuGet package id ↔ namespace correspondence isn't guaranteed.
    """
    matches: List[Tuple[Path, int, bool]] = []
    for ns, hits in scan.items():
        if ns == dep_name or ns.startswith(dep_name + "."):
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

def _imports_in(suffix: str, text: str) -> Iterable[Tuple[str, int]]:
    if suffix == ".cs":
        regex = _CS_USING_RE
    elif suffix == ".fs":
        regex = _FS_OPEN_RE
    elif suffix == ".vb":
        regex = _VB_IMPORTS_RE
    else:
        return
    for m in regex.finditer(text):
        yield m.group(1), text.count("\n", 0, m.start()) + 1


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
    if any(p in _TEST_DIR_NAMES for p in rel_parts):
        return True
    if path.stem.lower().endswith(("tests", "test")):
        return True
    return False


def _format_evidence(
    hits: List[Tuple[Path, int, bool]],
    *,
    target: Optional[Path],
    cap: int = 5,
) -> List[str]:
    out: List[str] = []
    for f, line, _ in hits[:cap]:
        rel = (f.relative_to(target) if target and target in f.parents
                else f)
        out.append(f"{rel}:{line}")
    if len(hits) > cap:
        out.append(f"... (+{len(hits) - cap} more)")
    return out
