"""Project-specific alias macro discovery.

Header pre-pass that finds ``#define MACRO_NAME ... __attribute__((...))``
patterns in the target's header files and classifies each by which
attribute family it expands to. The discovered aliases augment the
curated table in ``aliases.py``.

Scope (Phase 3c v1):
  * Walks ``*.h``, ``*.hpp``, ``*.hh``, ``*.hxx`` files under target.
  * Recursive macro resolution up to depth 3 (cycle-safe).
  * Per-family frequency cap of 30 — the top 30 discovered aliases by
    usage count in source files. Bounds output size on large kernels
    where dozens of project-specific aliases exist.
  * Safe-grep only — no preprocessor expansion, no `#include` following,
    no shelling out. Pure text inspection of header files; untrusted-
    target safe by construction.

What this does NOT do (deferred):
  * Function-name binding: alias-discovery records the macro names,
    not which functions they applied to. The PER-ALIAS cocci rules
    that ship with each axis (e.g. ``attr_warn_unused_result.cocci``)
    handle function binding when the alias spelling is known in
    advance. Discovery extends the alias-scan pass in ``analyze.py``;
    that pass records "alias spelling X was seen in this file" with
    ``function_name=""``.
  * Conditional discovery: we don't yet track when an alias is
    ``#ifdef``-gated. Could be added if corpus shows it matters.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from packages.source_intel.aliases import ALL_WUR_ALIASES


#: Per-family substring markers — the expansion of a discovered macro
#: must contain at least one of these to be classified into the family.
_KIND_MARKERS: Dict[str, Tuple[str, ...]] = {
    "wur": (
        "warn_unused_result",
        "__warn_unused_result__",
        "nodiscard",
    ),
    "nonnull": (
        "nonnull",
        "__nonnull__",
    ),
    "alloc_size": (
        "alloc_size",
        "__alloc_size__",
    ),
    "returns_nonnull": (
        "returns_nonnull",
        "__returns_nonnull__",
    ),
}


#: Per-family alias-cap (highest-frequency aliases kept; rest discarded).
#: Bounds the generated rule template / alias-scan size on dense kernels.
PER_FAMILY_ALIAS_CAP: int = 30

#: Maximum macro→macro resolution depth.
MAX_RESOLUTION_DEPTH: int = 3

#: Header file extensions inspected.
_HEADER_EXTS: Tuple[str, ...] = (".h", ".hpp", ".hh", ".hxx")

#: Source file extensions inspected for frequency-counting alias usage.
_SOURCE_EXTS: Tuple[str, ...] = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")

#: Bound on number of files walked. Kernels easily exceed 10k; the cap
#: keeps the pre-pass cost sub-second on small/medium projects and
#: bounded on large ones.
_MAX_FILES_HEADER_SCAN: int = 2000
_MAX_FILES_SOURCE_SCAN: int = 5000


# Regex matching `#define MACRO_NAME[(args)] EXPANSION` — captures the
# macro name and its expansion. Multi-line continuations (``\<newline>``)
# are pre-joined before scanning so the regex sees a single line.
#
# Macro names allow both upper and lower case: kernel uses ``__must_check``
# (lowercase), glibc uses ``__wur``; conventional project macros use
# uppercase (``MUST_CHECK``). Both shapes covered.
_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s+(.+?)$",
    re.MULTILINE,
)

# Word-boundary token capture for macro names so we can count usage
# in source files without false-positive substring matches. Same
# case-insensitive identifier rules as ``_DEFINE_RE``.
_TOKEN_NAME_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]+\b")


@dataclass(frozen=True)
class DiscoveryResult:
    """Outcome of a header pre-pass."""

    #: Per-family discovered macro names, capped per ``PER_FAMILY_ALIAS_CAP``,
    #: ordered by usage frequency in source files (descending).
    aliases_by_family: Dict[str, Tuple[str, ...]]

    #: Total number of header files scanned.
    headers_scanned: int

    #: Total number of source files scanned for frequency counts.
    sources_scanned: int


def discover_aliases(target: Path) -> DiscoveryResult:
    """Walk header files under ``target``, discover project-specific
    attribute alias macros, count their usage in source files, and
    return the top per family.

    Returns an empty :class:`DiscoveryResult` when ``target`` isn't a
    directory or contains no headers — same skip semantics as the
    rest of source_intel.

    Scope: scans ``target`` recursively AND any sibling ``include/``
    directory found by walking up to 2 parents. Many project
    structures (openssl, curl, kernel out-of-tree builds, autotools
    projects) keep public attribute-macro definitions in a parent
    ``include/`` tree separate from the per-subsystem source. Without
    the sibling walk, an operator narrowing the scan to one
    subsystem (e.g. ``openssl/crypto``) gets zero aliases.
    """
    target = Path(target)
    if not target.is_dir():
        return DiscoveryResult(
            aliases_by_family={k: () for k in _KIND_MARKERS},
            headers_scanned=0,
            sources_scanned=0,
        )

    scan_roots: List[Path] = [target]
    # Walk up at most 2 parents looking for a sibling include/ tree.
    # 1 hop covers `proj/crypto` → `proj/include`; 2 hops covers
    # `proj/sub/comp` → `proj/include`. Stop sooner if we hit /.
    for hops in (1, 2):
        if len(target.parts) <= hops:
            break
        parent = target.parents[hops - 1]
        sibling_include = parent / "include"
        if sibling_include.is_dir() and sibling_include not in scan_roots:
            scan_roots.append(sibling_include)
            break  # one include/ sibling is enough; deeper hops
                   # tend to false-positive on system /usr/include.

    # Phase 1: scan headers across all roots, build macro_name →
    # expansion map. First definition wins per C semantics.
    macros: Dict[str, str] = {}
    headers_seen = 0
    for root in scan_roots:
        for entry in root.rglob("*"):
            if headers_seen >= _MAX_FILES_HEADER_SCAN:
                break
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in _HEADER_EXTS:
                continue
            headers_seen += 1
            try:
                text = _join_continuations(entry.read_text(errors="replace"))
            except OSError:
                continue
            for m in _DEFINE_RE.finditer(text):
                name = m.group(1)
                expansion = m.group(2).strip()
                macros.setdefault(name, expansion)

    # Phase 2: classify each macro by family. A macro is in a family
    # iff its FULLY-RESOLVED expansion (recursive macro lookup up to
    # MAX_RESOLUTION_DEPTH) contains a family marker.
    family_to_aliases: Dict[str, List[str]] = defaultdict(list)
    for name, expansion in macros.items():
        resolved = _resolve_expansion(expansion, macros, depth=0)
        for family, markers in _KIND_MARKERS.items():
            if any(marker in resolved for marker in markers):
                family_to_aliases[family].append(name)

    # Phase 3: count usage of each candidate macro in source files.
    candidate_names: Set[str] = set()
    for names in family_to_aliases.values():
        candidate_names.update(names)
    usage_counts = _count_usage(target, candidate_names)

    # Phase 4: sort within each family by usage frequency desc, cap.
    out: Dict[str, Tuple[str, ...]] = {}
    for family, names in family_to_aliases.items():
        # Filter to candidates that appear at least once (drop dead
        # defines — common in kernel headers where alternate-config
        # branches define unused macros).
        used = [n for n in names if usage_counts.get(n, 0) > 0]
        # Sort: usage count desc, then alphabetical for stable order.
        used.sort(key=lambda n: (-usage_counts.get(n, 0), n))
        out[family] = tuple(used[:PER_FAMILY_ALIAS_CAP])

    # Ensure every known family has a key (empty tuple if no aliases).
    for family in _KIND_MARKERS:
        out.setdefault(family, ())

    return DiscoveryResult(
        aliases_by_family=out,
        headers_scanned=headers_seen,
        sources_scanned=sum(1 for _ in _iter_source_files(target)),
    )


# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _join_continuations(text: str) -> str:
    """Pre-join GNU make / cpp line-continuation backslashes so the
    define regex sees a single logical line per macro.

    Replaces ``\\<newline>`` with a single space.
    """
    return re.sub(r"\\\n", " ", text)


def _resolve_expansion(
    expansion: str,
    macros: Dict[str, str],
    *,
    depth: int,
    visited: Optional[Set[str]] = None,
) -> str:
    """Recursively expand any macro tokens in ``expansion`` using the
    discovered macro table. Bounded by ``MAX_RESOLUTION_DEPTH`` and a
    visited-set guard to prevent cycles (``#define A B`` + ``#define B A``).
    """
    if depth >= MAX_RESOLUTION_DEPTH:
        return expansion
    visited = set(visited) if visited else set()

    def _replace_token(match: re.Match) -> str:
        token = match.group(0)
        if token in visited:
            return token
        if token not in macros:
            return token
        # Recurse, marking this token as visited so cycles bottom out.
        visited.add(token)
        return _resolve_expansion(
            macros[token], macros, depth=depth + 1, visited=visited,
        )

    return _TOKEN_NAME_RE.sub(_replace_token, expansion)


def _iter_source_files(target: Path):
    """Yield source files under ``target`` whose extensions are in
    ``_SOURCE_EXTS``, bounded by ``_MAX_FILES_SOURCE_SCAN``."""
    seen = 0
    for entry in target.rglob("*"):
        if seen >= _MAX_FILES_SOURCE_SCAN:
            break
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _SOURCE_EXTS:
            continue
        seen += 1
        yield entry


def _count_usage(target: Path, names: Set[str]) -> Dict[str, int]:
    """Count word-boundary occurrences of each macro in source files
    under ``target``. Returns a dict mapping name → count.

    ``#define NAME …`` lines are NOT counted as usage — only real
    invocations of the macro count. This matters when scanning a
    project's own header that defines macros we just discovered:
    without the filter, every define-line would be counted as
    self-usage, inflating frequency to >= 1 and defeating the
    "filter zero-usage" pass.

    Returns zero for names not found. By construction our names are
    valid C identifiers, so word-boundary checks are safe against
    English-language false positives.
    """
    counts: Dict[str, int] = {n: 0 for n in names}
    if not names:
        return counts

    # Compile one large regex with all the candidate names. Word
    # boundaries on both sides eliminate substring false positives.
    pattern = re.compile(r"\b(" + "|".join(
        re.escape(n) for n in sorted(names, key=len, reverse=True)
    ) + r")\b")

    # Recognise the macro's own definition line so we can skip it.
    # Matches ``#define NAME`` with whitespace + optional ``(args)``.
    define_re = re.compile(
        r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b",
    )

    for entry in _iter_source_files(target):
        try:
            text = entry.read_text(errors="replace")
        except OSError:
            continue
        for line in text.split("\n"):
            # Skip lines that DEFINE one of our candidates — those
            # aren't usage, they're definition. (A define line may
            # also mention OTHER macros in its expansion; we still
            # count those via the inclusive substring match below
            # since they ARE usage from the define's perspective.)
            define_match = define_re.match(line)
            defined_name = define_match.group(1) if define_match else None
            for m in pattern.finditer(line):
                token = m.group(1)
                if token == defined_name:
                    # Define line for this macro — not usage.
                    continue
                counts[token] += 1
    return counts


# =====================================================================
# Curated-alias coverage check (sanity)
# =====================================================================

def alias_is_curated(spelling: str) -> bool:
    """Return True iff ``spelling`` already appears in the curated
    alias table (``packages.source_intel.aliases.ALL_WUR_ALIASES``).
    Used by the analyzer to tag discovered aliases that aren't
    redundant with the curated set."""
    return spelling in ALL_WUR_ALIASES
