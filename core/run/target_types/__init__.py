"""Target-type catalog substrate (QoL #17).

Per-target-type policy lives in YAML siblings of this module
(``<name>.yml``). The catalog tells consumers (``raptor plan``,
attack-surface ranking, default pack selection, budget defaults,
smart ``project create``) what the right defaults look like for a
given target shape, so each consumer doesn't have to invent its
own per-target-type heuristics fragmentarily.

## Schema

Each ``<name>.yml`` carries::

  name: c.userspace-daemon
  description: |
    Human-readable summary of what this target shape looks like.

  detection:
    # Positive signals — present-when-true.
    file_globs:        ["configure.ac", "Makefile.am"]
    file_extensions:   [".c", ".h"]
    function_names:    [main_loop, accept, listen]   # tree-sitter
    # Negative signals — disqualify this entry if matched.
    negative_globs:    ["kernel/**", "drivers/**"]

  semgrep_packs:
    default:  [security-audit, command-injection, owasp-top-ten]
    optional: [secrets, jwt]

  attack_surface:
    high_priority_dirs: [src/http, src/net, src/protocols]
    low_priority_dirs:  [src/device/sysdep_*, tests/, examples/]

  pipeline:
    recommended: [understand-map, scan-with-codeql, agentic-with-validate]
    estimated_cost_usd:  [25, 50]
    estimated_time_min:  [40, 75]

  budget_defaults:
    typical_findings_count:  25
    typical_cost_per_run_usd: 30

  version: 1

## Detection

``detect(target_path)`` walks the target's top-level files and
matches signals against each catalog entry. Negative signals are
deal-breakers (entry is dropped if any matches). Positive signals
contribute to a confidence score; the highest-scoring entry wins.

Tree-sitter function-name matching is on the roadmap but the v1
substrate uses file globs + extensions only — those cover the
common cases (Cargo.toml → rust, package.json → node, configure.ac
→ autotools daemon) without pulling in the tree-sitter dependency
chain.

## Why standalone substrate (not folded into ``raptor plan``)

Multiple consumers (#7 default pack selection, #9 attack-surface
ranking, #14 plan recommendation, #15 budget defaults, #18 smart
project-create) all depend on the same per-target-type mapping.
Folding into plan would force every other consumer to call into
plan to read its catalog. The substrate as a separate module is
authorable independently (community contributors can add
``php.wordpress-plugin.yml`` without touching the planner).

This commit ships substrate + 3 seed entries + the loader/detect
API. Per-consumer backfill (#7, #9, #14, #15, #18 wiring) lands
in follow-on commits as those code paths get touched.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


# Cap how deep we walk when matching ``**``-style globs. 4 levels
# covers ``src/<subsystem>/<file>.c`` shapes without exploding on
# pathological trees (node_modules / .git / build outputs).
_MAX_DETECT_DEPTH = 4

# Cap how many files we examine during detection. Walking a
# 100k-file target tree for every signal would dominate the
# lifecycle's startup cost; 10k is enough to catch the structural
# signals catalog entries rely on.
_MAX_DETECT_FILES = 10_000


@dataclass(frozen=True)
class CatalogEntry:
    """One target-type entry — loaded from its ``<name>.yml`` sibling.

    Frozen so a single instance can be safely shared across
    consumers without one mutating the catalog state another sees.
    """

    name: str
    description: str = ""

    # Detection signals
    file_globs: Tuple[str, ...] = field(default_factory=tuple)
    file_extensions: Tuple[str, ...] = field(default_factory=tuple)
    function_names: Tuple[str, ...] = field(default_factory=tuple)
    negative_globs: Tuple[str, ...] = field(default_factory=tuple)

    # Default policy hints — consumers consult these but the
    # substrate doesn't enforce them (operator overrides win).
    semgrep_packs_default: Tuple[str, ...] = field(default_factory=tuple)
    semgrep_packs_optional: Tuple[str, ...] = field(default_factory=tuple)
    attack_surface_high: Tuple[str, ...] = field(default_factory=tuple)
    attack_surface_low: Tuple[str, ...] = field(default_factory=tuple)
    pipeline_recommended: Tuple[str, ...] = field(default_factory=tuple)

    # Cost / time hints — pairs (low, high) USD / minutes
    estimated_cost_usd: Tuple[float, float] = (0.0, 0.0)
    estimated_time_min: Tuple[int, int] = (0, 0)
    typical_findings_count: int = 0
    typical_cost_per_run_usd: float = 0.0

    # Versioning — provenance + reproducibility. Bump when the
    # entry's defaults shift in a way operators might want to
    # detect (e.g. new packs added to ``semgrep_packs_default``).
    version: int = 1

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CatalogEntry":
        """Build a CatalogEntry from parsed YAML. Tolerant of
        missing optional sections — only ``name`` is required."""
        if "name" not in data:
            raise ValueError(
                "CatalogEntry.from_dict: missing required 'name' field"
            )
        detection = data.get("detection") or {}
        packs = data.get("semgrep_packs") or {}
        surface = data.get("attack_surface") or {}
        pipeline = data.get("pipeline") or {}
        budget = data.get("budget_defaults") or {}

        def _t(seq):
            return tuple(seq) if seq else tuple()

        cost_pair = pipeline.get("estimated_cost_usd") or [0.0, 0.0]
        time_pair = pipeline.get("estimated_time_min") or [0, 0]

        return cls(
            name=data["name"],
            description=data.get("description", "").strip(),
            file_globs=_t(detection.get("file_globs")),
            file_extensions=_t(detection.get("file_extensions")),
            function_names=_t(detection.get("function_names")),
            negative_globs=_t(detection.get("negative_globs")),
            semgrep_packs_default=_t(packs.get("default")),
            semgrep_packs_optional=_t(packs.get("optional")),
            attack_surface_high=_t(surface.get("high_priority_dirs")),
            attack_surface_low=_t(surface.get("low_priority_dirs")),
            pipeline_recommended=_t(pipeline.get("recommended")),
            estimated_cost_usd=(float(cost_pair[0]), float(cost_pair[1])),
            estimated_time_min=(int(time_pair[0]), int(time_pair[1])),
            typical_findings_count=int(budget.get("typical_findings_count", 0)),
            typical_cost_per_run_usd=float(
                budget.get("typical_cost_per_run_usd", 0)),
            version=int(data.get("version", 1)),
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


_CATALOG_DIR = Path(__file__).parent
_CACHED_CATALOG: Optional[Tuple[CatalogEntry, ...]] = None


def _load_one(yml_path: Path) -> Optional[CatalogEntry]:
    """Parse a single catalog YAML. Returns None on missing file /
    malformed YAML / missing required fields — substrate stays
    best-effort so a single broken entry doesn't break the loader
    for all consumers."""
    try:
        text = yml_path.read_text()
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return None
        return CatalogEntry.from_dict(data)
    except (OSError, yaml.YAMLError, ValueError):
        return None


def all_entries() -> Tuple[CatalogEntry, ...]:
    """Load every ``<name>.yml`` in the catalog dir (excluding
    ``tests/``). Cached after first call — entries are immutable so
    re-reading the YAML on every call would be wasted IO."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _CACHED_CATALOG
    entries: List[CatalogEntry] = []
    for p in sorted(_CATALOG_DIR.glob("*.yml")):
        entry = _load_one(p)
        if entry is not None:
            entries.append(entry)
    _CACHED_CATALOG = tuple(entries)
    return _CACHED_CATALOG


def load_by_name(name: str) -> Optional[CatalogEntry]:
    """Direct lookup by catalog name (e.g. ``c.userspace-daemon``).
    Returns None if no entry matches — caller should fall back to
    ``generic`` or operator-prompt."""
    for entry in all_entries():
        if entry.name == name:
            return entry
    return None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _walk_target(target_path: Path) -> List[str]:
    """Walk ``target_path`` up to ``_MAX_DETECT_DEPTH`` levels deep,
    returning relative POSIX paths (cap at ``_MAX_DETECT_FILES``).
    Skips dotted directories (``.git``, ``.cache``) — these are
    never the structural signals catalog entries care about."""
    if not target_path.is_dir():
        return []
    rels: List[str] = []
    target_path = target_path.resolve()
    for root, dirs, files in __import__("os").walk(target_path):
        # Skip dotted dirs.
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        root_path = Path(root)
        # Depth check.
        try:
            depth = len(root_path.relative_to(target_path).parts)
        except ValueError:
            continue
        if depth > _MAX_DETECT_DEPTH:
            dirs[:] = []
            continue
        for f in files:
            rels.append(
                str((root_path / f).relative_to(target_path).as_posix())
            )
            if len(rels) >= _MAX_DETECT_FILES:
                return rels
    return rels


def _matches_any(paths: List[str], globs: Tuple[str, ...]) -> int:
    """Count how many ``globs`` match at least one path. (Not
    ''how many path-glob pairs match'' — that would over-weight
    distinctive globs that happen to hit many files.)"""
    hits = 0
    for g in globs:
        if any(fnmatch.fnmatch(p, g) for p in paths):
            hits += 1
    return hits


def _has_extension(paths: List[str], extensions: Tuple[str, ...]) -> int:
    """Count distinct extensions matched (same intent as
    ``_matches_any`` — bool-per-signal, not per-file)."""
    matched: set = set()
    ext_set = {e.lower() for e in extensions}
    for p in paths:
        suffix = Path(p).suffix.lower()
        if suffix in ext_set:
            matched.add(suffix)
    return len(matched)


def _score_entry(entry: CatalogEntry, paths: List[str]) -> Optional[float]:
    """Score how well ``entry``'s detection signals match the
    target's file tree. Returns None when negative signals match
    (entry disqualified). Otherwise: positive-signal-count
    weighted by signal type.

    Weighting reflects how DISCRIMINATING each signal type is:
    file_globs (often specific like ``configure.ac``) > file_extensions
    (broad, many entries claim ``.c``). Function-name matching when
    tree-sitter substrate exists earns a higher weight; not used
    in v1.
    """
    # Negative signals are deal-breakers.
    if entry.negative_globs and _matches_any(paths, entry.negative_globs):
        return None
    score = 0.0
    score += 2.0 * _matches_any(paths, entry.file_globs)
    score += 1.0 * _has_extension(paths, entry.file_extensions)
    # function_names ignored in v1 (no tree-sitter dependency here).
    return score


def detect(target_path: Path) -> List[Tuple[CatalogEntry, float]]:
    """Walk the target and return all catalog entries ranked by
    confidence score (descending). Entries with score 0 are
    excluded — no positive signal matched.

    Caller picks the highest-scoring entry, or prompts the
    operator when scores are close (ambiguous polyglot repo), or
    falls back to ``generic`` when nothing matched.
    """
    paths = _walk_target(Path(target_path))
    if not paths:
        return []
    scored: List[Tuple[CatalogEntry, float]] = []
    for entry in all_entries():
        s = _score_entry(entry, paths)
        if s is None or s <= 0:
            continue
        scored.append((entry, s))
    scored.sort(key=lambda x: (-x[1], x[0].name))
    return scored


def load(target_path: Path) -> Optional[CatalogEntry]:
    """Pick the best-matching catalog entry for ``target_path``.
    Returns None when nothing scored above 0 — caller falls back
    to the ``generic`` entry or operator prompt."""
    ranked = detect(target_path)
    if not ranked:
        # Fall back to ``generic`` when present — operator gets a
        # working default rather than a None to handle.
        return load_by_name("generic")
    return ranked[0][0]


def _reset_cache_for_tests() -> None:
    """Clear the loader cache. Test-only hook — production code
    treats the catalog as immutable per process."""
    global _CACHED_CATALOG
    _CACHED_CATALOG = None


__all__ = [
    "CatalogEntry",
    "all_entries",
    "load_by_name",
    "detect",
    "load",
]
