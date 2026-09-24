"""Map→study seeding bridge for binary studies.

A binary ``--map`` run (and, when present, ``binary-hunt-*.json``
artifacts) already knows which functions look like parsers, which are
anchor-dense handlers, and which belong to a hunted family. This
bridge turns that knowledge into bounded, provenance-stamped study
seeds so a follow-up binary study starts where the evidence points
instead of asking the operator to re-type identifiers by hand.

Discovery mirrors :mod:`core.orchestration.understand_bridge`'s
three-tier precedence (co-located → project sibling → global out/),
with one binary-specific freshness gate: away from the co-located
tier, a candidate map must carry the SAME module content anchor
(``core.binary.addrmap``) as the study's RE database — the binary
analogue of the source bridge's checklist-hash freshness check. A
map of a different build (or a planted artifact for another binary
entirely) is rejected, never silently joined.

Seed candidates are extracted in priority order — parser boundaries,
then string-anchor leads, then hunt family members / check-sites —
and translated into the study's naming through the fid keystone
(:class:`core.binary.addrmap.FidIndex`: exact fid → bounded fuzzy →
unique non-placeholder name). Name normalization is bridge-local:
the study boundary has no ``sym.``/``fcn.`` stripper, so r2-style
decorations are stripped HERE before the name-fallback join.
Translation misses are recorded via
:func:`core.binary.addrmap.record_fid_misses` — never silently
dropped.

Trust posture: every emitted seed derives from attacker-controlled
bytes (``derived_from_target: true``). Seeds are attention hints for
the study's operator-identifier channel at a distinct ``bridge_seed``
tier BELOW operator seeds; they never mint findings, never bypass
the study pass loop, and are jointly capped with SAGE-recalled prior
concepts by :data:`DERIVED_ATTENTION_MAX_FRACTION` (anti-monopoly:
a decoy-flooded target must not own the paid study budget). Concept strings derived from anchor stems are constrained
to identifier-shaped tokens at emission and additionally routed
through the prompt envelope (``neutralize_tag_forgery``) by the
consumer before they reach an LLM prompt — the same discipline every
other target-derived interpolation in the study pipeline follows.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Phase-2 derived-attention ceiling: bridge seeds and SAGE-recalled
#: prior-concept seed blocks TOGETHER may claim at most this fraction
#: of one study batch's item budget (operator-passed identifiers
#: outrank both and never count). Enforced jointly at the study's
#: seeding chokepoint (``core.concepts.study`` imports this constant
#: where ``recall_concepts_for_study`` injects). Too high and a
#: decoy-flooded target (or a bloated prior store) owns the paid
#: study budget — the autonomous selection signals (xref centrality,
#: size) the adversary must trade off against never get a look. Too
#: low and legitimately strong leads from the binary map arrive
#: demoted to context while the study re-derives them at full price.
DERIVED_ATTENTION_MAX_FRACTION = 0.5

#: Hard ceiling on emitted bridge seeds. Too high and the bridge
#: crowds out the study's own autonomous selection even before the
#: joint derived-attention fraction bites (and a decoy-flooded map
#: buys more paid attention); too low and a legitimately rich map
#: (many real parser boundaries) is truncated to a sliver and the
#: study re-derives the rest at full LLM price.
MAX_BRIDGE_SEEDS = 24

#: Ceiling on emitted concept strings (anchor-stem derived). Concepts
#: fan out through LLM identifier seeding (20-80 identifiers per
#: concept), so they are far more attention-expensive per entry than
#: seeds — hence the much smaller cap; raising it hands target bytes
#: a multiplier on study scope, lowering it to zero discards the only
#: format-level hint a stripped binary offers.
MAX_BRIDGE_CONCEPTS = 6

#: Raw candidates considered before translation. Bounded so a planted
#: map with tens of thousands of records cannot make the join itself
#: a DoS; generous relative to MAX_BRIDGE_SEEDS so misses in the top
#: picks still leave translated material.
_MAX_CANDIDATES = 96

#: Per-artifact read ceiling — matches the other run-artifact readers.
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

#: Cap on hunt artifacts consumed per run (newest first).
_MAX_HUNT_FILES = 8

#: Shape a seed name must have to be emitted. The destination naming
#: is the decomp-tree study item name (identifier-shaped by
#: construction); anything looser would let hostile symbol bytes ride
#: into prompts and grep terms. ``$`` and ``.`` cover the common
#: compiler-generated suffixes (``foo.part.0``, ``bar$isra``).
BRIDGE_SEED_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]{1,119}$")

#: Identifier-shaped token extracted from anchor strings for concept
#: derivation. Deliberately narrower than seed names: concepts are
#: free-text-adjacent prompt material.
_CONCEPT_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,31}")

#: Stop-stems that carry no format/domain signal — common log noise.
_CONCEPT_STOPWORDS = frozenset({
    "error", "warning", "failed", "failure", "invalid", "unknown",
    "null", "true", "false", "debug", "info", "trace", "assert",
    "cannot", "could", "with", "from", "this", "that", "file",
    "line", "function", "return", "value", "size", "length",
})

#: r2-style name decorations stripped before the name-fallback join
#: (bridge-local by design — the study boundary has no stripper).
#: Deliberately EXCLUDES ``fcn.`` and ``loc.``: those prefixes wrap
#: tool-synthetic placeholders (address labels), never real symbol
#: names — stripping them laundered placeholders past the
#: looks_tool_synthetic refusal in the name-fallback join.
_R2_NAME_PREFIX_RE = re.compile(
    r"^(?:sym\.imp\.|sym\.|imp\.|reloc\.)",
)

_MAP_FILENAME = "binary-context-map.json"
_HUNT_GLOB = "binary-hunt-*.json"
_SEEDS_FILENAME = "bridge-seeds.json"

#: The honesty line the study report must carry verbatim.
HONESTY_LINE = "seed selection is target-influenced"


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BridgeSeed:
    """One translated study seed with full provenance."""

    name: str
    origin: str  # parser_boundary | string_anchor | hunt_member | hunt_check_site
    why: str
    match_method: str  # exact | fid_fuzzy | name
    fid: str = ""
    seed_source: str = "bridge_seed"
    derived_from_target: bool = True


@dataclass(frozen=True)
class BridgeArtifacts:
    """Discovered artifact set feeding one bridge run."""

    map_path: Path
    hunt_paths: list[Path] = field(default_factory=list)
    tier: str = "colocated"  # colocated | project_sibling | global_out


# ---------------------------------------------------------------------------
# Discovery (understand_bridge's 3-tier precedence, anchor-gated)
# ---------------------------------------------------------------------------

def _map_anchor(map_path: Path) -> str | None:
    """The candidate map's recorded content anchor, or ``None``.

    Routed through :func:`core.binary.addrmap.module_anchor` so a
    junk/degraded value collapses to ``None`` instead of comparing
    equal to another junk value.
    """
    from core.binary.addrmap import module_anchor
    from core.json import load_json
    try:
        data = load_json(map_path, max_bytes=_MAX_ARTIFACT_BYTES)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return module_anchor(build_id=str(data.get("content_anchor") or ""))


def _hunt_paths_beside(directory: Path) -> list[Path]:
    """Hunt artifacts co-located with a selected map, newest first."""
    try:
        found = sorted(
            (p for p in directory.glob(_HUNT_GLOB) if p.is_file()),
            key=lambda p: p.stat().st_mtime_ns,
            reverse=True,
        )
    except OSError:
        return []
    return found[:_MAX_HUNT_FILES]


def _candidate_dirs(root: Path, exclude: Path) -> list[Path]:
    """Direct child run dirs of *root* holding a binary map, newest
    first. One level only — run dirs are flat under their parent in
    both project and global layouts, and an unbounded walk over out/
    is a self-DoS on big installs."""
    results: list[tuple[int, Path]] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return []
    for child in children:
        try:
            if not child.is_dir() or child.resolve() == exclude.resolve():
                continue
            map_path = child / _MAP_FILENAME
            if map_path.is_file():
                results.append((child.stat().st_mtime_ns, child))
        except OSError:
            continue
    results.sort(key=lambda t: t[0], reverse=True)
    return [d for _, d in results]


def find_binary_artifacts(
    study_dir: Path,
    *,
    expected_anchor: str | None,
) -> BridgeArtifacts | None:
    """Locate the best map (+ hunt) artifacts for a binary study.

    Tier 1 — co-located in *study_dir* (the shared ``--out``
    handoff): accepted even when one side lacks an anchor (the
    operator aligned the directories deliberately), but REJECTED on
    a present-and-mismatching anchor pair — co-located artifacts of
    a different build would silently steer this study's seeds.

    Tiers 2/3 — sibling run dirs, then global out/: an anchor match
    is REQUIRED on both sides. Freshness-by-identity replaces the
    source bridge's checklist-hash freshness: without it, any run
    dir on the machine could volunteer seeds for any binary. Trust
    scope, stated plainly: the candidate's anchor is SELF-DECLARED
    by the artifact — the gate defends against cross-build/wrong-
    binary confusion inside RAPTOR-owned run dirs, not against an
    adversary who can already forge artifacts there (that run-dir
    trust domain is the same one every bridge and cache reader
    inhabits; seeds remain attention hints, never verdicts).
    """
    study_dir = Path(study_dir)

    # Tier 1: co-located.
    local_map = study_dir / _MAP_FILENAME
    if local_map.is_file():
        found = _map_anchor(local_map)
        if expected_anchor and found and found != expected_anchor:
            logger.warning(
                "binary_study_bridge: co-located %s is for a different "
                "binary (anchor mismatch) — ignoring it", _MAP_FILENAME,
            )
        else:
            return BridgeArtifacts(
                map_path=local_map,
                hunt_paths=_hunt_paths_beside(study_dir),
                tier="colocated",
            )

    if not expected_anchor:
        # Away from the co-located tier there is nothing to match
        # identity on — refuse rather than adopt an arbitrary map.
        return None

    # Tier 2: project sibling run dirs.
    for d in _candidate_dirs(study_dir.parent, exclude=study_dir):
        if _map_anchor(d / _MAP_FILENAME) == expected_anchor:
            return BridgeArtifacts(
                map_path=d / _MAP_FILENAME,
                hunt_paths=_hunt_paths_beside(d),
                tier="project_sibling",
            )

    # Tier 3: global out/.
    try:
        from core.config import RaptorConfig
        out_root = RaptorConfig.get_out_dir()
    except Exception:  # noqa: BLE001 — tier 3 is an aid, never a gate
        return None
    for d in _candidate_dirs(Path(out_root), exclude=study_dir):
        if _map_anchor(d / _MAP_FILENAME) == expected_anchor:
            return BridgeArtifacts(
                map_path=d / _MAP_FILENAME,
                hunt_paths=_hunt_paths_beside(d),
                tier="global_out",
            )
    return None


# ---------------------------------------------------------------------------
# Candidate extraction (priority order per the seeding design)
# ---------------------------------------------------------------------------

def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def extract_seed_candidates(
    map_data: dict[str, Any],
    hunt_datas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Priority-ordered raw candidates from the artifacts.

    Order is the seeding contract: parser boundaries (score-ranked)
    first, string-anchor leads (density-ranked) second, hunt family
    members / check-sites last. Each candidate carries ``name``,
    ``fid`` (may be empty), ``origin`` and ``why``; the ``why`` text
    embeds target-derived strings and is escaped at capture.
    """
    from core.security.log_sanitisation import escape_nonprintable

    def _why(text: str) -> str:
        return escape_nonprintable(text)[:200]

    candidates: list[dict[str, Any]] = []

    boundaries = map_data.get("parser_boundary_candidates")
    if isinstance(boundaries, list):
        ranked = sorted(
            (b for b in boundaries if isinstance(b, dict)),
            key=lambda b: _as_int(b.get("score")),
            reverse=True,
        )
        for b in ranked:
            name = str(b.get("boundary_function_name") or "")
            if not name:
                continue
            ingress = str(b.get("ingress_name") or "?")
            candidates.append({
                "name": name,
                "fid": b.get("fid"),
                "origin": "parser_boundary",
                "why": _why(f"parser boundary candidate "
                            f"(ingress {ingress})"),
            })

    anchors = map_data.get("string_anchor_functions")
    if isinstance(anchors, list):
        ranked = sorted(
            (a for a in anchors if isinstance(a, dict)),
            key=lambda a: _as_int(a.get("anchor_string_count")),
            reverse=True,
        )
        for a in ranked:
            name = str(a.get("name") or "")
            if not name:
                continue
            count = _as_int(a.get("anchor_string_count"))
            candidates.append({
                "name": name,
                "fid": a.get("fid"),
                "origin": "string_anchor",
                "why": _why(f"string-anchor lead "
                            f"({count} diagnostic string(s))"),
            })

    for hunt in hunt_datas:
        if not isinstance(hunt, dict):
            continue
        families = hunt.get("families")
        if not isinstance(families, list):
            families = [hunt]
        for fam in families:
            if not isinstance(fam, dict):
                continue
            label = str(fam.get("anchor") or fam.get("label") or "hunt")
            for member in fam.get("members") or []:
                if not isinstance(member, dict):
                    continue
                name = str(member.get("name") or "")
                if not name:
                    continue
                candidates.append({
                    "name": name,
                    "fid": member.get("fid"),
                    "origin": "hunt_member",
                    "why": _why(f"hunt family member ({label})"),
                })
            for site in fam.get("check_sites") or []:
                if not isinstance(site, dict):
                    continue
                name = str(site.get("name")
                           or site.get("function") or "")
                if not name:
                    continue
                candidates.append({
                    "name": name,
                    "fid": site.get("fid"),
                    "origin": "hunt_check_site",
                    "why": _why(f"hunt check-site ({label})"),
                })

    return candidates[:_MAX_CANDIDATES]


def extract_concepts(
    map_data: dict[str, Any],
    hunt_datas: list[dict[str, Any]],
) -> list[str]:
    """Concept strings from anchor stems (bounded, token-constrained).

    Sources: hunt family labels, then string-anchor sample strings.
    Every token is identifier-shaped by construction (inert), yet
    still ``derived_from_target`` — consumers route these through
    ``neutralize_tag_forgery`` before any LLM prompt (belt and
    braces; the study pipeline's standing interpolation discipline).
    """
    counts: Counter[str] = Counter()

    def _feed(text: Any, weight: int) -> None:
        for token in _CONCEPT_TOKEN_RE.findall(str(text or ""))[:16]:
            stem = token.lower()
            if stem not in _CONCEPT_STOPWORDS:
                counts[stem] += weight

    for hunt in hunt_datas:
        if not isinstance(hunt, dict):
            continue
        families = hunt.get("families")
        if not isinstance(families, list):
            families = [hunt]
        for fam in families:
            if isinstance(fam, dict):
                # Family labels are curated cluster names — weight
                # them above raw sample-string noise.
                _feed(fam.get("anchor") or fam.get("label"), 3)

    anchors = map_data.get("string_anchor_functions")
    if isinstance(anchors, list):
        for a in anchors:
            if not isinstance(a, dict):
                continue
            for sample in (a.get("sample_strings") or [])[:8]:
                _feed(sample, 1)

    return [stem for stem, _n in counts.most_common(MAX_BRIDGE_CONCEPTS)]


# ---------------------------------------------------------------------------
# Translation through the fid keystone
# ---------------------------------------------------------------------------

def _normalise_producer_name(name: str) -> str:
    """Bridge-local normalization of a map-side function name.

    Strips r2-style decorations only — the study boundary has no
    ``sym.``/``fcn.`` stripper, so the join must not rely on one.
    """
    return _R2_NAME_PREFIX_RE.sub("", name.strip())


def translate_candidates(
    candidates: list[dict[str, Any]],
    db: Any,
) -> tuple[list[BridgeSeed], list[dict[str, Any]]]:
    """Resolve raw candidates against the RE database's naming.

    Returns ``(seeds, misses)``; seeds keep candidate priority order,
    are deduplicated by resolved name (first — highest-priority —
    origin wins) and bounded by :data:`MAX_BRIDGE_SEEDS`. Every
    ATTEMPTED candidate that fails to resolve (or resolves to an
    unrepresentable name) lands in *misses* — the caller records
    them, they are never silently dropped. Candidates beyond the
    seed bound are neither attempted nor recorded: the bound stops
    the join itself, and the bounded emission is already the
    documented contract.
    """
    from core.binary.addrmap import FidIndex, stamp_redb_fids

    # Idempotent, fail-closed enrichment: databases imported before
    # producers minted fids get theirs here (recorded-base gated).
    try:
        stamp_redb_fids(db)
    except Exception:  # noqa: BLE001 — fids are enrichment; name path remains
        logger.debug("bridge: fid stamping failed", exc_info=True)

    index = FidIndex()
    functions = getattr(db, "functions", None) or []
    for fn in functions:
        if getattr(fn, "is_external", False):
            continue
        index.add(fn, fid=getattr(fn, "fid", None),
                  name=getattr(fn, "name", None))

    seeds: list[BridgeSeed] = []
    misses: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cand in candidates:
        if len(seeds) >= MAX_BRIDGE_SEEDS:
            break
        raw_name = str(cand.get("name") or "")
        match = index.resolve(
            fid=cand.get("fid"),
            name=_normalise_producer_name(raw_name),
        )
        if match is None:
            misses.append({
                "name": raw_name,
                "fid": str(cand.get("fid") or ""),
                "origin": str(cand.get("origin") or ""),
                "reason": "no-join",
            })
            continue
        resolved = str(getattr(match.payload, "name", "") or "")
        if not BRIDGE_SEED_NAME_RE.fullmatch(resolved):
            misses.append({
                "name": raw_name,
                "fid": str(cand.get("fid") or ""),
                "origin": str(cand.get("origin") or ""),
                "reason": "unrepresentable-name",
            })
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        seeds.append(BridgeSeed(
            name=resolved,
            origin=str(cand.get("origin") or ""),
            why=str(cand.get("why") or ""),
            match_method=match.method,
            fid=str(getattr(match.payload, "fid", "") or ""),
        ))
    return seeds, misses


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------

def _db_anchor(db: Any) -> str | None:
    """The study database's module content anchor, if derivable.

    A stamped fid's anchor half first (already normalised), else a
    fresh probe of the on-disk binary. ``None`` when neither exists —
    discovery then confines itself to the co-located tier.
    """
    from core.binary.addrmap import content_anchor, from_fid
    for fn in getattr(db, "functions", None) or []:
        parsed = from_fid(getattr(fn, "fid", None))
        if parsed is not None:
            return parsed[0]
    binary_path = getattr(db, "binary_path", None)
    if binary_path:
        try:
            return content_anchor(binary_path)
        except Exception:  # noqa: BLE001 — anchor probe is best-effort
            logger.debug("bridge: content-anchor probe failed",
                         exc_info=True)
    return None


def build_bridge_seeds(
    output_dir: Path,
    db: Any,
    *,
    item_budget: int | None = None,
) -> Path | None:
    """Discover, extract, translate and persist bridge seeds.

    Writes ``bridge-seeds.json`` into *output_dir* and records
    translation misses in the run's ``fid-misses.json``. Returns the
    seeds file path, or ``None`` when no matching artifacts exist or
    nothing translated. Never raises into the caller — the bridge is
    an enrichment; a broken artifact must not block the study.

    *item_budget* (the study's phase-2 batch item budget) tightens
    the seed bound to the derived-attention fraction so the joint
    cap in ``core.concepts.study`` rarely has to demote after the
    fact; the SAGE half of that accounting still applies there.
    """
    from core.json import load_json, save_json

    output_dir = Path(output_dir)
    try:
        artifacts = find_binary_artifacts(
            output_dir, expected_anchor=_db_anchor(db),
        )
    except Exception:  # noqa: BLE001 — discovery is enrichment
        logger.debug("bridge: artifact discovery failed", exc_info=True)
        return None
    if artifacts is None:
        return None

    try:
        map_data = load_json(artifacts.map_path,
                             max_bytes=_MAX_ARTIFACT_BYTES)
    except (OSError, ValueError):
        return None
    if not isinstance(map_data, dict):
        return None
    hunt_datas: list[dict[str, Any]] = []
    for hp in artifacts.hunt_paths:
        try:
            hd = load_json(hp, max_bytes=_MAX_ARTIFACT_BYTES)
        except (OSError, ValueError):
            continue
        if isinstance(hd, dict):
            hunt_datas.append(hd)

    candidates = extract_seed_candidates(map_data, hunt_datas)
    seeds, misses = translate_candidates(candidates, db)

    max_seeds = MAX_BRIDGE_SEEDS
    if item_budget is not None and item_budget > 0:
        max_seeds = min(
            max_seeds,
            max(1, int(item_budget * DERIVED_ATTENTION_MAX_FRACTION)),
        )
    seeds = seeds[:max_seeds]

    if misses:
        from core.binary.addrmap import record_fid_misses
        record_fid_misses(output_dir, "binary-study-bridge", misses)

    if not seeds and not misses:
        return None

    concepts = extract_concepts(map_data, hunt_datas)
    payload = {
        "schema_version": 1,
        "generated_by": "binary_study_bridge",
        "honesty": HONESTY_LINE,
        "discovery_tier": artifacts.tier,
        "source_map": str(artifacts.map_path),
        "source_hunts": [str(p) for p in artifacts.hunt_paths],
        "seeds": [asdict(s) for s in seeds],
        "concepts": [
            {"text": c, "derived_from_target": True,
             "origin": "anchor_stem"}
            for c in concepts
        ],
        "miss_count": len(misses),
    }
    seeds_path = output_dir / _SEEDS_FILENAME
    try:
        save_json(seeds_path, payload)
    except OSError:
        logger.warning("bridge: could not write %s", seeds_path,
                       exc_info=True)
        return None
    logger.info(
        "binary_study_bridge: %d seed(s), %d concept hint(s), "
        "%d miss(es) — tier %s",
        len(seeds), len(concepts), len(misses), artifacts.tier,
    )
    return seeds_path if seeds or concepts else None


__all__ = [
    "BRIDGE_SEED_NAME_RE",
    "DERIVED_ATTENTION_MAX_FRACTION",
    "HONESTY_LINE",
    "MAX_BRIDGE_CONCEPTS",
    "MAX_BRIDGE_SEEDS",
    "BridgeArtifacts",
    "BridgeSeed",
    "build_bridge_seeds",
    "extract_concepts",
    "extract_seed_candidates",
    "find_binary_artifacts",
    "translate_candidates",
]
