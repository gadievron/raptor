"""Bridge between binary analysis artifacts and the audit pipeline.

Discovers binary analysis output (graph stores, investigation reports,
parser boundaries) from sibling run directories and extracts
security-relevant data for priority scoring, evidence enrichment,
and Joern cross-validation.

Integration points:
  A. Graph store CALLS_SURFACE edges → sink discovery enrichment
  B. Investigation ranked surfaces → priority boost
  C. Parser boundaries → entry point enrichment
  D-F. Joern cross-validation of binary candidates (via sweep.py)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from core.json import load_json

logger = logging.getLogger(__name__)

GRAPH_SUBDIR = "graph"
GRAPH_FILENAME = "binary-graph.sqlite"
INVESTIGATION_FILENAME = "binary-investigation.json"
CONTEXT_MAP_FILENAME = "binary-context-map.json"

# Byte budgets: run manifests are tiny descriptors; investigation /
# binary-context-map artifacts are RAPTOR-written run output — the
# audit-artifact budget class.
_MAX_RUN_META_BYTES = 1024 * 1024
_MAX_BINARY_ARTIFACT_BYTES = 64 * 1024 * 1024


@dataclass
class BinarySinkEdge:
    """A function→sink call discovered from binary analysis."""

    caller: str
    sink: str
    evidence_tier: str
    confidence: str
    binary_path: str


@dataclass
class BinaryRankedSurface:
    """A security surface ranked by binary investigation."""

    function: str
    category: str
    score: float
    is_sink: bool


@dataclass
class BinaryParserBoundary:
    """A parser boundary discovered from binary analysis."""

    function: str
    ingress_function: str
    depth: int
    score: float
    evidence_tier: str


@dataclass
class BinaryBridgeResult:
    """Aggregated binary analysis data for audit consumption."""

    sink_edges: list[BinarySinkEdge] = field(default_factory=list)
    ranked_surfaces: list[BinaryRankedSurface] = field(default_factory=list)
    parser_boundaries: list[BinaryParserBoundary] = field(default_factory=list)
    source_dirs: list[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        return bool(
            self.sink_edges or self.ranked_surfaces or self.parser_boundaries
        )

    def sink_callers(self) -> set[str]:
        """Function names that call dangerous sinks (binary-confirmed)."""
        return {e.caller for e in self.sink_edges}

    def surface_functions(self) -> dict[str, float]:
        """Function name → highest investigation score."""
        scores: dict[str, float] = {}
        for s in self.ranked_surfaces:
            if s.function not in scores or s.score > scores[s.function]:
                scores[s.function] = s.score
        return scores

    def boundary_functions(self) -> set[str]:
        """Function names identified as parser boundaries."""
        return {b.function for b in self.parser_boundaries}


RUN_METADATA_FILE = ".raptor-run.json"


def find_binary_run_dirs(
    out_dir: Path,
    *,
    target_path: Path | None = None,
    max_dirs: int = 10,
) -> list[Path]:
    """Find sibling directories containing binary analysis output.

    When *target_path* is set, only siblings whose ``.raptor-run.json``
    records the same resolved target are included.  This prevents
    unrelated binary analyses (e.g. a SAProuter run) from leaking edges
    into a kernel audit.
    """
    parent = out_dir.parent
    if not parent.is_dir():
        return []

    resolved_target = target_path.resolve() if target_path else None

    candidates: list[Path] = []
    try:
        for child in parent.iterdir():
            if not child.is_dir():
                continue
            if child == out_dir:
                continue
            has_graph = (child / GRAPH_SUBDIR / GRAPH_FILENAME).exists()
            has_investigation = (child / INVESTIGATION_FILENAME).exists()
            has_context = (child / CONTEXT_MAP_FILENAME).exists()
            if not (has_graph or has_investigation or has_context):
                continue
            if resolved_target is not None:
                manifest = child / RUN_METADATA_FILE
                if not manifest.exists():
                    continue
                meta = load_json(manifest, max_bytes=_MAX_RUN_META_BYTES)
                if not isinstance(meta, dict):
                    continue
                try:
                    sibling_target = meta.get("target_path") or meta.get("target", "")
                    if not sibling_target:
                        continue
                    if Path(sibling_target).resolve() != resolved_target:
                        continue
                except OSError:
                    # Path.resolve on an unresolvable stored path.
                    continue
            candidates.append(child)
    except OSError:
        return []

    def _safe_mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0

    candidates.sort(key=_safe_mtime, reverse=True)
    return candidates[:max_dirs]


def _load_graph_sink_edges(run_dir: Path) -> list[BinarySinkEdge]:
    """Extract CALLS_SURFACE edges from a binary graph store."""
    graph_path = run_dir / GRAPH_SUBDIR / GRAPH_FILENAME
    if not graph_path.exists():
        return []

    try:
        from packages.binary_analysis.graph_store import query_edges
    except ImportError:
        logger.debug("binary_analysis.graph_store not importable")
        return []

    try:
        raw_edges = query_edges(graph_path, kind=None)
    except Exception:
        logger.debug("failed to query graph store %s", graph_path, exc_info=True)
        return []

    edges: list[BinarySinkEdge] = []
    for e in raw_edges:
        kind = e.get("kind", "")
        src = e.get("source") or {}
        tgt = e.get("target") or {}
        caller = src.get("name", "")
        sink = tgt.get("name", "")
        if not caller or not sink:
            continue
        props = e.get("props") or {}
        is_sink_edge = (
            kind == "CALLS_SURFACE"
            or (kind == "CALLS" and props.get("is_sink"))
        )
        if is_sink_edge:
            edges.append(BinarySinkEdge(
                caller=caller,
                sink=sink,
                evidence_tier=e.get("confidence", "candidate"),
                confidence=e.get("confidence", "candidate"),
                binary_path=props.get("binary_path", ""),
            ))

    if edges:
        logger.info(
            "binary_bridge: loaded %d sink edges from %s",
            len(edges), graph_path,
        )
    return edges


def _load_investigation(run_dir: Path) -> tuple:
    """Load ranked surfaces and parser boundaries from investigation output."""
    inv_path = run_dir / INVESTIGATION_FILENAME
    if not inv_path.exists():
        return [], []

    data = load_json(inv_path, max_bytes=_MAX_BINARY_ARTIFACT_BYTES)
    if not isinstance(data, dict):
        return [], []

    surfaces: list[BinaryRankedSurface] = []
    for fact in data.get("facts", []):
        if fact.get("type") != "surface_classification":
            continue
        detail = fact.get("detail") or {}
        try:
            surfaces.append(BinaryRankedSurface(
                function=detail.get("function", fact.get("subject", "")),
                category=detail.get("category", ""),
                score=float(detail.get("score", 0)),
                is_sink=bool(detail.get("is_sink", False)),
            ))
        except (ValueError, TypeError):
            continue

    for item in data.get("priority_queue", []):
        name = item.get("name", "")
        if not name:
            continue
        try:
            surfaces.append(BinaryRankedSurface(
                function=name,
                category=item.get("category", ""),
                score=float(item.get("score", 0)),
                is_sink=bool(item.get("is_sink", False)),
            ))
        except (ValueError, TypeError):
            continue

    boundaries: list[BinaryParserBoundary] = []
    for item in data.get("parser_boundaries", []):
        fn = item.get("function", "")
        if not fn:
            continue
        try:
            boundaries.append(BinaryParserBoundary(
                function=fn,
                ingress_function=item.get("ingress_function", ""),
                depth=int(item.get("depth", 0)),
                score=float(item.get("score", 0)),
                evidence_tier=item.get("evidence_tier", "xref_backed"),
            ))
        except (ValueError, TypeError):
            continue

    if surfaces or boundaries:
        logger.info(
            "binary_bridge: loaded %d surfaces, %d parser boundaries from %s",
            len(surfaces), len(boundaries), inv_path,
        )
    return surfaces, boundaries


def _load_binary_context_map(run_dir: Path) -> tuple:
    """Extract surfaces and boundaries from binary-context-map.json."""
    ctx_path = run_dir / CONTEXT_MAP_FILENAME
    if not ctx_path.exists():
        return [], []

    data = load_json(ctx_path, max_bytes=_MAX_BINARY_ARTIFACT_BYTES)
    if not isinstance(data, dict):
        return [], []

    surfaces: list[BinaryRankedSurface] = []
    for sink in data.get("sinks", []):
        name = sink.get("name", "")
        if not name:
            continue
        try:
            surfaces.append(BinaryRankedSurface(
                function=name,
                category=sink.get("category", "sink"),
                score=float(sink.get("score", 0)),
                is_sink=True,
            ))
        except (ValueError, TypeError):
            continue

    boundaries: list[BinaryParserBoundary] = []
    for ep in data.get("external_ingress", []):
        fn = ep.get("function", "")
        if not fn:
            continue
        try:
            boundaries.append(BinaryParserBoundary(
                function=fn,
                ingress_function=ep.get("ingress", ""),
                depth=0,
                score=float(ep.get("score", 0)),
                evidence_tier=ep.get("evidence_tier", "header_backed"),
            ))
        except (ValueError, TypeError):
            continue

    return surfaces, boundaries


def load_binary_bridge(
    out_dir: Path,
    *,
    target_path: Path | None = None,
    build_id_cache: object | None = None,
    current_build_ids: dict[str, str] | None = None,
) -> BinaryBridgeResult | None:
    """Load all binary analysis artifacts from sibling run directories.

    When *target_path* is set, only sibling runs that analysed the same
    target are considered (via ``.raptor-run.json`` target_path match).
    When *build_id_cache* is provided, cached layer0 findings are merged
    in addition to sibling-directory scanning — but ONLY for the
    build-ids named in *current_build_ids* (``{build_id: binary_path}``
    of the binaries actually present in this run's target set, the
    cache-side mirror of ``find_binary_run_dirs``'s target matching).
    Without that scoping every entry an external writer ever left in
    the shared cache merged into every audit as current-target sink
    evidence. No known build-ids → nothing merges (fail closed).
    Returns None when no binary analysis output is found.
    """
    run_dirs = find_binary_run_dirs(out_dir, target_path=target_path)

    result = BinaryBridgeResult()

    if build_id_cache is not None:
        try:
            _merge_from_build_cache(
                result, build_id_cache, current_build_ids,
            )
        except Exception:
            logger.debug("build_id_cache merge failed", exc_info=True)

    if not run_dirs and not result.has_data:
        return None

    result.source_dirs = [str(d) for d in run_dirs]

    for d in run_dirs:
        result.sink_edges.extend(_load_graph_sink_edges(d))

        surfaces, boundaries = _load_investigation(d)
        result.ranked_surfaces.extend(surfaces)
        result.parser_boundaries.extend(boundaries)

        ctx_surfaces, ctx_boundaries = _load_binary_context_map(d)
        result.ranked_surfaces.extend(ctx_surfaces)
        result.parser_boundaries.extend(ctx_boundaries)

    if result.has_data:
        logger.info(
            "binary_bridge: %d sink edges, %d surfaces, %d boundaries "
            "from %d run dirs",
            len(result.sink_edges),
            len(result.ranked_surfaces),
            len(result.parser_boundaries),
            len(run_dirs),
        )

    return result if result.has_data else None


def _merge_from_build_cache(
    result: BinaryBridgeResult,
    cache: object,
    current_build_ids: dict[str, str] | None = None,
) -> None:
    """Pull cached binary artifacts for the CURRENT binaries into the result.

    The shared build-ID cache is externally writable (documented public
    contract, optionally a network mount) and its keys are
    linker-choosable. Only entries whose build-id belongs to a binary
    actually present in this run's target set may merge, and only via
    ``cache.get`` (envelope + format-version + artifact-allowlist
    validation). When the entry envelope records the producing binary's
    content hash, it must match the current binary's hash — a forged
    build-id then cannot substitute artifacts computed for a different
    binary. No known current build-ids → nothing merges. A current
    binary that cannot be hashed (deleted / unreadable / race) does
    NOT degrade to build-id scope: its merge is skipped entirely —
    without the current binary's content hash there is nothing to bind
    foreign envelopes to, and build-ids are linker-choosable.
    """
    if not current_build_ids or not hasattr(cache, "get"):
        if current_build_ids is None:
            logger.debug(
                "build_id_cache merge skipped: no current-run build-ids "
                "known — cached layer0 findings stay out of this audit",
            )
        return
    for build_id, binary_path in current_build_ids.items():
        if not binary_path or not Path(binary_path).is_file():
            logger.warning(
                "build_id_cache merge skipped for build-id %s: current "
                "binary %r is not a readable file — refusing "
                "build-id-scoped merge (fail closed)",
                build_id, binary_path,
            )
            continue
        try:
            from .build_id_cache import _binary_sha256

            expected_sha = _binary_sha256(binary_path)
        except Exception:  # noqa: BLE001 — unhashable = no binding = no merge
            expected_sha = None
        if not expected_sha:
            logger.warning(
                "build_id_cache merge skipped for build-id %s: current "
                "binary %s cannot be hashed — refusing build-id-scoped "
                "merge (fail closed)",
                build_id, binary_path,
            )
            continue
        try:
            envelope = cache.get(
                build_id, "layer0-findings",
                expected_binary_sha256=expected_sha,
            )
        except TypeError:
            # Older cache object without the binding kwarg: read at
            # build-id scope, then enforce the content binding here so
            # the injected object cannot skip it (envelopes without a
            # recorded hash keep their legacy build-id-scope
            # readability, matching BuildIDCache.get).
            envelope = cache.get(build_id, "layer0-findings")
            if isinstance(envelope, dict):
                recorded = envelope.get("binary_sha256") or ""
                if recorded and recorded != expected_sha:
                    logger.warning(
                        "build_id_cache merge skipped for build-id %s: "
                        "envelope records binary_sha256 %s but the "
                        "current binary hashes to %s — content mismatch",
                        build_id, recorded[:16], expected_sha[:16],
                    )
                    continue
        except Exception:
            logger.debug(
                "build_id_cache read failed for %s", build_id,
                exc_info=True,
            )
            continue
        if not isinstance(envelope, dict):
            continue
        inner = envelope.get("data", envelope)
        if not isinstance(inner, dict):
            continue
        for f in inner.get("findings", []):
            if not isinstance(f, dict):
                continue
            caller = f.get("function", "")
            sink = f.get("target", "")
            if caller and sink:
                result.sink_edges.append(BinarySinkEdge(
                    caller=caller,
                    sink=sink,
                    evidence_tier="layer0",
                    confidence="layer0",
                    binary_path=f.get("binary_path", ""),
                ))
