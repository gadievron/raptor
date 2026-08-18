"""Consumer-facing API for IRIS taint specs.

Every RAPTOR pipeline that needs project-specific taint knowledge calls
one of these functions.  They resolve the project directory, load specs
from the persistent store, and return filtered results.

Usage::

    from core.iris.api import get_project_sinks, load_project_specs

    # In /understand --map, enrich sink discovery:
    extra_sinks = get_project_sinks(out_dir=run_output_dir)

    # In /validate, load sanitisers for proximity assessment:
    specs = load_project_specs(out_dir=run_output_dir, roles={"sanitiser"})
"""

from __future__ import annotations

import logging
from pathlib import Path

from core.evidence import TIER_RANK, EvidenceTier

from .specs import TaintSpec
from .store import load_specs, load_store_metadata, save_specs

logger = logging.getLogger(__name__)


def load_project_specs(
    out_dir: Path | None = None,
    target_path: Path | None = None,
    *,
    min_tier: EvidenceTier = EvidenceTier.HEURISTIC,
    roles: set[str] | None = None,
) -> list[TaintSpec]:
    """Load IRIS specs for a project, with optional filtering.

    Resolution order for the store location:

    1. ``out_dir`` — treated as a run output dir; the store lives in
       its parent (project output dir).
    2. Active project — resolved via ``.active`` symlink.
    3. Empty list — first run, no specs yet.

    Parameters
    ----------
    out_dir:
        A run's output directory.  The store is at ``out_dir.parent``.
    target_path:
        Currently unused; reserved for future global-store lookup.
    min_tier:
        Only return specs with ``evidence_tier >= min_tier``.
    roles:
        Only return specs whose ``role`` is in this set
        (e.g. ``{"sink", "source"}``).
    """
    resolved = _resolve_out_dir(out_dir)
    if resolved is None:
        return []

    specs = load_specs(resolved, target_path=target_path)
    if not specs:
        return []

    min_rank = TIER_RANK.get(min_tier, 0)
    result = []
    for spec in specs:
        if TIER_RANK.get(spec.evidence_tier, 0) < min_rank:
            continue
        if roles is not None and spec.role not in roles:
            continue
        result.append(spec)
    return result


def get_project_sinks(
    out_dir: Path | None = None,
    target_path: Path | None = None,
) -> frozenset[str]:
    """Return IRIS-confirmed sink function names.

    Convenience wrapper for ``load_project_specs(roles={"sink"})``.
    Returns a frozenset of function names suitable for merging with
    ``core.inventory.sink_discovery._SOURCE_LEVEL_SINKS``.
    """
    specs = load_project_specs(out_dir=out_dir, target_path=target_path, roles={"sink"})
    return frozenset(s.function for s in specs)


# Suppression-direction evidence gate: recognising a function as a
# sanitiser can only ever *weaken* scrutiny (guard adequacy treats a
# recognised sanitiser as adequate, downgrading the finding), so a
# spec must be tool-corroborated before it may flow in that direction.
# XREF_BACKED is the floor: reached only via tool confirmation in the
# refine loop (_promote_confirmed) or an interactive operator
# annotation (promote_spec_on_annotation, human_grade). Heuristic /
# hint-tier specs (LLM-synthesised, machine-attributed annotations)
# stay prompt-direction only — they are still returned by
# ``load_project_specs`` for unverified-context injection, but never
# by the suppression-direction readers below.
SUPPRESSION_MIN_TIER = EvidenceTier.XREF_BACKED


def get_project_sanitisers(
    out_dir: Path | None = None,
    target_path: Path | None = None,
) -> frozenset[str]:
    """Return tool-corroborated sanitiser function names.

    Used by guard quality analysis and condition_adequacy to recognise
    project-specific sanitisation that the static set wouldn't know.

    Suppression-direction reader: only specs at or above
    ``SUPPRESSION_MIN_TIER`` (tool-corroborated / operator-confirmed)
    are returned. An LLM-refined sanitiser at heuristic tier must not
    be able to mark a guard adequate — that would let a hallucinated
    sanitiser suppress a real finding.
    """
    specs = load_project_specs(
        out_dir=out_dir, target_path=target_path, roles={"sanitiser"},
        min_tier=SUPPRESSION_MIN_TIER,
    )
    return frozenset(s.function for s in specs)


def get_project_sources(
    out_dir: Path | None = None,
    target_path: Path | None = None,
) -> frozenset[str]:
    """Return IRIS-confirmed source function names."""
    specs = load_project_specs(
        out_dir=out_dir, target_path=target_path, roles={"source"},
    )
    return frozenset(s.function for s in specs)


def get_project_propagators(
    out_dir: Path | None = None,
    target_path: Path | None = None,
) -> frozenset[str]:
    """Return IRIS-confirmed propagator function names.

    Used by the exploit engine to identify wrapper functions that
    pass taint through without sanitising — opaque to stock rules
    but known to propagate attacker-controlled data.
    """
    specs = load_project_specs(
        out_dir=out_dir, target_path=target_path, roles={"propagator"},
    )
    return frozenset(s.function for s in specs)


def load_project_assumptions(
    out_dir: Path | None = None,
    target_path: Path | None = None,
) -> list:
    """Load safety assumptions from the IRIS store.

    Returns a list of ``SafetyAssumption`` objects, or an empty list
    when no store exists.
    """
    from .store import load_assumptions

    resolved = _resolve_out_dir(out_dir)
    if resolved is None:
        return []
    result = load_assumptions(resolved, target_path=target_path)
    return result


def get_bypass_findings(
    out_dir: Path | None = None,
) -> list:
    """Load bypass findings written by the orchestrator.

    Bypass findings are written to ``iris-bypass-findings.json`` in
    the run output directory by the compositional analysis phase.
    Returns a list of ``BypassFinding`` objects.
    """
    from .assumptions import BypassFinding

    if out_dir is None:
        return []
    path = Path(out_dir) / "iris-bypass-findings.json"
    if not path.is_file():
        return []
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        return [BypassFinding.from_dict(d) for d in data]
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        logger.debug("iris.api: failed to load bypass findings from %s", path, exc_info=True)
        return []


_ANNOTATION_STATUS_TO_ROLE = {
    "sink": "sink",
    "entry_point": "source",
    "finding": "sink",
}


def promote_spec_on_annotation(
    source_file: str,
    function: str,
    status: str,
    *,
    out_dir: Path | None = None,
    human_grade: bool = True,
) -> EvidenceTier | None:
    """Promote an IRIS spec when an annotation confirms it.

    When a function is annotated with status ``sink``,
    ``entry_point``, or ``finding``, any matching IRIS spec is
    promoted:

      * ``human_grade=True`` (operator note: ``source=human`` with an
        interactive-TTY provenance stamp, or a legacy pre-stamp note)
        → XREF_BACKED, the highest automatically assignable tier,
        with ``source="operator_confirmed"``.
      * ``human_grade=False`` (agent/llm-sourced, or a human claim
        stamped non-interactive) → HEADER_BACKED, the hint tier,
        with ``source="annotation_asserted"``. Useful signal, but
        never operator authority.

    Promotion only raises a spec's tier; a spec already at or above
    the target keeps its tier (so a non-human-grade note can never
    touch an XREF_BACKED spec).

    Returns the tier applied when at least one spec was promoted and
    the store updated, else ``None``.
    """
    role = _ANNOTATION_STATUS_TO_ROLE.get(status)
    if role is None:
        return None

    resolved = _resolve_out_dir(out_dir)
    if resolved is None:
        return None

    specs = load_specs(resolved)
    if not specs:
        return None

    promoted = False
    if human_grade:
        target_tier = EvidenceTier.XREF_BACKED
        spec_source = "operator_confirmed"
    else:
        target_tier = EvidenceTier.HEADER_BACKED
        spec_source = "annotation_asserted"
    target_rank = TIER_RANK.get(target_tier, 0)

    for spec in specs:
        if spec.function != function:
            continue
        if not spec.file or not source_file:
            continue
        if not (source_file == spec.file
                or source_file.endswith("/" + spec.file)):
            continue
        if spec.role != role:
            continue
        if TIER_RANK.get(spec.evidence_tier, 0) >= target_rank:
            continue
        spec.evidence_tier = target_tier
        spec.source = spec_source
        promoted = True

    if promoted:
        meta = load_store_metadata(resolved)
        from .store import assumptions_from_list
        existing_assumptions = assumptions_from_list(
            meta.get("assumptions", []),
        )
        stored_target = meta.get("target_path")
        save_specs(
            resolved, specs,
            cl_sha=meta.get("checklist_sha", ""),
            round_num=meta.get("round", 0),
            history=meta.get("history"),
            assumptions=existing_assumptions or None,
            target_path=Path(stored_target) if stored_target else None,
        )
        logger.info(
            "IRIS: promoted %s:%s to %s via %s annotation",
            source_file, function, target_tier.value,
            "operator" if human_grade else "machine-attributed",
        )
        return target_tier
    return None


def _resolve_out_dir(out_dir: Path | None) -> Path | None:
    """Resolve a run output dir for store lookup."""
    if out_dir is not None:
        return Path(out_dir)

    try:
        from core.run.output import _resolve_active_project
        active = _resolve_active_project()
        if active is not None:
            # active[0] is the project output dir; store functions
            # expect a run-level dir and call .parent, so return a
            # child so .parent resolves back to the project dir.
            return Path(active[0]) / "_active"
    except ImportError:
        pass

    return None
