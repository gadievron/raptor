"""Bridge frida runtime observations into /understand context maps.

Discovers frida evidence for a target, converts events to
ObserveProfile, and merges into the context map using the existing
merge_observation_into_context_map() pipeline.

Depends on packages.frida.evidence (PR #1) for discovery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.logging import get_logger
from core.sandbox.observe_context_merge import merge_observation_into_context_map

from .evidence import discover_evidence
from .observe_adapter import events_to_observe_profile

log = get_logger("frida.context_bridge")

__all__ = ["enrich_context_map_with_frida"]

_MAX_EVIDENCE_FILES = 5


def enrich_context_map_with_frida(
    context_map: dict,
    search_dirs: list[Path],
    target_path: Optional[str] = None,
) -> dict:
    """Discover frida evidence and merge into context map.

    When evidence is merged, returns a new dict (original untouched).
    When no usable evidence is found, returns the original reference.
    Degrades gracefully: missing evidence or import errors -> no-op.
    """
    evidence_list = discover_evidence(search_dirs, target_path=target_path)
    if not evidence_list:
        return context_map

    # discover_evidence returns newest-first; cap to prevent performance
    # degradation with many old runs.
    evidence_list = evidence_list[:_MAX_EVIDENCE_FILES]

    result = context_map

    for ev in evidence_list:
        if not ev.has_events:
            continue
        events_path = ev.run_dir / "events.jsonl"
        try:
            profile = events_to_observe_profile(events_path)
        except Exception as exc:
            log.warning("failed to parse events from %s: %s", events_path, exc)
            continue
        if (not profile.paths_read and not profile.paths_written
                and not profile.paths_stat and not profile.connect_targets):
            continue
        result = merge_observation_into_context_map(
            result,
            profile,
            target_dir=target_path,
            binary=ev.target_binary,
        )
        log.info(
            "merged frida observation from %s: %d reads, %d writes, "
            "%d stats, %d connects",
            ev.run_dir,
            len(profile.paths_read),
            len(profile.paths_written),
            len(profile.paths_stat),
            len(profile.connect_targets),
        )

    return result
