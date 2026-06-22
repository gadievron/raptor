"""Resource-aware scoring for fleet task routing.

Each RAPTOR mode has a resource profile: fuzzing is CPU-bound,
CodeQL is memory-bound, web scanning is I/O-bound.  Scoring
applies mode-specific weights so the router picks the machine
that will finish fastest, not just the first one that qualifies.

Scores are unitless — only the *relative ordering* matters.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence

from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    CapabilityVerdict,
    ModeRequirements,
    SystemCapabilities,
)
from core.broker.transport import RemoteSystemEntry


@dataclass(frozen=True)
class ResourceWeights:
    """Per-mode weight multipliers for resource dimensions."""
    cores: float = 1.0
    ram_mb: float = 1.0
    disk_mb: float = 1.0


_DEFAULT_WEIGHTS = ResourceWeights()

MODE_RESOURCE_WEIGHTS: dict[str, ResourceWeights] = {
    "fuzz": ResourceWeights(cores=3.0, ram_mb=1.0, disk_mb=0.5),
    "codeql": ResourceWeights(cores=0.5, ram_mb=3.0, disk_mb=2.0),
    "scan": ResourceWeights(cores=1.0, ram_mb=1.0, disk_mb=0.5),
    "web": ResourceWeights(cores=1.0, ram_mb=0.5, disk_mb=0.2),
    "agentic": ResourceWeights(cores=1.5, ram_mb=2.0, disk_mb=1.0),
    "crash-analysis": ResourceWeights(cores=2.0, ram_mb=2.0, disk_mb=1.0),
}

_TOOL_BONUS = 10.0


def _log_score(value: int, weight: float) -> float:
    """Log2-scaled score.  Diminishing returns: 32 cores isn't 8x better than 4."""
    if value <= 0:
        return 0.0
    return math.log2(max(value, 1)) * weight


def score_system(caps: SystemCapabilities, mode: str) -> float:
    """Score a system for running *mode*.  Higher is better.

    Combines log2-scaled resource scores with mode-specific weights
    and a tool-completeness bonus.
    """
    weights = MODE_RESOURCE_WEIGHTS.get(mode, _DEFAULT_WEIGHTS)

    score = 0.0
    score += _log_score(caps.cores, weights.cores)
    score += _log_score(caps.ram_mb, weights.ram_mb)
    score += _log_score(caps.free_disk_mb, weights.disk_mb)

    reqs = MODE_REQUIREMENTS.get(mode, ModeRequirements(mode=mode))
    if reqs.tools:
        present = len(caps.tools & reqs.tools)
        total = len(reqs.tools)
        score += (present / total) * _TOOL_BONUS

    return round(score, 2)


@dataclass(frozen=True)
class ScoredSystem:
    """A fleet member with its score for a specific mode."""
    entry: RemoteSystemEntry
    capabilities: SystemCapabilities
    score: float
    verdict: CapabilityVerdict


def rank_fleet(
    fleet: Sequence[tuple[RemoteSystemEntry, SystemCapabilities]],
    mode: str,
    *,
    require_capable: bool = True,
    labels: frozenset[str] = frozenset(),
) -> list[ScoredSystem]:
    """Rank fleet members for *mode*, best first.

    Parameters
    ----------
    fleet:
        (entry, caps) pairs — typically from ``Inventory.list_all_with_caps()``.
    mode:
        RAPTOR mode to score for.
    require_capable:
        If True (default), exclude systems that fail the hard capability gate.
    labels:
        Extra labels the system must carry (e.g. ``{"gpu"}``).
    """
    reqs = MODE_REQUIREMENTS.get(mode, ModeRequirements(mode=mode))
    scored: list[ScoredSystem] = []

    for entry, caps in fleet:
        if labels and not labels.issubset(caps.labels | entry.labels):
            continue

        verdict = caps.satisfies(reqs)
        if require_capable and not verdict.met:
            continue

        scored.append(ScoredSystem(
            entry=entry,
            capabilities=caps,
            score=score_system(caps, mode),
            verdict=verdict,
        ))

    scored.sort(key=lambda s: s.score, reverse=True)
    return scored
