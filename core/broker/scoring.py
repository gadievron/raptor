"""Resource-aware scoring for fleet task routing.

Each RAPTOR mode has a resource profile: fuzzing is CPU-bound,
CodeQL is memory-bound, web scanning is I/O-bound.  Scoring
applies mode-specific weights so the router picks the machine
that will finish fastest, not just the first one that qualifies.

Beyond resources, scoring factors in:
    - **OS/arch match** — hard gate + soft bonus for exact match
    - **Tool completeness** — required tools present on the system
    - **Transport affinity** — prefer WinRM fleet members when
      the task targets Windows, SSH for Linux/macOS
    - **Architecture suitability** — ARM vs x86 tool availability

Scores are unitless — only the *relative ordering* matters.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence

from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    Architecture,
    CapabilityVerdict,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.transport import RemoteSystemEntry, TransportKind


@dataclass(frozen=True)
class ResourceWeights:
    """Per-mode weight multipliers for resource dimensions."""
    cores: float = 1.0
    ram_mb: float = 1.0
    disk_mb: float = 1.0


@dataclass(frozen=True)
class TaskConstraints:
    """OS/arch/transport constraints for task routing.

    These act as hard gates (require_*) and soft bonuses (prefer_*).
    Hard gates filter systems out; soft bonuses influence ranking
    among qualifying systems.
    """
    require_os: Optional[OperatingSystem] = None
    require_arch: Optional[Architecture] = None
    require_transport: Optional[TransportKind] = None
    prefer_os: Optional[OperatingSystem] = None
    prefer_arch: Optional[Architecture] = None
    prefer_transport: Optional[TransportKind] = None
    require_tools: frozenset[str] = frozenset()


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
_OS_MATCH_BONUS = 5.0
_ARCH_MATCH_BONUS = 3.0
_TRANSPORT_MATCH_BONUS = 4.0

# Tools that only work on specific OS+arch combos.
# Routing uses this to avoid sending AFL++ tasks to ARM macOS.
TOOL_PLATFORM_MATRIX: dict[str, set[tuple[OperatingSystem, Optional[Architecture]]]] = {
    "afl++": {
        (OperatingSystem.LINUX, Architecture.X86_64),
        (OperatingSystem.LINUX, Architecture.AARCH64),
    },
    "rr": {
        (OperatingSystem.LINUX, Architecture.X86_64),
    },
    "codeql": {
        (OperatingSystem.LINUX, Architecture.X86_64),
        (OperatingSystem.LINUX, Architecture.AARCH64),
        (OperatingSystem.DARWIN, Architecture.X86_64),
        (OperatingSystem.DARWIN, Architecture.AARCH64),
        (OperatingSystem.WINDOWS, Architecture.X86_64),
    },
    "frida": {
        (OperatingSystem.LINUX, None),
        (OperatingSystem.DARWIN, None),
        (OperatingSystem.WINDOWS, None),
        (OperatingSystem.ANDROID, None),
    },
    "frida-server": {
        (OperatingSystem.ANDROID, None),
    },
    "gdb": {
        (OperatingSystem.LINUX, None),
        (OperatingSystem.ANDROID, None),
    },
    "windbg": {
        (OperatingSystem.WINDOWS, None),
    },
    "coccinelle": {
        (OperatingSystem.LINUX, None),
    },
    "drozer": {
        (OperatingSystem.ANDROID, None),
    },
    "objection": {
        (OperatingSystem.ANDROID, None),
        (OperatingSystem.LINUX, None),
        (OperatingSystem.DARWIN, None),
    },
}


def _log_score(value: int, weight: float) -> float:
    """Log2-scaled score.  Diminishing returns: 32 cores isn't 8x better than 4."""
    if value <= 0:
        return 0.0
    return math.log2(max(value, 1)) * weight


def tool_available_on(
    tool: str,
    os: OperatingSystem,
    arch: Architecture,
) -> bool:
    """Check if *tool* is known to run on *os*/*arch*.

    Returns True for tools not in the matrix (assume portable).
    """
    platforms = TOOL_PLATFORM_MATRIX.get(tool)
    if platforms is None:
        return True
    for plat_os, plat_arch in platforms:
        if plat_os == os and (plat_arch is None or plat_arch == arch):
            return True
    return False


def score_system(
    caps: SystemCapabilities,
    mode: str,
    *,
    constraints: Optional[TaskConstraints] = None,
    entry: Optional[RemoteSystemEntry] = None,
) -> float:
    """Score a system for running *mode*.  Higher is better.

    Combines log2-scaled resource scores with mode-specific weights,
    tool-completeness bonus, and constraint-based affinity bonuses.
    """
    weights = MODE_RESOURCE_WEIGHTS.get(mode, _DEFAULT_WEIGHTS)

    score = 0.0
    score += _log_score(caps.cores, weights.cores)
    score += _log_score(caps.ram_mb, weights.ram_mb)
    score += _log_score(caps.free_disk_mb, weights.disk_mb)

    reqs = MODE_REQUIREMENTS.get(mode, ModeRequirements(mode=mode))
    all_required = reqs.tools | (constraints.require_tools if constraints else frozenset())
    if all_required:
        present = len(caps.tools & all_required)
        total = len(all_required)
        score += (present / total) * _TOOL_BONUS

    if constraints:
        if constraints.prefer_os and caps.os == constraints.prefer_os:
            score += _OS_MATCH_BONUS
        if constraints.prefer_arch and caps.arch == constraints.prefer_arch:
            score += _ARCH_MATCH_BONUS
        if constraints.prefer_transport and entry:
            if entry.transport == constraints.prefer_transport:
                score += _TRANSPORT_MATCH_BONUS

    return round(score, 2)


def _passes_hard_gates(
    entry: RemoteSystemEntry,
    caps: SystemCapabilities,
    constraints: Optional[TaskConstraints],
) -> bool:
    """Check hard gates — a system that fails any is excluded."""
    if not constraints:
        return True
    if constraints.require_os and caps.os != constraints.require_os:
        return False
    if constraints.require_arch and caps.arch != constraints.require_arch:
        return False
    if constraints.require_transport and entry.transport != constraints.require_transport:
        return False
    if constraints.require_tools and not constraints.require_tools.issubset(caps.tools):
        return False
    return True


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
    constraints: Optional[TaskConstraints] = None,
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
    constraints:
        OS/arch/transport hard gates and soft preferences.
    """
    reqs = MODE_REQUIREMENTS.get(mode, ModeRequirements(mode=mode))
    scored: list[ScoredSystem] = []

    for entry, caps in fleet:
        if labels and not labels.issubset(caps.labels | entry.labels):
            continue

        if not _passes_hard_gates(entry, caps, constraints):
            continue

        verdict = caps.satisfies(reqs)
        if require_capable and not verdict.met:
            continue

        scored.append(ScoredSystem(
            entry=entry,
            capabilities=caps,
            score=score_system(
                caps, mode, constraints=constraints, entry=entry,
            ),
            verdict=verdict,
        ))

    scored.sort(key=lambda s: s.score, reverse=True)
    return scored
