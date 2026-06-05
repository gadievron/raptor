"""Signal-based "Recommended next:" picks for /describe.

Augments the catalog's static ``pipeline_recommended`` defaults
(rendered as "Pipeline: scan → agentic" by the matched target
type) with picks derived from what we actually detected on this
target: dep counts, build system, CI scanners already running,
license, …

Two-layer rendering is deliberate. The catalog line is the
template ("for a project of this type, these commands by
default"); the signal-based line is informed by today's tree
("these commands are particularly applicable given what's
actually here"). Operator sees both — the template recommends
broad coverage, the signals refine.

Recommendations are RAPTOR commands only (sandboxed,
operator-typed-free). No raw shell commands; no operator-typed
build steps. Same security rationale as the /describe scope
(see ``report.py`` module docstring).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from packages.describe.target_shape import TargetShape


@dataclass(frozen=True)
class Recommendation:
    """One signal-derived recommendation: which RAPTOR command
    to consider next + the one-line reason (so operator can
    judge whether it applies)."""
    command: str   # "/sca", "/codeql", "/agentic", …
    reason: str    # one-line WHY, derived from signals


def recommend_next(shape: TargetShape) -> List[Recommendation]:
    """Pick RAPTOR commands likely to add value for THIS target.

    Order is significant — high-signal picks first (per-target
    specifics), broad always-applicable picks last. Operator
    reads top-down.
    """
    out: List[Recommendation] = []

    # /sca — dep counts present. The strongest signal for "you
    # have a dep tree worth scanning".
    if shape.deps is not None and shape.deps.by_ecosystem:
        eco_blurb = ", ".join(
            f"{count} {eco}"
            for eco, count in sorted(
                shape.deps.by_ecosystem.items(), key=lambda x: -x[1],
            )[:3]   # top 3 ecosystems by count, avoid wrapping
        )
        out.append(Recommendation(
            command="/sca",
            reason=f"{eco_blurb} dep manifests detected",
        ))

    # /codeql — build system available. (We don't check whether
    # CodeQL is already running in CI: RAPTOR's /codeql does
    # different work than a generic CI codeql scan — different
    # queries, different suites, different IRIS Tier 1 dataflow
    # — and "duplicate effort" is bad advice for a security
    # framework where defensive scanning is additive.)
    has_build = bool(shape.primary_language and shape.build_systems.get(
        shape.primary_language,
    ))
    if has_build:
        bs = shape.build_systems[shape.primary_language]
        out.append(Recommendation(
            command="/codeql",
            reason=f"{bs} build available",
        ))

    # /agentic — broad LLM-driven analysis. Only surface when
    # there are no signal-driven picks AND when it'd actually
    # add value; otherwise the "always applicable" line is
    # marketing noise that crowds the real recommendations.
    # When other recs are present, the operator already knows
    # /agentic exists from the catalog Pipeline line above.
    if not out:
        out.append(Recommendation(
            command="/agentic",
            reason="LLM-driven analysis — applicable to any target",
        ))

    return out


__all__ = ["Recommendation", "recommend_next"]
