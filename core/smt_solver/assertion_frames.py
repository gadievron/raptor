"""Native assertion ownership for conservative proofs across model frames."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .availability import z3
from .explain import track


@dataclass
class TrackedFrames:
    """Keep display labels distinct from native assertion ownership."""

    labels: dict[str, str] = field(default_factory=dict)
    origins: dict[str, int | None] = field(default_factory=dict)
    _solver: Any = field(default=None, repr=False)
    _assertion_ids: tuple[int, ...] = ()

    def single_core_origin(self, solver: Any) -> int | None:
        """Return the core's sole known owner, failing closed on missing data."""
        if solver is not self._solver:
            return None
        if tuple(expr.get_id() for expr in solver.assertions()) != self._assertion_ids:
            return None
        try:
            owners = {self.origins.get(str(marker)) for marker in solver.unsat_core()}
        except (z3.Z3Exception, AttributeError):
            return None
        if len(owners) == 1 and None not in owners:
            return next(iter(owners))
        return None


def track_frames(
    solver: Any,
    frames: Iterable[tuple[Iterable[tuple[str, Any]], Iterable[int | None] | None]],
) -> TrackedFrames:
    """Track provenance by native markers, never by possibly duplicate text.

    None origins are deliberately unowned. Validate every frame's metadata
    before changing assertions; identifiers are exact nonnegative integers.
    Requires a fresh solver. Combining frames changes bookkeeping only,
    with no solver queries; later assertion changes invalidate ownership.
    """
    frames = tuple((tuple(labeled), tuple(origins) if origins is not None else None)
                   for labeled, origins in frames)
    for labeled, origins in frames:
        if origins is not None:
            if len(origins) != len(labeled):
                raise ValueError("constraint origin count must match the tracked frame")
            if any(origin is not None and (type(origin) is not int or origin < 0) for origin in origins):
                raise ValueError("constraint origins must be nonnegative integers or None")
    if len(solver.assertions()):
        raise ValueError("frame tracking requires a fresh solver without assertions")
    labeled_all: list[tuple[str, Any]] = []
    origins_all: list[int | None] = []
    for labeled, origins in frames:
        labeled_all.extend(labeled)
        origins_all.extend(origins if origins is not None else [None] * len(labeled))
    # Track the complete formula in one batch: global collision checks and
    # sort/context validation must see later frames before any assertion is
    # added. track() appends one marker per input, in the same order.
    labels = track(solver, labeled_all)
    return TrackedFrames(labels, dict(zip(labels, origins_all, strict=True)), solver,
                         tuple(expr.get_id() for expr in solver.assertions()))
