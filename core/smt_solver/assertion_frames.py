"""Native assertion ownership for conservative proofs across model frames."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from core.logging import get_logger

from .availability import z3
from .explain import track
from .session import check_solver


@dataclass(frozen=True)
class TrackedFrames:
    """Immutable ownership for a formula and its frame-owned tracking query.

    A native solver can retain a stale core after pop(), even when its
    assertions match this frame again. Only check() captures proof data;
    arbitrary external checks never establish provenance for this frame.
    The owned query explicitly assumes this frame's markers: rebuilding
    identical implication assertions after pop/reset must not lose their
    meaning when native assert-and-track bookkeeping has disappeared.
    """

    labels: Mapping[str, str] = field(default_factory=dict)
    origins: Mapping[str, int | None] = field(default_factory=dict)
    _solver: Any = field(default=None, repr=False)
    # Retain AST references: native numeric IDs alone can be recycled when
    # a reset releases the original assertions.
    _assertions: tuple[Any, ...] = field(default=(), repr=False)
    _markers: tuple[Any, ...] = field(default=(), repr=False)
    _core: tuple[int, ...] | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        # Copy before wrapping so a caller's original dictionary cannot
        # rewrite native positions or mutation-segment ownership later.
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))
        object.__setattr__(self, "origins", MappingProxyType(dict(self.origins)))

    def _matches(self, solver: Any) -> bool:
        if solver is not self._solver:
            return False
        try:
            current = tuple(solver.assertions())
            return len(current) == len(self._assertions) and all(
                actual.eq(original) for actual, original in zip(current, self._assertions, strict=True)
            )
        except (z3.Z3Exception, AttributeError):
            return False

    def check(self) -> Any:
        """Solve this exact frame once and capture its native core immediately.

        No caller assumptions or temporary facts are accepted. The only
        explicit assumptions are the immutable markers owned by this frame.
        Failed/unknown/sat checks clear earlier proof data. Reading ownership adds no
        queries and never reads a potentially stale native core.
        Optimize can also return unsat for an exhausted Pareto frontier;
        accept its negative verdict only with a frame-owned contradiction core.
        """
        object.__setattr__(self, "_core", None)
        if not self._matches(self._solver):
            raise ValueError("tracked frame assertions changed before check")
        result = check_solver(self._solver, *self._markers)
        if result == z3.unsat and self._matches(self._solver):
            try:
                # Native AST identity includes context. Printed marker names
                # from another context cannot claim ownership of this proof.
                positions = {marker.get_id(): index for index, marker in enumerate(self._markers)}
                markers = tuple(self._solver.unsat_core())
                if markers and all(
                    z3.is_const(marker) and z3.is_bool(marker)
                    and marker.ctx == self._solver.ctx and marker.get_id() in positions
                    for marker in markers
                ):
                    object.__setattr__(self, "_core", tuple(positions[marker.get_id()] for marker in markers))
            except (z3.Z3Exception, AttributeError):
                get_logger().debug("SMT native core ownership unavailable", exc_info=True)
        if result == z3.unsat and isinstance(self._solver, z3.Optimize) and self._core is None:
            get_logger().debug("SMT optimizer negative result lacks an owned contradiction core")
            return z3.unknown
        return result

    def core_indices(self, solver: Any) -> tuple[int, ...] | None:
        """Return captured native positions only for this unchanged frame."""
        return self._core if self._matches(solver) else None

    def single_core_origin(self, solver: Any) -> int | None:
        """Return the core's sole known owner, failing closed on missing data."""
        indices = self.core_indices(solver)
        if indices is None:
            return None
        owners = {self.origins.get(str(self._markers[index])) for index in indices}
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
    with no solver queries. Use the returned frame's check() to capture
    native proof data; later assertion changes invalidate ownership.
    """
    materialized = tuple(
        (tuple(labeled), tuple(origins) if origins is not None else None)
        for labeled, origins in frames
    )
    for labeled, origins in materialized:
        if origins is not None:
            if len(origins) != len(labeled):
                raise ValueError("constraint origin count must match the tracked frame")
            if any(origin is not None and (type(origin) is not int or origin < 0) for origin in origins):
                raise ValueError("constraint origins must be nonnegative integers or None")
    if len(solver.assertions()):
        raise ValueError("frame tracking requires a fresh solver without assertions")
    labeled_all: list[tuple[str, Any]] = []
    origins_all: list[int | None] = []
    for labeled, origins in materialized:
        labeled_all.extend(labeled)
        origins_all.extend(origins if origins is not None else [None] * len(labeled))
    # Track the complete formula in one batch: global collision checks and
    # sort/context validation must see later frames before any assertion is
    # added. track() appends one marker per input, in the same order.
    labels = track(solver, labeled_all)
    return TrackedFrames(labels, dict(zip(labels, origins_all, strict=True)), solver,
                         tuple(solver.assertions()),
                         tuple(z3.Bool(marker, ctx=solver.ctx) for marker in labels))
