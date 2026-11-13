"""Keep completed final status corrections after retained Collector rows."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .collector import Collector
    from .orchestrator import OrchestratorConfig, OrchestratorResult, ReviewOutcome


@dataclass(frozen=True, slots=True)
class _FinalStatus:
    file: str
    function: str
    status: str
    line: int
    model: str
    cost_usd: float
    duration_s: float
    function_qualified: str
    hypothesis: str
    evidence_tool: str

    @classmethod
    def capture(cls, outcome: ReviewOutcome) -> _FinalStatus:
        return cls(outcome.file, outcome.function, outcome.status, outcome.line,
                   outcome.model, outcome.cost_usd, outcome.duration_s,
                   outcome.function_qualified, outcome.hypothesis, outcome.evidence_tool)


@dataclass(frozen=True, slots=True)
class _FinalLogSnapshot:
    outcomes: tuple[_FinalStatus, ...]


class FinalAuditLogFlush:
    """Run-local forced-flush callback with a fixed final status snapshot.

    Before finish, this is the ordinary Collector flush. Finish publishes
    its scalar snapshot before the first corrective append, so a callback
    during that append can also restore the same final statuses. Retained
    rows are never discarded. Each completed callback reconciles after its
    flush; this is best effort, not an atomic forced-exit or durability bound.
    """

    def __init__(self, collector: Collector, config: OrchestratorConfig) -> None:
        self._collector = collector
        self._config = config
        self._snapshot: _FinalLogSnapshot | None = None

    def __call__(self) -> None:
        try:
            self._collector.flush()
        except BaseException as primary:
            try:
                self._reconcile()
            except BaseException as cleanup:
                primary.add_note("Final audit-log reconciliation also failed: " + type(cleanup).__name__)
            raise
        else:
            self._reconcile()

    def finish(self, result: OrchestratorResult) -> int:
        if self._snapshot is None:
            self._snapshot = _FinalLogSnapshot(tuple(
                _FinalStatus.capture(outcome) for outcome in result.outcomes))
        return self._reconcile()

    def _reconcile(self) -> int:
        snapshot = self._snapshot
        if snapshot is None:
            return 0
        from .orchestrator import _relog_final_statuses

        return _relog_final_statuses(snapshot, self._config)
