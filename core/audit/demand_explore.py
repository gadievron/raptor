"""Demand-driven exploration budget for the audit review loop.

During review the LLM may chase hypotheses beyond the pre-computed
context by requesting extra function context ("expansions").
ExpansionBudget caps how many functions can be expanded per run so a
runaway review can't pull the whole codebase into the prompt.

Historical note: this module used to also carry a typed Joern query
builder and a triage classifier. The classifier was a drifted
duplicate of core/audit/triage.py (the live implementation — see
orchestrator's `from .triage import ...`); the query builder and
context-expansion dataclasses had no callers. All were removed —
only ExpansionBudget was ever consumed (orchestrator, shared_state).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class ExpansionBudget:
    """Tracks how many functions the LLM can expand during review."""

    max_expansions: int = 50
    _expanded: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def remaining(self) -> int:
        return max(0, self.max_expansions - len(self._expanded))

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def try_expand(self, function_key: str) -> bool:
        with self._lock:
            if function_key in self._expanded:
                return True
            if self.exhausted:
                return False
            self._expanded.append(function_key)
            return True

    def summary(self) -> str:
        return (
            f"Context expansion: {len(self._expanded)}/{self.max_expansions} "
            f"functions expanded ({self.remaining} remaining)"
        )
