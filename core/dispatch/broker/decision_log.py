"""Per-run decision logging — structured JSONL of every routing decision.

Each record captures what model was selected, why, what alternatives
were considered, and the outcome (latency, cost, success/failure).
Written to ``decisions.jsonl`` in the run's output directory.

Thread-safe: a lock serialises writes so concurrent dispatch threads
don't interleave lines.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.json import append_jsonl, load_jsonl


@dataclass
class DecisionRecord:
    """One routing decision.  Serialised as one JSONL line."""

    selected_model: str
    reason: str
    hint_tier: str = "defer"
    hint_model: str = ""
    decision_class: str = ""
    prompt_tokens: int = 0
    alternatives: list[dict[str, str]] = field(default_factory=list)
    speed_tier: str = "express"
    was_fallback: bool = False
    was_retry: bool = False
    cache_hit: bool = False
    latency_ms: float | None = None
    cost_usd: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    success: bool = True
    error: str = ""
    timestamp: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)


class DecisionLog:
    """Append-only JSONL writer for routing decisions.

    Usage::

        log = DecisionLog(output_dir / "decisions.jsonl")
        log.record(DecisionRecord(
            selected_model="claude-haiku-4-5",
            reason="cheapest fitting model",
            prompt_tokens=1200,
        ))
        # ... later
        log.record(rec)
        print(log.stats())
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._count = 0
        self._models: dict[str, int] = {}
        self._total_cost = 0.0
        self._failures = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def count(self) -> int:
        return self._count

    def record(self, rec: DecisionRecord) -> None:
        """Append one decision record as a JSONL line."""
        with self._lock:
            append_jsonl(self._path, asdict(rec), compact=True)
            self._count += 1
            self._models[rec.selected_model] = (
                self._models.get(rec.selected_model, 0) + 1
            )
            if rec.cost_usd is not None:
                self._total_cost += rec.cost_usd
            if not rec.success:
                self._failures += 1

    def stats(self) -> dict[str, Any]:
        """Summary statistics for the current run."""
        with self._lock:
            return {
                "total_decisions": self._count,
                "models_used": dict(self._models),
                "total_cost_usd": round(self._total_cost, 6),
                "failures": self._failures,
            }

    def read_all(self) -> list[DecisionRecord]:
        """Read back all records (for analysis / testing).

        ``load_jsonl`` is the symmetric hardened reader for the
        ``append_jsonl`` writer above (O_NOFOLLOW, shared backend) with
        the same best-effort policy this method always had: a missing
        trail reads as empty and malformed lines are skipped. Non-dict
        lines (a foreign writer's arrays/scalars) are skipped too —
        they can't build a :class:`DecisionRecord`.
        """
        return [
            DecisionRecord(**d)
            for d in load_jsonl(self._path)
            if isinstance(d, dict)
        ]
