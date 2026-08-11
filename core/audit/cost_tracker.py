"""Per-phase cost tracking for /audit runs.

Tracks time and token usage across orchestrator phases so operators
can see where the budget goes. Written to cost-breakdown.json at
the end of each run.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PhaseCost:
    """Cost for a single phase of the audit."""

    wall_time_s: float = 0.0
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "wall_time_s": round(self.wall_time_s, 2),
            "calls": self.calls,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": round(self.cost_usd, 4),
        }
        if self.cache_read_tokens or self.cache_write_tokens:
            d["cache_read_tokens"] = self.cache_read_tokens
            d["cache_write_tokens"] = self.cache_write_tokens
        return d


@dataclass
class CostTracker:
    """Accumulates per-phase cost for an audit run."""

    phases: Dict[str, PhaseCost] = field(default_factory=dict)
    _active_phase: Optional[str] = field(default=None, repr=False)
    _phase_start: float = field(default=0.0, repr=False)

    _KNOWN_PHASES = (
        "triage",
        "prefilter",
        "review",
        "refinement",
        "clean_check",
        "sweep",
        "synthesis",
        "dynamic",
        "reachability",
        "propagation",
        "attacker_synthesis",
        "error_retry",
        "re_review",
        "dark_verify",
        "report",
    )

    def _ensure_phase(self, phase: str) -> PhaseCost:
        if phase not in self.phases:
            self.phases[phase] = PhaseCost()
        return self.phases[phase]

    def start_phase(self, phase: str) -> None:
        """Mark the start of a phase for wall-clock tracking."""
        if self._active_phase:
            self.end_phase()
        self._active_phase = phase
        self._phase_start = time.monotonic()

    def end_phase(self) -> None:
        """Mark the end of the current phase."""
        if self._active_phase:
            pc = self._ensure_phase(self._active_phase)
            pc.wall_time_s += time.monotonic() - self._phase_start
            self._active_phase = None
            self._phase_start = 0.0

    def record_call(
        self,
        phase: str,
        *,
        cost_usd: float = 0.0,
        tokens_in: int = 0,
        tokens_out: int = 0,
        wall_time_s: float = 0.0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        """Record a single call within a phase."""
        pc = self._ensure_phase(phase)
        pc.calls += 1
        pc.cost_usd += cost_usd
        pc.tokens_in += tokens_in
        pc.tokens_out += tokens_out
        pc.wall_time_s += wall_time_s
        pc.cache_read_tokens += cache_read_tokens
        pc.cache_write_tokens += cache_write_tokens

    @property
    def total_cost_usd(self) -> float:
        return sum(p.cost_usd for p in self.phases.values())

    @property
    def total_wall_time_s(self) -> float:
        return sum(p.wall_time_s for p in self.phases.values())

    @property
    def total_calls(self) -> int:
        return sum(p.calls for p in self.phases.values())

    @property
    def total_cache_read_tokens(self) -> int:
        return sum(p.cache_read_tokens for p in self.phases.values())

    @property
    def total_cache_write_tokens(self) -> int:
        return sum(p.cache_write_tokens for p in self.phases.values())

    def to_dict(self) -> Dict[str, Any]:
        totals: Dict[str, Any] = {
            "cost_usd": round(self.total_cost_usd, 4),
            "wall_time_s": round(self.total_wall_time_s, 2),
            "calls": self.total_calls,
        }
        cr = self.total_cache_read_tokens
        cw = self.total_cache_write_tokens
        if cr or cw:
            totals["cache_read_tokens"] = cr
            totals["cache_write_tokens"] = cw
        return {
            "phases": {k: v.to_dict() for k, v in sorted(self.phases.items())},
            "totals": totals,
        }

    def write(self, out_dir: Path) -> Path:
        """Write cost-breakdown.json to the run directory."""
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "cost-breakdown.json"
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        return path

    def summary(self) -> str:
        """One-line summary of total cost."""
        parts: List[str] = []
        for name in self._KNOWN_PHASES:
            if name in self.phases:
                pc = self.phases[name]
                if pc.calls > 0:
                    parts.append(f"{name}={pc.calls}calls/${pc.cost_usd:.2f}")
        total = self.total_cost_usd
        return f"cost: ${total:.2f} ({', '.join(parts)})"

    def phase_summary(self) -> str:
        """Multi-line breakdown by phase."""
        lines = ["## Cost breakdown"]
        for name in sorted(self.phases):
            pc = self.phases[name]
            lines.append(
                f"- **{name}**: {pc.calls} calls, "
                f"${pc.cost_usd:.4f}, "
                f"{pc.wall_time_s:.1f}s wall"
            )
        lines.append(
            f"\n**Total**: {self.total_calls} calls, "
            f"${self.total_cost_usd:.4f}, "
            f"{self.total_wall_time_s:.1f}s wall"
        )
        cr = self.total_cache_read_tokens
        cw = self.total_cache_write_tokens
        if cr or cw:
            lines.append(
                f"**Prompt cache**: {cr:,} read, {cw:,} written"
            )
        return "\n".join(lines)
