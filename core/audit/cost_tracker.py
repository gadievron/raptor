"""Per-phase cost tracking for /audit runs.

Tracks time and token usage across orchestrator phases so operators
can see where the budget goes. Written to cost-breakdown.json at
the end of each run.

Ledger semantics — one audit run has three cost surfaces that MUST
reconcile (a real run once showed $8.08 / $4.52 / $2.82 for the same
money, all "true" for different ledgers):

* ``phases.<p>.cost_usd``    — spend on calls that produced a usable
  outcome (the "completed" figure).
* ``phases.<p>.failed_attempts_cost_usd`` — spend consumed by attempts
  that raised (timeouts, retries, budget kills). Tracked by the LLM
  client's budget but carried by no outcome; before this field it
  vanished from every report while still counting against the cap.
* ``totals.total_spend_usd`` — the authoritative LLM-client ledger
  (everything above plus anything not attributable to a phase),
  injected via :meth:`PhaseCostLedger.set_total_spend` at run end. Any
  residual is surfaced as ``totals.unattributed_cost_usd`` so the
  arithmetic always closes: total_spend = cost + failed + unattributed.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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
    failed_calls: int = 0
    failed_attempts_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "wall_time_s": round(self.wall_time_s, 2),
            "calls": self.calls,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": round(self.cost_usd, 4),
        }
        if self.cache_read_tokens or self.cache_write_tokens:
            d["cache_read_tokens"] = self.cache_read_tokens
            d["cache_write_tokens"] = self.cache_write_tokens
        if self.failed_calls or self.failed_attempts_cost_usd:
            d["failed_calls"] = self.failed_calls
            d["failed_attempts_cost_usd"] = round(
                self.failed_attempts_cost_usd, 4,
            )
        return d


PRIOR_SEGMENTS_PHASE = "prior_segments"


@dataclass
class PhaseCostLedger:
    """Accumulates per-phase cost for an audit run."""

    phases: dict[str, PhaseCost] = field(default_factory=dict)
    # Segment provenance for resumed runs: one row per resume boundary
    # (``{"segment": n, "prior_spend_usd": x}``). Serialised into
    # cost-breakdown.json when non-empty so the ledger states which
    # money belongs to which segment.
    segments: list[dict[str, Any]] = field(default_factory=list)
    _active_phase: str | None = field(default=None, repr=False)
    _phase_start: float = field(default=0.0, repr=False)
    # Authoritative end-of-run LLM-client ledger (None until injected
    # via set_total_spend — e.g. runs without a budget client).
    _total_spend_usd: float | None = field(default=None, repr=False)

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

    def record_failed_attempt(
        self,
        phase: str,
        *,
        cost_usd: float = 0.0,
        count_call: bool = True,
    ) -> None:
        """Record spend consumed by an attempt that raised.

        Timed-out / retried / budget-killed calls still cost money on
        the LLM client's ledger but produce no outcome to carry the
        cost — record them here so the ledgers reconcile.
        ``count_call=False`` is the end-of-run reconciliation path:
        it books residual unattributed spend as failed-attempt cost
        without inventing a call count for it.
        """
        pc = self._ensure_phase(phase)
        if count_call:
            pc.failed_calls += 1
        pc.failed_attempts_cost_usd += cost_usd

    def set_total_spend(self, spend_usd: float) -> None:
        """Inject the authoritative end-of-run LLM-client ledger.

        On a resumed run the client ledger covers THIS segment only —
        book the prior-segment spend on top so ``total_spend_usd``
        keeps describing the whole run.
        """
        self._total_spend_usd = (
            max(0.0, float(spend_usd)) + self.prior_segments_spend_usd
        )

    def book_prior_segments(self, spend_usd: float, *, segment: int) -> None:
        """Book prior segments' reconciled spend (same-run resume).

        The amount lands in a dedicated ``prior_segments`` phase (no
        call count — the calls are itemised in the prior segments'
        telemetry) and a segment row records the boundary, so the
        rewritten cost-breakdown.json APPENDS to the story instead of
        silently replacing it with segment-local numbers.
        """
        amount = max(0.0, float(spend_usd))
        pc = self._ensure_phase(PRIOR_SEGMENTS_PHASE)
        pc.cost_usd += amount
        self.segments.append({
            "segment": segment,
            "prior_spend_usd": round(amount, 4),
        })

    @property
    def prior_segments_spend_usd(self) -> float:
        """Spend booked from prior segments of a resumed run."""
        pc = self.phases.get(PRIOR_SEGMENTS_PHASE)
        return pc.cost_usd if pc else 0.0

    # Call classes booked at outcome level into phases whose names
    # don't match the class ("review" outcomes land in the review /
    # re_review / error_retry / refinement phases). Every other class
    # is matched to a phase by name.
    _OUTCOME_BOOKED_CLASSES = frozenset({"review"})

    def book_unbooked_classes(
        self, class_costs: dict[str, tuple[int, float]],
    ) -> dict[str, float]:
        """Book telemetry call classes that no phase captured.

        ``class_costs`` is the telemetry sink's per-class snapshot
        (``{call_class: (calls, cost_usd)}``). Classes that already
        map to a phase — by name, or via the outcome-level booking of
        review calls — are skipped; everything else (iris, audit,
        glance_batch, summary, …) is booked as a phase named after the
        class. Pre-fix these were SUCCESSFUL calls whose spend either
        surfaced under the "failed/timed-out" console label
        (unattributed residual) or vanished from the summary entirely
        (standalone-client spend outside the budget ledger).

        Returns ``{class: cost}`` for the classes booked.
        """
        booked: dict[str, float] = {}
        for cls, (calls, cost) in sorted(class_costs.items()):
            if calls <= 0 and cost <= 0:
                continue
            if cls in self._OUTCOME_BOOKED_CLASSES or cls in self.phases:
                continue
            pc = self._ensure_phase(cls)
            pc.calls += max(0, int(calls))
            pc.cost_usd += max(0.0, float(cost))
            booked[cls] = float(cost)
        return booked

    @property
    def total_cost_usd(self) -> float:
        return sum(p.cost_usd for p in self.phases.values())

    @property
    def total_failed_attempts_cost_usd(self) -> float:
        return sum(p.failed_attempts_cost_usd for p in self.phases.values())

    @property
    def total_spend_usd(self) -> float:
        """Total money spent: the client ledger when injected, else the
        sum of everything the phase ledgers captured."""
        tracked = self.total_cost_usd + self.total_failed_attempts_cost_usd
        if self._total_spend_usd is None:
            return tracked
        # The client ledger is authoritative but can't be LOWER than
        # what the phases demonstrably recorded (multiple clients or a
        # missing snapshot would otherwise hide tracked spend).
        return max(self._total_spend_usd, tracked)

    @property
    def unattributed_cost_usd(self) -> float:
        """Client-ledger spend no phase captured (residual)."""
        return max(
            0.0,
            self.total_spend_usd
            - self.total_cost_usd
            - self.total_failed_attempts_cost_usd,
        )

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

    def to_dict(self) -> dict[str, Any]:
        totals: dict[str, Any] = {
            "cost_usd": round(self.total_cost_usd, 4),
            "wall_time_s": round(self.total_wall_time_s, 2),
            "calls": self.total_calls,
        }
        cr = self.total_cache_read_tokens
        cw = self.total_cache_write_tokens
        if cr or cw:
            totals["cache_read_tokens"] = cr
            totals["cache_write_tokens"] = cw
        failed = self.total_failed_attempts_cost_usd
        unattributed = self.unattributed_cost_usd
        # ``segments`` forces the authoritative-total block: a resumed
        # run's ledger must always state the whole-run spend, even
        # when this segment ran without a budget client.
        if (failed or unattributed or self._total_spend_usd is not None
                or self.segments):
            totals["failed_attempts_cost_usd"] = round(failed, 4)
            totals["unattributed_cost_usd"] = round(unattributed, 4)
            totals["total_spend_usd"] = round(self.total_spend_usd, 4)
        out: dict[str, Any] = {
            "phases": {k: v.to_dict() for k, v in sorted(self.phases.items())},
            "totals": totals,
        }
        if self.segments:
            out["segments"] = list(self.segments)
        return out

    def write(self, out_dir: Path) -> Path:
        """Write cost-breakdown.json to the run directory."""
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "cost-breakdown.json"
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        return path

    def summary(self) -> str:
        """One-line summary of total cost."""
        parts: list[str] = []
        for name in self._KNOWN_PHASES:
            if name in self.phases:
                pc = self.phases[name]
                if pc.calls > 0:
                    parts.append(f"{name}={pc.calls}calls/${pc.cost_usd:.2f}")
        # Phases outside the known set — call classes booked by
        # book_unbooked_classes and any future ad-hoc phase names.
        for name in sorted(self.phases):
            if name in self._KNOWN_PHASES:
                continue
            pc = self.phases[name]
            if pc.calls > 0:
                parts.append(f"{name}={pc.calls}calls/${pc.cost_usd:.2f}")
        # Failed/timed-out spend and unattributed residual are DIFFERENT
        # things — the residual is usually spend from successful calls
        # no phase captured, and labelling it "failed/timed-out" (as a
        # single lumped figure once did) misreports healthy runs.
        failed = self.total_failed_attempts_cost_usd
        if failed > 0:
            parts.append(f"failed/timed-out=${failed:.2f}")
        unattributed = self.unattributed_cost_usd
        if unattributed >= 0.005:
            parts.append(f"unattributed=${unattributed:.2f}")
        total = self.total_spend_usd
        return f"cost: ${total:.2f} ({', '.join(parts)})"

    def phase_summary(self) -> str:
        """Multi-line breakdown by phase."""
        lines = ["## Cost breakdown"]
        for name in sorted(self.phases):
            pc = self.phases[name]
            line = (
                f"- **{name}**: {pc.calls} calls, "
                f"${pc.cost_usd:.4f}, "
                f"{pc.wall_time_s:.1f}s wall"
            )
            if pc.failed_calls or pc.failed_attempts_cost_usd:
                line += (
                    f" (+{pc.failed_calls} failed attempts, "
                    f"${pc.failed_attempts_cost_usd:.4f})"
                )
            lines.append(line)
        lines.append(
            f"\n**Total**: {self.total_calls} calls, "
            f"${self.total_cost_usd:.4f}, "
            f"{self.total_wall_time_s:.1f}s wall"
        )
        failed = self.total_failed_attempts_cost_usd
        unattributed = self.unattributed_cost_usd
        if failed > 0 or unattributed >= 0.005:
            detail: list[str] = []
            if failed > 0:
                detail.append(
                    f"${failed:.4f} on failed/timed-out attempts"
                )
            if unattributed >= 0.005:
                detail.append(f"${unattributed:.4f} unattributed")
            lines.append(
                f"**Total spend**: ${self.total_spend_usd:.4f} "
                f"({'; '.join(detail)})"
            )
        cr = self.total_cache_read_tokens
        cw = self.total_cache_write_tokens
        if cr or cw:
            lines.append(
                f"**Prompt cache**: {cr:,} read, {cw:,} written"
            )
        return "\n".join(lines)


def format_cost_summary(result: Any) -> str | None:
    """Operator-facing "Cost:" line for the end-of-run summary.

    One number with its own explanation: total spend (the LLM client's
    ledger, which includes failed/timed-out attempts) with the
    completed-vs-failed split when they differ, e.g.::

        Cost: $8.08 ($2.82 across 3 completed reviews; $5.26 on
        failed/timed-out attempts)

    Returns None when the run spent nothing (no line printed).
    Duck-typed over OrchestratorResult so the CLI shim stays thin.
    """
    completed_cost = getattr(result, "total_cost_usd", 0.0) or 0.0
    failed_cost = getattr(result, "failed_attempts_cost_usd", 0.0) or 0.0
    total_spend = max(
        getattr(result, "llm_spend_usd", 0.0) or 0.0,
        completed_cost + failed_cost,
    )
    if total_spend <= 0:
        return None
    # Spend the client billed beyond completed outcomes splits into
    # KNOWN failed-attempt spend and the unattributed residual. The
    # residual is typically successful call classes no outcome carried
    # (audit/iris/summary support calls) — labelling it "failed/
    # timed-out" (as the pre-fix single lump did) misreported healthy
    # runs whose telemetry showed zero failures.
    failed_spend = min(failed_cost, total_spend)
    other_spend = max(0.0, total_spend - completed_cost - failed_spend)
    detail: list[str] = []
    if failed_spend >= 0.005:
        detail.append(f"${failed_spend:.2f} on failed/timed-out attempts")
    if other_spend >= 0.005:
        detail.append(
            f"${other_spend:.2f} on unattributed calls "
            f"(see cost-breakdown.json)"
        )
    if not detail:
        return f"Cost: ${total_spend:.2f}"
    completed_reviews = max(
        0,
        (getattr(result, "reviewed", 0) or 0)
        - (getattr(result, "errors", 0) or 0),
    )
    noun = "review" if completed_reviews == 1 else "reviews"
    return (
        f"Cost: ${total_spend:.2f} (${completed_cost:.2f} across "
        f"{completed_reviews} completed {noun}; {'; '.join(detail)})"
    )
