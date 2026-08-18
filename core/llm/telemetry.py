"""Per-call LLM telemetry — run-local JSONL + end-of-run summary.

One record per provider round-trip (successful call, failed attempt,
or cache hit), appended to ``llm-telemetry.jsonl`` in the run's output
directory. The record carries what the spend ledgers cannot: which
call class spent the time/money, how many attempts a call burned, how
timeouts were disposed of, and the cache-read/cache-write token counts
when the transport surfaces them — the raw data for measuring prompt
cache hit rates and retry policy effectiveness on real runs.

Design constraints:

* Zero coupling for callers: :func:`emit` is a no-op unless a sink is
  installed, so the LLM client can emit unconditionally and library
  consumers (tests, one-shot CLI calls) pay nothing.
* Never breaks the run: sink I/O failures are swallowed after a
  single warning. Telemetry is diagnostics, not control flow.
* Thread-safe: the audit executor calls the client from worker
  threads; records are single ``write()`` appends under a lock.

The orchestrator installs a sink at run start and logs
:meth:`TelemetrySink.summary_line` at run end.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TELEMETRY_FILENAME = "llm-telemetry.jsonl"


@dataclass
class _ClassStats:
    """Aggregated per-call-class counters."""

    calls: int = 0
    cache_hits: int = 0
    failed_attempts: int = 0
    timeouts: int = 0
    blocked: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class TelemetrySink:
    """Appends per-call records to a JSONL file and aggregates totals."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._write_failed = False
        self._by_class: dict[str, _ClassStats] = {}

    # ── Recording ─────────────────────────────────────────────────

    def record(self, rec: dict[str, Any]) -> None:
        """Append one record; update aggregates. Never raises."""
        rec.setdefault("ts", time.time())
        with self._lock:
            self._aggregate(rec)
            if self._write_failed:
                return
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(rec, separators=(",", ":"), default=str)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                # One warning, then stay silent — aggregation still
                # works so the end-of-run summary line survives a
                # read-only or vanished output directory.
                self._write_failed = True
                logger.warning(
                    "llm telemetry: append to %s failed — per-call "
                    "records disabled for this run",
                    self.path, exc_info=True,
                )

    def _aggregate(self, rec: dict[str, Any]) -> None:
        cls = str(rec.get("call_class") or "unclassified")
        st = self._by_class.setdefault(cls, _ClassStats())
        event = rec.get("event")
        if event == "attempt_failed":
            st.failed_attempts += 1
            if rec.get("disposition") == "timeout":
                st.timeouts += 1
            elif rec.get("disposition") == "blocked":
                st.blocked += 1
        elif rec.get("disposition") == "cache_hit":
            st.cache_hits += 1
        else:
            st.calls += 1
        st.cost_usd += float(rec.get("cost_usd") or 0.0)
        st.duration_s += float(rec.get("duration_s") or 0.0)
        st.tokens_in += int(rec.get("tokens_in") or 0)
        st.tokens_out += int(rec.get("tokens_out") or 0)
        st.cache_read_tokens += int(rec.get("cache_read_tokens") or 0)
        st.cache_write_tokens += int(rec.get("cache_write_tokens") or 0)

    # ── Reporting ─────────────────────────────────────────────────

    def mean_call_cost(self, call_class: str) -> float | None:
        """Mean cost of completed calls in ``call_class``, or None when
        the class has no completed calls yet. Feeds the LLM client's
        per-call budget reservation estimate (cache hits count no call
        and ~zero cost; failed attempts carry no ``cost_usd`` record —
        neither skews the mean)."""
        with self._lock:
            st = self._by_class.get(str(call_class))
            if st is None or st.calls <= 0:
                return None
            return st.cost_usd / st.calls

    def class_costs(self) -> dict[str, tuple[int, float]]:
        """Snapshot of per-class completed-call counts and spend:
        ``{call_class: (calls, cost_usd)}``. Used by end-of-run ledger
        reconciliation to book call classes no phase captured."""
        with self._lock:
            return {
                cls: (s.calls, s.cost_usd)
                for cls, s in self._by_class.items()
            }

    def total_cost_usd(self) -> float:
        """Total spend across every class (completed calls; failed
        attempts and cache hits contribute whatever ``cost_usd`` their
        records carried, usually zero)."""
        with self._lock:
            return sum(s.cost_usd for s in self._by_class.values())

    @property
    def total_records(self) -> int:
        with self._lock:
            return sum(
                s.calls + s.cache_hits + s.failed_attempts
                for s in self._by_class.values()
            )

    def summary_line(self) -> str:
        """Compact one-line rollup for the end-of-run log."""

        def _k(n: int) -> str:
            return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

        with self._lock:
            calls = sum(s.calls for s in self._by_class.values())
            hits = sum(s.cache_hits for s in self._by_class.values())
            failed = sum(s.failed_attempts for s in self._by_class.values())
            timeouts = sum(s.timeouts for s in self._by_class.values())
            blocked = sum(s.blocked for s in self._by_class.values())
            cost = sum(s.cost_usd for s in self._by_class.values())
            tin = sum(s.tokens_in for s in self._by_class.values())
            tout = sum(s.tokens_out for s in self._by_class.values())
            cread = sum(s.cache_read_tokens for s in self._by_class.values())
            cwrite = sum(s.cache_write_tokens for s in self._by_class.values())

            parts = [
                (f"llm telemetry: {calls} calls (${cost:.2f}, "
                 f"{_k(tin)} in / {_k(tout)} out)"),
            ]
            if cread or cwrite:
                parts.append(
                    f"cache {_k(cread)} read / {_k(cwrite)} written"
                )
            if hits:
                parts.append(f"{hits} local cache hits")
            if failed:
                breakdown = f"{timeouts} timeout"
                if blocked:
                    # Model refusals / content-filter blocks — a model
                    # boundary, not a transport failure. Called out
                    # separately so an operator reading the rollup
                    # sees "the model declined N calls" instead of
                    # lumping them in with retryable infrastructure
                    # noise.
                    breakdown += f", {blocked} blocked"
                parts.append(
                    f"{failed} failed attempts ({breakdown})"
                )
            per_class = ", ".join(
                f"{cls}={s.calls}/${s.cost_usd:.2f}"
                for cls, s in sorted(self._by_class.items())
                if s.calls
            )
            if per_class:
                parts.append(f"classes: {per_class}")
            return "; ".join(parts)


# ── Module-level sink registry ────────────────────────────────────────

_sink_lock = threading.Lock()
_sink: TelemetrySink | None = None


def set_sink(sink: TelemetrySink | None) -> None:
    """Install (or clear) the process-wide telemetry sink."""
    global _sink
    with _sink_lock:
        _sink = sink


def current_sink() -> TelemetrySink | None:
    return _sink


def emit(**fields: Any) -> None:
    """Record one telemetry event. No-op when no sink is installed.

    Never raises — telemetry must not alter LLM-call control flow.
    """
    sink = _sink
    if sink is None:
        return
    try:
        sink.record(dict(fields))
    except Exception:
        logger.debug("llm telemetry emit failed", exc_info=True)
