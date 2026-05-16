"""Real-time fuzzing telemetry.

Streams events from a fuzzing campaign so the operator can see what's
happening as it happens: payloads generated, executions run, paths
discovered, crashes found, coverage progression, plateau detection.

Two consumers:
  - Live terminal output (a status line that refreshes in place,
    plus per-event log lines for significant events).
  - Persistent JSONL on disk for the UI / post-mortem analysis.

Designed to be cheap. Recording an event is a dict append plus a single
file write; the periodic status line is rate-limited.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TextIO

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event types -- the schema for what a fuzzer can emit
# ---------------------------------------------------------------------------

@dataclass
class FuzzEvent:
    """A single telemetry event."""

    kind: str                  # campaign_start | exec_stat | crash | timeout | oom |
                               # path_new | coverage_update | corpus_grow |
                               # payload_generated | plateau | campaign_end
    timestamp: float           # epoch seconds
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "ts": self.timestamp, **self.payload}


@dataclass
class CampaignStats:
    """Cumulative campaign stats. Updated whenever the fuzzer reports."""

    fuzzer: str = ""
    target: str = ""
    started: float = 0.0
    last_update: float = 0.0
    duration_s: float = 0.0

    total_executions: int = 0
    executions_per_second: int = 0
    paths_found: int = 0
    coverage_features: int = 0
    coverage_percent: float = 0.0
    corpus_size: int = 0

    crashes: int = 0
    timeouts: int = 0
    oom_events: int = 0

    # LLM payload generation stats
    payloads_generated: int = 0
    payloads_failed: int = 0
    last_payload_excerpt: str = ""

    # Plateau detection
    plateau_seconds: int = 0
    last_path_at: float = 0.0

    def update_from(self, **kwargs) -> None:
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
        self.last_update = time.time()
        self.duration_s = self.last_update - self.started if self.started else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------
# Reporter: writes a status line to a stream periodically
# ---------------------------------------------------------------------------


class StatusLineReporter:
    """Render a single-line status update to a TTY, refreshed in place.

    Fall back to a one-line-per-update mode when not attached to a TTY
    (CI logs, pipes) so the output stays sensible.
    """

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        refresh_interval_seconds: float = 2.0,
    ) -> None:
        self.stream = stream or sys.stderr
        self.refresh_interval = refresh_interval_seconds
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_render = 0.0

    def render(self, stats: CampaignStats, *, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_render < self.refresh_interval:
            return
        self._last_render = now

        line = self._format_line(stats)
        if self.is_tty:
            # \r returns to start of line; \x1b[K clears to end of line.
            # Together they let us repaint without scrolling.
            self.stream.write(f"\r\x1b[K{line}")
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    def finish(self, stats: CampaignStats) -> None:
        """Print the final state and end the status line cleanly."""
        line = self._format_line(stats)
        if self.is_tty:
            self.stream.write(f"\r\x1b[K{line}\n")
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    @staticmethod
    def _format_line(s: CampaignStats) -> str:
        parts = [
            f"[{s.fuzzer or '?':<9}]",
            f"{int(s.duration_s):>5}s",
            f"execs={_fmt_count(s.total_executions)}",
            f"{_fmt_count(s.executions_per_second)}/s",
            f"paths={s.paths_found}",
            f"cov={s.coverage_percent:.1f}%" if s.coverage_percent else f"feats={s.coverage_features}",
            f"corp={s.corpus_size}",
            f"crash={s.crashes}",
        ]
        if s.timeouts:
            parts.append(f"to={s.timeouts}")
        if s.oom_events:
            parts.append(f"oom={s.oom_events}")
        if s.payloads_generated:
            parts.append(f"llm={s.payloads_generated}")
        if s.plateau_seconds > 60:
            parts.append(f"plateau={s.plateau_seconds}s")
        return " ".join(parts)


def _fmt_count(n: int) -> str:
    """Compact human count: 12345 -> '12.3k', 1234567 -> '1.2M'."""
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.1f}M"
    return f"{n / 1_000_000_000:.1f}G"


# ---------------------------------------------------------------------------
# Telemetry: the central event sink
# ---------------------------------------------------------------------------


class FuzzingTelemetry:
    """Thread-safe event recorder + status reporter.

    Usage:
        tel = FuzzingTelemetry(out_dir=run_dir, fuzzer='afl', target='/path/to/bin')
        tel.start()                                        # opens jsonl, prints campaign_start
        tel.record_payload("...", source="llm")            # before each payload test
        tel.update_stats(total_executions=12345, ...)      # called by the runner loop
        tel.record_crash("/path/to/crash-001", "SIGSEGV")  # on crash
        tel.stop()                                         # close out, print summary
    """

    def __init__(
        self,
        out_dir: Path,
        fuzzer: str = "",
        target: str = "",
        refresh_interval_seconds: float = 2.0,
        plateau_threshold_seconds: int = 300,
        on_event: Optional[Callable[[FuzzEvent], None]] = None,
    ) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.out_dir / "fuzz-events.jsonl"
        self.summary_path = self.out_dir / "fuzz-summary.json"

        self._lock = threading.Lock()
        self._events_fp: Optional[TextIO] = None
        self._reporter = StatusLineReporter(
            refresh_interval_seconds=refresh_interval_seconds
        )

        self.stats = CampaignStats(fuzzer=fuzzer, target=target)
        self.plateau_threshold = plateau_threshold_seconds
        self.on_event = on_event
        self._significant_event_kinds = {
            "campaign_start", "campaign_end",
            "crash", "timeout", "oom",
            "plateau", "first_path", "fuzzer_error",
        }
        self._announced_first_path = False

    def start(self) -> None:
        with self._lock:
            self.stats.started = time.time()
            self.stats.last_path_at = self.stats.started
            self._events_fp = self.events_path.open("a", buffering=1)
            self._emit(FuzzEvent(
                kind="campaign_start",
                timestamp=self.stats.started,
                payload={"fuzzer": self.stats.fuzzer, "target": self.stats.target},
            ))
            logger.info(
                f"Fuzzing campaign started: fuzzer={self.stats.fuzzer} "
                f"target={self.stats.target}"
            )

    def stop(self) -> None:
        with self._lock:
            self.stats.duration_s = time.time() - self.stats.started
            self._emit(FuzzEvent(
                kind="campaign_end",
                timestamp=time.time(),
                payload=self.stats.to_dict(),
            ))
            self._reporter.finish(self.stats)
            if self._events_fp:
                self._events_fp.close()
                self._events_fp = None
            self.summary_path.write_text(json.dumps(self.stats.to_dict(), indent=2, default=str))
            logger.info(
                f"Fuzzing campaign complete: {self.stats.duration_s:.1f}s, "
                f"{self.stats.total_executions} execs, "
                f"{self.stats.crashes} crashes, "
                f"{self.stats.paths_found} paths"
            )

    def record_payload(
        self,
        payload: bytes | str,
        *,
        source: str = "fuzzer",
        rationale: str = "",
    ) -> None:
        """Record that a payload was just generated/tested.

        For high-volume fuzzers this is called millions of times. We do
        not write each payload to disk, just count them and keep an
        excerpt of the most recent for live display.
        """
        with self._lock:
            self.stats.payloads_generated += 1
            if isinstance(payload, bytes):
                excerpt = payload[:64].hex()
            else:
                excerpt = str(payload)[:128]
            self.stats.last_payload_excerpt = excerpt
            # Only emit a per-payload event if explicitly LLM-generated
            # (high signal, low volume); skip for fuzzer-generated payloads
            # to avoid drowning the JSONL.
            if source == "llm":
                self._emit(FuzzEvent(
                    kind="payload_generated",
                    timestamp=time.time(),
                    payload={"source": source, "excerpt": excerpt, "rationale": rationale[:200]},
                ))

    def record_payload_failure(self, reason: str = "") -> None:
        with self._lock:
            self.stats.payloads_failed += 1

    def update_stats(self, **kwargs) -> None:
        """Update the cumulative stats. Triggers status line refresh."""
        with self._lock:
            old_paths = self.stats.paths_found
            self.stats.update_from(**kwargs)

            # First path -- significant event
            if old_paths == 0 and self.stats.paths_found > 0 and not self._announced_first_path:
                self._announced_first_path = True
                self._emit(FuzzEvent(
                    kind="first_path",
                    timestamp=time.time(),
                    payload={"after_seconds": self.stats.duration_s},
                ))

            # New paths reset plateau timer
            if self.stats.paths_found > old_paths:
                self.stats.last_path_at = time.time()

            # Plateau detection
            since_last = time.time() - self.stats.last_path_at
            self.stats.plateau_seconds = int(since_last)
            if since_last > self.plateau_threshold and since_last - self.stats.plateau_seconds < 1:
                self._emit(FuzzEvent(
                    kind="plateau",
                    timestamp=time.time(),
                    payload={"seconds": int(since_last)},
                ))

            # Lightweight stat event
            self._emit(FuzzEvent(
                kind="exec_stat",
                timestamp=time.time(),
                payload={
                    "total_executions": self.stats.total_executions,
                    "executions_per_second": self.stats.executions_per_second,
                    "paths_found": self.stats.paths_found,
                    "corpus_size": self.stats.corpus_size,
                },
            ), force_disk=False)

            self._reporter.render(self.stats)

    def record_crash(self, crash_path: str, signal: str = "") -> None:
        with self._lock:
            self.stats.crashes += 1
            self._emit(FuzzEvent(
                kind="crash",
                timestamp=time.time(),
                payload={"path": str(crash_path), "signal": signal},
            ))
            logger.warning(f"CRASH FOUND: {crash_path} ({signal})")

    def record_timeout(self, input_path: str = "") -> None:
        with self._lock:
            self.stats.timeouts += 1
            self._emit(FuzzEvent(
                kind="timeout",
                timestamp=time.time(),
                payload={"path": str(input_path)},
            ))

    def record_oom(self, input_path: str = "") -> None:
        with self._lock:
            self.stats.oom_events += 1
            self._emit(FuzzEvent(
                kind="oom",
                timestamp=time.time(),
                payload={"path": str(input_path)},
            ))

    def record_error(self, message: str) -> None:
        with self._lock:
            self._emit(FuzzEvent(
                kind="fuzzer_error",
                timestamp=time.time(),
                payload={"message": message[:500]},
            ))
            logger.error(f"Fuzzer error: {message}")

    def _emit(self, event: FuzzEvent, *, force_disk: bool = True) -> None:
        """Write to JSONL and call the optional callback. Caller holds the lock."""
        # Significant events: log line + disk
        is_significant = event.kind in self._significant_event_kinds
        if is_significant or force_disk:
            if self._events_fp:
                try:
                    self._events_fp.write(
                        json.dumps(event.to_dict(), default=str) + "\n"
                    )
                except Exception as e:
                    logger.debug(f"Telemetry write failed: {e}")
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    def snapshot(self) -> Dict[str, Any]:
        """Return the current stats snapshot (for the UI)."""
        with self._lock:
            return self.stats.to_dict()
