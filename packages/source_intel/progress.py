"""Operator-facing progress for long cocci (spatch) runs.

A source_intel ``analyze()`` on a large C target runs dozens of spatch
invocations, each potentially minutes long — historically with ZERO
output in between (the openssh audit's enrichment pass sat >300s
silent on a 543-file target). This module provides the one printer the
CLI wrappers share:

* one ``[done+1/total] cocci <rule> ...`` line as each rule starts
  (house progress-line shape: leading two-space indent, ``[i/N]``
  counter), and
* a heartbeat line when NOTHING has been printed for
  ``heartbeat_interval_s`` (default 30s) — a single rule can hold
  spatch for its full per-rule timeout, so per-rule lines alone can
  leave minutes of silence.

No spam by construction: rule lines are bounded by the rule count and
the heartbeat only fires while the stream is otherwise idle.
"""

from __future__ import annotations

import threading
import time
from typing import Any

__all__ = ["RuleProgressPrinter"]


class RuleProgressPrinter:
    """Prints per-rule progress lines plus an idle heartbeat.

    Use as a context manager; pass the bound :meth:`on_rule` as the
    ``progress`` callback of :func:`packages.source_intel.analyze.analyze`::

        with RuleProgressPrinter(sys.stderr, label="cocci") as prog:
            analyze(target, progress=prog.on_rule)

    ``stream`` only needs a ``write`` method (``print(file=...)``
    compatible). All printing failures are the caller's — the analyze
    runner already swallows callback exceptions.
    """

    def __init__(
        self,
        stream: Any,
        *,
        label: str = "cocci",
        heartbeat_interval_s: float = 30.0,
        poll_interval_s: float = 5.0,
    ) -> None:
        self._stream = stream
        self._label = label
        self._heartbeat_interval_s = heartbeat_interval_s
        self._poll_interval_s = poll_interval_s
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at = time.monotonic()
        self._last_line_at = time.monotonic()
        self._current_rule = ""

    # ── context manager ──────────────────────────────────────────────

    def __enter__(self) -> RuleProgressPrinter:
        self._started_at = time.monotonic()
        self._last_line_at = self._started_at
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name="cocci-progress-heartbeat",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval_s + 1)
            self._thread = None

    # ── callbacks ────────────────────────────────────────────────────

    def on_rule(self, done: int, total: int, rule_name: str) -> None:
        """``analyze(progress=...)`` callback — one line per rule start."""
        with self._lock:
            self._current_rule = rule_name
            self._last_line_at = time.monotonic()
        self._emit(f"  [{done + 1}/{total}] {self._label} {rule_name} ...")

    # ── internals ────────────────────────────────────────────────────

    def _emit(self, line: str) -> None:
        print(line, file=self._stream, flush=True)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self._poll_interval_s):
            now = time.monotonic()
            with self._lock:
                idle = now - self._last_line_at
                current = self._current_rule
                if idle < self._heartbeat_interval_s:
                    continue
                self._last_line_at = now
            elapsed = int(now - self._started_at)
            suffix = f", current rule: {current}" if current else ""
            self._emit(
                f"  {self._label}: still running "
                f"({elapsed}s elapsed{suffix})"
            )
