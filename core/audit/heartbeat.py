"""Best-effort progress heartbeat for long mechanical phases.

The mechanical phases (coccinelle sweeps, the census pre-passes, the
joern pre-sweep) can grind for hours without touching the run
directory, leaving operators nothing but ``/proc`` spelunking to tell
a live run from a wedged one. Instrumented loops call
:meth:`Heartbeat.beat` freely; the object throttles to at most one
write per :data:`HEARTBEAT_INTERVAL_S` and replaces
``<run_dir>/heartbeat.json`` atomically (tempfile + rename), so a
reader never sees a torn file and the hot loops never pay more than a
monotonic-clock read per call.

Strictly diagnostic: a write failure warns once per instance, the
instance disables itself, and the run is never affected. Not a
pipeline stage — phases that already loop just call ``beat`` from
inside the loop. Phases may overlap (the joern pre-sweep runs
concurrently with prep); each write is atomic and self-describing
(``phase`` names the writer), so the file always shows the most
recent activity from SOME live phase.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HEARTBEAT_FILENAME = "heartbeat.json"

# Throttle floor between writes. Not lower: beat() sits inside hot
# per-file/per-candidate loops (tens of thousands of iterations), and
# each write is a tempfile + fsync-less rename pair — sub-minute
# cadence would turn a diagnostic into steady run-dir churn (and
# needless writes on network/overlay filesystems). Not higher: the
# file exists so an operator can distinguish a live 10-hour phase
# from a hung one at a glance; multi-minute staleness makes "is it
# stuck?" ambiguous again, which is the exact question this answers.
HEARTBEAT_INTERVAL_S = 60.0

# Detail excerpt bound. Not lower: progress messages carry a file
# path plus a short verb and truncating mid-path removes the only
# useful content. Not higher: detail can echo per-item text from
# large trees, and heartbeat.json should stay a glanceable few
# hundred bytes, not an unbounded log line.
_MAX_DETAIL_CHARS = 200


class Heartbeat:
    """Throttled atomic writer of ``<run_dir>/heartbeat.json``.

    ``run_dir`` may be None/empty (no-op instance — callers never
    need their own guard). Thread-safe: parallel workers of one phase
    share an instance.
    """

    def __init__(
        self,
        run_dir: Path | str | None,
        phase: str,
        interval_s: float = HEARTBEAT_INTERVAL_S,
    ) -> None:
        self._dir: Path | None = Path(run_dir) if run_dir else None
        self.phase = phase
        self._interval_s = float(interval_s)
        self._lock = threading.Lock()
        self._last_write = 0.0  # monotonic; 0.0 = first beat writes
        self._failed = False

    def beat(
        self,
        done: int | None = None,
        total: int | None = None,
        detail: str | None = None,
    ) -> None:
        """Record progress (throttled; never raises, never blocks long).

        ``done``/``total`` are the phase's own counters (e.g. files
        swept / total); ``detail`` is an optional short free-text
        excerpt, truncated to a bounded length.
        """
        if self._dir is None or self._failed:
            return
        now = time.monotonic()
        with self._lock:
            if self._failed:
                return
            if self._last_write and (
                now - self._last_write < self._interval_s
            ):
                return
            payload: dict[str, Any] = {
                "phase": self.phase,
                "pid": os.getpid(),
                "timestamp": datetime.now(timezone.utc).isoformat(
                    timespec="seconds",
                ),
            }
            if done is not None:
                payload["done"] = int(done)
            if total is not None:
                payload["total"] = int(total)
            if detail:
                payload["detail"] = detail[:_MAX_DETAIL_CHARS]
            try:
                self._write(payload)
            except Exception:  # noqa: BLE001 — diagnostics never bite
                self._failed = True
                logger.warning(
                    "heartbeat write to %s failed — heartbeat disabled "
                    "for the %s phase (the run is unaffected)",
                    self._dir / HEARTBEAT_FILENAME, self.phase,
                    exc_info=True,
                )
                return
            self._last_write = now

    def _write(self, payload: dict[str, Any]) -> None:
        """Atomic replace: a reader sees the old file or the new one,
        never a torn write."""
        assert self._dir is not None
        target = self._dir / HEARTBEAT_FILENAME
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._dir), prefix=".heartbeat-", suffix=".tmp",
        )
        try:
            os.write(
                fd,
                (json.dumps(payload, sort_keys=True) + "\n").encode(
                    "utf-8",
                ),
            )
            os.close(fd)
            fd = -1
            os.replace(tmp_name, str(target))
        except BaseException:
            if fd >= 0:
                os.close(fd)
            _unlink_quietly(tmp_name)
            raise


def _unlink_quietly(path: str) -> None:
    """Best-effort unlink of a stranded tempfile."""
    try:
        os.unlink(path)
    except OSError:
        pass
