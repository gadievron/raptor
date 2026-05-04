"""macOS audit-mode log capture.

When ``--audit`` is engaged on macOS, the SBPL profile uses
``(allow file-write* (with report))`` — the write succeeds AND the
kernel Sandbox.kext emits an entry to the unified log. This module
streams those entries live via ``log stream``, parses them, and
appends RAPTOR-format records to ``<run_dir>/.sandbox-denials.jsonl``
— matching the JSONL schema produced by the Linux ptrace tracer so
the existing ``summarize_and_write`` aggregation works unchanged.

Spike-validated facts (see scripts/macos_sandbox_spike4.py):

  * Sandbox kext entries have ``subsystem=""`` and ``category=""`` —
    cannot filter on those.
  * The reliable filter is ``senderImagePath ==
    "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"``.
  * eventMessage format:
        ``Sandbox: <ProcessName>(<PID>) <verdict> <action> <path>``
    where verdict ∈ {allow, deny} and action is e.g. file-write-create,
    file-read-data, network-outbound.

Threading: the streamer runs as a daemon thread that reads
``log stream`` ndjson output line-by-line. Daemon=True so it doesn't
block process shutdown. ``stop()`` terminates the underlying
subprocess.

Per-call lifecycle: caller in _macos_spawn starts the streamer just
before running the sandboxed workload and stops it after. The brief
warm-up window is acceptable — sandbox events arrive within tens of
milliseconds of the workload's syscall, well within the post-workload
drain period.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .seatbelt import SANDBOX_KEXT_SENDER

logger = logging.getLogger(__name__)


# Filename matches the Linux tracer convention so summarize_and_write
# in summary.py picks it up unchanged.
DENIALS_FILE = ".sandbox-denials.jsonl"


# Skip-budget delegated to core.sandbox.audit_budget.AuditBudget,
# which is shared with the Linux ptrace tracer so the two backends
# stay in sync. See that module for the full mechanism (token-bucket
# + per-category + per-PID + 1-in-N sampling + CLI override).
from . import audit_budget as _audit_budget


# Sandbox kext eventMessage format. Spike #4 confirmed:
#   "Sandbox: <ProcessName>(<PID>) <verdict> <action> <path>"
# verdict ∈ {allow, deny}; action is file-* / network-* / etc.
_LOG_LINE_RE = re.compile(
    r"Sandbox:\s+(\S+)\((\d+)\)\s+(allow|deny)\s+(\S+)\s+(.+)$"
)


# Map SBPL action prefixes to the RAPTOR sandbox-summary type taxonomy
# (matches Linux tracer's _NAME_TO_TYPE mapping).
def _action_to_type(action: str) -> str:
    if action.startswith("file-write") or action.startswith("file-mknod"):
        return "write"
    if action.startswith("file-read"):
        return "read"
    if action.startswith("network"):
        return "network"
    # mach-lookup, iokit-open, sysctl-*, process-*, etc.
    return "seccomp"  # closest analogue in the Linux taxonomy


def parse_log_entry(entry: dict) -> Optional[dict]:
    """Convert a `log stream` ndjson entry to a RAPTOR audit record.

    Returns None if the entry isn't a recognisable Sandbox.kext
    message (silently dropped — many kext entries pass through and
    aren't meaningful audit events).
    """
    if entry.get("senderImagePath") != SANDBOX_KEXT_SENDER:
        return None
    msg = entry.get("eventMessage", "")
    m = _LOG_LINE_RE.search(msg)
    if not m:
        return None
    process_name, pid, verdict, action, path = m.groups()
    return {
        "ts": entry.get("timestamp") or _now_iso(),
        "cmd": f"<sandbox audit: {action} {path}>",
        "returncode": 0,
        "type": _action_to_type(action),
        "audit": True,
        "verdict": verdict,           # allow | deny — present here, absent in Linux records
        "syscall": action,            # field name matches Linux for compatibility
        "path": path,
        "target_pid": int(pid),
        "process_name": process_name,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LogStreamer:
    """Background log-stream subprocess feeding parsed audit records
    into ``run_dir/.sandbox-denials.jsonl``.

    Owned by ``_macos_spawn.run_sandboxed`` for the duration of one
    sandboxed call. NOT a singleton — a fresh streamer per sandbox()
    call, so concurrent sandboxes don't conflict on filtering /
    routing of records. Slight overhead (one log-stream subprocess
    per call) but each is cheap (~10MB resident, ~0 CPU when idle).
    """

    def __init__(self, run_dir: Path,
                 budget: Optional["_audit_budget.AuditBudget"] = None):
        self._run_dir = Path(run_dir)
        self._proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._stopped = threading.Event()
        # Skip-budget — defaults to the CLI-aware factory so
        # --audit-budget propagates without callers wiring it
        # explicitly. Tests can pass a custom AuditBudget for
        # deterministic clock + smaller caps.
        self._budget = budget or _audit_budget.from_cli_state()
        # Serialises _append_record() across the reader-thread
        # writes and the parent-thread summary write at stop().
        # O_APPEND atomicity guarantees no inter-line tearing at the
        # kernel for sub-PIPE_BUF writes, but doesn't guarantee
        # ORDERING between the two threads — the parent's summary
        # could land before residual data records the reader is
        # still draining. Lock makes the summary unambiguously the
        # last write. AuditBudget itself is also single-writer
        # (it's mutated only inside the held lock).
        self._append_lock = threading.Lock()
        # Lazily-opened directory fd for openat(). See
        # _append_record_locked for the TOCTOU rationale.
        self._dirfd: Optional[int] = None

    def start(self) -> None:
        """Spawn `log stream` filtered to sandbox kext events and
        start the reader thread. Non-blocking; returns immediately
        once the subprocess is launched."""
        predicate = (
            f'senderImagePath == "{SANDBOX_KEXT_SENDER}"'
        )
        self._proc = subprocess.Popen(
            [
                "/usr/bin/log", "stream",
                "--predicate", predicate,
                "--style", "ndjson",
                "--info",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            # Buffering: line-buffered so we get records as they
            # arrive rather than accumulating in a 4K pipe buffer.
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """Read ndjson lines from `log stream`, parse, and append
        records to the JSONL. Robust to malformed lines (silently
        skip)."""
        try:
            assert self._proc is not None
            for raw_line in self._proc.stdout or ():
                if self._stopped.is_set():
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                record = parse_log_entry(entry)
                if record is None:
                    continue
                # Defer all budget logic to AuditBudget.evaluate.
                # Returns (KEEP|DROP, optional marker dict). Marker
                # is appended FIRST so it lands in the JSONL right
                # before the (or not, if dropped) original record —
                # operators see the suppression in-line.
                #
                # Hold the append lock across budget.evaluate AND
                # the marker/record appends so:
                #   (a) summary_record() called from stop() on the
                #       parent thread sees a consistent snapshot of
                #       budget internals (no "dict changed size
                #       during iteration").
                #   (b) the marker lands in the JSONL immediately
                #       before its associated record without another
                #       writer slipping a record in between.
                try:
                    with self._append_lock:
                        decision, marker = self._budget.evaluate(
                            record["syscall"], record["target_pid"],
                        )
                        if marker is not None:
                            self._append_record_locked(marker)
                        if decision != _audit_budget.DROP:
                            self._append_record_locked(record)
                except OSError:
                    # Best-effort. Don't crash the reader thread on
                    # transient FS errors — a missed record is
                    # acceptable, a dead reader thread is not.
                    logger.debug("seatbelt audit append failed",
                                 exc_info=True)
        except Exception:
            logger.debug("seatbelt audit reader thread crashed",
                         exc_info=True)

    def _append_record(self, record: dict) -> None:
        """Append one record to the JSONL using the same O_NOFOLLOW
        + O_APPEND atomicity dance as core.sandbox.summary.record_denial.
        Each line is one JSON object; under PIPE_BUF (~4KB) the kernel
        guarantees write atomicity against concurrent appenders. The
        in-process lock serialises ORDERING between the reader thread
        and the parent's summary write at stop()."""
        with self._append_lock:
            self._append_record_locked(record)

    def _append_record_locked(self, record: dict) -> None:
        """Real append logic. Called with self._append_lock held.

        Uses an O_DIRECTORY|O_NOFOLLOW dirfd cached at first call
        and an `openat(dirfd, DENIALS_FILE, ...)` for each append.
        Without the dirfd, an attacker who can write to run_dir's
        parent could swap run_dir with a symlink between
        `mkdir(...)` and `open(...)` (TOCTOU) and redirect audit
        records into a host file. The dirfd is opened once, before
        any writes, and survives any later replacement of the
        path-to-the-directory.
        """
        line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        if self._dirfd is None:
            # First call: materialise run_dir AND pin it as a dirfd.
            self._run_dir.mkdir(parents=True, exist_ok=True)
            self._dirfd = os.open(
                str(self._run_dir),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        fd = os.open(DENIALS_FILE, flags, mode=0o600,
                     dir_fd=self._dirfd)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

    def stop(self, *, drain_timeout: float = 1.5) -> None:
        """Stop the streamer. Gives `log stream` a brief window to
        flush any in-flight records, then terminates.

        Called by _macos_spawn after the workload exits. The drain
        window matters: kernel → log subsystem → log stream pipeline
        has visible latency (spike #4 measured ~1.5s for a cold
        first event); without the drain we'd lose the tail-end
        records of short workloads.
        """
        self._stopped.set()
        if self._proc is not None:
            # Give the reader a brief window to consume any buffered
            # output before we kill the subprocess.
            self._proc.terminate()
            try:
                self._proc.wait(timeout=drain_timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                try:
                    self._proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            # Reader thread is daemon — if it's still draining stdout,
            # let it finish naturally; we don't block process exit on it.
            if self._reader is not None and self._reader.is_alive():
                self._reader.join(timeout=0.5)
        # Final summary record. Always emitted regardless of proc
        # state so operators see one of:
        #   - 0 records, 0 drops → audit ran cleanly, nothing to log
        #   - N records, 0 drops → audit ran, captured everything
        #   - N records, K drops → audit ran, K events suppressed by cap
        # The alternative (no summary on cold-start failure) makes
        # "did audit run?" undecidable from the JSONL alone. Even
        # the never-started case (no proc) emits a summary with
        # zero counts — operators can distinguish it from
        # "summary file missing entirely" (streamer never even
        # constructed).
        try:
            # Hold the lock across summary_record + append so the
            # snapshot read and the JSONL write are atomic with
            # respect to any reader thread still draining.
            with self._append_lock:
                summary = self._budget.summary_record()
                self._append_record_locked(summary)
        except OSError:
            logger.debug("seatbelt audit summary append failed",
                         exc_info=True)
        # Close the cached dirfd. Best-effort — fd leaks on
        # daemon-thread paths are bounded by the per-process fd
        # limit, but keeping process exit clean here avoids
        # ResourceWarnings in test runs.
        with self._append_lock:
            if self._dirfd is not None:
                try:
                    os.close(self._dirfd)
                except OSError:
                    pass
                self._dirfd = None


def start_log_streamer(run_dir: Path) -> LogStreamer:
    """Convenience: instantiate + start a LogStreamer.

    Caller is responsible for calling ``.stop()`` after the
    sandboxed workload exits. Use a try/finally to guarantee
    cleanup (see _macos_spawn for the canonical pattern).
    """
    s = LogStreamer(run_dir)
    s.start()
    return s
