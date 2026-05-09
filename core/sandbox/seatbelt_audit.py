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
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .seatbelt import SANDBOX_KEXT_SENDER

logger = logging.getLogger(__name__)


# Filename matches the Linux tracer convention so summarize_and_write
# in summary.py picks it up unchanged.
DENIALS_FILE = ".sandbox-denials.jsonl"

# Observe-mode JSONL — the macOS analogue of
# core.sandbox.tracer._OBSERVE_FILENAME. When the streamer is engaged
# for profile-extraction (sandbox(observe=True) on macOS), records go
# here instead of DENIALS_FILE so:
#   * the denial-summary aggregator (summarize_and_write) doesn't
#     misinterpret observation events as enforcement events;
#   * core.sandbox.observe_profile.parse_observe_log finds the
#     records in the same place it does on Linux.
# Constant duplicated (not imported) so this module stays free of the
# tracer's ctypes/seccomp graph; test_seatbelt_observe.py pins the two
# values together against tracer._OBSERVE_FILENAME.
OBSERVE_FILE = ".sandbox-observe.jsonl"

# Wall-clock cap on the warm-up gate in `start()`. The gate spawns a
# synthetic `sandbox-exec` workload and waits for `log stream` to emit
# the resulting kext deny event — that's the deterministic signal that
# attachment to the kernel log feed is live. The warm-up exits in
# 50-200ms on a warm `log` daemon; cold-start (first invocation in a
# shell) runs longer. 5s is generous enough that healthy systems never
# trip it, tight enough that a wedged log subsystem doesn't block
# sandbox spawn indefinitely.
_WARM_UP_TIMEOUT_S = 5.0

# SBPL profile for the warm-up workload. ``(deny default (with
# report))`` denies every operation AND emits a kext audit event for
# each denial. The first thing the kernel does after applying the
# profile is the loader's image-read for the target binary — that
# generates a deny event with the warm-up's PID, which is what we
# wait for. The workload itself never runs (exec is denied), which
# keeps the warm-up cheap and side-effect-free.
_WARM_UP_SBPL = "(version 1)(deny default (with report))"

# Path to the system sandbox-exec binary. Resolved via shutil.which at
# call site so a non-standard PATH (operator override) works, falling
# back to the canonical /usr/bin location that ships with macOS.
_SANDBOX_EXEC_FALLBACK = "/usr/bin/sandbox-exec"


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


def parse_log_entry(entry: dict, *,
                    observe_mode: bool = False,
                    nonce: Optional[str] = None) -> Optional[dict]:
    """Convert a `log stream` ndjson entry to a RAPTOR audit record.

    Returns None if the entry isn't a recognisable Sandbox.kext
    message (silently dropped — many kext entries pass through and
    aren't meaningful audit events).

    `observe_mode`: stamp the record with ``"observe": True`` instead
    of ``"audit": True`` so a downstream parser can tell observation
    runs apart from enforcement runs. Mirrors the
    Linux-tracer convention (core.sandbox.tracer._resolve_record_mode_field).

    `nonce`: when set, included in the record as the ``"nonce"``
    field — the parser drops records without a matching value so a
    target binary that wrote into the bind-mounted JSONL can't spoof
    runtime evidence. Generated by the parent and passed via the
    LogStreamer constructor; the streamer reads it from process
    state, never from the JSONL itself, so the target cannot
    forge a record that survives parser validation.
    """
    if entry.get("senderImagePath") != SANDBOX_KEXT_SENDER:
        return None
    msg = entry.get("eventMessage", "")
    m = _LOG_LINE_RE.search(msg)
    if not m:
        return None
    process_name, pid, verdict, action, path = m.groups()
    record = {
        "ts": entry.get("timestamp") or _now_iso(),
        "cmd": f"<sandbox audit: {action} {path}>",
        "returncode": 0,
        "type": _action_to_type(action),
        "verdict": verdict,           # allow | deny — present here, absent in Linux records
        "syscall": action,            # field name matches Linux for compatibility
        "path": path,
        "target_pid": int(pid),
        "process_name": process_name,
    }
    record["observe" if observe_mode else "audit"] = True
    if nonce is not None:
        record["nonce"] = nonce
    return record


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
                 budget: Optional["_audit_budget.AuditBudget"] = None,
                 *, observe_mode: bool = False,
                 observe_nonce: Optional[str] = None):
        self._run_dir = Path(run_dir)
        self._proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._stopped = threading.Event()
        # Per-run provenance secret — included in every record so the
        # parser can drop spoofed entries written by the target
        # binary into the bind-mounted JSONL. Held in process state
        # only; never written anywhere the target binary can read.
        self._observe_nonce = observe_nonce
        # Observe-mode routing: pick the JSONL filename + record stamp
        # field once at construction so the per-record write path uses
        # the same destination as the parent's eventual summary append.
        # Defaults preserve audit-mode behaviour.
        self._observe_mode = bool(observe_mode)
        self._filename = OBSERVE_FILE if self._observe_mode else DENIALS_FILE
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
        """Spawn `log stream` filtered to sandbox kext events, gate
        on a synthetic warm-up workload to confirm attachment to the
        kernel log feed, then start the reader thread.

        The warm-up runs ``sandbox-exec`` against a deny-default SBPL
        profile and waits until ``log stream`` emits a kext record
        whose PID matches the warm-up child. This is the deterministic
        signal that the kernel-side filter is live — without it, fast
        workloads (e.g. ``claude --version`` finishing in tens of ms)
        can complete before ``log stream`` attaches, producing zero
        captured records on cold-start.

        On hosts where ``sandbox-exec`` is missing (non-Darwin or
        stripped installs) or the warm-up times out, falls back to a
        best-effort proceed: the streamer is started anyway, callers
        accept that early events may be missed. Logged at debug for
        operator triage."""
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
        try:
            attached = self._warm_up_until_attached()
            if not attached:
                logger.debug(
                    "seatbelt audit: warm-up gate did not see kext events "
                    "from synthetic workload within %ss; proceeding in "
                    "best-effort mode (early records from the real "
                    "workload may be missed)",
                    _WARM_UP_TIMEOUT_S,
                )
        except BaseException:
            # Warm-up itself raised: tear down `log stream` so caller
            # doesn't leak a zombie subprocess with nobody reading it.
            try:
                self._proc.terminate()
            except OSError:
                pass
            raise
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _warm_up_until_attached(self) -> bool:
        """Spawn a synthetic ``sandbox-exec`` workload and drain
        ``log stream`` stdout until we see a kext record from that
        workload's PID. Returns True when attachment is confirmed,
        False when the timeout elapsed without a matching record.

        The warm-up exits on its own (the deny-default profile blocks
        the loader's image read, so ``sandbox-exec`` returns non-zero
        in <50ms). We never read its output — the kernel emits the
        kext event regardless, and that's all we need.

        Records consumed during the warm-up gate are intentionally
        discarded: they belong to the warm-up's own PID or to other
        unrelated sandboxed processes running on the host, not to
        the real workload. The reader thread starts fresh after
        return, so caller-relevant events flow through ``_read_loop``
        as designed.
        """
        import selectors as _selectors

        sandbox_exec = (
            shutil.which("sandbox-exec") or _SANDBOX_EXEC_FALLBACK
        )
        if not Path(sandbox_exec).exists():
            # Non-Darwin host or stripped install — no point spawning
            # a missing binary. Best-effort fallback applies.
            return False

        try:
            warm_up = subprocess.Popen(
                [
                    sandbox_exec, "-p", _WARM_UP_SBPL,
                    "/usr/bin/true",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return False

        target_pid = warm_up.pid

        assert self._proc is not None
        if self._proc.stdout is None:
            try:
                warm_up.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                warm_up.terminate()
            return False

        sel = _selectors.DefaultSelector()
        sel.register(self._proc.stdout, _selectors.EVENT_READ)
        deadline = time.monotonic() + _WARM_UP_TIMEOUT_S
        seen = False
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                events = sel.select(timeout=remaining)
                if not events:
                    break
                line = self._proc.stdout.readline()
                if not line:
                    # `log stream` died — let caller handle in
                    # best-effort fallback.
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = entry.get("eventMessage", "")
                m = _LOG_LINE_RE.search(msg)
                if not m:
                    continue
                # Group 2 is the PID per `_LOG_LINE_RE`.
                pid_str = m.group(2)
                try:
                    if int(pid_str) == target_pid:
                        seen = True
                        break
                except ValueError:
                    continue
        finally:
            sel.unregister(self._proc.stdout)
            # Reap the warm-up child. With (deny default) the exec
            # itself is denied, so sandbox-exec exits ~immediately
            # with non-zero. Wait briefly; terminate as a safety net.
            try:
                warm_up.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    warm_up.terminate()
                except OSError:
                    pass
                try:
                    warm_up.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass

        return seen

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
                record = parse_log_entry(
                    entry,
                    observe_mode=self._observe_mode,
                    nonce=self._observe_nonce,
                )
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
        fd = os.open(self._filename, flags, mode=0o600,
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
                # Stamp nonce on the summary so an observe-mode
                # parser attributes it to this run and rejects one
                # spoofed by a target binary writing a fake summary
                # into the JSONL.
                if self._observe_nonce is not None:
                    summary["nonce"] = self._observe_nonce
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


def start_log_streamer(run_dir: Path, *,
                       observe_mode: bool = False,
                       observe_nonce: Optional[str] = None,
                       ) -> LogStreamer:
    """Convenience: instantiate + start a LogStreamer.

    Caller is responsible for calling ``.stop()`` after the
    sandboxed workload exits. Use a try/finally to guarantee
    cleanup (see _macos_spawn for the canonical pattern).

    `observe_mode`: when True, the streamer routes records to
    OBSERVE_FILE (.sandbox-observe.jsonl) with `"observe": True`
    stamps instead of DENIALS_FILE / `"audit": True`. Used by
    sandbox(observe=True) on macOS for profile-extraction probes.

    `observe_nonce`: per-run provenance secret stamped on every
    record. Pass the same value to parse_observe_log(expected_nonce)
    so spoofed records (written by the target into the bind-mounted
    JSONL) get dropped. Generated by core.sandbox.context.
    """
    s = LogStreamer(run_dir, observe_mode=observe_mode,
                    observe_nonce=observe_nonce)
    s.start()
    return s
