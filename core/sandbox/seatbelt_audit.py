"""macOS audit-mode log capture.

When ``--audit`` is engaged on macOS, the SBPL profile uses
``(allow file-write* (with report))`` — the write succeeds AND the
kernel Sandbox.kext emits an entry to the unified log. This module
streams those entries live via ``log stream``, parses them, and
appends RAPTOR-format records to the run's evidence directory —
``<run_dir>/.audit/.sandbox-denials.jsonl`` (see
core/sandbox/evidence.py) — matching the JSONL schema produced by the
Linux ptrace tracer so the existing ``summarize_and_write``
aggregation works unchanged. macOS records additionally carry a
``verdict`` field (``allow`` under the audit profile's
allow-with-report clauses, ``deny`` for genuine blocks);
``summarize_and_write`` counts only deny-verdict — or verdict-less
Linux — records as denials and buckets allow-verdict records into a
separate informational section. The seatbelt profile denies the target
all writes beneath ``<run_dir>/.audit`` (seatbelt.build_profile's
``audit_evidence_dir``), so only this parent-side streamer can touch
the file; appends go through a held fd whose inode is verified when
the streamer stops.

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
import time
from datetime import datetime, timezone
from pathlib import Path

from core.sandbox.escalation_signatures import is_credential_path
from core.security.log_sanitisation import sanitise_for_terminal

# Skip-budget delegated to core.sandbox.audit_budget.AuditBudget,
# which is shared with the Linux ptrace tracer so the two backends
# stay in sync. See that module for the full mechanism (token-bucket
# + per-category + per-PID + 1-in-N sampling + CLI override).
from . import audit_budget as _audit_budget
from . import evidence as _evidence_mod
from .seatbelt import SANDBOX_KEXT_SENDER

logger = logging.getLogger(__name__)


class AuditWarmUpError(RuntimeError):
    """The warm-up attachment gate could not confirm the log-stream
    feed is live and the caller demanded proof (warm_up_required=True
    — what _macos_spawn passes for audit_required runs). Raised from
    ``LogStreamer.start()`` so the fail-closed decision happens
    BEFORE the workload spawns."""


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

# Path to the system sandbox-exec binary. The warm-up resolves it via
# the trusted-dirs helper (probes._find_sandbox_binary) — never the
# inherited PATH — falling back to the canonical /usr/bin location
# that ships with macOS.
_SANDBOX_EXEC_FALLBACK = "/usr/bin/sandbox-exec"


# Sandbox kext eventMessage format. Spike #4 confirmed:
#   "Sandbox: <ProcessName>(<PID>) <verdict> <action> <path>"
# verdict ∈ {allow, deny}; action is file-* / network-* / etc.
# Tolerated variants beyond the spike's canonical shape:
#   * repeat-count verdicts — the kernel coalesces repeated events as
#     "deny(12) file-read-data ..." — matched and discarded via the
#     optional (?:\(\d+\)) group;
#   * process names containing spaces or parentheses ("Google Chrome
#     Helper (Renderer)") — the name is a non-greedy (.+?) anchored by
#     the "(<PID>) <verdict>" tail, so the LAST "(digits)" before the
#     verdict is always the PID.
# Pre-fix, both shapes silently failed the match and their records
# were dropped from the audit trail.
_LOG_LINE_RE = re.compile(
    r"Sandbox:\s+(.+?)\((\d+)\)\s+(allow|deny)(?:\(\d+\))?\s+(\S+)\s+(.+)$"
)

# Parse-ratio diagnostic thresholds (see LogStreamer.stop). When at
# least this many kext-sender lines were seen and fewer than this
# fraction parsed into records, emit a loud "parsed M of N" warning —
# the likely cause is a kernel eventMessage format drift that the
# regex above no longer matches.
_PARSE_DIAG_MIN_LINES = 10
_PARSE_DIAG_MIN_RATIO = 0.5

# Scope/lineage filter tunables (see LogStreamer's class docstring).
# The `log stream` predicate filters by kext SENDER only — records
# from EVERY sandboxed process on the host come through, so without
# a scoping gate a concurrent RAPTOR run (or a hostile same-host
# sandboxed process minting records that would steer an
# observe-derived allowlist) pollutes this run's JSONL with the
# run's own nonce stamped on.
#   * poll interval: the lineage poller snapshots the process tree so
#     descendants seen alive are still attributable when their kext
#     records arrive AFTER they exit (the kernel→log pipeline has
#     ~1.5s latency; short workloads routinely deliver post-exit).
#   * pending cap: records arriving between streamer start and the
#     first register_target_pid are buffered (bounded) and filtered
#     on registration.
#   * foreign cache cap: negative attribution results are memoised;
#     cleared wholesale past the cap so PID reuse cannot poison the
#     cache indefinitely.
_LINEAGE_POLL_INTERVAL_S = 0.2
_PENDING_BUFFER_CAP = 512
_FOREIGN_CACHE_CAP = 4096

# ppid-chain walk bound in the scope filter — defends against a
# cyclic/corrupt process-table probe ever looping the reader thread.
_LINEAGE_WALK_MAX = 64


def _default_get_ppid(pid: int) -> int | None:
    """Best-effort parent PID lookup. /proc on Linux; ps(1) fallback
    (macOS has no /proc). None when the process is gone or unreadable."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read().decode("utf-8", errors="replace")
        return int(data.rpartition(")")[2].split()[1])
    except (OSError, ValueError, IndexError):
        pass
    try:
        out = subprocess.run(
            ["ps", "-o", "ppid=", "-p", str(int(pid))],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout.strip()
        return int(out) if out else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _default_list_pid_ppids() -> list[tuple[int, int]]:
    """Best-effort (pid, ppid) snapshot of the whole process table.
    /proc scan on Linux; one ps(1) invocation elsewhere. Empty list on
    failure — the poller then contributes nothing this tick."""
    pairs: list[tuple[int, int]] = []
    try:
        entries = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        entries = []
    if entries:
        for d in entries:
            try:
                with open(f"/proc/{d}/stat", "rb") as fh:
                    data = fh.read().decode("utf-8", errors="replace")
                pairs.append(
                    (int(d), int(data.rpartition(")")[2].split()[1]))
                )
            except (OSError, ValueError, IndexError):
                continue
        return pairs
    try:
        out = subprocess.run(
            ["ps", "-axo", "pid=,ppid="],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                pairs.append((int(parts[0]), int(parts[1])))
            except ValueError:
                continue
    return pairs


# Live-escalation: credential-path matching is shared with triage.py's
# post-hoc `credential_path_touch` signal via the leaf
# core.sandbox.escalation_signatures module, so the live stderr notice
# here and the post-hoc signal agree on what counts by construction.
#
# Unlike Linux's escape-primitive syscall set (ptrace, bpf, keyctl,
# io_uring_*, ...), there is no macOS/SBPL analogue worth inventing
# here: non-file/network SBPL actions (mach-lookup, process-*,
# iokit-open, sysctl-*, ...) all collapse to the generic "seccomp"
# bucket in `_action_to_type` below with no established HIGH-severity
# subset — fabricating one would be an ungrounded judgment call.
# Network-level live escalation (resolved_ip_screened / host_recon) is
# already covered platform-wide by core/sandbox/proxy.py, which both
# platforms share. Credential-path touches on file-read/file-write
# records are the one live signal this platform's audit stream can
# attribute meaningfully on its own.
def _announce_credential_path_touch(path: str, pid: int) -> None:
    """Best-effort immediate stderr banner — mirrors
    core.sandbox.tracer._announce_escape_primitive's use of raw
    os.write(2, ...) so it survives redirected/odd stdio state.

    The path is attacker-controlled (the sandboxed target chose what
    to touch); sanitise + bound it before it reaches the operator's
    terminal — ascii/replace alone keeps ESC/CR/BEL, which are ASCII,
    so a crafted filename could otherwise inject terminal control
    sequences into the banner."""
    try:
        os.write(2, (
            f"RAPTOR sandbox ALERT: credential-looking path touched: "
            f"'{sanitise_for_terminal(path)}' (pid={pid}). "
            f"See sandbox-triage.json at run end for full context.\n"
        ).encode("ascii", errors="replace"))
    except OSError:
        pass


# Map SBPL action prefixes to the RAPTOR sandbox-summary type taxonomy
# (matches Linux tracer's _NAME_TO_TYPE mapping).
def _action_to_type(action: str) -> str:
    if action.startswith(("file-write", "file-mknod")):
        return "write"
    if action.startswith("file-read"):
        return "read"
    if action.startswith("network"):
        return "network"
    # mach-lookup, iokit-open, sysctl-*, process-*, etc.
    return "seccomp"  # closest analogue in the Linux taxonomy


def parse_log_entry(entry: dict, *,
                    observe_mode: bool = False,
                    nonce: str | None = None) -> dict | None:
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
    into ``run_dir/.audit/.sandbox-denials.jsonl``.

    Owned by ``_macos_spawn.run_sandboxed`` for the duration of one
    sandboxed call. NOT a singleton — a fresh streamer per sandbox()
    call, so concurrent sandboxes never conflict on ROUTING: each
    run's records land in its own run_dir / JSONL with its own nonce.
    Slight overhead (one log-stream subprocess per call) but each is
    cheap (~10MB resident, ~0 CPU when idle).

    Event ATTRIBUTION is a separate, weaker guarantee. ``log stream``
    is a host-wide feed — every Sandbox.kext event on the machine
    matches the sender predicate, including events from unrelated or
    sibling sandboxed processes running concurrently. Two scoping
    layers narrow attribution to this run's process tree:

      * predicate-level — when ``target_pid`` is known at
        construction, the log-stream predicate itself is narrowed to
        eventMessages carrying that exact PID (the only PID datum the
        kext embeds). Precise but narrow: processes the target forks
        carry other PIDs and their events never arrive, and the
        warm-up attachment gate is skipped (its synthetic workload's
        events cannot match the scoped predicate).
      * parse-time — ``register_target_pid()`` marks a PID (and its
        process group AND session, when resolvable) as in-scope; the
        reader thread drops every parsed record whose PID is out of
        scope BEFORE it is nonce-stamped, budget-counted, or
        appended. Defence in depth behind the predicate, and the
        only layer that can widen beyond the exact PID. The session
        widening is what lets registering the OUTER seatbelt shim
        cover the sandbox-exec subtree: the shim deliberately forks
        sandbox-exec into its own process group (so it can killpg
        it), but every descendant stays in the shim's session until
        it setsid()s — a setsid()'d descendant is a documented
        residual of this layer.

    With no scope registered (legacy callers), attribution stays
    host-wide: kext events from unrelated sandboxed processes ARE
    written into this run's JSONL, and allowlists derived from it
    can be contaminated by them. Register the child PID as soon as
    it is known to close that window.

    ``require_scope=True`` (what ``_macos_spawn`` passes) removes the
    legacy pass-through entirely: the caller promises to call
    ``register_target_pid()`` as soon as the workload is spawned.
    Until then, records are buffered (bounded) rather than appended;
    afterwards, only records attributable to the registered scope are
    admitted. Attribution widens beyond exact PID + process group to
    the workload's process LINEAGE: a background poller snapshots the
    process tree so descendants seen alive stay attributable when
    their kext records arrive after they exit (the kernel→log
    pipeline delivers post-exit for short workloads), and a live
    ppid-chain walk catches descendants the poller has not seen yet.
    Foreign records are dropped, counted, and surfaced via a
    ``foreign_records_dropped`` field on the audit_summary record.
    Residual: a descendant that lives shorter than one poll interval
    and whose record arrives post-exit cannot be attributed and is
    dropped — visible in the same counter.
    Session widening applies on top: ``register_target_pid``
    captures the registered PID's session, and same-session
    records stay attributable — the shim forks sandbox-exec into
    its own process group but the subtree keeps the shim's
    session (a setsid()'d descendant is covered by the lineage
    layers instead).
    """

    def __init__(self, run_dir: Path,
                 budget: _audit_budget.AuditBudget | None = None,
                 *, observe_mode: bool = False,
                 observe_nonce: str | None = None,
                 target_pid: int | None = None,
                 require_scope: bool = False,
                 warm_up_required: bool = False,
                 get_ppid=None,
                 getpgid=None,
                 list_pid_ppids=None,
                 lineage_poll_interval: float = _LINEAGE_POLL_INTERVAL_S) -> None:
        self._run_dir = Path(run_dir)
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stopped = threading.Event()
        # Scope-required + lineage state (see class docstring). All of
        # it is guarded by _scope_lock. The process-tree probes are
        # injectable so tests drive attribution deterministically
        # without a real /proc, ps, or getpgid.
        self._require_scope = bool(require_scope)
        # Fail-closed warm-up: when True, a warm-up gate miss raises
        # AuditWarmUpError from start() instead of proceeding
        # best-effort (see start()'s docstring for the trade-offs).
        self._warm_up_required = bool(warm_up_required)
        self._pending: list[dict] = []
        self._foreign_records_dropped = 0
        self._foreign_pid_cache: set[int] = set()
        self._get_ppid = get_ppid or _default_get_ppid
        self._getpgid = getpgid or os.getpgid
        self._list_pid_ppids = list_pid_ppids or _default_list_pid_ppids
        self._lineage_poll_interval = float(lineage_poll_interval)
        self._lineage_poller: threading.Thread | None = None
        # PID scoping state (see class docstring). _target_pid drives
        # the predicate-level narrowing in start(); the pid/pgid sets
        # drive the parse-time filter in _read_loop. Guarded by a
        # dedicated lock because register_target_pid() is called from
        # the parent thread while the reader thread consults the sets.
        self._scope_lock = threading.Lock()
        self._scope_pids: set[int] = set()
        self._scope_pgids: set[int] = set()
        self._scope_sids: set[int] = set()
        # require_scope=True flips the empty-scope default from
        # pass-all (legacy host-wide attribution) to drop-all: no
        # record may be attributed to this run until the caller has
        # registered its child. See the class docstring.
        self._require_scope = bool(require_scope)
        self._target_pid = int(target_pid) if target_pid is not None else None
        if self._target_pid is not None:
            self.register_target_pid(self._target_pid)
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
        # Lazily-opened held evidence fd (core/sandbox/evidence.py).
        # See _append_record_locked for the tamper rationale.
        self._evidence: _evidence_mod.EvidenceFile | None = None
        # Live-escalation dedup: paths already announced to stderr
        # this run, so a target repeatedly touching the same
        # credential-looking path doesn't spam the operator's
        # terminal. One banner per distinct path per run — mirrors
        # tracer.py's per-syscall-name dedup.
        self._escalated_paths: set = set()
        # Parse-ratio bookkeeping for the "parsed M of N kext lines"
        # diagnostic (kernel eventMessage format drift detector).
        # Mutated only on the reader thread; read at stop() after the
        # reader join, so no lock needed.
        self._kext_lines_seen = 0
        self._kext_lines_parsed = 0

    def register_target_pid(self, pid: int) -> None:
        """Mark ``pid`` — and its process group and session, when
        resolvable — as in-scope for event attribution.

        Call as soon as the sandboxed child's PID is known (it is
        usually not known when the streamer starts). Repeatable:
        each call widens the scope, so hybrid runs can register the
        workload plus helper processes. The group/session lookups are
        best-effort — a PID that is already gone (or was never local)
        still gets exact-PID matching, just no group widening.

        Under ``require_scope=True`` this call additionally: flushes
        the records buffered while no scope was known through the
        scope gate, and starts the lineage poller so descendants of
        the registered PID stay attributable after they exit.
        The session widening is load-bearing for the production
        caller: the registered PID is the outer seatbelt shim, whose
        sandbox-exec child runs in a DIFFERENT process group (the
        shim forks it into its own group so it can killpg it) but the
        SAME session — under ``start_new_session=True`` a fresh
        session private to this run. When the caller opted out of a
        new session, the scope degrades to the caller's own session:
        wider than one run, still strictly narrower than host-wide.
        """
        pid = int(pid)
        pgid: int | None = None
        try:
            pgid = self._getpgid(pid)
        except OSError:
            pass
        sid: int | None = None
        try:
            sid = os.getsid(pid)
        except OSError:
            pass
        with self._scope_lock:
            self._scope_pids.add(pid)
            self._foreign_pid_cache.discard(pid)
            if pgid is not None:
                self._scope_pgids.add(pgid)
            if sid is not None:
                self._scope_sids.add(sid)
            pending, self._pending = self._pending, []
        if (self._require_scope
                and self._lineage_poller is None
                and self._lineage_poll_interval > 0):
            self._lineage_poller = threading.Thread(
                target=self._lineage_poll_loop, daemon=True,
            )
            self._lineage_poller.start()
        # Flush the pre-registration buffer through the gate. The
        # scope is set before the swap above, so a record the reader
        # processes concurrently either lands in `pending` (swapped
        # and flushed here) or sees the non-empty scope directly —
        # never lost, never double-filtered.
        for record in pending:
            self._filter_and_append(record)

    def _lineage_poll_loop(self) -> None:
        """Periodically fold live descendants of the registered scope
        into it. Runs until stop() sets the event; one final refresh
        after that catches late spawns."""
        try:
            while not self._stopped.wait(self._lineage_poll_interval):
                self._refresh_lineage_from_tree()
            self._refresh_lineage_from_tree()
        except Exception:
            # A dead poller degrades attribution for post-exit
            # records (they fall back to the live ppid walk) — worth
            # a warning, never a crash.
            logger.warning("seatbelt audit lineage poller crashed",
                           exc_info=True)

    def _refresh_lineage_from_tree(self) -> None:
        """One poller tick: walk the (pid, ppid) snapshot and add
        every transitive child of an in-scope PID to the scope."""
        pairs = self._list_pid_ppids()
        if not pairs:
            return
        children: dict[int, list[int]] = {}
        for pid, ppid in pairs:
            children.setdefault(ppid, []).append(pid)
        with self._scope_lock:
            frontier = list(self._scope_pids)
            while frontier:
                parent = frontier.pop()
                for child in children.get(parent, ()):
                    if child in self._scope_pids:
                        continue
                    self._scope_pids.add(child)
                    # An earlier walk-miss may have negative-cached a
                    # pid the tree now attributes; lineage wins.
                    self._foreign_pid_cache.discard(child)
                    frontier.append(child)
                    try:
                        self._scope_pgids.add(self._getpgid(child))
                    except OSError:
                        pass

    def _record_in_scope(self, record: dict) -> bool:
        """Parse-time PID filter (see class docstring).

        With no scope registered, every record passes — legacy
        host-wide attribution, documented as unguaranteed (callers
        under ``require_scope=True`` never reach this arm: records
        are buffered until registration). With a scope, a record is
        in-scope when its PID was registered directly, or when its
        process group matches a registered one (catches children the
        target forked, which the predicate-level narrowing cannot).
        Under ``require_scope=True`` attribution additionally covers
        the workload's process lineage: PIDs folded in by the tree
        poller, and a live ppid-chain walk up to a registered PID. A
        PID that cannot be attributed by any layer is out of scope —
        reject rather than attribute an unverifiable event to this
        run.
        """
        with self._scope_lock:
            if not self._scope_pids and not self._scope_pgids:
                # Under require_scope nothing may be attributed until
                # a registration arrives (the reader buffers, but a
                # direct query must not claim scope membership).
                return not self._require_scope
            pid = record.get("target_pid")
            if not isinstance(pid, int):
                return False
            return self._pid_in_scope_locked(pid)

    def _pid_in_scope_locked(self, pid: int) -> bool:
        """Attribution for one PID. Caller holds ``_scope_lock``."""
        if pid in self._scope_pids:
            return True
        if pid in self._foreign_pid_cache:
            return False
        try:
            if self._getpgid(pid) in self._scope_pgids:
                self._scope_pids.add(pid)
                return True
        except OSError:
            pass
        if self._scope_sids:
            try:
                if os.getsid(pid) in self._scope_sids:
                    self._scope_pids.add(pid)
                    return True
            except OSError:
                pass
        if not self._require_scope:
            # Legacy scoped callers keep exact-PID + pgid semantics;
            # the lineage machinery engages only for owners that
            # promised a registration (require_scope=True).
            return False
        chain: list[int] = []
        cur = pid
        for _ in range(_LINEAGE_WALK_MAX):
            if cur in self._scope_pids:
                self._scope_pids.update(chain)
                return True
            chain.append(cur)
            parent = self._get_ppid(cur)
            if not parent or parent == cur or parent == 1:
                break
            cur = parent
        if len(self._foreign_pid_cache) > _FOREIGN_CACHE_CAP:
            self._foreign_pid_cache.clear()
        self._foreign_pid_cache.update(chain)
        return False

    def _build_predicate(self) -> str:
        """log-stream predicate. Always sender-scoped to Sandbox.kext;
        additionally PID-scoped when the target PID was known at
        construction. The kext embeds the acting PID in eventMessage
        as ``<name>(<pid>) ...`` — the only PID datum available at
        predicate level — so the narrowing is a CONTAINS clause on
        ``(<pid>) ``. The close-paren + trailing space keep a PID
        like 123 from matching 1234."""
        predicate = f'senderImagePath == "{SANDBOX_KEXT_SENDER}"'
        if self._target_pid is not None:
            predicate += (
                f' AND eventMessage CONTAINS "({self._target_pid}) "'
            )
        return predicate

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
        accept that early events may be missed. Those two causes are
        logged at debug for operator triage; a third — the warm-up
        probe's Popen itself failing (ENOENT / EACCES) — is
        deliberately logged at WARNING with traceback, since it
        signals a sandbox-exec regression the operator must see.

        Under ``warm_up_required=True`` (what _macos_spawn passes for
        audit_required runs) there is no best-effort fallback: a
        warm-up miss raises :class:`AuditWarmUpError` — with the
        `log stream` subprocess torn down — so the caller's
        fail-closed path refuses to run the workload with an
        unproven log-stream attachment.

        When the predicate is PID-scoped (``target_pid`` at
        construction), the warm-up gate is skipped entirely: the
        synthetic workload runs under its own PID, so its kext
        events can never pass the scoped predicate and the gate
        would always time out. Callers choosing predicate-level
        scoping trade away the cold-start attachment confirmation."""
        predicate = self._build_predicate()
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
            # `start_new_session=True` so a Ctrl-C delivered to the
            # parent's terminal session doesn't propagate SIGINT to
            # the `log stream` subprocess via the shared controlling
            # terminal. Pre-fix the audit streamer died on the
            # operator's first Ctrl-C — even though the parent's
            # KeyboardInterrupt handler was structured to terminate
            # it explicitly via `_proc.terminate()` later, the
            # SIGINT got there first and left the log records
            # un-collected for the killed run. Detached session
            # ensures the parent's Ctrl-C handler controls the
            # streamer's lifecycle.
            start_new_session=True,
        )
        try:
            if self._target_pid is not None:
                # PID-scoped predicate — the warm-up's synthetic
                # workload events can't match it (see docstring), so
                # the gate is structurally unavailable here and
                # warm_up_required cannot apply: callers choosing
                # predicate-level scoping trade away the cold-start
                # attachment confirmation (_macos_spawn never does).
                logger.debug(
                    "seatbelt audit: warm-up gate skipped — predicate "
                    "is PID-scoped to %d and cannot see the synthetic "
                    "workload's events",
                    self._target_pid,
                )
            elif not self._warm_up_until_attached():
                if self._warm_up_required:
                    # Fail closed: the raise lands in the except arm
                    # below, which tears down the `log stream`
                    # subprocess before re-raising, so a refused
                    # attachment never leaks a zombie streamer.
                    raise AuditWarmUpError(
                        f"log-stream warm-up attachment was not "
                        f"confirmed within {_WARM_UP_TIMEOUT_S}s — "
                        f"refusing to proceed with an unproven audit "
                        f"feed (warm_up_required=True)"
                    )
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
                try:
                    self._proc.wait(timeout=5)
                except Exception:  # noqa: BLE001 — any wait failure (timeout, interpreter shutdown) must escalate to kill
                    self._proc.kill()
                    self._proc.wait()
            except OSError:
                # KEEP-SILENT (F070 per-site triage W21): terminate()
                # on an already-dead process is the only realistic
                # OSError here. The outer `raise` re-raises the
                # underlying cause; a WARNING about a cleanup attempt
                # would be noise that obscures the real failure.
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

        # Trusted-dirs resolution, never the inherited PATH: the
        # warm-up executes this binary in the UNSANDBOXED parent, so a
        # PATH-planted sandbox-exec stub (direnv/.envrc-compatible
        # attack surface) would run host-side with the parent's
        # authority. Same doctrine (and helper) as the Linux
        # uidmap/getcap pinning in _spawn.py — this site was the one
        # shutil.which() left behind.
        from core.sandbox.probes import _find_sandbox_binary
        sandbox_exec = (
            _find_sandbox_binary("sandbox-exec") or _SANDBOX_EXEC_FALLBACK
        )
        if not Path(sandbox_exec).exists():
            # Non-Darwin host or stripped install — no point spawning
            # a missing binary. Best-effort fallback applies.
            return False

        try:
            # Pass through ``get_safe_env()`` so the warm-up child
            # doesn't inherit shell-evaluated env vars (``TERMINAL`` /
            # ``EDITOR`` / ``VISUAL`` / ``BROWSER`` / ``PAGER``) from
            # an untrusted parent. ``sandbox-exec /usr/bin/true`` is
            # benign on its own but ``get_safe_env()`` is the
            # codebase-wide posture for subprocess spawn under
            # untrusted-repo context — symmetry trumps the small
            # marginal risk here.
            from core.config import RaptorConfig
            warm_up = subprocess.Popen(
                [
                    sandbox_exec, "-p", _WARM_UP_SBPL,
                    "/usr/bin/true",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # Detach from parent's terminal session — see the
                # streamer Popen above for the same rationale.
                # Operator Ctrl-C shouldn't kill our own warm-up
                # probe; the probe finishes on its own.
                start_new_session=True,
                env=RaptorConfig.get_safe_env(),
            )
        except OSError:
            # WARNING (promoted from DEBUG): the warm-up gate failing to
            # spawn its probe means we will silently fall back to
            # best-effort mode and may miss early audit records. The
            # operator must see this so they can triage (ENOENT means
            # sandbox-exec is not where the trusted-dirs resolution
            # claimed it was;
            # EACCES means a profile/permissions regression). Mirrors
            # the family-wide DEBUG -> WARNING promotion for producer-error
            # logs (see core/sandbox/proxy.py for the sibling case).
            logger.warning(
                "seatbelt audit warm-up Popen failed; "
                "proceeding without warm-up gate",
                exc_info=True,
            )
            return False

        target_pid = warm_up.pid

        # Explicit guard rather than assert — survives `python -O`.
        if self._proc is None:
            msg = "seatbelt_audit: internal invariant — log-stream proc not started"
            raise RuntimeError(msg)
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
            # On Linux DefaultSelector is an epoll FD; explicit
            # close() releases the kernel-side FD immediately
            # instead of waiting for GC. Long-lived audit scenarios
            # that re-warm-up otherwise accumulate epoll FDs over
            # the process lifetime.
            sel.close()
            # Reap the warm-up child. With (deny default) the exec
            # itself is denied, so sandbox-exec exits ~immediately
            # with non-zero. Wait briefly; terminate as a safety net.
            try:
                warm_up.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    warm_up.terminate()
                except OSError:
                    # KEEP-SILENT (F070 per-site triage W21): we're in
                    # the gate's finally-block cleanup. terminate() on
                    # an already-dead process (sandbox-exec exits in
                    # <50ms with deny-default) is the realistic case.
                    # WARNING noise here would obscure the actual gate
                    # outcome the caller cares about.
                    pass
                try:
                    warm_up.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass

        return seen

    def _maybe_escalate_credential_path(self, record: dict) -> None:
        """Live stderr escalation for credential-looking path touches.
        Pulled out of `_read_loop` as its own method purely so tests
        can exercise it directly against a synthetic `record` dict
        without needing a real `log stream` subprocess."""
        path = record.get("path")
        if (path
                and record.get("type") in ("read", "write")
                and path not in self._escalated_paths
                and not _audit_budget.live_escalation_disabled()
                and is_credential_path(path)):
            self._escalated_paths.add(path)
            # .get: the never-raise-out-of-the-hot-path contract must
            # not hinge on every record shape carrying target_pid.
            _announce_credential_path_touch(
                path, record.get("target_pid", -1))

    def _read_loop(self) -> None:
        """Read ndjson lines from `log stream`, parse, and append
        records to the JSONL. Robust to malformed lines (silently
        skip).

        Runs to EOF, deliberately: stop() terminates the producer and
        joins this thread BEFORE setting the stop flag, so lines that
        were already buffered in the subprocess pipe at stop() time
        get parsed rather than dropped. Pre-fix the loop broke on the
        flag mid-stream and the tail records of every run were
        silently lost while a healthy summary was appended. EOF is
        guaranteed: stop() escalates terminate → kill on the
        producer, which closes the pipe's write end."""
        try:
            # Explicit guard — survives `python -O`.
            if self._proc is None:
                msg = "seatbelt_audit._read_loop: proc not started"
                raise RuntimeError(msg)
            for raw_line in self._proc.stdout or ():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("senderImagePath") == SANDBOX_KEXT_SENDER:
                    self._kext_lines_seen += 1
                record = parse_log_entry(
                    entry,
                    observe_mode=self._observe_mode,
                    nonce=self._observe_nonce,
                )
                if record is None:
                    continue
                # Counted before the scope filter: "parsed" measures
                # regex/format health only — foreign-but-well-formed
                # events dropped by scoping must not read as drift.
                self._kext_lines_parsed += 1
                self._filter_and_append(record)
        except Exception:
            # WARNING (F070 W21 promote): a dead reader thread means
            # ALL subsequent audit records for this run are lost. The
            # operator MUST see this — same rationale as the L447
            # append-failure promote above.
            logger.warning("seatbelt audit reader thread crashed",
                           exc_info=True)

    def _filter_and_append(self, record: dict) -> None:
        """Scope gate + budget + JSONL append for one parsed record."""
        if self._require_scope:
            with self._scope_lock:
                if not self._scope_pids and not self._scope_pgids:
                    # No scope registered yet — the workload cannot
                    # have produced records, but buffer (bounded)
                    # rather than drop so the spawn/registration race
                    # loses nothing. If registration never happens,
                    # stop() drops the buffer as unattributable.
                    if len(self._pending) < _PENDING_BUFFER_CAP:
                        self._pending.append(record)
                    else:
                        self._foreign_records_dropped += 1
                    return
        if not self._record_in_scope(record):
            # Host-wide kext event from a process outside the
            # registered scope — a sibling sandboxed run or an
            # unrelated sandboxed app. Drop BEFORE the budget
            # and the append so foreign events are never
            # nonce-stamped into this run's JSONL and never
            # consume its audit budget.
            with self._scope_lock:
                self._foreign_records_dropped += 1
            return
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
        #       during iteration");
        #   (b) the marker lands in the JSONL immediately
        #       before its associated record without another
        #       writer slipping a record in between.
        try:
            self._maybe_escalate_credential_path(record)

            with self._append_lock:
                decision, marker = self._budget.evaluate(
                    record["syscall"], record["target_pid"],
                )
                if marker is not None:
                    self._append_record_locked(marker)
                # Global-cap notice: the Linux tracer surfaces
                # this on stderr; there is no tracer on macOS,
                # so pre-fix the global cap suppressed
                # silently (only the sub-caps got in-band
                # markers). Emit the one-shot marker into the
                # stream where operators actually look.
                if self._budget.pop_global_cap_notice():
                    self._append_record_locked(
                        self._budget.global_cap_marker(),
                    )
                if decision != _audit_budget.DROP:
                    self._append_record_locked(record)
        except OSError:
            # Best-effort. Don't crash the reader thread on
            # transient FS errors — a missed record is
            # acceptable, a dead reader thread is not.
            #
            # WARNING (F070 W21 promote): operators rarely run
            # with DEBUG enabled, so pre-fix every dropped
            # audit record was invisible. Mirrors the family-
            # wide DEBUG -> WARNING convention from c5a4505
            # and 8edf0f6 (sibling F069 in proxy.py).
            logger.warning("seatbelt audit append failed",
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

        Uses a held evidence fd (core/sandbox/evidence.EvidenceFile)
        opened O_EXCL in ``<run_dir>/.audit/`` at first call. The
        held fd means a swap/rename of the JSONL path cannot
        redirect later appends (the fd pins the original inode), and
        the O_EXCL create defeats a pre-planted file or symlink. The
        inode recorded at open is verified when stop() closes the
        streamer. The profile-side ``audit_evidence_dir`` deny keeps
        the target away from the path entirely; this is the
        defence-in-depth layer for operator-misconfigured profiles.
        """
        if self._evidence is None:
            # First call: materialise run_dir AND pin the evidence
            # file beneath it.
            self._run_dir.mkdir(parents=True, exist_ok=True)
            self._evidence = _evidence_mod.EvidenceFile.open(
                self._run_dir, self._filename,
            )
        if not self._evidence.write_record(record):
            msg = (
                f"evidence append failed for {self._filename} "
                f"under {self._run_dir}"
            )
            raise OSError(msg)

    def stop(self, *, drain_timeout: float = 1.5) -> None:
        """Stop the streamer. Gives `log stream` a brief window to
        flush any in-flight records, then terminates.

        Called by _macos_spawn after the workload exits. The drain
        window matters: kernel → log subsystem → log stream pipeline
        has visible latency (spike #4 measured ~1.5s for a cold
        first event); without the drain we'd lose the tail-end
        records of short workloads.

        Ordering is load-bearing: terminate the producer FIRST, drain
        the reader to EOF (bounded join), and only THEN set the stop
        flag and append the summary. Pre-fix the flag was set before
        the terminate while _read_loop broke on it before parsing
        already-buffered lines — the pipe-buffered tail of every run
        was silently dropped, yet the summary still asserted a
        healthy capture.
        """
        if self._proc is not None:
            # Terminate the producer: no new lines are generated, the
            # pipe's write end closes, and whatever is already
            # buffered drains to EOF under the reader.
            self._proc.terminate()
            try:
                self._proc.wait(timeout=drain_timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                try:
                    self._proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            # Drain the reader to EOF before the summary fires (the
            # append lock makes the summary the last write only for
            # appends that RACE it — records the reader hasn't parsed
            # yet would simply be lost after it). Bounded join: the
            # kernel log streamer buffers messages in its stdout
            # pipe, and bytes already in the buffer still need
            # parsing after the terminate above. Operators are
            # willing to wait 3s for shutdown to fully drain the
            # audit trail; missing the last few sandbox-denial
            # events is a worse outcome than a 3s extra shutdown
            # delay. Daemon status preserves the original "don't
            # block exit forever" intent — a hung reader after 3s
            # still gets killed by interpreter shutdown.
            if self._reader is not None and self._reader.is_alive():
                self._reader.join(timeout=3.0)
        # Stop flag AFTER the drain: _read_loop runs to EOF by design
        # (see its docstring); the flag's remaining consumer is the
        # lineage poller's clock.
        self._stopped.set()
        # Lineage poller: signalled via _stopped above; its loop does
        # one final tree refresh on the way out. Bounded join.
        if (self._lineage_poller is not None
                and self._lineage_poller.is_alive()):
            self._lineage_poller.join(timeout=2.0)
        # Records still pending mean no scope was ever registered
        # (the spawn failed before register_target_pid) — they are
        # unattributable, so drop + count as foreign.
        with self._scope_lock:
            if self._pending:
                self._foreign_records_dropped += len(self._pending)
                self._pending = []
            foreign_dropped = self._foreign_records_dropped
        if foreign_dropped:
            logger.info(
                "seatbelt audit: dropped %d kext record(s) from outside "
                "the workload's process scope (records from other "
                "sandboxed processes on this host, or descendants that "
                "exited before they could be attributed)",
                foreign_dropped,
            )
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
        # Parse-ratio diagnostic: a high drop ratio on kext-sender
        # lines means the eventMessage format drifted away from
        # _LOG_LINE_RE — the audit trail is silently incomplete and
        # operators must see it. Counters are stable here (reader
        # joined or abandoned above; a straggler under-counts at
        # worst, never crashes).
        seen = self._kext_lines_seen
        parsed = self._kext_lines_parsed
        if (seen >= _PARSE_DIAG_MIN_LINES
                and parsed < seen * _PARSE_DIAG_MIN_RATIO):
            logger.warning(
                "seatbelt audit: parsed %d of %d kext log lines — "
                "the kernel Sandbox log format may have drifted from "
                "_LOG_LINE_RE; the audit JSONL is likely incomplete",
                parsed, seen,
            )
        try:
            # Hold the lock across summary_record + append so the
            # snapshot read and the JSONL write are atomic with
            # respect to any reader thread still draining.
            with self._append_lock:
                summary = self._budget.summary_record()
                # Parse-ratio surface for operators reading the JSONL
                # (extra keys tolerated by consumers per contract).
                summary["kext_lines_seen"] = seen
                summary["kext_lines_parsed"] = parsed
                # Scope-gate diagnostic: how many records were
                # rejected as outside the workload's process scope.
                summary["foreign_records_dropped"] = foreign_dropped
                # Stamp nonce on the summary so an observe-mode
                # parser attributes it to this run and rejects one
                # spoofed by a target binary writing a fake summary
                # into the JSONL.
                if self._observe_nonce is not None:
                    summary["nonce"] = self._observe_nonce
                self._append_record_locked(summary)
        except OSError:
            # WARNING (F070 W21 promote): the summary record is the
            # last write of every audit-mode run and the only record
            # operators rely on for "did the budget cap engage?"
            # signal. Silent loss = silent audit integrity gap.
            # Mirrors c5a4505 / 8edf0f6 promotion family.
            logger.warning("seatbelt audit summary append failed",
                           exc_info=True)
        # Finalise the held evidence fd: verify the on-disk path
        # still names the inode created at first append (loud
        # warning inside close() on a swap), then release the fd so
        # test runs stay free of ResourceWarnings.
        with self._append_lock:
            if self._evidence is not None:
                self._evidence.close()
                self._evidence = None


def start_log_streamer(run_dir: Path, *,
                       observe_mode: bool = False,
                       observe_nonce: str | None = None,
                       target_pid: int | None = None,
                       require_scope: bool = False,
                       warm_up_required: bool = False,
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

    `target_pid`: scope event attribution to this PID at the
    log-stream predicate level (see LogStreamer's class docstring
    for the trade-offs). Callers that only learn the child PID after
    spawn should instead call ``register_target_pid()`` on the
    returned streamer for parse-time scoping.

    `require_scope`: engage the mandatory scope gate — the caller
    promises to call ``register_target_pid(pid)`` as soon as the
    workload is spawned; until then records are buffered, and from
    then on only records attributable to the registered scope's
    process lineage are admitted (foreign sandboxed processes on the
    host are dropped + counted). _macos_spawn passes True.

    `warm_up_required`: fail closed on the warm-up attachment gate —
    a miss raises AuditWarmUpError from start() instead of the
    best-effort proceed. _macos_spawn passes the run's
    audit_required flag.
    """
    s = LogStreamer(run_dir, observe_mode=observe_mode,
                    observe_nonce=observe_nonce,
                    target_pid=target_pid,
                    require_scope=require_scope,
                    warm_up_required=warm_up_required)
    s.start()
    return s
