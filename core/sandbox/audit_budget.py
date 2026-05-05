"""Centralised audit-record rate / volume control.

Used by both backends:
  * core.sandbox.tracer            — Linux ptrace tracer
  * core.sandbox.seatbelt_audit    — macOS log-stream reader

A single source of truth for the budget mechanics keeps the two
backends from drifting and means a future tweak (new category, new
sampling rate, new CLI knob) lands in one place.

Four mechanisms compose:

  1. Global cap (`global_cap`). Hard ceiling on total records per
     run. Once hit, EVERY record is evaluated through sampling
     (defaulting to drop for un-sampled categories).

  2. Per-category sub-cap (`category_caps`). Stops one chatty
     category (file-read-metadata, process-info-*) from squeezing
     low-volume but operationally-important categories (network,
     exec, mach-lookup) out of the global budget.

  3. Per-PID sub-cap (`pid_cap`). One spamming subprocess can't
     dominate the JSONL — past the per-PID cap, that PID's records
     are dropped (with a one-time marker per PID).

  4. Token-bucket rate limiting (`refill_rates`). The cap is a
     burst capacity; the refill rate is the steady-state allowance.
     A long-running audited workload that legitimately produces
     events at e.g. 10/sec for an hour DOESN'T blow through the
     burst cap — the bucket refills as it drains.

  5. Post-cap sampling (`sampling_rates`). Once a category's burst
     cap is hit, instead of going completely dark the budget can
     emit 1-in-N records. Operators see "is this still happening?"
     at a fraction of the volume.

Decision return shape:
    (action: str, marker: dict | None)

  action:  "keep" → caller writes the record
           "drop" → caller drops silently
  marker:  dict to append to the JSONL BEFORE acting on the action
           (the caller writes the marker first, then either writes
           the record or drops it). None when no marker is needed.
           Markers fire ONCE per category-cap-exhaust and ONCE per
           pid-cap-exhaust so operators see the suppression in-line.

Thread-safety: each backend's writer is single-threaded (Linux
tracer is a separate process, macOS LogStreamer has one daemon
reader thread), so no internal locking. Two budgets in the same
process must not share state.

CLI:
  --audit-budget N   set the global cap to N (CLI override of the
                     default global_cap=10000). Per-category caps
                     are scaled proportionally so the relative
                     allocation is preserved.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, Optional, Tuple


# ---------------------------------------------------------------------
# Defaults — STARTING HEURISTICS, not measured truths.
#
# These were picked by inspection from a few /scan + /agentic runs
# and Apple's open-source SBPL profiles. They are NOT calibrated
# against a corpus of real workloads. After first production
# deployment, measure the distributions in real `audit_summary`
# records (see core.sandbox.summary aggregation):
#
#   * If a category disappears entirely into `dropped_by_category`
#     while the workload is still producing useful events, raise
#     that category's cap and refill rate.
#   * If the JSONL bloats past operational tolerance under
#     `--audit-verbose`, tighten the high-volume categories
#     (file-read-metadata, process-info) further OR add a sampling
#     rate to a category that currently has none.
#   * If a long-running workload (>1 hour) drains its bucket at
#     steady-state, raise that category's `refill_rate` rather than
#     its cap — caps absorb bursts; refill rate absorbs sustained
#     load.
#
# Operators tuning per-deployment can override via
# AuditBudget(global_cap=..., category_caps=..., refill_rates=...,
# sampling_rates=...). The CLI flag --audit-budget=N propagates the
# global override and scales per-category and per-PID sub-caps
# proportionally (see __init__ docstring).
# ---------------------------------------------------------------------

DEFAULT_GLOBAL_CAP = 10000

# Per-category burst caps. Coarse buckets — see _default_categorise()
# for the action → category mapping.
DEFAULT_CATEGORY_CAPS = {
    "file-read-metadata": 500,
    "file-read-data":    2000,
    "file-write":        3000,
    "network":            500,
    "mach-lookup":       1000,
    "process-info":       200,
    "process-exec":       200,
    "process-fork":       200,
    "signal":             500,
    "iokit-open":         500,
    "sysctl-read":        500,
    "sysctl-write":       200,
}

# Per-PID burst cap — half the global cap by default. A single
# subprocess shouldn't be able to consume more than half the run's
# budget on its own.
DEFAULT_PID_CAP = 5000

# Token bucket refill rate (records per second). Bucket capacity
# equals the per-category cap above. A category with cap 500 +
# refill 10/sec allows steady-state 10/sec indefinitely (refills
# replenish the bucket); bursts up to 500 flow through immediately.
# Refill rates for the residual global category default to
# global_cap / 600 (tuned so a 1-hour run doesn't drain the bucket
# at a steady rate of ≤ refill).
DEFAULT_REFILL_RATES = {
    "file-read-metadata":  10,
    "file-read-data":      50,
    "file-write":          50,
    "network":             20,
    "mach-lookup":         30,
    "process-info":         5,
    "process-exec":         5,
    "process-fork":         5,
    "signal":              10,
    "iokit-open":          10,
    "sysctl-read":         20,
    "sysctl-write":         5,
}

# Post-cap sampling: 1-in-N once a category's bucket is empty.
# Categories not listed default to N=0 → drop entirely after cap
# (no post-cap visibility). Listed categories produce a steady
# trickle even when fully throttled, so operators can see "is this
# still happening?" without flooding.
DEFAULT_SAMPLING_RATES = {
    "file-read-metadata": 100,   # 1 of every 100
    "file-read-data":      50,
    "process-info":        50,
    "iokit-open":         100,
    "sysctl-read":         50,
}


def _default_categorise(action: str) -> str:
    """Map an SBPL or syscall name to a budget category.

    The mapping is deliberately coarse — variants of the same
    category collapse together so the per-category cap is meaningful.
    Used by both backends; SBPL action names dominate but Linux
    syscall names happen to fit too (open/openat → file-read-data,
    write → file-write, etc.). Unrecognised actions return their
    own name (sharing only the global cap, no category sub-cap).
    """
    if action.startswith("file-write") or action.startswith("file-mknod"):
        return "file-write"
    if action == "file-read-metadata":
        return "file-read-metadata"
    if action.startswith("file-read"):
        return "file-read-data"
    if action.startswith("network"):
        return "network"
    if action.startswith("mach-lookup"):
        return "mach-lookup"
    if action.startswith("process-info"):
        return "process-info"
    if action.startswith("process-exec"):
        return "process-exec"
    if action == "process-fork":
        return "process-fork"
    if action == "signal":
        return "signal"
    if action.startswith("iokit-open"):
        return "iokit-open"
    if action == "sysctl-read":
        return "sysctl-read"
    if action == "sysctl-write":
        return "sysctl-write"
    # Linux syscall-name analogues (no SBPL category match) so the
    # ptrace tracer benefits from the same coarsening.
    if action in ("write", "writev", "pwrite64", "pwritev",
                  "creat", "mknod", "mknodat", "truncate"):
        return "file-write"
    if action in ("openat", "open", "stat", "fstat", "lstat",
                  "newfstatat", "statx", "access", "faccessat"):
        return "file-read-metadata"
    if action in ("read", "readv", "pread64", "preadv"):
        return "file-read-data"
    if action in ("connect", "sendto", "sendmsg", "socket"):
        return "network"
    if action in ("execve", "execveat"):
        return "process-exec"
    if action in ("clone", "clone3", "fork", "vfork"):
        return "process-fork"
    if action in ("kill", "tkill", "tgkill"):
        return "signal"
    return action


# ---------------------------------------------------------------------
# Decision shape
# ---------------------------------------------------------------------

KEEP = "keep"
DROP = "drop"


# ---------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------

class AuditBudget:
    """Per-run audit budget. One instance per audit session.

    Constructor knobs let callers override defaults for tests and
    for the CLI's --audit-budget flag. ``categorise`` and ``clock``
    are injection points for tests (no real time, deterministic
    category mapping).
    """

    def __init__(self,
                 *,
                 global_cap: Optional[int] = None,
                 category_caps: Optional[Dict[str, int]] = None,
                 pid_cap: Optional[int] = None,
                 refill_rates: Optional[Dict[str, float]] = None,
                 sampling_rates: Optional[Dict[str, int]] = None,
                 categorise: Optional[Callable[[str], str]] = None,
                 clock: Optional[Callable[[], float]] = None,
                 ):
        # Defaults — copy so external dicts can't be mutated through
        # ours and vice versa.
        self.global_cap = (DEFAULT_GLOBAL_CAP
                            if global_cap is None else int(global_cap))
        self.category_caps = (
            dict(DEFAULT_CATEGORY_CAPS)
            if category_caps is None else dict(category_caps)
        )
        # Scale per-category caps proportionally to global_cap when
        # the caller overrides global without overriding categories.
        # Without this, --audit-budget=100000 would still be capped
        # per-category at the original 500/2000/3000 numbers and the
        # operator's intent (10× more headroom) would be partially
        # ignored.
        if (global_cap is not None and category_caps is None
                and self.global_cap != DEFAULT_GLOBAL_CAP):
            scale = self.global_cap / DEFAULT_GLOBAL_CAP
            self.category_caps = {
                k: max(1, int(v * scale))
                for k, v in self.category_caps.items()
            }
        self.pid_cap = (DEFAULT_PID_CAP
                        if pid_cap is None else int(pid_cap))
        if (pid_cap is None and global_cap is not None
                and self.global_cap != DEFAULT_GLOBAL_CAP):
            self.pid_cap = max(1, int(self.pid_cap
                                       * (self.global_cap
                                          / DEFAULT_GLOBAL_CAP)))
        self.refill_rates = (
            dict(DEFAULT_REFILL_RATES)
            if refill_rates is None else dict(refill_rates)
        )
        self.sampling_rates = (
            dict(DEFAULT_SAMPLING_RATES)
            if sampling_rates is None else dict(sampling_rates)
        )
        self._categorise = categorise or _default_categorise
        self._clock = clock or time.monotonic

        # First-global-drop notification flag. Used by callers (the
        # Linux tracer in particular) to emit a one-time stderr
        # message when the global cap fires, restoring the operator-
        # visible cue that the legacy `_MAX_RECORDS_PER_RUN = 10000`
        # path used to print to tracer stderr. The dropping is
        # in-band; this flag just lets callers query "did we just
        # cross the global ceiling?" via `pop_global_cap_notice()`.
        self._global_cap_notified = False
        # Per-instance bookkeeping. dict-based; insertion-ordered
        # since Python 3.7 so we get LRU semantics on `_pid_counts`
        # for free (move_to_end on access).
        self._record_count = 0
        self._category_counts: Dict[str, int] = {}
        self._pid_counts: Dict[int, int] = {}
        self._dropped: Dict[str, int] = {}
        self._cat_marker_emitted: set = set()
        self._pid_marker_emitted: set = set()
        # Token bucket: per-category (current_tokens, last_refill_ts).
        # Initialised lazily on first event in each category so the
        # bucket starts at full capacity.
        self._buckets: Dict[str, Tuple[float, float]] = {}
        # Sampling counter: per-category modular counter so 1-in-N
        # is deterministic (caller knows exactly which Nth event
        # leaked through). Starts at 0; sampled records emitted on
        # _sampling_counter % N == 0.
        self._sampling_counters: Dict[str, int] = {}
        # PID dict cap. A fork-bomb-style target spawning millions
        # of distinct short-lived PIDs would otherwise grow
        # _pid_counts unbounded (~120 bytes/entry; 1M PIDs ≈ 120MB
        # resident in the parent before pid_cap admission stops
        # accepting new records). LRU-evict past this many entries —
        # evicted PIDs lose their per-PID accounting and rejoin the
        # admission flow as if newly seen, which is fine: their
        # records still count against the GLOBAL cap so the budget
        # remains bounded. _pid_marker_emitted is also evicted in
        # lock-step so a re-seen PID can re-emit its marker if it
        # again hits the per-PID cap.
        self._pid_dict_cap = 10_000

    # ----- snapshot accessors (for end-of-run summary) -------------

    @property
    def total_records(self) -> int:
        return self._record_count

    @property
    def category_counts(self) -> Dict[str, int]:
        return dict(self._category_counts)

    @property
    def dropped_by_category(self) -> Dict[str, int]:
        return dict(self._dropped)

    @property
    def pid_counts(self) -> Dict[int, int]:
        return dict(self._pid_counts)

    # ----- core decision -------------------------------------------

    def evaluate(self, action: str, pid: int) -> Tuple[str, Optional[dict]]:
        """Decide whether to keep or drop a record.

        Returns ``(KEEP, marker)`` or ``(DROP, marker)``. The marker
        (when non-None) MUST be appended to the JSONL by the caller
        BEFORE writing or dropping the record — the marker shows the
        cap-exhaust point in-line so operators see suppression
        without a separate sidecar file.
        """
        cat = self._categorise(action)
        marker = None

        # Per-PID cap fires regardless of category. Hits this branch
        # before the category check so the marker mentions the PID,
        # not the category.
        pid_cur = self._pid_counts.get(pid, 0)
        if pid_cur >= self.pid_cap:
            self._dropped[cat] = self._dropped.get(cat, 0) + 1
            if pid not in self._pid_marker_emitted:
                self._pid_marker_emitted.add(pid)
                marker = self._make_marker(
                    "pid_budget_exceeded",
                    pid=pid, cap=self.pid_cap,
                    note=(f"Per-PID audit-record cap reached for "
                          f"pid {pid}; further records from this "
                          f"PID will be dropped. Tune pid_cap in "
                          f"AuditBudget or pass a larger "
                          f"--audit-budget to raise."),
                )
            return DROP, marker

        # Token-bucket consumption for the category. The bucket's
        # capacity is the category cap; refill rate is per-cat.
        # Categories without an explicit refill rate get a default
        # tied to the global cap so the residual bucket is non-zero.
        cap = self.category_caps.get(cat, self.global_cap)
        refill = self.refill_rates.get(cat, self.global_cap / 600.0)
        if not self._take_token(cat, cap, refill):
            self._dropped[cat] = self._dropped.get(cat, 0) + 1
            # Sampling: 1-in-N once the bucket is empty. Emits a
            # trickle even at full throttle so operators see "still
            # happening" without flooding. When sampling is
            # configured for this category, the marker fires on the
            # first SAMPLED record (operators see "sampling kicked in
            # NOW" alongside the first kept-after-cap record). When
            # sampling is NOT configured, the marker fires on the
            # first DROP (operators see the cap exhaust there
            # instead).
            sample_n = self.sampling_rates.get(cat, 0)
            if sample_n > 0:
                # Emit the "sampling kicking in" marker on the FIRST
                # over-cap drop, regardless of whether THIS event is
                # the one that gets sampled. Operators see "this
                # category just hit its cap; from now on you'll see
                # 1-in-N records" right at the moment the cap fires,
                # not N events later when the first sampled record
                # happens to land. (Earlier behaviour emitted the
                # marker on the Nth event — confusing because by
                # then the cap had already been exceeded for N-1
                # silent drops.)
                if cat not in self._cat_marker_emitted:
                    self._cat_marker_emitted.add(cat)
                    marker = self._make_marker(
                        "category_budget_exceeded_sampling",
                        category=cat, cap=cap,
                        sampling_rate=sample_n,
                        note=(f"Category {cat!r} cap reached; "
                              f"sampling 1-in-{sample_n} from now."),
                    )
                self._sampling_counters[cat] = (
                    self._sampling_counters.get(cat, 0) + 1
                )
                if self._sampling_counters[cat] % sample_n == 0:
                    # Sampled record IS kept — doesn't refill the
                    # bucket (already over cap) and doesn't bump
                    # the global counter (we promised the global
                    # cap).
                    return KEEP, marker
                # Not the sampled one — drop, but the marker (if
                # any was just generated) still flushes so
                # operators see the state-change event in-line.
                return DROP, marker
            # No sampling configured: emit the "no sampling" marker
            # on the first drop.
            if cat not in self._cat_marker_emitted:
                self._cat_marker_emitted.add(cat)
                marker = self._make_marker(
                    "category_budget_exceeded",
                    category=cat, cap=cap,
                    note=(f"Category {cat!r} cap reached and no "
                          f"post-cap sampling rate is configured; "
                          f"further records dropped silently."),
                )
            return DROP, marker

        # Global cap — hits when many small-cap categories
        # collectively exhaust the global pool. We just took a
        # category token but the record is being dropped → refund
        # the token so the bucket is available for future events
        # (e.g., if an operator-side process raises the global cap
        # mid-run, or sampling kicks in for this category later).
        if self._record_count >= self.global_cap:
            self._dropped[cat] = self._dropped.get(cat, 0) + 1
            # Refund the token we just consumed in _take_token —
            # this drop is global-cap, not category-cap. Without
            # the refund, category buckets stay drained even when
            # the actual constraint is global.
            tokens, last_ts = self._buckets[cat]
            self._buckets[cat] = (
                min(float(cap), tokens + 1.0), last_ts,
            )
            # Set the once-only notification flag so the caller can
            # surface a stderr warning. Markers in JSONL are nice
            # but easy to miss — the legacy tracer's stderr line
            # was the operator's first signal that audit was
            # truncated. Restore parity.
            self._global_cap_notified = True
            return DROP, marker

        # Allowed. Bump counters.
        self._record_count += 1
        self._category_counts[cat] = self._category_counts.get(cat, 0) + 1
        # Move PID to end of insertion order so LRU eviction (below)
        # discards the genuinely-oldest entries when the cap is hit.
        # `d[k] += 1` does NOT update insertion order — pop+reinsert does.
        if pid in self._pid_counts:
            count = self._pid_counts.pop(pid) + 1
            self._pid_counts[pid] = count
        else:
            self._pid_counts[pid] = 1
            if len(self._pid_counts) > self._pid_dict_cap:
                # Evict the oldest entry — Python dict preserves
                # insertion order, popitem(last=False) is the LRU
                # evictee. (Plain dict has no popitem(last=) but
                # iter+next gives the first key.)
                oldest = next(iter(self._pid_counts))
                del self._pid_counts[oldest]
                # Drop the marker-emitted memory too so a re-seen
                # PID can re-emit its cap-exceeded marker.
                self._pid_marker_emitted.discard(oldest)
        return KEEP, marker

    # ----- helpers --------------------------------------------------

    def _take_token(self, cat: str, capacity: int,
                    refill_rate: float) -> bool:
        """Refill the bucket for `cat` based on elapsed time, then
        try to take one token. Returns True if taken, False if
        bucket was empty (= over cap)."""
        now = self._clock()
        tokens, last_ts = self._buckets.get(cat, (float(capacity), now))
        # Refill since last check, capped at capacity.
        elapsed = max(0.0, now - last_ts)
        tokens = min(float(capacity), tokens + elapsed * refill_rate)
        if tokens < 1.0:
            self._buckets[cat] = (tokens, now)
            return False
        self._buckets[cat] = (tokens - 1.0, now)
        return True

    def _make_marker(self, marker_type: str, **fields) -> dict:
        """Construct a marker record. Caller writes the dict as a
        JSONL line. Marker shape mirrors the audit_summary record
        so summary.py can recognise both as control-plane entries
        (vs data records)."""
        from datetime import datetime, timezone
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": marker_type,
            "audit": True,
            **fields,
        }

    def pop_global_cap_notice(self) -> bool:
        """Returns True ONCE if the global cap has fired since last
        call, then False forever after. Lets callers (e.g., the
        Linux tracer) emit a one-time stderr line when the cap is
        crossed without re-emitting it on every subsequent drop."""
        if self._global_cap_notified:
            self._global_cap_notified = False
            return True
        return False

    def summary_record(self) -> dict:
        """End-of-run summary. Caller appends this once when the
        audit session closes (LogStreamer.stop / tracer exit)."""
        from datetime import datetime, timezone
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "audit_summary",
            "audit": True,
            "total_records": self._record_count,
            "dropped_by_category": dict(self._dropped),
            "category_counts": dict(self._category_counts),
            "pid_counts": dict(self._pid_counts),
            "global_cap": self.global_cap,
        }


# ---------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------

def from_cli_state() -> AuditBudget:
    """Construct an AuditBudget honouring the --audit-budget CLI flag.

    Reads `core.sandbox.state._cli_sandbox_audit_budget`. None →
    defaults; integer → override global_cap (per-category and per-
    PID caps scaled proportionally inside AuditBudget.__init__).

    Centralised here so consumers (tracer, LogStreamer) don't each
    have to re-read state directly.
    """
    from . import state
    cli_cap = getattr(state, "_cli_sandbox_audit_budget", None)
    return AuditBudget(global_cap=cli_cap if cli_cap else None)
