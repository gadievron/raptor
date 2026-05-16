"""Tests for the unified AuditBudget shared by the Linux tracer
and the macOS LogStreamer.

These are pure-logic tests — no fork, no subprocess, no time.sleep.
They use the AuditBudget's `clock` injection point to drive the
token-bucket deterministically and run in milliseconds.
"""

from __future__ import annotations

from core.sandbox import audit_budget


# ---------------------------------------------------------------------
# Categorisation
# ---------------------------------------------------------------------

def test_categorise_collapses_action_variants():
    """File-write variants and mknod collapse together so a chatty
    writer that mixes action names doesn't bypass the per-cat cap."""
    cf = audit_budget._default_categorise
    assert cf("file-write-create") == "file-write"
    assert cf("file-write-data") == "file-write"
    assert cf("file-write-mode") == "file-write"
    assert cf("file-mknod") == "file-write"


def test_categorise_distinguishes_metadata_from_data():
    """file-read-metadata is split from file-read-data because
    metadata reads (every stat/readdir) are 100x noisier than data
    reads in typical workloads."""
    cf = audit_budget._default_categorise
    assert cf("file-read-metadata") == "file-read-metadata"
    assert cf("file-read-data") == "file-read-data"
    assert cf("file-read-xattr") == "file-read-data"


def test_categorise_handles_linux_syscall_names():
    """Same coarsening should apply to Linux syscall names so the
    Linux tracer benefits from the same per-cat semantics."""
    cf = audit_budget._default_categorise
    assert cf("openat") == "file-read-metadata"
    assert cf("write") == "file-write"
    assert cf("read") == "file-read-data"
    assert cf("connect") == "network"
    assert cf("execve") == "process-exec"
    assert cf("clone") == "process-fork"
    assert cf("kill") == "signal"


def test_categorise_unknown_action_returns_self():
    """Unrecognised actions get their own category — they share
    only the global cap, no per-cat sub-cap. Returning the action
    name itself ensures _category_counts has a unique key."""
    cf = audit_budget._default_categorise
    assert cf("user-preference-write") == "user-preference-write"
    assert cf("totally-made-up-action") == "totally-made-up-action"


# ---------------------------------------------------------------------
# Per-category cap
# ---------------------------------------------------------------------

class _FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_per_category_cap_drops_excess_with_marker():
    """Once a category bucket empties, further records of that
    category are dropped. The first drop emits a marker; subsequent
    drops are silent (operator already saw the warning)."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"process-info": 5},
        # No refill — bucket once-empty stays empty.
        refill_rates={"process-info": 0.0},
        # No sampling — drops are clean.
        sampling_rates={},
        clock=clock,
    )
    decisions = []
    markers = []
    for _ in range(8):
        d, m = budget.evaluate("process-info-pidinfo", pid=100)
        decisions.append(d)
        if m is not None:
            markers.append(m)
    # First 5 keep, last 3 drop.
    assert decisions[:5] == [audit_budget.KEEP] * 5
    assert decisions[5:] == [audit_budget.DROP] * 3
    # Exactly one marker — on the first drop.
    assert len(markers) == 1
    assert markers[0]["type"] == "category_budget_exceeded"
    assert markers[0]["category"] == "process-info"
    assert markers[0]["cap"] == 5
    # Bookkeeping
    assert budget.total_records == 5
    assert budget.dropped_by_category == {"process-info": 3}


def test_per_category_caps_independent():
    """A category at cap doesn't squeeze other categories out."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"process-info": 2, "mach-lookup": 5},
        refill_rates={"process-info": 0.0, "mach-lookup": 0.0},
        sampling_rates={},
        clock=clock,
    )
    # Burn process-info, then push mach-lookup.
    for _ in range(4):
        budget.evaluate("process-info-pidinfo", pid=10)
    for _ in range(5):
        d, _ = budget.evaluate("mach-lookup", pid=10)
        assert d == audit_budget.KEEP
    assert budget.category_counts["process-info"] == 2
    assert budget.category_counts["mach-lookup"] == 5


# ---------------------------------------------------------------------
# Token bucket refill
# ---------------------------------------------------------------------

def test_token_bucket_refills_over_time():
    """A burst that empties the bucket can resume after the refill
    rate has produced new tokens. Verifies the bucket is rate-
    limited rather than hard-capped."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"network": 3},
        refill_rates={"network": 1.0},   # 1/sec sustained
        sampling_rates={},
        clock=clock,
    )
    # Burst of 3 — bucket empties.
    for _ in range(3):
        d, _ = budget.evaluate("network-outbound", pid=1)
        assert d == audit_budget.KEEP
    # 4th immediate → drop.
    d, m = budget.evaluate("network-outbound", pid=1)
    assert d == audit_budget.DROP
    assert m is not None  # first-drop marker
    # Advance 2 seconds → 2 tokens regenerated → 2 more should pass.
    clock.advance(2.0)
    for _ in range(2):
        d, _ = budget.evaluate("network-outbound", pid=1)
        assert d == audit_budget.KEEP
    # 3rd → drop again (bucket empty, no marker — already emitted).
    d, m = budget.evaluate("network-outbound", pid=1)
    assert d == audit_budget.DROP
    assert m is None


def test_token_bucket_capped_at_capacity():
    """Long idle period doesn't accumulate tokens past capacity —
    operators get burst-tolerance equal to the cap, not unbounded."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"network": 5},
        refill_rates={"network": 1.0},
        sampling_rates={},
        clock=clock,
    )
    # Burn 1 token, then idle for an hour.
    budget.evaluate("network-outbound", pid=1)
    clock.advance(3600.0)
    # Should have at most 5 tokens (capacity), so 5 evaluates pass
    # and the 6th drops.
    for _ in range(5):
        d, _ = budget.evaluate("network-outbound", pid=1)
        assert d == audit_budget.KEEP
    d, _ = budget.evaluate("network-outbound", pid=1)
    assert d == audit_budget.DROP


# ---------------------------------------------------------------------
# Per-PID cap
# ---------------------------------------------------------------------

def test_pid_cap_isolates_chatty_pid():
    """One spamming subprocess can't squeeze sibling PIDs out."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        pid_cap=3,
        category_caps={"file-write": 100},
        refill_rates={"file-write": 0.0},
        sampling_rates={},
        clock=clock,
    )
    # PID 100 spams 5 events — only 3 keep.
    decisions = []
    markers = []
    for _ in range(5):
        d, m = budget.evaluate("file-write-data", pid=100)
        decisions.append(d)
        if m is not None:
            markers.append(m)
    assert decisions[:3] == [audit_budget.KEEP] * 3
    assert decisions[3:] == [audit_budget.DROP] * 2
    assert len(markers) == 1
    assert markers[0]["type"] == "pid_budget_exceeded"
    assert markers[0]["pid"] == 100
    # PID 200 unaffected.
    for _ in range(3):
        d, _ = budget.evaluate("file-write-data", pid=200)
        assert d == audit_budget.KEEP


# ---------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------

def test_sampling_emits_one_in_n_after_cap():
    """High-volume categories with a sampling rate get a trickle
    even after the bucket empties — operators see "still happening"
    rather than going completely dark."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"file-read-metadata": 2},
        refill_rates={"file-read-metadata": 0.0},
        sampling_rates={"file-read-metadata": 3},  # 1-in-3 after cap
        clock=clock,
    )
    decisions = []
    for _ in range(10):
        d, _ = budget.evaluate("file-read-metadata", pid=1)
        decisions.append(d)
    # First 2 keep (in-bucket), then over cap with 1-in-3 sampling.
    # Drops at index 2,3 then keep at 4 (3rd over-cap is sampled),
    # drop 5,6, keep 7, drop 8,9.
    assert decisions[0] == audit_budget.KEEP
    assert decisions[1] == audit_budget.KEEP
    # Pattern: D D K D D K D D for indices 2..9 (every 3rd over-cap kept).
    over_cap = decisions[2:]
    keeps_post = sum(1 for d in over_cap if d == audit_budget.KEEP)
    # 8 over-cap events → 8/3 = 2 sampled.
    assert keeps_post == 2


def test_sampling_marker_advertises_sampling_rate():
    """The marker that fires when sampling kicks in tells operators
    explicitly what the post-cap rate is."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"iokit-open": 1},
        refill_rates={"iokit-open": 0.0},
        sampling_rates={"iokit-open": 7},
        clock=clock,
    )
    budget.evaluate("iokit-open", pid=1)  # in-bucket
    markers = []
    for _ in range(7):
        _, m = budget.evaluate("iokit-open", pid=1)
        if m is not None:
            markers.append(m)
    assert len(markers) == 1
    assert markers[0]["type"] == "category_budget_exceeded_sampling"
    assert markers[0]["sampling_rate"] == 7


# ---------------------------------------------------------------------
# Global cap
# ---------------------------------------------------------------------

def test_global_cap_fires_when_categories_collectively_exhaust():
    """No single category at cap — but collective volume across
    many small categories trips the global ceiling. pid_cap pinned
    high so the per-PID gate doesn't dominate (when global_cap is
    overridden small, the proportional scale would make pid_cap=2,
    which would mask the global-cap behaviour we're testing)."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        global_cap=5,
        pid_cap=1000,  # don't let per-PID scale steal the show
        # Inflate per-cat caps so the global ceiling is the binding
        # constraint, not per-cat.
        category_caps={"network": 100, "process-exec": 100},
        refill_rates={"network": 0.0, "process-exec": 0.0},
        sampling_rates={},
        clock=clock,
    )
    decisions = []
    for i in range(8):
        cat = "network-outbound" if i % 2 == 0 else "execve"
        d, _ = budget.evaluate(cat, pid=1)
        decisions.append(d)
    # 5 keep, 3 drop.
    assert sum(1 for d in decisions if d == audit_budget.KEEP) == 5
    assert sum(1 for d in decisions if d == audit_budget.DROP) == 3


# ---------------------------------------------------------------------
# CLI scaling
# ---------------------------------------------------------------------

def test_cli_global_override_scales_per_category_caps():
    """When --audit-budget=N is set without per-category overrides,
    per-cat caps must scale proportionally so the operator's intent
    (more headroom overall) reaches the per-cat layer."""
    default = audit_budget.AuditBudget()
    larger = audit_budget.AuditBudget(global_cap=100000)  # 10x default
    # Each per-cat cap should be ~10x.
    for cat, default_cap in audit_budget.DEFAULT_CATEGORY_CAPS.items():
        assert larger.category_caps[cat] == default_cap * 10, (
            f"category {cat}: expected {default_cap*10}, "
            f"got {larger.category_caps[cat]}"
        )
    # default unchanged.
    for cat, default_cap in audit_budget.DEFAULT_CATEGORY_CAPS.items():
        assert default.category_caps[cat] == default_cap


def test_cli_global_override_scales_pid_cap_too():
    larger = audit_budget.AuditBudget(global_cap=20000)  # 2x default
    assert larger.pid_cap == audit_budget.DEFAULT_PID_CAP * 2


def test_explicit_category_caps_override_scaling():
    """Explicit per-cat overrides win over the proportional scale."""
    b = audit_budget.AuditBudget(
        global_cap=100000,
        category_caps={"file-write": 42},
    )
    assert b.category_caps == {"file-write": 42}


def test_from_cli_state_honours_state_field():
    """from_cli_state reads state._cli_sandbox_audit_budget and
    propagates it to AuditBudget. Tests both None (default) and an
    explicit override."""
    from core.sandbox import state
    state._cli_sandbox_audit_budget = None
    b = audit_budget.from_cli_state()
    assert b.global_cap == audit_budget.DEFAULT_GLOBAL_CAP
    state._cli_sandbox_audit_budget = 250
    b = audit_budget.from_cli_state()
    assert b.global_cap == 250
    state._cli_sandbox_audit_budget = None  # cleanup (autouse fixture also resets)


# ---------------------------------------------------------------------
# Summary record
# ---------------------------------------------------------------------

def test_summary_record_includes_all_counts():
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"network": 100, "file-write": 100},
        refill_rates={"network": 0.0, "file-write": 0.0},
        sampling_rates={},
        clock=clock,
    )
    for _ in range(3):
        budget.evaluate("network-outbound", pid=1)
    for _ in range(5):
        budget.evaluate("file-write-data", pid=2)
    s = budget.summary_record()
    assert s["type"] == "audit_summary"
    assert s["total_records"] == 8
    assert s["category_counts"] == {"network": 3, "file-write": 5}
    assert s["pid_counts"] == {1: 3, 2: 5}
    assert s["dropped_by_category"] == {}


def test_pop_global_cap_notice_one_shot():
    """pop_global_cap_notice() returns True ONCE after the global
    cap fires, then False forever. Used by callers (Linux tracer)
    to emit a one-time stderr line."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        global_cap=2, pid_cap=1000,
        category_caps={"network": 100},
        refill_rates={"network": 0.0},
        sampling_rates={},
        clock=clock,
    )
    # Before any drops — no notice.
    assert budget.pop_global_cap_notice() is False
    # Two events fit, third drops on global cap.
    for _ in range(3):
        budget.evaluate("network-outbound", pid=1)
    # First call returns True (notice owed).
    assert budget.pop_global_cap_notice() is True
    # Subsequent calls return False — caller already got the cue.
    assert budget.pop_global_cap_notice() is False


def test_pid_dict_lru_eviction_caps_memory():
    """A target spawning many distinct PIDs must not balloon
    _pid_counts unbounded. After _pid_dict_cap entries, oldest
    are evicted."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"file-write": 10000},
        refill_rates={"file-write": 0.0},
        sampling_rates={},
        clock=clock,
    )
    budget._pid_dict_cap = 5  # tighten for the test
    for pid in range(20):
        budget.evaluate("file-write-data", pid=pid)
    # Only the 5 most-recent PIDs survive.
    assert len(budget._pid_counts) == 5
    assert set(budget._pid_counts) == {15, 16, 17, 18, 19}


def test_global_cap_drop_refunds_category_token():
    """When global cap (not category cap) drops a record, the
    category token is refunded so the bucket isn't drained
    spuriously. Without this, repeated global-cap drops would
    permanently drain category buckets even though the actual
    constraint is global."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        global_cap=2,
        pid_cap=1000,
        category_caps={"network": 5},
        refill_rates={"network": 0.0},
        sampling_rates={},
        clock=clock,
    )
    # Burn the global cap with two records.
    budget.evaluate("network-outbound", pid=1)
    budget.evaluate("network-outbound", pid=1)
    # Capture bucket state.
    tokens_before, _ = budget._buckets["network"]  # 5 - 2 = 3
    assert tokens_before == 3.0
    # Drop one more — global cap refuses, category refund kicks in.
    decision, _ = budget.evaluate("network-outbound", pid=1)
    assert decision == audit_budget.DROP
    tokens_after, _ = budget._buckets["network"]
    # Bucket is unchanged: take consumed, then refund restored.
    assert tokens_after == 3.0


def test_sampling_marker_fires_on_first_drop():
    """The sampling marker now emits on the FIRST over-cap drop,
    not the Nth. Operators see the state-change cue immediately
    instead of N silent drops first."""
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"file-read-metadata": 1},
        refill_rates={"file-read-metadata": 0.0},
        sampling_rates={"file-read-metadata": 5},
        clock=clock,
    )
    # First event in-bucket — no marker.
    _, m0 = budget.evaluate("file-read-metadata", pid=1)
    assert m0 is None
    # Second event over-cap — first drop, marker fires NOW.
    _, m1 = budget.evaluate("file-read-metadata", pid=1)
    assert m1 is not None
    assert m1["type"] == "category_budget_exceeded_sampling"
    # Third+ — no further markers (already emitted).
    for _ in range(3):
        _, m = budget.evaluate("file-read-metadata", pid=1)
        assert m is None


def test_summary_record_after_drops():
    clock = _FakeClock()
    budget = audit_budget.AuditBudget(
        category_caps={"network": 2},
        refill_rates={"network": 0.0},
        sampling_rates={},
        clock=clock,
    )
    for _ in range(5):
        budget.evaluate("network-outbound", pid=1)
    s = budget.summary_record()
    assert s["total_records"] == 2
    assert s["dropped_by_category"] == {"network": 3}
