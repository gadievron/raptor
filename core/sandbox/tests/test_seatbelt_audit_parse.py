"""macOS audit-log parser tests — cross-platform.

These tests exercise ``core.sandbox.seatbelt_audit.parse_log_entry``
and the JSONL-append behaviour of ``LogStreamer._append_record``
without spawning ``log stream``. The Darwin-only end-to-end log
capture lives in test_macos_e2e.py.

Sample entries are reproduced from spike #4 output (run on macOS
26.4.1 arm64) so the regex and field expectations are anchored to
real kernel output, not invented.
"""

from __future__ import annotations

import json

from core.sandbox import seatbelt_audit
from core.sandbox.seatbelt import SANDBOX_KEXT_SENDER


# Real Sandbox.kext entry observed in spike #4 (formatting trimmed
# to the fields we read). Spike #4 confirmed:
#   subsystem="" category=""  ← cannot filter on these
#   senderImagePath = SANDBOX_KEXT_SENDER  ← reliable filter
#   eventMessage   = "Sandbox: <name>(<pid>) <verdict> <action> <path>"
def _kext_entry(*, msg: str, ts: str = "2026-04-30 12:34:56.789012+0000"):
    return {
        "senderImagePath": SANDBOX_KEXT_SENDER,
        "eventMessage": msg,
        "timestamp": ts,
        "subsystem": "",
        "category": "",
    }


def test_parse_allow_file_write_create():
    """Canonical (with report) entry: file-write-create allowed +
    logged. Spike #4 verified this format."""
    entry = _kext_entry(msg="Sandbox: Python(12345) allow file-write-create /private/tmp/x")
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["verdict"] == "allow"
    assert rec["syscall"] == "file-write-create"
    assert rec["path"] == "/private/tmp/x"
    assert rec["target_pid"] == 12345
    assert rec["process_name"] == "Python"
    assert rec["audit"] is True
    assert rec["type"] == "write"


def test_parse_deny_file_read_data():
    entry = _kext_entry(msg="Sandbox: ls(99) deny file-read-data /etc/passwd")
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["verdict"] == "deny"
    assert rec["syscall"] == "file-read-data"
    assert rec["type"] == "read"
    assert rec["path"] == "/etc/passwd"


def test_parse_network_outbound():
    entry = _kext_entry(
        msg="Sandbox: curl(2222) deny network-outbound /tmp/sock"
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["type"] == "network"
    assert rec["syscall"] == "network-outbound"


def test_parse_action_to_type_mapping():
    """The taxonomy must mirror Linux's _NAME_TO_TYPE so
    summarize_and_write produces consistent buckets across
    platforms."""
    assert seatbelt_audit._action_to_type("file-write-create") == "write"
    assert seatbelt_audit._action_to_type("file-write-data") == "write"
    assert seatbelt_audit._action_to_type("file-mknod") == "write"
    assert seatbelt_audit._action_to_type("file-read-data") == "read"
    assert seatbelt_audit._action_to_type("file-read-metadata") == "read"
    assert seatbelt_audit._action_to_type("network-outbound") == "network"
    assert seatbelt_audit._action_to_type("network-inbound") == "network"
    # Catch-all: mach/iokit/sysctl/process actions land in the closest
    # Linux analogue ("seccomp" — that's the bucket Linux uses for
    # syscall-class denials).
    assert seatbelt_audit._action_to_type("mach-lookup") == "seccomp"
    assert seatbelt_audit._action_to_type("iokit-open") == "seccomp"
    assert seatbelt_audit._action_to_type("sysctl-read") == "seccomp"


def test_parse_drops_non_kext_sender():
    """Entries from other senders (e.g. com.apple.WindowServer) must
    be silently dropped — we only care about Sandbox.kext output."""
    entry = {
        "senderImagePath": "/System/Library/Frameworks/Foo.framework/Foo",
        "eventMessage": "Sandbox: ls(99) deny file-read-data /etc/passwd",
    }
    assert seatbelt_audit.parse_log_entry(entry) is None


def test_parse_drops_unparseable_message():
    """A kext entry whose eventMessage doesn't match the
    Sandbox-format regex (other kext output, or a future format
    change) must drop silently rather than crash."""
    entry = _kext_entry(msg="Sandbox profile evaluated successfully")
    assert seatbelt_audit.parse_log_entry(entry) is None


def test_parse_drops_missing_eventmessage():
    """Defensive: entries with no eventMessage at all must drop
    cleanly — log stream occasionally emits skeletal entries."""
    entry = {"senderImagePath": SANDBOX_KEXT_SENDER}
    assert seatbelt_audit.parse_log_entry(entry) is None


def test_parse_handles_path_with_spaces():
    """File paths with spaces are common on macOS (~/Library/Application
    Support/...). The regex's `(.+)$` greedy tail captures them
    intact."""
    entry = _kext_entry(
        msg="Sandbox: foo(1) deny file-read-data /Users/Bob/Library/Application Support/x"
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["path"] == "/Users/Bob/Library/Application Support/x"


def test_parse_uses_entry_timestamp():
    """The kernel-supplied timestamp is preserved when present —
    important for ordering against host-side events. Falls back to
    now() when absent (spike confirmed timestamps are usually
    populated, but defensive)."""
    entry = _kext_entry(
        msg="Sandbox: foo(1) allow file-write-create /tmp/x",
        ts="2026-04-30 12:00:00.000000+0000",
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec["ts"] == "2026-04-30 12:00:00.000000+0000"


def test_parse_falls_back_to_now_when_no_timestamp():
    entry = {
        "senderImagePath": SANDBOX_KEXT_SENDER,
        "eventMessage": "Sandbox: foo(1) allow file-write-create /tmp/x",
    }
    rec = seatbelt_audit.parse_log_entry(entry)
    # Some ISO-format string is generated; we don't assert on the
    # exact value but it must be present and roughly resemble ISO.
    assert "T" in rec["ts"]
    assert "+" in rec["ts"] or "Z" in rec["ts"]


def test_log_streamer_appends_one_line_per_record(tmp_path):
    """End-to-end JSONL append behaviour: each record is one JSON
    object per line (matches Linux summary.record_denial format
    exactly)."""
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    rec1 = {"a": 1}
    rec2 = {"b": 2}
    streamer._append_record(rec1)
    streamer._append_record(rec2)
    path = tmp_path / seatbelt_audit.DENIALS_FILE
    assert path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == rec1
    assert json.loads(lines[1]) == rec2


def test_log_streamer_creates_run_dir(tmp_path):
    """The streamer must materialise its own run_dir if absent —
    mirrors Linux summary.record_denial behaviour."""
    new_dir = tmp_path / "fresh"
    assert not new_dir.exists()
    streamer = seatbelt_audit.LogStreamer(new_dir)
    streamer._append_record({"x": 1})
    assert new_dir.exists()
    assert (new_dir / seatbelt_audit.DENIALS_FILE).exists()


# --- LogStreamer ↔ AuditBudget integration ----------------------------
# Pure-budget mechanics live in test_audit_budget.py. The integration
# tests below verify that LogStreamer wires its (parsed) records to
# the budget AND emits a summary record on stop().

def test_log_streamer_uses_injected_budget_for_summary(tmp_path):
    """stop() must always emit an audit_summary record sourced from
    the budget. Tests the wiring: inject a budget with known state,
    call stop(), verify the JSONL contains the budget's summary."""
    from core.sandbox import audit_budget
    budget = audit_budget.AuditBudget()
    # Bump the budget's internal counters via real evaluate calls
    # (no clock games needed — we just want non-zero state).
    budget.evaluate("file-write-data", pid=42)
    budget.evaluate("file-write-data", pid=42)
    budget.evaluate("network-outbound", pid=99)

    streamer = seatbelt_audit.LogStreamer(tmp_path, budget=budget)
    # No proc started — stop() should still flush the summary.
    streamer.stop()

    lines = (tmp_path / seatbelt_audit.DENIALS_FILE).read_text().splitlines()
    summaries = [json.loads(l) for l in lines
                  if json.loads(l).get("type") == "audit_summary"]
    assert len(summaries) == 1
    s = summaries[0]
    assert s["total_records"] == 3
    assert s["category_counts"] == {"file-write": 2, "network": 1}
    # JSON round-trip stringifies int dict keys — match what
    # operators actually read from the JSONL.
    assert s["pid_counts"] == {"42": 2, "99": 1}


def test_log_streamer_default_budget_is_cli_aware(tmp_path):
    """LogStreamer with no explicit budget pulls one from
    audit_budget.from_cli_state() — picks up --audit-budget."""
    from core.sandbox import state
    state._cli_sandbox_audit_budget = 250
    try:
        streamer = seatbelt_audit.LogStreamer(tmp_path)
        assert streamer._budget.global_cap == 250
    finally:
        state._cli_sandbox_audit_budget = None


def test_log_streamer_o_nofollow_blocks_symlink(tmp_path):
    """Defence in depth: a sandboxed child with write access to
    run_dir could pre-plant DENIALS_FILE as a symlink to a host
    file. O_NOFOLLOW must reject the open with ELOOP rather than
    follow the link and append to the host file."""
    target = tmp_path / "target"
    target.write_text("")
    link = tmp_path / seatbelt_audit.DENIALS_FILE
    link.symlink_to(target)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    try:
        streamer._append_record({"x": 1})
        # If we reach here, O_NOFOLLOW didn't engage — fail loudly.
        assert False, "O_NOFOLLOW should have blocked the symlink"
    except OSError as e:
        # ELOOP on Linux, similar errno on macOS — either way, the
        # symlink was refused.
        assert e.errno in (40, 62), f"unexpected errno {e.errno}"
    # The symlink target must remain empty (no leak).
    assert target.read_text() == ""
