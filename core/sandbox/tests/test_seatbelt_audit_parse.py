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
import os

from core.sandbox import evidence as evidence_mod
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


def test_parse_repeat_count_verdict_shape():
    """The kernel coalesces repeated events as `deny(N) <action>`.
    Pre-fix the regex required a bare verdict and dropped these
    records entirely."""
    entry = _kext_entry(
        msg="Sandbox: ls(99) deny(12) file-read-data /etc/passwd"
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["verdict"] == "deny"
    assert rec["syscall"] == "file-read-data"
    assert rec["path"] == "/etc/passwd"
    assert rec["target_pid"] == 99


def test_parse_process_name_with_spaces():
    """Process names with spaces are common on macOS (helper apps).
    Pre-fix the \\S+ name arm failed the match."""
    entry = _kext_entry(
        msg="Sandbox: Google Chrome Helper(4242) deny file-read-data /x"
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["process_name"] == "Google Chrome Helper"
    assert rec["target_pid"] == 4242


def test_parse_process_name_with_parens():
    """Names containing parentheses must not confuse the PID capture —
    the LAST `(digits)` before the verdict is the PID."""
    entry = _kext_entry(
        msg="Sandbox: Helper (Renderer)(77) allow(3) file-write-create /tmp/y"
    )
    rec = seatbelt_audit.parse_log_entry(entry)
    assert rec is not None
    assert rec["process_name"] == "Helper (Renderer)"
    assert rec["target_pid"] == 77
    assert rec["verdict"] == "allow"
    assert rec["path"] == "/tmp/y"


class _FakeLogProc:
    """Stand-in for the `log stream` Popen: stdout is a plain list of
    ndjson lines; terminate/wait are no-ops."""

    def __init__(self, lines):
        self.stdout = list(lines)

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0


def test_parse_ratio_diagnostic_on_high_drop(tmp_path, caplog):
    """When most kext-sender lines fail to parse (format drift), stop()
    must emit a 'parsed M of N' warning and stamp the counters on the
    audit_summary record."""
    import logging

    good = json.dumps(_kext_entry(
        msg="Sandbox: foo(1) deny file-read-data /etc/passwd"))
    bad = json.dumps(_kext_entry(msg="Sandbox format drifted entirely"))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer._proc = _FakeLogProc([good] + [bad] * 19)
    streamer._read_loop()
    with caplog.at_level(logging.WARNING,
                         logger="core.sandbox.seatbelt_audit"):
        streamer.stop()
    assert any("parsed 1 of 20 kext log lines" in rec.message
               for rec in caplog.records)
    lines = (tmp_path / evidence_mod.AUDIT_SUBDIR
             / seatbelt_audit.DENIALS_FILE).read_text().splitlines()
    summary = next(json.loads(line) for line in lines
                   if json.loads(line).get("type") == "audit_summary")
    assert summary["kext_lines_seen"] == 20
    assert summary["kext_lines_parsed"] == 1


def test_parse_ratio_no_diagnostic_when_healthy(tmp_path, caplog):
    """A healthy parse ratio must NOT trip the drift warning."""
    import logging

    good = json.dumps(_kext_entry(
        msg="Sandbox: foo(1) deny file-read-data /etc/passwd"))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer._proc = _FakeLogProc([good] * 20)
    streamer._read_loop()
    with caplog.at_level(logging.WARNING,
                         logger="core.sandbox.seatbelt_audit"):
        streamer.stop()
    assert not any("kext log lines" in rec.message
                   for rec in caplog.records)


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
    path = (tmp_path / evidence_mod.AUDIT_SUBDIR
            / seatbelt_audit.DENIALS_FILE)
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
    assert (new_dir / evidence_mod.AUDIT_SUBDIR
            / seatbelt_audit.DENIALS_FILE).exists()


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

    lines = (tmp_path / evidence_mod.AUDIT_SUBDIR
             / seatbelt_audit.DENIALS_FILE).read_text().splitlines()
    summaries = [json.loads(line) for line in lines
                  if json.loads(line).get("type") == "audit_summary"]
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


def test_log_streamer_emits_global_cap_marker_once(tmp_path):
    """When the GLOBAL cap fires, the streamer must append the
    one-shot global_budget_exceeded marker in-band — pre-fix only the
    Linux tracer polled the notice (stderr), so macOS global-cap
    suppression was markerless."""
    from core.sandbox import audit_budget
    budget = audit_budget.AuditBudget(
        global_cap=2,
        pid_cap=1000,
        category_caps={"file-write": 100},
        refill_rates={"file-write": 0.0},
        sampling_rates={},
    )
    streamer = seatbelt_audit.LogStreamer(tmp_path, budget=budget)
    streamer._proc = _FakeLogProc([
        json.dumps(_kext_entry(
            msg=f"Sandbox: test(999) allow file-write-data /tmp/{i}"))
        for i in range(6)
    ])
    streamer._read_loop()
    streamer.stop()
    records = [json.loads(line) for line in
               (tmp_path / evidence_mod.AUDIT_SUBDIR
                / seatbelt_audit.DENIALS_FILE)
               .read_text().splitlines() if line.strip()]
    markers = [r for r in records
               if r.get("type") == "global_budget_exceeded"]
    assert len(markers) == 1, f"records: {records!r}"
    assert markers[0]["cap"] == 2
    assert markers[0]["audit"] is True


# --- LogStreamer PID scoping ------------------------------------------
# `log stream` is a host-wide feed: every Sandbox.kext event on the
# machine matches the sender predicate, including events from
# unrelated or sibling sandboxed processes. The scoping layers below
# keep foreign events out of this run's JSONL (and its nonce and
# budget). Canned records; runs hermetically on Linux.

def _scope_record(pid: int, *, action: str = "file-write-data",
                  path: str = "/tmp/x", name: str = "proc") -> dict:
    entry = _kext_entry(msg=f"Sandbox: {name}({pid}) deny {action} {path}")
    return seatbelt_audit.parse_log_entry(entry)


def _no_pgid(monkeypatch):
    """Pin the exact-PID path: process-group AND session resolution
    always fail, as they do for a PID that has already exited (or one
    from a canned record that never existed on the test host)."""
    def _raise(pid):
        raise ProcessLookupError(pid)
    monkeypatch.setattr(seatbelt_audit.os, "getpgid", _raise)
    monkeypatch.setattr(seatbelt_audit.os, "getsid", _raise)


def test_unscoped_streamer_accepts_any_pid(tmp_path):
    """Back-compat: with no scope registered, attribution stays
    host-wide (documented as unguaranteed in the class docstring)."""
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    assert streamer._record_in_scope(_scope_record(4444)) is True


def test_own_pid_event_kept(tmp_path, monkeypatch):
    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(1234)
    assert streamer._record_in_scope(_scope_record(1234)) is True


def test_foreign_pid_event_rejected(tmp_path, monkeypatch):
    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(1234)
    assert streamer._record_in_scope(_scope_record(4444)) is False


def test_record_without_pid_rejected_when_scoped(tmp_path, monkeypatch):
    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(1234)
    rec = _scope_record(1234)
    del rec["target_pid"]
    assert streamer._record_in_scope(rec) is False


def test_process_group_widens_scope(tmp_path, monkeypatch):
    """Children the target forks carry other PIDs but share its
    process group — the parse-time filter must keep them."""
    pgids = {1234: 500, 777: 500, 999: 600}

    def fake_getpgid(pid):
        try:
            return pgids[pid]
        except KeyError:
            raise ProcessLookupError(pid) from None

    def _no_sid(pid):
        raise ProcessLookupError(pid)

    monkeypatch.setattr(seatbelt_audit.os, "getpgid", fake_getpgid)
    monkeypatch.setattr(seatbelt_audit.os, "getsid", _no_sid)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(1234)
    assert streamer._record_in_scope(_scope_record(777)) is True   # same pgid
    assert streamer._record_in_scope(_scope_record(999)) is False  # other pgid
    assert streamer._record_in_scope(_scope_record(31337)) is False  # gone


def test_session_widens_scope(tmp_path, monkeypatch):
    """The production caller registers the OUTER seatbelt shim, whose
    sandbox-exec subtree runs in a DIFFERENT process group (the shim
    forks it into its own group so it can killpg it) but the SAME
    session. The parse-time filter must keep same-session events and
    still reject foreign-session ones."""
    pgids = {1234: 1234, 777: 777, 999: 999}
    sids = {1234: 1234, 777: 1234, 999: 900}

    def fake_getpgid(pid):
        try:
            return pgids[pid]
        except KeyError:
            raise ProcessLookupError(pid) from None

    def fake_getsid(pid):
        try:
            return sids[pid]
        except KeyError:
            raise ProcessLookupError(pid) from None

    monkeypatch.setattr(seatbelt_audit.os, "getpgid", fake_getpgid)
    monkeypatch.setattr(seatbelt_audit.os, "getsid", fake_getsid)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(1234)
    # Different pgid, same session — the shim-forked sandbox subtree.
    assert streamer._record_in_scope(_scope_record(777)) is True
    # Different pgid AND different session — a foreign run.
    assert streamer._record_in_scope(_scope_record(999)) is False


def test_session_widens_scope_real_processes(tmp_path):
    """Same shape as above but against the real OS: a child moved
    into its OWN process group (mirroring the shim's fork of
    sandbox-exec) stays in our session and must remain in scope once
    our own PID is registered."""
    import subprocess
    import sys

    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer.register_target_pid(os.getpid())
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        preexec_fn=os.setpgrp,  # own pgrp, same session — shim analogue
    )
    try:
        assert os.getpgid(child.pid) != os.getpgid(os.getpid())
        assert streamer._record_in_scope(_scope_record(child.pid)) is True
    finally:
        child.kill()
        child.wait(timeout=5)


def test_require_scope_drops_records_before_registration(tmp_path):
    """require_scope=True: nothing may be attributed to this run
    until the caller registers its child — the streamer-start-to-
    registration window must not stamp foreign host events."""
    streamer = seatbelt_audit.LogStreamer(tmp_path, require_scope=True)
    assert streamer._record_in_scope(_scope_record(4444)) is False


def test_require_scope_accepts_registered_pid(tmp_path, monkeypatch):
    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(tmp_path, require_scope=True)
    streamer.register_target_pid(1234)
    assert streamer._record_in_scope(_scope_record(1234)) is True
    assert streamer._record_in_scope(_scope_record(4444)) is False


def test_read_loop_drops_foreign_pid_records(tmp_path, monkeypatch):
    """End-to-end through _read_loop with a canned log-stream feed:
    the foreign-PID event must never be nonce-stamped into this
    run's JSONL; the own-PID event must land."""
    import types

    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(
        tmp_path, observe_mode=True, observe_nonce="nonce-own-run",
    )
    streamer.register_target_pid(1234)
    own = _kext_entry(
        msg="Sandbox: mine(1234) deny file-write-data /tmp/mine",
    )
    foreign = _kext_entry(
        msg="Sandbox: other(4444) deny file-write-data /tmp/theirs",
    )
    streamer._proc = types.SimpleNamespace(
        stdout=[json.dumps(own) + "\n", json.dumps(foreign) + "\n"],
    )
    streamer._read_loop()

    lines = (tmp_path / evidence_mod.AUDIT_SUBDIR
             / seatbelt_audit.OBSERVE_FILE).read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert len(records) == 1
    assert records[0]["target_pid"] == 1234
    assert records[0]["path"] == "/tmp/mine"
    assert records[0]["nonce"] == "nonce-own-run"


def test_predicate_default_is_sender_scoped_only(tmp_path):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    predicate = streamer._build_predicate()
    assert SANDBOX_KEXT_SENDER in predicate
    assert "eventMessage" not in predicate


def test_predicate_pid_scoped_when_target_pid_known(tmp_path):
    streamer = seatbelt_audit.LogStreamer(tmp_path, target_pid=4242)
    predicate = streamer._build_predicate()
    assert SANDBOX_KEXT_SENDER in predicate
    assert 'eventMessage CONTAINS "(4242) "' in predicate


def test_constructor_target_pid_also_registers_parse_scope(tmp_path,
                                                           monkeypatch):
    """Defence in depth: a construction-time target_pid engages the
    parse-time filter too, not just the predicate."""
    _no_pgid(monkeypatch)
    streamer = seatbelt_audit.LogStreamer(tmp_path, target_pid=4242)
    assert streamer._record_in_scope(_scope_record(4242)) is True
    assert streamer._record_in_scope(_scope_record(4444)) is False


def test_start_log_streamer_threads_target_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(seatbelt_audit.LogStreamer, "start",
                        lambda self: None)
    streamer = seatbelt_audit.start_log_streamer(tmp_path, target_pid=99)
    assert streamer._target_pid == 99


def test_log_streamer_o_nofollow_blocks_symlink(tmp_path):
    """Defence in depth: an attacker with write access to the
    evidence dir could pre-plant DENIALS_FILE as a symlink to a host
    file. The evidence open (O_EXCL create → O_NOFOLLOW append
    fallback) must reject it with ELOOP rather than follow the link
    and append to the host file."""
    target = tmp_path / "target"
    target.write_text("")
    evdir = tmp_path / evidence_mod.AUDIT_SUBDIR
    evdir.mkdir(mode=0o700)
    link = evdir / seatbelt_audit.DENIALS_FILE
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


# --- Live stderr escalation: credential-path touches -------------------
# _maybe_escalate_credential_path is pulled out of _read_loop precisely
# so it's testable against a synthetic record without a real `log
# stream` subprocess. See core.sandbox.tracer's mirror-image escalation
# for escape-primitive syscalls (Linux-only, tested in
# test_tracer_event_loop.py).

def test_credential_path_touch_escalates_once(tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    record = {"type": "read", "path": "/Users/x/.ssh/id_rsa",
              "target_pid": 4242}

    streamer._maybe_escalate_credential_path(record)
    assert len(writes) == 1
    assert writes[0][0] == 2
    assert b".ssh/id_rsa" in writes[0][1]

    # Same path again this run: no second banner.
    streamer._maybe_escalate_credential_path(record)
    assert len(writes) == 1, "dedup: one banner per path per run"


def test_non_credential_path_does_not_escalate(tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    record = {"type": "read", "path": "/tmp/ordinary-file.txt",
              "target_pid": 4242}
    streamer._maybe_escalate_credential_path(record)
    assert writes == []


def test_credential_path_escalation_ignores_non_read_write_types(
        tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    # "seccomp" bucket (mach-lookup, process-*, etc.) never carries the
    # same "did the target actually see file content" implication a
    # read/write does — see seatbelt_audit.py's comment on why no
    # macOS escape-primitive-syscall equivalent is fabricated.
    record = {"type": "seccomp", "path": "/Users/x/.ssh/id_rsa",
              "target_pid": 4242}
    streamer._maybe_escalate_credential_path(record)
    assert writes == []


def test_credential_path_escalation_disabled_by_env_var(
        tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED", "1")
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    record = {"type": "write", "path": "/Users/x/.aws/credentials",
              "target_pid": 4242}
    streamer._maybe_escalate_credential_path(record)
    assert writes == []


def test_credential_path_escalation_survives_stderr_write_failure(
        tmp_path, monkeypatch):
    def raising_write(fd, data):
        raise OSError("stderr closed")
    monkeypatch.setattr(seatbelt_audit.os, "write", raising_write)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    record = {"type": "write", "path": "/Users/x/.netrc",
              "target_pid": 4242}
    # Must not raise — mirrors tracer.py's
    # test_escalation_never_raises_out_of_hot_path.
    streamer._maybe_escalate_credential_path(record)
    assert record["path"] in streamer._escalated_paths


def test_credential_path_banner_sanitises_control_chars(
        tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    # The path is attacker-controlled (the target chose what to touch);
    # ESC/BEL are ASCII so ascii/replace encoding alone keeps them.
    record = {"type": "read",
              "path": "/Users/x/.ssh/\x1b]0;pwned\x07id_rsa",
              "target_pid": 4242}
    streamer._maybe_escalate_credential_path(record)
    assert len(writes) == 1
    assert b"\x1b" not in writes[0][1]
    assert b"\x07" not in writes[0][1]
    assert b"\\x1b" in writes[0][1]


def test_credential_path_escalation_tolerates_missing_target_pid(
        tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(seatbelt_audit.os, "write",
                        lambda fd, data: writes.append((fd, data)))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    # never-raise-out-of-the-hot-path: a record shape without
    # target_pid must not KeyError the read loop.
    record = {"type": "read", "path": "/Users/x/.ssh/id_rsa"}
    streamer._maybe_escalate_credential_path(record)
    assert len(writes) == 1
    assert b"pid=-1" in writes[0][1]
