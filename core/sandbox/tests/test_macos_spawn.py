"""Darwin-only tests for ``core.sandbox._macos_spawn``.

These tests invoke ``/usr/bin/sandbox-exec`` and assert behavioural
outcomes (writes blocked, network blocked, audit JSONL produced).
They skip cleanly on Linux so the CI suite stays green there; the
macOS runner picks them up.

Cross-platform smoke tests for the kwarg surface (signature parity
with Linux _spawn) live alongside as plain unit tests so we catch
breakage at every PR even before the macOS runner is wired up.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from core.sandbox import _macos_spawn

darwin_only = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS-only — sandbox-exec is Apple-specific",
)


# --- Cross-platform sanity tests (signature parity, no exec) ----------

def test_run_sandboxed_signature_matches_linux_spawn():
    """Backend dispatch in context.py keys off platform and forwards
    the SAME kwargs to whichever backend. Any kwarg present on
    _spawn.run_sandboxed but absent on _macos_spawn.run_sandboxed
    becomes an unexpected-keyword TypeError on macOS at runtime.
    Inspect both signatures and assert _macos_spawn accepts every
    Linux kwarg (extra Linux-only kwargs are accepted-and-ignored,
    which the explicit `noqa: ARG001` annotations document)."""
    import inspect
    from core.sandbox import _spawn as linux_spawn
    linux_params = set(
        inspect.signature(linux_spawn.run_sandboxed).parameters.keys()
    )
    macos_params = set(
        inspect.signature(_macos_spawn.run_sandboxed).parameters.keys()
    )
    missing = linux_params - macos_params
    assert not missing, (
        f"_macos_spawn.run_sandboxed missing kwargs from Linux "
        f"_spawn.run_sandboxed: {missing}"
    )


def test_is_available_returns_bool():
    """is_available is the cheap presence check; it must return a
    bool regardless of platform (False on Linux, may be True or
    False on macOS depending on whether sandbox-exec is installed)."""
    assert isinstance(_macos_spawn.is_available(), bool)


def test_is_available_false_on_non_darwin():
    """On Linux, /usr/bin/sandbox-exec doesn't exist; is_available
    must return False without raising."""
    if sys.platform == "darwin":
        pytest.skip("Darwin host — is_available may legitimately be True")
    assert _macos_spawn.is_available() is False


# --- Darwin-only behavioural tests ------------------------------------

@darwin_only
def test_smoke_test_invocation_succeeds(tmp_path):
    """Most basic smoke test: run /usr/bin/true under the sandbox.
    Confirms sandbox-exec invocation works AND our kwarg threading
    doesn't break the simplest possible invocation."""
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/true"],
        output=str(tmp_path),
        capture_output=True,
        timeout=10,
    )
    assert r.returncode == 0
    assert r.sandbox_info["backend"] == "macos-seatbelt"


@darwin_only
def test_write_outside_output_blocked(tmp_path):
    """Enforcement: write to a path OUTSIDE the writable allowlist
    must fail (sandbox-exec returns the kernel sandbox error)."""
    output = tmp_path / "out"
    output.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    target_file = other / "should_not_exist"
    py = (
        f"import os\n"
        f"try:\n"
        f"    open({str(target_file)!r}, 'w').write('x')\n"
        f"    print('LEAK')\n"
        f"except OSError as e:\n"
        f"    print('BLOCKED', e.errno)\n"
    )
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        capture_output=True, text=True, timeout=10,
    )
    # The process should still run successfully (returncode 0); the
    # WRITE inside should fail. If sandbox-exec totally blocked exec
    # we'd see rc != 0; that's a different bug.
    assert r.returncode == 0
    assert "BLOCKED" in r.stdout
    assert "LEAK" not in r.stdout
    assert not target_file.exists()


@darwin_only
def test_write_inside_output_allowed(tmp_path):
    """Inverse of the above: writes INSIDE output= must succeed.
    Catches over-restrictive profile generation."""
    output = tmp_path / "out"
    output.mkdir()
    target_file = output / "allowed"
    py = f"open({str(target_file)!r}, 'w').write('ok')"
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    assert target_file.exists()
    assert target_file.read_text() == "ok"


@darwin_only
def test_write_to_private_tmp_allowed():
    """The default exception list always includes /private/tmp so
    standard temp-file APIs keep working. Regression catch: if we
    drop /private/tmp from the default list, every tool that
    writes to tempfile.mkstemp() breaks under our sandbox."""
    py = (
        "import tempfile\n"
        "f = tempfile.mkstemp(prefix='macos_spawn_test_')[1]\n"
        "open(f, 'w').write('ok')\n"
        "import os; os.unlink(f)\n"
        "print('OK')\n"
    )
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    assert "OK" in r.stdout


@darwin_only
def test_block_network_actually_blocks(tmp_path):
    """block_network=True must cause network connect to fail. Use a
    non-routable address with a short timeout to keep the test fast
    even if the deny doesn't engage."""
    py = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 443))\n"
        "    print('LEAK')\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e.errno)\n"
    )
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(tmp_path),
        block_network=True,
        capture_output=True, text=True, timeout=10,
    )
    assert "BLOCKED" in r.stdout
    assert "LEAK" not in r.stdout


@darwin_only
def test_audit_mode_writes_jsonl(tmp_path):
    """End-to-end: with audit_mode=True the LogStreamer must
    capture sandbox kext entries and append them as JSONL records
    matching the Linux schema."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    # Trigger a write under audit mode. The (with report) clause
    # makes it succeed AND log.
    target_file = output / "audited"
    py = f"open({str(target_file)!r}, 'w').write('x')"
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        audit_mode=True,
        audit_run_dir=str(audit_dir),
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    # Allow the kernel→log→stream pipeline a moment to flush. Spike
    # #4 measured ~1.5s end-to-end; the LogStreamer.stop() drain
    # window covers most of this but in CI the wall-clock can stretch.
    time.sleep(2.0)
    jsonl_path = audit_dir / ".sandbox-denials.jsonl"
    assert jsonl_path.exists(), (
        "audit_mode=True did not produce .sandbox-denials.jsonl"
    )
    lines = jsonl_path.read_text().splitlines()
    # We want at least one record about our write — be lenient
    # about which one (the kernel may emit multiple file-* entries
    # for one Python write).
    parsed = [json.loads(l) for l in lines if l.strip()]
    matching = [r for r in parsed if "audited" in r.get("path", "")]
    assert matching, (
        f"no audit record matched our test path; got {len(parsed)} "
        f"records, paths={[r.get('path') for r in parsed]}"
    )


@darwin_only
def test_fake_home_redirects_HOME(tmp_path):
    """fake_home=True must override HOME inside the child. The
    profile itself doesn't restrict HOME (env-side concern); the
    test confirms the env override actually reached the child."""
    output = tmp_path / "out"
    output.mkdir()
    py = "import os; print(os.environ.get('HOME'))"
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        fake_home=True,
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    expected = os.path.realpath(str(output / ".home"))
    actual = os.path.realpath(r.stdout.strip())
    assert actual == expected


@darwin_only
def test_rlimits_applied(tmp_path):
    """Resource limits must apply via the preexec_fn pattern. Test
    with a small max_file_mb (file size cap)."""
    py = (
        "import resource\n"
        "soft, _ = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
        "print(soft)\n"
    )
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(tmp_path),
        limits={"max_file_mb": 10},
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    soft = int(r.stdout.strip())
    # 10 MB cap — let preexec set it; assert the child SEES the cap.
    assert soft == 10 * 1024 * 1024


@darwin_only
def test_audit_verbose_records_extended_categories(tmp_path):
    """End-to-end: with audit_verbose=True, the SBPL profile gets
    `(allow X (with report))` for an extended set of categories
    (file-read-data, mach-lookup, process-exec*, process-fork,
    signal, file-read-metadata, process-info*, iokit-open,
    sysctl-read). The LogStreamer must capture records from MORE
    than just file-write events.

    Mirror of the Linux test_spawn_audit.py pattern: run a real
    sandboxed subprocess, then inspect the JSONL the streamer
    appended. Asserts on category breadth, not exact counts (the
    kernel→log pipeline timing varies)."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    # Workload that exercises several action categories: writes a
    # file (file-write), reads a system file (file-read-data),
    # opens IOKit-style resource info (mach-lookup), execs a child
    # (process-exec / process-fork). Don't actually need the spawn
    # to succeed — just need the SYSCALLS to fire so the kernel
    # emits sandbox events.
    target_file = output / "audited"
    py = (
        f"open({str(target_file)!r}, 'w').write('x')\n"
        f"open('/etc/hostname', 'r').read()\n"
        f"import subprocess; subprocess.run(['/bin/echo','hi'], "
        f"capture_output=True)\n"
    )
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        audit_mode=True,
        audit_verbose=True,
        audit_run_dir=str(audit_dir),
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, (
        f"workload failed: stderr={r.stderr!r}"
    )
    # Allow kernel→log→stream pipeline to flush.
    time.sleep(2.0)
    jsonl_path = audit_dir / ".sandbox-denials.jsonl"
    assert jsonl_path.exists(), (
        "audit_verbose=True did not produce .sandbox-denials.jsonl"
    )
    records = [json.loads(l) for l in
                jsonl_path.read_text().splitlines() if l.strip()]
    # Filter out control-plane records (audit_summary, markers).
    data = [r for r in records if "syscall" in r]
    assert data, f"expected data records, got: {records!r}"
    # Verbose audit MUST show categories beyond just file-write.
    # We accept ANY non-write category (the workload triggers many,
    # but exact set depends on macOS version + dyld behaviour).
    types_seen = {r["type"] for r in data}
    assert types_seen != {"write"}, (
        f"audit_verbose only captured write events — extended "
        f"category SBPL clauses didn't engage. Types: {types_seen}"
    )


@darwin_only
def test_audit_summary_record_emitted(tmp_path):
    """LogStreamer.stop() must always emit an audit_summary record
    so the sandbox-summary aggregator can distinguish "audit ran
    cleanly" from "audit dir empty because streamer never started"."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    target_file = output / "audited"
    py = f"open({str(target_file)!r}, 'w').write('x')"
    _macos_spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", py],
        output=str(output),
        audit_mode=True,
        audit_run_dir=str(audit_dir),
        capture_output=True, text=True, timeout=10,
    )
    time.sleep(1.0)
    jsonl_path = audit_dir / ".sandbox-denials.jsonl"
    records = [json.loads(l) for l in
                jsonl_path.read_text().splitlines() if l.strip()]
    summaries = [r for r in records if r.get("type") == "audit_summary"]
    assert len(summaries) == 1, (
        f"expected exactly one audit_summary record, got "
        f"{len(summaries)}; all records: {records!r}"
    )
    s = summaries[0]
    assert "total_records" in s
    assert "category_counts" in s
    assert "dropped_by_category" in s
    assert "global_cap" in s


@darwin_only
def test_audit_budget_drops_when_cap_hit(tmp_path):
    """End-to-end budget enforcement: pass a tiny global cap and
    verify the JSONL contains a budget_exceeded marker. Uses the
    LogStreamer's `budget` injection point so we don't need to
    fiddle with CLI state for the test."""
    from core.sandbox import audit_budget, seatbelt_audit
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    # Build an instance with a tight cap + no refill so the
    # workload's first few file events are kept then everything
    # else drops.
    budget = audit_budget.AuditBudget(
        global_cap=3,
        pid_cap=1000,
        category_caps={"file-write": 3, "file-read-data": 3},
        refill_rates={"file-write": 0.0, "file-read-data": 0.0},
        sampling_rates={},
    )
    streamer = seatbelt_audit.LogStreamer(audit_dir, budget=budget)
    # Manually drive a few synthetic records through the budget +
    # streamer's append path to verify the marker emits. (Full
    # subprocess invocation also works but is harder to make
    # deterministic given kernel timing.)
    for i in range(8):
        record = {
            "ts": "2026-05-03T10:00:00+00:00",
            "cmd": f"<sandbox audit: file-write-data /tmp/{i}>",
            "type": "write", "audit": True, "verdict": "allow",
            "syscall": "file-write-data", "path": f"/tmp/{i}",
            "target_pid": 999, "process_name": "test",
        }
        decision, marker = budget.evaluate(
            record["syscall"], record["target_pid"],
        )
        if marker is not None:
            streamer._append_record(marker)
        if decision == audit_budget.KEEP:
            streamer._append_record(record)
    streamer.stop()
    records = [json.loads(l) for l in
                (audit_dir / seatbelt_audit.DENIALS_FILE)
                .read_text().splitlines() if l.strip()]
    markers = [r for r in records
                if r.get("type") in ("category_budget_exceeded",
                                     "category_budget_exceeded_sampling")]
    assert len(markers) == 1, (
        f"expected 1 budget marker, got {len(markers)}; "
        f"records: {records!r}"
    )
    summary = next(r for r in records if r.get("type") == "audit_summary")
    assert summary["dropped_by_category"]["file-write"] == 5


@darwin_only
def test_seccomp_kwargs_silently_ignored(tmp_path):
    """seccomp_profile= and seccomp_block_udp= are Linux-only;
    accepted on macOS for signature parity but must NOT raise.
    Catches accidental kwarg-rejection."""
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/true"],
        output=str(tmp_path),
        seccomp_profile="full",
        seccomp_block_udp=True,
        capture_output=True, timeout=10,
    )
    assert r.returncode == 0
