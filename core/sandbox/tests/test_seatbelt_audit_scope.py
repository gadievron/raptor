"""Mandatory scope gate for the macOS seatbelt log streamer.

The `log stream` predicate filters by kext SENDER only, so records
from EVERY sandboxed process on the host reach the streamer. Without
a scope gate, a concurrent RAPTOR run cross-contaminates this run's
denials/observe JSONL, and a hostile same-host sandboxed process can
mint records that get OUR nonce stamped (steering an observe-derived
allowlist). These tests drive the gate with injected process-tree
probes so they are deterministic on any host; the spawn-level tests
run the real shim chain against a pass-through fake sandbox-exec.
"""

from __future__ import annotations

import json
import os

import pytest

from core.sandbox import evidence as evidence_mod
from core.sandbox import seatbelt_audit

ROOT = 5_000_001  # fake workload root (the shim pid)

# Trivial real workload for the spawn-level tests. NOT a hardcoded
# "/bin/true": macOS ships true(1) at /usr/bin/true and has no
# /bin/true at all, so the Linux path made the real shim chain
# exec-fail (exit 126) on macOS hosts. /usr/bin/true exists on both
# macOS and usr-merged Linux; the fallback covers pre-merge layouts.
_TRUE = next(p for p in ("/usr/bin/true", "/bin/true")
             if os.path.exists(p))


def _no_pgid(pid):
    raise ProcessLookupError(pid)


def _streamer(tmp_path, *, ppid_map=None, tree=None, **kwargs):
    """LogStreamer with the mandatory scope gate engaged and all
    process-tree probes injected (no real /proc, ps, or getpgid)."""
    ppid_map = ppid_map or {}
    return seatbelt_audit.LogStreamer(
        tmp_path,
        require_scope=True,
        get_ppid=lambda pid: ppid_map.get(pid),
        getpgid=_no_pgid,
        list_pid_ppids=lambda: list(tree or []),
        # Poller thread not needed for the deterministic tests —
        # _refresh_lineage_from_tree is driven directly.
        lineage_poll_interval=0,
        **kwargs,
    )


def _record(pid, path="/tmp/x"):
    return {
        "ts": "2026-05-03T10:00:00+00:00",
        "cmd": f"<sandbox audit: file-write-data {path}>",
        "returncode": 0,
        "type": "write",
        "verdict": "allow",
        "syscall": "file-write-data",
        "path": path,
        "target_pid": pid,
        "process_name": "test",
        "audit": True,
    }


def _read_jsonl(tmp_path):
    p = (tmp_path / evidence_mod.AUDIT_SUBDIR
         / seatbelt_audit.DENIALS_FILE)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines()
            if line.strip()]


def test_root_and_descendants_admitted_foreign_dropped(tmp_path):
    """PID attribution: the registered root, a ppid-chain descendant,
    and a process seen by the tree poller are admitted; a process
    whose chain ends elsewhere is dropped and counted."""
    child, grandchild, foreign = ROOT + 1, ROOT + 2, ROOT + 500
    streamer = _streamer(
        tmp_path,
        ppid_map={child: ROOT, grandchild: child, foreign: 1},
    )
    streamer.register_target_pid(ROOT)
    streamer._filter_and_append(_record(ROOT, "/tmp/root"))
    streamer._filter_and_append(_record(grandchild, "/tmp/gc"))
    streamer._filter_and_append(_record(foreign, "/tmp/foreign"))
    streamer.stop()

    records = _read_jsonl(tmp_path)
    paths = [r.get("path") for r in records if "path" in r]
    assert "/tmp/root" in paths
    assert "/tmp/gc" in paths
    assert "/tmp/foreign" not in paths
    summary = next(r for r in records if r.get("type") == "audit_summary")
    assert summary["foreign_records_dropped"] == 1


def test_records_before_registration_are_buffered_then_filtered(tmp_path):
    """A required-scoping run must record NOTHING before
    register_target_pid: records that arrive early (spawn/attach
    race) are buffered — not appended — and flushed through the
    scope gate once the root is registered."""
    child, foreign = ROOT + 1, ROOT + 500
    streamer = _streamer(
        tmp_path, ppid_map={child: ROOT, foreign: 1},
    )
    streamer._filter_and_append(_record(child, "/tmp/early-ours"))
    streamer._filter_and_append(_record(foreign, "/tmp/early-foreign"))
    assert _read_jsonl(tmp_path) == []  # nothing written yet
    streamer.register_target_pid(ROOT)
    streamer.stop()

    records = _read_jsonl(tmp_path)
    paths = [r.get("path") for r in records if "path" in r]
    assert "/tmp/early-ours" in paths
    assert "/tmp/early-foreign" not in paths


def test_pending_dropped_when_scope_never_registered(tmp_path):
    """If the spawn fails before register_target_pid, buffered
    records are unattributable: dropped + counted, never written."""
    streamer = _streamer(tmp_path, ppid_map={})
    streamer._filter_and_append(_record(ROOT + 1))
    streamer.stop()
    records = _read_jsonl(tmp_path)
    assert [r for r in records if "path" in r] == []
    summary = next(r for r in records if r.get("type") == "audit_summary")
    assert summary["foreign_records_dropped"] == 1


def test_tree_poller_attributes_post_exit_descendants(tmp_path):
    """A descendant seen alive by the tree snapshot stays attributable
    after it exits (kernel→log latency delivers records post-exit,
    when the ppid walk can no longer see the process)."""
    short_lived = ROOT + 7
    streamer = _streamer(
        tmp_path,
        ppid_map={},  # already dead: live walk finds nothing
        tree=[(short_lived, ROOT), (99, 1)],
    )
    streamer.register_target_pid(ROOT)
    streamer._refresh_lineage_from_tree()   # poller tick while alive
    streamer._filter_and_append(_record(short_lived, "/tmp/late"))
    streamer.stop()
    paths = [r.get("path") for r in _read_jsonl(tmp_path) if "path" in r]
    assert "/tmp/late" in paths


def test_nonce_never_reaches_disk_on_foreign_records(tmp_path):
    """The run's nonce must only ever be persisted on scope-matched
    records — a foreign record with our nonce stamped would count as
    runtime evidence for a process we never ran."""
    foreign = ROOT + 500
    streamer = seatbelt_audit.LogStreamer(
        tmp_path,
        require_scope=True,
        observe_mode=True,
        observe_nonce="sekrit-nonce",
        get_ppid=lambda pid: {ROOT + 1: ROOT, foreign: 1}.get(pid),
        getpgid=_no_pgid,
        list_pid_ppids=lambda: [],
        lineage_poll_interval=0,
    )
    streamer.register_target_pid(ROOT)
    ours = dict(_record(ROOT + 1, "/tmp/ours"), nonce="sekrit-nonce")
    theirs = dict(_record(foreign, "/tmp/theirs"), nonce="sekrit-nonce")
    streamer._filter_and_append(ours)
    streamer._filter_and_append(theirs)
    streamer.stop()
    observe = (tmp_path / evidence_mod.AUDIT_SUBDIR
               / seatbelt_audit.OBSERVE_FILE)
    records = [json.loads(line) for line in
               observe.read_text().splitlines() if line.strip()]
    stamped = [r for r in records if r.get("nonce") == "sekrit-nonce"
               and "path" in r]
    assert [r["path"] for r in stamped] == ["/tmp/ours"]


def test_legacy_callers_without_require_scope_unfiltered(tmp_path):
    """Back-compat: a streamer constructed without require_scope
    keeps the pre-gate behaviour (host-wide attribution, documented
    as unguaranteed)."""
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer._filter_and_append(_record(12345, "/tmp/any"))
    streamer.stop()
    paths = [r.get("path") for r in _read_jsonl(tmp_path) if "path" in r]
    assert "/tmp/any" in paths


def test_pgid_match_admits_reparented_descendant(tmp_path):
    """A descendant reparented to init (its parent died) keeps the
    sandbox process group — the pgid probe must attribute it even
    though the ppid walk dead-ends at pid 1."""
    reparented = ROOT + 9
    sandbox_pgid = 4_200_000

    def fake_getpgid(pid):
        if pid in (ROOT, reparented):
            return sandbox_pgid
        raise ProcessLookupError(pid)

    streamer = seatbelt_audit.LogStreamer(
        tmp_path,
        require_scope=True,
        get_ppid=lambda pid: 1,
        getpgid=fake_getpgid,
        list_pid_ppids=lambda: [],
        lineage_poll_interval=0,
    )
    streamer.register_target_pid(ROOT)
    streamer._filter_and_append(_record(reparented, "/tmp/reparented"))
    streamer.stop()
    paths = [r.get("path") for r in _read_jsonl(tmp_path) if "path" in r]
    assert "/tmp/reparented" in paths


def test_read_loop_buffers_pre_registration_records(tmp_path):
    """End-to-end through _read_loop: a canned log-stream feed
    processed before registration must land nothing in the JSONL;
    registering the root flushes the attributable record through."""
    from core.sandbox.seatbelt import SANDBOX_KEXT_SENDER

    child, foreign = ROOT + 1, ROOT + 500
    streamer = _streamer(tmp_path, ppid_map={child: ROOT, foreign: 1})

    def _line(pid, path):
        return json.dumps({
            "senderImagePath": SANDBOX_KEXT_SENDER,
            "eventMessage":
                f"Sandbox: proc({pid}) deny file-write-data {path}",
            "timestamp": "2026-05-03 10:00:00.000000+0000",
        }) + "\n"

    class _FakeLogProc:
        stdout = [_line(child, "/tmp/ours"), _line(foreign, "/tmp/theirs")]

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    streamer._proc = _FakeLogProc()
    streamer._read_loop()
    assert _read_jsonl(tmp_path) == []  # scope not yet registered
    streamer.register_target_pid(ROOT)
    streamer.stop()
    paths = [r.get("path") for r in _read_jsonl(tmp_path) if "path" in r]
    assert paths == ["/tmp/ours"]


# --- Spawn-level wiring: _macos_spawn registers the shim PID ----------
# Cross-platform: SANDBOX_EXEC is swapped for a pass-through shell
# script so the REAL outer shim + inner trampoline run on Linux too
# (same pattern as test_macos_spawn.test_timeout_kills_whole_sandbox_tree).

class _StubStreamer:
    """Records the register/stop calls _macos_spawn makes."""

    def __init__(self, *, register_raises: bool = False):
        self.registered_pids: list[int] = []
        self.stopped = False
        self._register_raises = register_raises

    def register_target_pid(self, pid: int) -> None:
        if self._register_raises:
            raise RuntimeError("scope registration refused")
        self.registered_pids.append(int(pid))

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def fake_sandbox_exec(tmp_path, monkeypatch):
    from core.sandbox import _macos_spawn
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC", str(fake))
    return fake


def test_spawn_registers_child_pid_with_streamer(
        tmp_path, monkeypatch, fake_sandbox_exec):
    """run_sandboxed must register the workload root (the shim's
    Popen pid) with the streamer immediately after spawn — pre-fix
    no production caller ever called register_target_pid, so the
    host-wide kext feed passed the scope filter wholesale."""
    from core.sandbox import _macos_spawn

    stub = _StubStreamer()
    captured_kwargs: dict = {}

    def _fake_start(run_dir, **kwargs):
        captured_kwargs.update(kwargs)
        return stub

    # run_sandboxed does `from . import seatbelt_audit` at call time,
    # so patching the module attribute is what its lookup resolves.
    monkeypatch.setattr(seatbelt_audit, "start_log_streamer", _fake_start)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _macos_spawn.run_sandboxed(
        [_TRUE],
        output=str(out_dir),
        audit_mode=True,
        audit_run_dir=str(out_dir),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert len(stub.registered_pids) == 1
    assert stub.registered_pids[0] > 0
    assert stub.stopped is True
    # The production caller engages the mandatory scope gate.
    assert captured_kwargs.get("require_scope") is True


@pytest.mark.parametrize("mode_kwargs", [
    {"audit_required": True},
    {"observe_mode": True, "observe_nonce": "n0"},
])
def test_spawn_fails_closed_when_scoping_cannot_be_established(
        tmp_path, monkeypatch, fake_sandbox_exec, mode_kwargs):
    """observe mode and audit_required demand attributable evidence:
    when the workload root cannot be registered, run_sandboxed must
    raise rather than run with host-wide, unattributable audit."""
    from core.sandbox import _macos_spawn
    from core.sandbox.errors import SandboxSetupError

    stub = _StubStreamer(register_raises=True)
    monkeypatch.setattr(seatbelt_audit, "start_log_streamer",
                        lambda run_dir, **kwargs: stub)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(SandboxSetupError):
        _macos_spawn.run_sandboxed(
            [_TRUE],
            output=str(out_dir),
            audit_mode=True,
            audit_run_dir=str(out_dir),
            capture_output=True, text=True, timeout=30,
            **mode_kwargs,
        )
    assert stub.stopped is True  # streamer still cleaned up


def test_spawn_proceeds_with_warning_when_scoping_optional(
        tmp_path, monkeypatch, fake_sandbox_exec):
    """Plain audit mode (no observe, no audit_required): a scope
    registration failure degrades with a warning — the run proceeds
    and the streamer's own pending-drop machinery keeps the JSONL
    free of unattributable records."""
    from core.sandbox import _macos_spawn

    stub = _StubStreamer(register_raises=True)
    monkeypatch.setattr(seatbelt_audit, "start_log_streamer",
                        lambda run_dir, **kwargs: stub)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _macos_spawn.run_sandboxed(
        [_TRUE],
        output=str(out_dir),
        audit_mode=True,
        audit_run_dir=str(out_dir),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert stub.stopped is True
