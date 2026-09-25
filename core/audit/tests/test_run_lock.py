"""Orchestrator-lifetime run-dir lock (``core.audit.run_lock``).

The contention shapes: a LIVE holder (including one draining after
SIGTERM) refuses a second orchestrator loudly; a proven-dead holder's
stale lock is reclaimed automatically; an unverifiable holder fails
closed; in-process re-entry (ensemble passes, threads of one
orchestrator) is a no-op; lifecycle stubs and read-only consumers
never touch the lock.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from core.audit.run_lock import (
    RUN_LOCK_NAME,
    AuditRunLocked,
    acquire_run_lock,
    holder_liveness,
    read_holder,
    run_lock_path,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]

_HOLDER_SCRIPT = textwrap.dedent("""\
    import os, signal, sys
    sys.path.insert(0, sys.argv[2])
    from core.audit.run_lock import acquire_run_lock
    acquire_run_lock(sys.argv[1], "run")
    # Drain simulation: SIGTERM does NOT release the lock — the real
    # orchestrator keeps it through salvage until actual exit.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    print("READY", os.getpid(), flush=True)
    sys.stdin.read()          # exit (and release) when stdin closes
""")

_SLEEPER_SCRIPT = textwrap.dedent("""\
    import os, sys
    print("READY", os.getpid(), flush=True)
    sys.stdin.read()
""")


def _spawn(script: str, *argv: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-c", script, *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    line = proc.stdout.readline()
    assert line.startswith("READY"), f"child failed to start: {line!r}"
    return proc


def _finish(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.stdin.close()
        proc.wait(timeout=30)
    proc.stdout.close()


def _wait_acquirable(run_dir: Path, deadline_s: float = 30.0):
    """Poll acquire until the (just-exited) holder's flock is gone."""
    end = time.monotonic() + deadline_s
    while True:
        try:
            return acquire_run_lock(run_dir, "resume")
        except AuditRunLocked:
            if time.monotonic() >= end:
                raise
            time.sleep(0.05)


def _own_identity() -> dict:
    from core.project import sessions
    fields: dict = {}
    boot = sessions.boot_id()
    if boot:
        fields["boot_id"] = boot
    ns = sessions.pidns_id()
    if ns:
        fields["pidns"] = ns
    machine = sessions.machine_id()
    if machine:
        fields["machine_id"] = machine
    return fields


def _write_stamp(run_dir: Path, **fields) -> Path:
    lock = run_lock_path(run_dir)
    lock.write_text(json.dumps(fields) + "\n", encoding="utf-8")
    return lock


# ---------------------------------------------------------------------------
# live holder / drain
# ---------------------------------------------------------------------------

def test_live_holder_refused_with_pid_and_start_time(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    try:
        with pytest.raises(AuditRunLocked) as exc:
            acquire_run_lock(run_dir, "resume")
        msg = str(exc.value)
        assert f"pid {proc.pid}" in msg
        assert "started" in msg            # holder start time is named
        assert "live audit orchestrator" in msg
        assert "wait" in msg.lower()       # operator options are named
    finally:
        _finish(proc)


def test_sigterm_drain_keeps_the_lock_until_exit(tmp_path):
    """The motivating incident: a SIGTERM'd orchestrator still draining
    must keep refusing a second starter; only its ACTUAL exit frees the
    run dir."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    try:
        proc.send_signal(15)               # SIGTERM — child ignores it
        time.sleep(0.2)
        assert proc.poll() is None         # still draining
        with pytest.raises(AuditRunLocked):
            acquire_run_lock(run_dir, "resume")
    finally:
        _finish(proc)
    handle = _wait_acquirable(run_dir)     # exit releases; reclaim ok
    assert handle.held
    handle.release()


# ---------------------------------------------------------------------------
# dead holder / recycled pid
# ---------------------------------------------------------------------------

def test_dead_holder_stale_lock_is_reclaimed(tmp_path, capfd):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    _finish(proc)                          # holder exits; stamp remains
    assert read_holder(run_lock_path(run_dir)).get("pid") == proc.pid
    handle = _wait_acquirable(run_dir)
    assert handle.held
    assert read_holder(run_lock_path(run_dir)).get("pid") == os.getpid()
    assert "reclaiming stale audit run lock" in capfd.readouterr().err
    handle.release()


@pytest.mark.skipif(sys.platform != "linux",
                    reason="starttime identity needs /proc")
def test_recycled_pid_never_reads_live(tmp_path):
    """A RUNNING pid whose starttime mismatches the stamp is the dead
    holder, not a live one — the ledger v2 pattern's test shape."""
    stamp = {
        "pid": os.getpid(),                # definitely running
        "starttime": "1",                  # provably not this process
        "since": "2026-01-01T00:00:00+00:00",
        **_own_identity(),
    }
    verdict, reason = holder_liveness(stamp)
    assert verdict == "dead"
    assert "recycled" in reason
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_stamp(run_dir, **stamp)
    handle = acquire_run_lock(run_dir, "resume")   # reclaims
    assert handle.held
    handle.release()


# ---------------------------------------------------------------------------
# fail-closed shapes
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux",
                    reason="starttime identity needs /proc")
def test_alive_holder_without_flock_fails_closed(tmp_path):
    """A stamp whose process is provably alive refuses even when the
    flock is free (no-fcntl writer / lost fd shapes)."""
    from core.project import sessions
    proc = _spawn(_SLEEPER_SCRIPT)         # alive, holds NO flock
    try:
        start = sessions.proc_starttime(proc.pid)
        assert start is not None
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _write_stamp(
            run_dir, pid=proc.pid, starttime=start,
            since="2026-01-01T00:00:00+00:00", **_own_identity(),
        )
        with pytest.raises(AuditRunLocked) as exc:
            acquire_run_lock(run_dir, "run")
        assert "live audit orchestrator" in str(exc.value)
    finally:
        _finish(proc)


def test_foreign_boot_stamp_fails_closed_with_remedy(tmp_path):
    """A holder stamped under another boot (no machine identity to
    prove prior-boot death) is INDETERMINATE — never reclaimed."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_stamp(
        run_dir, pid=1, starttime="12345",
        boot_id="00000000-0000-0000-0000-000000000000",
        since="2026-01-01T00:00:00+00:00",
    )
    with pytest.raises(AuditRunLocked) as exc:
        acquire_run_lock(run_dir, "run")
    msg = str(exc.value)
    assert "cannot be verified" in msg
    assert "delete the lock file" in msg   # manual remedy is named
    # fail-closed twice in a row — no state was consumed by refusing
    with pytest.raises(AuditRunLocked):
        acquire_run_lock(run_dir, "run")


def test_malformed_stamp_fails_closed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    run_lock_path(run_dir).write_bytes(b"\x00 not json {")
    with pytest.raises(AuditRunLocked) as exc:
        acquire_run_lock(run_dir, "run")
    assert "cannot be verified" in str(exc.value)


def test_prior_boot_stamp_of_this_machine_reads_dead():
    """Same machine identity + different boot_id is PROVEN death
    (``_prior_boot_entry``) — reboots must not brick resume."""
    from core.project import sessions
    machine = sessions.machine_id()
    live_boot = sessions.boot_id()
    if not machine or not live_boot:
        pytest.skip("no machine/boot identity on this platform")
    verdict, _ = holder_liveness({
        "pid": 1, "starttime": "12345",
        "boot_id": "00000000-0000-0000-0000-000000000000",
        "machine_id": machine,
    })
    assert verdict == "dead"


def test_empty_lock_file_is_fresh(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    run_lock_path(run_dir).touch()
    handle = acquire_run_lock(run_dir, "run")
    assert handle.held
    handle.release()


def test_huge_pid_stamp_fails_closed_without_crash(tmp_path):
    """A planted multi-KB pid — digit string or JSON bignum — must
    read as indeterminate (fail closed), never escape as ValueError/
    OverflowError through the CLI."""
    for planted in ("9" * 5000, 10 ** 30):
        verdict, _ = holder_liveness({
            "pid": planted, "starttime": "1", "boot_id": "x",
        })
        assert verdict == "indeterminate"
        run_dir = tmp_path / f"run-{len(str(planted))}"
        run_dir.mkdir()
        _write_stamp(run_dir, pid=planted, starttime="1", boot_id="x")
        with pytest.raises(AuditRunLocked):
            acquire_run_lock(run_dir, "run")


# ---------------------------------------------------------------------------
# planted lock-path artifacts fail closed (never captured, never a
# kill switch)
# ---------------------------------------------------------------------------

def test_dangling_symlink_lock_path_fails_closed(tmp_path):
    """A dangling symlink must neither create the attacker-named
    target nor degrade to unlocked."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    target = run_dir / "attacker-named-file"
    run_lock_path(run_dir).symlink_to(target)
    with pytest.raises(AuditRunLocked) as exc:
        acquire_run_lock(run_dir, "run")
    assert "not an openable regular file" in str(exc.value)
    assert "remove it" in str(exc.value)
    assert not target.exists()             # no attacker-named create


def test_symlink_to_empty_victim_fails_closed_victim_untouched(tmp_path):
    """A symlink onto another run's (empty) lock file must not carry
    this run's stamp or flock onto the victim inode."""
    victim_dir = tmp_path / "victim-run"
    victim_dir.mkdir()
    victim = run_lock_path(victim_dir)
    victim.touch()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    run_lock_path(run_dir).symlink_to(victim)
    with pytest.raises(AuditRunLocked):
        acquire_run_lock(run_dir, "run")
    assert victim.read_bytes() == b""      # victim stamp not overwritten
    # ... and the victim run stays acquirable (its flock was never
    # captured by the refused acquisition above).
    handle = acquire_run_lock(victim_dir, "run")
    assert handle.held
    handle.release()


def test_symlink_to_nonempty_victim_fails_closed_victim_intact(tmp_path):
    victim = tmp_path / "precious.json"
    victim.write_bytes(b'{"precious": true}\n')
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    run_lock_path(run_dir).symlink_to(victim)
    with pytest.raises(AuditRunLocked):
        acquire_run_lock(run_dir, "run")
    assert victim.read_bytes() == b'{"precious": true}\n'


def test_directory_at_lock_path_fails_closed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    run_lock_path(run_dir).mkdir()
    with pytest.raises(AuditRunLocked) as exc:
        acquire_run_lock(run_dir, "run")
    assert "not an openable regular file" in str(exc.value)


@pytest.mark.skipif(os.geteuid() == 0,
                    reason="root opens mode-0 files regardless")
def test_mode0_lock_file_fails_closed(tmp_path):
    """An unopenable-but-existing lock file is the planted kill-switch
    shape — it must refuse, not degrade to unlocked."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    lock = run_lock_path(run_dir)
    lock.touch()
    lock.chmod(0)
    try:
        with pytest.raises(AuditRunLocked) as exc:
            acquire_run_lock(run_dir, "run")
        assert "not an openable regular file" in str(exc.value)
    finally:
        lock.chmod(0o600)


def test_genuine_cannot_create_degrades_loud(tmp_path, capfd):
    """Nothing at the lock path and no way to create it (parent is a
    file) is the GENUINE cannot-create shape: proceed unserialised
    with the loud warning, never refuse."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    handle = acquire_run_lock(blocker / "run", "run")
    assert not handle.held
    assert "proceeding WITHOUT run-dir mutual exclusion" in \
        capfd.readouterr().err


def test_acquired_fd_is_cloexec_and_registered(tmp_path):
    """The lock fd must never leak into exec'd tool children (a dead
    orchestrator's flock must not survive in a child), and the handle
    must be module-registered so it provably lives to process exit."""
    from core.audit import run_lock as rl
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    handle = acquire_run_lock(run_dir, "run")
    try:
        assert os.get_inheritable(handle.fd) is False
        assert handle in rl._HELD
    finally:
        handle.release()
    assert handle not in rl._HELD


# ---------------------------------------------------------------------------
# in-process flows (ensemble passes, threads) are unaffected
# ---------------------------------------------------------------------------

def test_in_process_reacquisition_is_a_noop(tmp_path):
    """One orchestrator's own threads/passes may hit acquire again —
    never a refusal, never a deadlock (the lock is per-PROCESS)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    handle = acquire_run_lock(run_dir, "run")
    assert handle.held
    try:
        again = acquire_run_lock(run_dir, "run")   # same thread
        assert not again.held                       # no-op handle

        results: list = []

        def worker():
            try:
                results.append(acquire_run_lock(run_dir, "run"))
            except AuditRunLocked as exc:            # pragma: no cover
                results.append(exc)

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=30)
        assert not t.is_alive()                     # never blocked
        assert len(results) == 1
        assert not isinstance(results[0], AuditRunLocked)
    finally:
        handle.release()


# ---------------------------------------------------------------------------
# self-held is decided by the process-local registry, never the stamp
# ---------------------------------------------------------------------------

_FLOCK_HOLDER_SCRIPT = textwrap.dedent("""\
    import fcntl, os, sys
    fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    print("READY", os.getpid(), flush=True)
    sys.stdin.read()          # exit (and release) when stdin closes
""")


@pytest.mark.skipif(sys.platform != "linux",
                    reason="starttime identity needs /proc")
def test_forged_own_identity_stamp_under_foreign_flock_refuses(tmp_path):
    """The stamp-forgery attack: a run-dir writer copies THIS
    process's identity (pid + starttime are world-readable) into the
    lock file while a FOREIGN process holds the flock. Self-held must
    come from the process-local handle registry, so the forged stamp
    earns the foreign holder's refusal — never a proceed (two live
    orchestrators)."""
    from core.project import sessions
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc = _spawn(_FLOCK_HOLDER_SCRIPT, str(run_lock_path(run_dir)))
    try:
        own_start = sessions.proc_starttime(os.getpid())
        assert own_start is not None
        _write_stamp(
            run_dir, pid=os.getpid(), starttime=own_start,
            since="2026-01-01T00:00:00+00:00", **_own_identity(),
        )
        with pytest.raises(AuditRunLocked) as exc:
            acquire_run_lock(run_dir, "resume")
        assert "live audit orchestrator" in str(exc.value)
    finally:
        _finish(proc)


@pytest.mark.skipif(sys.platform != "linux",
                    reason="starttime identity needs /proc")
def test_forged_own_identity_stamp_without_holder_fails_closed(tmp_path):
    """A planted stamp naming this very process, with no handle
    registered here, is a forged identity, not a self-hold: the
    alive-stamp fail direction (refuse) applies even to 'ourselves'."""
    from core.project import sessions
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    own_start = sessions.proc_starttime(os.getpid())
    assert own_start is not None
    _write_stamp(
        run_dir, pid=os.getpid(), starttime=own_start,
        since="2026-01-01T00:00:00+00:00", **_own_identity(),
    )
    with pytest.raises(AuditRunLocked) as exc:
        acquire_run_lock(run_dir, "run")
    assert "live audit orchestrator" in str(exc.value)


def test_reentry_with_failed_stamp_is_a_selfheld_noop(tmp_path):
    """In-process re-acquisition must be a no-op even when the first
    acquisition's stamp write failed (holder reads {}) or the stamp
    was corrupted after the fact — the registry, not the stamp,
    carries the self-held fact."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    handle = acquire_run_lock(run_dir, "run")
    assert handle.held
    try:
        for content in (b"", b"\x00 not json {"):
            run_lock_path(run_dir).write_bytes(content)
            again = acquire_run_lock(run_dir, "run")
            assert not again.held              # no-op, never a refusal
    finally:
        handle.release()


def test_no_fcntl_reentry_with_corrupt_stamp_is_a_selfheld_noop(
        tmp_path, monkeypatch):
    """The no-fcntl branch reaches the same registry-decided no-op —
    its pre-fix spelling consulted the (forgeable) stamp too."""
    from core.audit import run_lock as rl
    monkeypatch.setattr(rl, "_HAS_FCNTL", False)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    handle = acquire_run_lock(run_dir, "run")
    assert handle.held
    try:
        run_lock_path(run_dir).write_bytes(b"\x00 not json {")
        again = acquire_run_lock(run_dir, "run")
        assert not again.held
    finally:
        handle.release()


# ---------------------------------------------------------------------------
# stubs and readers never take the lock
# ---------------------------------------------------------------------------

def test_lifecycle_stub_never_touches_the_lock():
    """The orchestrator invokes ``raptor-run-lifecycle complete``/
    ``fail`` as CHILD processes while holding the lock — a stub taking
    it would deadlock against its own parent. Fence the stub source."""
    stub = (_REPO_ROOT / "libexec" / "raptor-run-lifecycle").read_text(
        encoding="utf-8")
    assert RUN_LOCK_NAME not in stub
    assert "acquire_run_lock" not in stub
    assert "run_lock" not in stub


def test_readers_work_against_a_held_lock(tmp_path):
    """Read-only consumers of a live run dir neither block nor refuse."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "audit-run-config.json").write_text(
        json.dumps({"target_path": str(tmp_path)}), encoding="utf-8")
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    try:
        from core.audit.resume import load_run_config
        cfg = load_run_config(run_dir)              # completes, no lock
        assert cfg and cfg.get("target_path") == str(tmp_path)
        assert read_holder(run_lock_path(run_dir)).get("pid") == proc.pid
    finally:
        _finish(proc)


# ---------------------------------------------------------------------------
# system-level incident replay (slow tier)
# ---------------------------------------------------------------------------

_DRAINING_ORCHESTRATOR = textwrap.dedent("""\
    import json, os, signal, sys
    run_dir, repo = sys.argv[1], sys.argv[2]
    sys.path.insert(0, repo)
    from core.audit.run_lock import acquire_run_lock
    acquire_run_lock(run_dir, "run")
    meta = os.path.join(run_dir, ".raptor-run.json")
    def _write(status):
        with open(meta, "w", encoding="utf-8") as fh:
            json.dump({"status": status, "tool_pid": os.getpid(),
                       "command": "audit"}, fh)
    _write("running")
    def _drain(signum, frame):
        # The incident shape: the drain stamps a TERMINAL status while
        # the process (and its lock) is still alive.
        _write("interrupted")
        print("DRAINING", flush=True)
    signal.signal(signal.SIGTERM, _drain)
    print("READY", os.getpid(), flush=True)
    sys.stdin.read()          # actual exit releases the lock
""")


@pytest.mark.slow
def test_incident_replay_resume_refused_during_real_drain(tmp_path):
    """The production incident, end-to-end with the REAL CLI: a
    SIGTERM'd orchestrator flips the run to `interrupted` while still
    alive (the status gate alone would let resume through — that WAS
    the incident); every real `raptor-audit resume` during the drain
    must be refused BY THE LOCK, and only the holder's actual exit
    frees the directory. Kills the release-at-salvage mutant class
    directly."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = str(_REPO_ROOT / "libexec" / "raptor-audit")
    proc = subprocess.Popen(
        [sys.executable, "-c", _DRAINING_ORCHESTRATOR,
         str(run_dir), str(_REPO_ROOT)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        line = proc.stdout.readline()
        assert line.startswith("READY"), f"child failed: {line!r}"
        proc.send_signal(15)                       # SIGTERM → drain
        assert proc.stdout.readline().strip() == "DRAINING"
        meta = json.loads(
            (run_dir / ".raptor-run.json").read_text(encoding="utf-8"))
        assert meta["status"] == "interrupted"     # gate would allow
        assert proc.poll() is None                 # ... but holder lives
        for _ in range(5):
            r = subprocess.run(
                [sys.executable, cli, "resume", str(run_dir)],
                capture_output=True, text=True, timeout=120,
            )
            assert r.returncode != 0
            assert "live audit orchestrator" in r.stderr
            assert f"pid {proc.pid}" in r.stderr
    finally:
        _finish(proc)
    # Holder exited: the next real resume gets PAST the lock (its
    # stale stamp reclaims silently — the run status is terminal) and
    # fails on run-config eligibility instead.
    r = subprocess.run(
        [sys.executable, cli, "resume", str(run_dir)],
        capture_output=True, text=True, timeout=120,
    )
    assert r.returncode != 0
    assert "live audit orchestrator" not in r.stderr
    assert "no audit-run-config.json" in r.stderr
    assert read_holder(run_lock_path(run_dir)).get("pid") != proc.pid


# ---------------------------------------------------------------------------
# CLI wiring: run/resume refuse a held dir before touching it
# ---------------------------------------------------------------------------

def _load_cli():
    import importlib.util
    from importlib.machinery import SourceFileLoader
    cli_path = str(_REPO_ROOT / "libexec" / "raptor-audit")
    loader = SourceFileLoader("raptor_audit_cli_runlock_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_runlock_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_cmd_resume_refuses_locked_dir_first(tmp_path, capsys):
    mod = _load_cli()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    try:
        from types import SimpleNamespace
        rc = mod.cmd_resume(SimpleNamespace(out_dir=str(run_dir)))
        assert rc == 1
        err = capsys.readouterr().err
        assert "live audit orchestrator" in err
        assert f"pid {proc.pid}" in err
    finally:
        _finish(proc)


def test_cmd_run_refuses_locked_out_dir_before_lifecycle(
        tmp_path, capsys, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    calls: list = []
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd))
    proc = _spawn(_HOLDER_SCRIPT, str(run_dir), str(_REPO_ROOT))
    try:
        from types import SimpleNamespace
        rc = mod.cmd_run(
            SimpleNamespace(target=str(target), out=str(run_dir)))
        assert rc == 1
        assert "live audit orchestrator" in capsys.readouterr().err
        assert calls == []      # refused BEFORE lifecycle start ran
    finally:
        _finish(proc)
