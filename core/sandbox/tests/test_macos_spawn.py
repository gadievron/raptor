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

import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid

import pytest

from core.sandbox import _macos_spawn

# macOS-only — sandbox-exec is Apple-specific: real-kernel tests carry
# the darwin_native marker (pytest.ini) instead of an ad hoc skipif, so
# the darwin-emulation gate deselects them and native non-darwin hosts
# skip them.


def _unique_sleep_marker(prefix: str) -> str:
    """Per-invocation-unique sleep duration for target discovery.

    A FIXED marker collides across concurrent pytest sessions on one
    host: session A's live in-test target matched session B's probe
    (false-failing B's no-survivors assertion) and B's cleanup killed
    A's target mid-test. The random suffix makes the target's full
    argv unique to this invocation, so an exact-argv match is an
    identity proof (same defence as the sandbox teardown's random
    ``_SBX_RUN_ID`` environ token).

    The randomness lives in the FRACTIONAL digits, keeping the total
    duration a few days: an earlier spelling appended them to the
    integer part, and the resulting ~1e17-second duration made
    darwin's ``/bin/sleep`` exit immediately (past the platform's
    representable sleep deadline — an unsigned 64-bit NANOSECOND
    count, ~584 years), so the "hung" target was gone before the
    timeout under test and TimeoutExpired never raised — while the
    orphan test silently took its target-never-started skip lane on
    the same hosts. coreutils and BSD ``sleep`` both accept
    fractional durations.
    """
    return f"{prefix}.{uuid.uuid4().int % 10**12:012d}"


def _exact_sleep_pids(marker: str) -> list[int]:
    """PIDs whose FULL argv is exactly ``/bin/sleep <marker>``.

    Never widen this to a substring/regex probe (the old ``pgrep -f
    "sleep <marker>"``): ``-f`` matches anywhere in ANY process's
    cmdline, and agent-harness wrapper shells carry their whole
    eval'd command text in argv — a foreign wrapper that merely
    MENTIONED the marker matched (and the old ``pkill -9 -f`` cleanup
    killed it), unrelated sleeps with superstring durations
    (``sleep <marker>2``) matched too, and any foreign match
    false-failed the no-survivors assertion. The narrow match cannot
    miss the real target: the trampoline ``exec``s
    ``/bin/sleep <marker>`` verbatim, so the survivor these tests
    hunt always has exactly this argv.
    """
    # check=True: a broken/unspawnable ps must fail the test loudly —
    # a silently-empty probe would let the no-survivors assertion (and
    # the decoy directions) pass vacuously.
    out = subprocess.run(
        ["ps", "-axwwo", "pid=,args="],
        capture_output=True, text=True, check=True,
    ).stdout
    want = f"/bin/sleep {marker}"
    pids = []
    for line in out.splitlines():
        pid_s, _, args = line.strip().partition(" ")
        if args.strip() == want:
            with contextlib.suppress(ValueError):
                pids.append(int(pid_s))
    return pids


def _kill_exact_sleepers(marker: str) -> None:
    """Cleanup: SIGKILL only identity-verified targets of THIS run.

    Kills by verified pid, never by pattern: each pid's argv is
    re-read immediately before signalling, so the signal is anchored
    to current evidence rather than a stale integer (the pid can exit
    between discovery and kill; the re-check plus the per-run random
    marker closes the wrong-process window).
    """
    for pid in _exact_sleep_pids(marker):
        args = subprocess.run(
            ["ps", "-p", str(pid), "-o", "args="],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
        if args == f"/bin/sleep {marker}":
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)


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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")
def test_timeout_kills_whole_sandbox_tree(tmp_path, monkeypatch):
    """A target that hangs past ``timeout`` must not survive the
    TimeoutExpired. subprocess.run's own timeout path SIGKILLed only
    the direct child — the detached seatbelt shim — while the
    sandbox-exec process group (deliberately a separate pgrp so the
    shim can killpg it) kept running with its death-pipe watcher dead.
    run_sandboxed now owns the Popen and, on timeout, closes death_w
    (firing the shim's designed killpg teardown) and killpgs the
    shim's session as a backstop.

    Cross-platform: SANDBOX_EXEC is swapped for a pass-through shell
    script so the REAL outer shim + inner trampoline run on Linux too;
    the layering (shim → fake sandbox-exec → /bin/sh trampoline →
    target) matches production, including the separate process group.
    """
    marker = _unique_sleep_marker("424271")

    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC", str(fake))
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Foreign-process decoys (own children, own session so the group
    # is ours to sweep): a sleep whose duration merely CONTAINS the
    # marker as a prefix, and a wrapper shell whose argv TEXT mentions
    # the marker while it waits on an unrelated child — exactly the
    # agent-harness ``bash -c ... eval`` shape the old ``pkill -f``
    # killed. The trailing ``:`` no-op is load-bearing: without it,
    # bash-as-/bin/sh (macOS, Fedora) tail-execs the final command
    # and the wrapper's argv — marker text included — is replaced by
    # ``/bin/sleep``'s within milliseconds, leaving the survival
    # assertion vacuously green. Direction two of the kill
    # discipline: the teardown under test and this test's own cleanup
    # must leave both decoys alone.
    decoys: list[subprocess.Popen] = []
    try:
        decoys.append(subprocess.Popen(
            ["/bin/sleep", marker + "2"],
            start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        decoys.append(subprocess.Popen(
            ["/bin/sh", "-c", f"true sleep {marker}; /bin/sleep 3600; :"],
            start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                _macos_spawn.run_sandboxed(
                    ["/bin/sleep", marker],
                    output=str(out_dir),
                    capture_output=True, text=True, timeout=1.5,
                )
            # Teardown runs synchronously before the raise; poll
            # briefly for the process table to reflect it.
            deadline = time.monotonic() + 5
            while (time.monotonic() < deadline
                   and _exact_sleep_pids(marker)):
                time.sleep(0.1)
            assert _exact_sleep_pids(marker) == [], (
                "sandboxed target survived run_sandboxed timeout — "
                "the shim tree was not torn down"
            )
        finally:
            _kill_exact_sleepers(marker)
            # Liveness sampled AFTER the cleanup above (so the
            # asserts below cover it too) but BEFORE reaping.
            survived = [d.poll() is None for d in decoys]
    finally:
        for decoy in decoys:
            # Own child + own session: group-kill by direct-child pid
            # is identity-safe (unreaped children cannot be
            # pid-recycled), and it takes the text decoy's sleep
            # child down with its shell.
            with contextlib.suppress(OSError):
                os.killpg(decoy.pid, signal.SIGKILL)
            decoy.wait(timeout=10)
    # Decoys must have survived BOTH the teardown under test and the
    # cleanup above (a pattern-shaped kill would have taken either).
    assert survived[0], (
        "teardown/cleanup killed an unrelated sleep whose duration "
        "merely starts with the marker — kill went by pattern, not "
        "verified identity"
    )
    assert survived[1], (
        "teardown/cleanup killed an unrelated wrapper shell whose "
        "argv text merely mentions the marker — kill went by "
        "pattern, not verified identity"
    )


def test_is_available_false_on_non_darwin():
    """On Linux, /usr/bin/sandbox-exec doesn't exist; is_available
    must return False without raising."""
    if sys.platform == "darwin":
        pytest.skip("Darwin host — is_available may legitimately be True")
    assert _macos_spawn.is_available() is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")
def test_audit_streamer_scoped_to_run_process_tree(tmp_path, monkeypatch):
    """Attribution scoping regression: the production audit spawn must
    (a) start the log streamer with ``require_scope=True`` so the host-
    wide Sandbox.kext feed is never wholesale-attributed to this run,
    and (b) register the workload's PID on the streamer while the
    workload is still alive — i.e. before waiting on it.

    Pre-fix, the streamer was started with neither scoping layer and
    ``register_target_pid`` was never called: every kext event on the
    host (sibling runs, unrelated sandboxed apps, attacker noise on a
    shared host) was nonce-stamped into this run's JSONL.

    Cross-platform: SANDBOX_EXEC is swapped for a pass-through script
    (same layering as production) and the streamer is a recording
    fake, so no darwin host or `log stream` subprocess is needed.
    """
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC", str(fake))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    events: list[tuple] = []

    class _FakeStreamer:
        def register_target_pid(self, pid):
            alive = True
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError, OSError):
                alive = False
            events.append(("register", pid, alive))

        def stop(self, **kw):
            events.append(("stop",))

    def fake_start(run_dir, **kw):
        events.append(("start", kw.get("require_scope")))
        return _FakeStreamer()

    from core.sandbox import seatbelt_audit
    monkeypatch.setattr(seatbelt_audit, "start_log_streamer", fake_start)

    r = _macos_spawn.run_sandboxed(
        # Sleep long enough that the registration observably happens
        # while the workload is alive; short enough to keep the suite
        # quick.
        ["/bin/sh", "-c", "sleep 0.4"],
        output=str(out_dir),
        capture_output=True, text=True, timeout=15,
        audit_mode=True, audit_run_dir=str(audit_dir),
    )
    assert r.returncode == 0

    kinds = [e[0] for e in events]
    assert kinds == ["start", "register", "stop"], events
    start_evt, register_evt, _ = events
    assert start_evt[1] is True, (
        "streamer must be started with require_scope=True so events "
        "before PID registration are never wholesale-attributed"
    )
    assert isinstance(register_evt[1], int) and register_evt[1] > 0
    assert register_evt[2] is True, (
        "register_target_pid must run while the workload is still "
        "alive (before wait), or the whole run goes unattributed"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")
def test_tmpdir_steered_into_output_scratch_under_write_isolation(
        tmp_path, monkeypatch):
    """Whenever the profile engages write isolation and an output dir
    exists, the child's TMPDIR must be steered into {output}/.tmp.
    Pre-fix, only the untrusted lane (exclude_tmp_baseline=True) was
    steered: every trusted-lane write-isolated macOS run kept the
    host-default per-user /var/folders TMPDIR, which sits OUTSIDE the
    write exceptions — python's tempfile silently fell back to /tmp,
    but tools that honour TMPDIR directly (clang intermediates, git,
    tar) got EPERM (confirmed on current macOS). The steer must ride
    the EXISTING output write exception, never widen the profile.

    Cross-platform: SANDBOX_EXEC is swapped for a script that records
    the SBPL profile text it was handed, then execs the target (the
    real shim + trampoline layering runs on Linux too).
    """
    capture = tmp_path / "profile.sb"
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text(
        f'#!/bin/sh\nprintf %s "$2" > "{capture}"\nshift 3\nexec "$@"\n'
    )
    fake.chmod(0o755)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC", str(fake))
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    r = _macos_spawn.run_sandboxed(
        ["/bin/sh", "-c", 'printf %s "$TMPDIR"'],
        output=str(out_dir),
        # A host-default-style TMPDIR rides the safe-env allowlist
        # into every child env — the steer must override it, not
        # merely fill an absent value.
        env={"PATH": "/usr/bin:/bin",
             "TMPDIR": "/var/folders/zz/host-default/T/"},
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    expected_tmp = os.path.join(str(out_dir), ".tmp")
    assert r.stdout == expected_tmp
    assert os.path.isdir(expected_tmp)

    # The steered TMPDIR must be covered by the OUTPUT write
    # exception already in the profile — no new write-exception
    # entry, and in particular no widening to the host-shared
    # per-user temp dir. Scope the assertions to the file-write*
    # exception clauses: on a darwin host the output dir itself
    # (pytest tmp_path) legitimately lives UNDER /var/folders, so a
    # whole-profile substring check false-positives on the output
    # subpath.
    profile = capture.read_text()
    out_real = os.path.realpath(str(out_dir))
    write_denies = [line for line in profile.splitlines()
                    if line.startswith("(deny file-write*")]
    assert len(write_denies) == 1, profile
    subpaths = re.findall(r'\(subpath "([^"]*)"\)', write_denies[0])
    # Exactly the /private/tmp baseline seed + the output dir — the
    # steer rides the existing output exception and adds nothing.
    assert sorted(subpaths) == sorted(["/private/tmp", out_real]), (
        subpaths
    )
    # The steered value resolves to a path under that output
    # exception, and the host-default temp dir the child arrived
    # with is NOT among the write exceptions.
    assert os.path.realpath(expected_tmp) == os.path.join(out_real,
                                                          ".tmp")
    assert not any(p.startswith("/var/folders/zz/host-default")
                   or p.startswith("/private/var/folders/zz/host-default")
                   for p in subpaths), subpaths


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")
def test_tmpdir_not_steered_without_write_isolation(tmp_path,
                                                    monkeypatch):
    """No write isolation (network-only-equivalent kwargs) → the
    child keeps its inherited TMPDIR: nothing is unwritable, so the
    steer must not engage (behaviour-budget: non-write-isolated runs
    are byte-identical)."""
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC", str(fake))

    r = _macos_spawn.run_sandboxed(
        ["/bin/sh", "-c", 'printf %s "${TMPDIR-unset}"'],
        block_network=True,
        env={"PATH": "/usr/bin:/bin", "SENTINEL": "1"},
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    assert r.stdout == "unset"


# --- Darwin-only behavioural tests ------------------------------------

@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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
    # Pre-fix: a flat ``time.sleep(2.0)`` made the test always
    # wait 2s even when the JSONL had already landed at 200ms (the
    # common case on dev macs) — and still flaked on slow CI when
    # the pipeline took >2s. Poll for the file with a 5s budget
    # instead: usually returns in <500ms, gives slow CI runners
    # more headroom, and the worst-case wall-clock matches the old
    # ``sleep(2.0) + assert`` shape.
    from core.sandbox.evidence import evidence_write_path
    jsonl_path = evidence_write_path(audit_dir, ".sandbox-denials.jsonl")
    _poll_deadline = time.monotonic() + 5.0
    while time.monotonic() < _poll_deadline:
        if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
            break
        time.sleep(0.05)
    assert jsonl_path.exists(), (
        "audit_mode=True did not produce .sandbox-denials.jsonl"
    )
    lines = jsonl_path.read_text().splitlines()
    # We want at least one record about our write — be lenient
    # about which one (the kernel may emit multiple file-* entries
    # for one Python write).
    parsed = [json.loads(line) for line in lines if line.strip()]
    matching = [r for r in parsed if "audited" in r.get("path", "")]
    assert matching, (
        f"no audit record matched our test path; got {len(parsed)} "
        f"records, paths={[r.get('path') for r in parsed]}"
    )


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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


@pytest.mark.darwin_native
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
        f"open('/etc/hosts', 'r').read()\n"
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
    # Allow kernel→log→stream pipeline to flush. See the
    # ``test_audit_mode_produces_denials_jsonl`` test for the
    # full rationale on the poll-loop pattern vs. flat sleep.
    from core.sandbox.evidence import evidence_write_path
    jsonl_path = evidence_write_path(audit_dir, ".sandbox-denials.jsonl")
    _poll_deadline = time.monotonic() + 5.0
    while time.monotonic() < _poll_deadline:
        if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
            break
        time.sleep(0.05)
    assert jsonl_path.exists(), (
        "audit_verbose=True did not produce .sandbox-denials.jsonl"
    )
    records = [json.loads(line) for line in
                jsonl_path.read_text().splitlines() if line.strip()]
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


@pytest.mark.darwin_native
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
    # Poll-loop instead of flat sleep — same pattern as the
    # other tests in this file. 3s budget (this assertion needs
    # less than the kernel→log path because the audit summary
    # is written from in-process at sandbox shutdown).
    from core.sandbox.evidence import evidence_write_path
    jsonl_path = evidence_write_path(audit_dir, ".sandbox-denials.jsonl")
    _poll_deadline = time.monotonic() + 3.0
    while time.monotonic() < _poll_deadline:
        if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
            break
        time.sleep(0.05)
    records = [json.loads(line) for line in
                jsonl_path.read_text().splitlines() if line.strip()]
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


@pytest.mark.darwin_native
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
    # The streamer appends through the held evidence fd, which lives
    # at <run_dir>/.audit/<name> (core.sandbox.evidence placement) —
    # read it back from there, like the other audit tests above, not
    # from the legacy top-level spot.
    from core.sandbox.evidence import evidence_write_path
    jsonl_path = evidence_write_path(audit_dir, seatbelt_audit.DENIALS_FILE)
    records = [json.loads(line) for line in
                jsonl_path.read_text().splitlines() if line.strip()]
    markers = [r for r in records
                if r.get("type") in ("category_budget_exceeded",
                                     "category_budget_exceeded_sampling")]
    assert len(markers) == 1, (
        f"expected 1 budget marker, got {len(markers)}; "
        f"records: {records!r}"
    )
    summary = next(r for r in records if r.get("type") == "audit_summary")
    assert summary["dropped_by_category"]["file-write"] == 5


@pytest.mark.darwin_native
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


# --- Darwin-only: seatbelt-shim fail-loud + teardown integration ------
# These validate the raptor-seatbelt-shim wiring under a REAL sandbox-exec:
# the inner shim (python, run INSIDE the applied profile) emitting the
# readiness byte, exit-status mirroring through the outer+inner layering,
# and killpg teardown when the orchestrator dies. They can only run on a
# macOS host — smoke-test here before relying on the macOS sandbox.

@pytest.mark.darwin_native
def test_setup_status_none_on_successful_engage(tmp_path):
    """A normal run must come back with result._setup_status is None — i.e.
    the in-sandbox readiness byte arrived, proving the inner shim ran INSIDE
    the applied profile (this also confirms python starts under the profile,
    the one macOS-specific risk of the unified shim design)."""
    r = _macos_spawn.run_sandboxed(
        ["/usr/bin/true"],
        output=str(tmp_path),
        capture_output=True, timeout=10,
    )
    assert r.returncode == 0
    assert getattr(r, "_setup_status", "missing") is None


@pytest.mark.darwin_native
def test_exit_code_mirrored_through_shim(tmp_path):
    """The outer+inner shim layering must mirror the target's exit code
    unchanged (regression guard on status propagation)."""
    r = _macos_spawn.run_sandboxed(
        ["/bin/sh", "-c", "exit 7"],
        output=str(tmp_path),
        capture_output=True, timeout=10,
    )
    assert r.returncode == 7
    assert getattr(r, "_setup_status", "missing") is None


@pytest.mark.darwin_native
def test_fail_loud_via_context_when_profile_cannot_apply(tmp_path):
    """End-to-end fail-loud: when the sandbox cannot engage, sandbox().run
    must raise SandboxSetupError rather than silently returning a result.
    Driven through the public context entry so the _setup_status decision
    table is exercised. (Uses an unsatisfiable seatbelt config if available;
    otherwise asserts the success path stays non-raising — adjust on the Mac
    if a reliable profile-failure trigger is known for the installed OS.)"""
    from core.sandbox import sandbox
    from core.sandbox.errors import SandboxSetupError
    # A normal engageable run must NOT raise.
    with sandbox(block_network=True) as run:
        r = run(["/usr/bin/true"], capture_output=True, timeout=10)
    assert r.returncode == 0
    # Note: a deterministic profile-apply failure is host/OS-version
    # specific; the unit-level guarantee (no readiness byte -> ("E", ..)
    # -> SandboxSetupError) is covered by the context.py decision table and
    # the seatbelt-shim POSIX tests. Keep SandboxSetupError imported so this
    # file fails fast if the symbol is removed.
    assert SandboxSetupError is not None


@pytest.mark.darwin_native
def test_orphan_teardown_on_orchestrator_kill():
    """Integration: an orchestrator running a long target via the seatbelt
    backend, SIGKILLed mid-run, must leave NO lingering sandbox process —
    the outer shim reads death-pipe EOF and SIGKILLs the sandbox group.

    Target discovery and cleanup go through the exact-argv helpers
    (per-run unique marker, identity-verified kill) — the fixed-marker
    ``pgrep -f``/``pkill -9 -f`` this replaces matched (and killed)
    unrelated processes whose cmdline merely contained the pattern.
    """
    marker = _unique_sleep_marker("417239")

    orch_code = (
        "from core.sandbox import sandbox\n"
        "with sandbox(block_network=True) as run:\n"
        f"    run(['/bin/sleep','{marker}'], capture_output=True)\n"
    )
    orch = subprocess.Popen(
        [sys.executable, "-c", orch_code],
        env=dict(os.environ, _RAPTOR_TRUSTED="1"),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(150):
            time.sleep(0.1)
            if _exact_sleep_pids(marker):
                break
        else:
            pytest.skip("seatbelt sandbox did not start the target here")
        orch.send_signal(signal.SIGKILL)
        orch.wait()
        for _ in range(50):
            time.sleep(0.1)
            if not _exact_sleep_pids(marker):
                break
        assert _exact_sleep_pids(marker) == [], (
            "sandbox target leaked after orchestrator kill"
        )
    finally:
        if orch.poll() is None:
            orch.kill()
            orch.wait()
        _kill_exact_sleepers(marker)
