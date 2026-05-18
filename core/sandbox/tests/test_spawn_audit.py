"""End-to-end tests for `audit_mode=True` in run_sandboxed.

These run the full audit flow:
- Pre-flight ptrace probe.
- Tracer subprocess fork.
- PR_SET_PTRACER_ANY in target preexec.
- Tracer-ready handshake.
- Seccomp filter with SCMP_ACT_TRACE.
- Target executes; tracer logs syscall events to JSONL.
- Parent reaps both target and tracer.

Skipped on environments without the prerequisites (mount-ns / ptrace
unavailable).
"""

from __future__ import annotations

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import json
import os
import platform
import signal
import time

import pytest

from core.sandbox import probes
from core.sandbox import ptrace_probe
from core.sandbox._spawn import run_sandboxed
from core.sandbox import tracer as tracer_mod


pytestmark = [
    pytest.mark.skipif(
        not tracer_mod._is_supported_arch(),
        reason=f"tracer doesn't support {platform.machine()}",
    ),
]


def _audit_prereqs_ok() -> tuple:
    """Return (ok: bool, reason: str) for whether audit mode can run
    on this host. Used by individual tests to skip cleanly.

    `_spawn.run_sandboxed` requires mount-ns to be functionally
    available, which on Ubuntu 24.04+ needs both `uidmap` package AND
    `kernel.apparmor_restrict_unprivileged_userns=0`. The probe
    `check_mount_available()` covers the apparmor side; `_spawn`'s
    own `mount_ns_available()` covers the uidmap side. Both must
    pass for the mount call inside the user-ns to succeed.
    """
    if not probes.check_net_available():
        return False, "user namespaces not available"
    if not ptrace_probe.check_ptrace_available():
        return False, "ptrace not permitted (Yama / cap-drop)"
    if not probes.check_mount_available():
        return False, ("mount-ns blocked — apparmor_restrict_"
                       "unprivileged_userns=1 (Ubuntu 24.04+ default)")
    from core.sandbox._spawn import mount_ns_available
    if not mount_ns_available():
        return False, "uidmap package not installed (newuidmap/newgidmap)"
    return True, ""


class TestAuditPreflightDecision:
    """The audit pre-flight decides _audit_engaged based on the
    ptrace probe result. These tests verify the decision logic
    without exercising the full mount-ns spawn flow."""

    def test_audit_disabled_when_audit_mode_false(self, monkeypatch):
        # When audit_mode=False, ptrace probe is NOT consulted (we
        # don't spend the cost of probing if we don't need it).
        called = []

        def fake_probe():
            called.append(True)
            return True

        monkeypatch.setattr(ptrace_probe, "check_ptrace_available",
                            fake_probe)

        # Run via the lower-level function; we expect it to either
        # succeed or fail at mount-ns (this host) — but in EITHER case
        # we just want to confirm the probe was NOT called.
        try:
            run_sandboxed(
                ["true"],
                target="/tmp", output="/tmp",
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=False, audit_run_dir=None,
            )
        except Exception:
            pass  # mount-ns failure on this host is fine
        assert called == [], (
            f"ptrace probe was called with audit_mode=False — wasted work. "
            f"Got {len(called)} calls."
        )

    def test_audit_engaged_when_probe_passes(self, monkeypatch, tmp_path):
        # When audit_mode=True AND probe says yes, _audit_engaged
        # should be True. We can't easily inspect a local variable
        # of run_sandboxed, but we CAN observe the side effect:
        # seccomp filter gets built with audit_mode=True.
        from core.sandbox import seccomp
        from core.sandbox import state

        # Force probe positive.
        state._ptrace_available_cache = True

        captured_audit_mode = []
        original = seccomp._make_seccomp_preexec

        def spy(profile, block_udp=False, audit_mode=False,
                observe_mode=False):
            captured_audit_mode.append(audit_mode)
            return original(profile, block_udp=block_udp,
                            audit_mode=audit_mode,
                            observe_mode=observe_mode)
        monkeypatch.setattr("core.sandbox._spawn._make_seccomp_preexec", spy)

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        try:
            run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=True, audit_run_dir=str(run_dir),
            )
        except Exception:
            pass  # mount-ns failure ok; we just want the spy data

        assert captured_audit_mode == [True], (
            f"expected seccomp built with audit_mode=True, "
            f"got {captured_audit_mode}"
        )

    def test_audit_disabled_when_probe_fails(self, monkeypatch, tmp_path):
        # When audit_mode=True BUT probe says no (Yama scope 3 etc.),
        # _audit_engaged is False — seccomp built with audit_mode=False
        # so the target survives without a tracer attached.
        from core.sandbox import seccomp
        from core.sandbox import state

        # Force probe negative.
        state._ptrace_available_cache = False

        captured_audit_mode = []
        original = seccomp._make_seccomp_preexec

        def spy(profile, block_udp=False, audit_mode=False,
                observe_mode=False):
            captured_audit_mode.append(audit_mode)
            return original(profile, block_udp=block_udp,
                            audit_mode=audit_mode,
                            observe_mode=observe_mode)
        monkeypatch.setattr("core.sandbox._spawn._make_seccomp_preexec", spy)

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        try:
            run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=True, audit_run_dir=str(run_dir),
            )
        except Exception:
            pass

        # SECCOMP_ACT_TRACE without a tracer = SIGSYS-kill. Degrade
        # path must use the regular ERRNO action instead.
        assert captured_audit_mode == [False], (
            f"expected seccomp built with audit_mode=False under "
            f"ptrace-blocked degrade, got {captured_audit_mode} — "
            f"target would SIGSYS on first traced syscall"
        )


class TestAuditModeRequiresRunDir:
    """audit_mode=True without audit_run_dir raises ValueError —
    pin the contract."""

    def test_missing_run_dir_raises(self, tmp_path):
        with pytest.raises(ValueError, match="audit_run_dir"):
            run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=True,
                # audit_run_dir omitted on purpose
            )


class TestAuditModeBasicFlow:
    """Full end-to-end: target runs `true` under audit mode; tracer
    attaches; target exits clean; tracer reaped; no orphans."""

    def test_audit_mode_target_runs_to_completion(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        # `true` is a trivial command — exits 0, exercises minimal
        # syscalls. Goal here is just "audit mode doesn't break
        # the basic happy path." Richer end-to-end (asserting on
        # JSONL records) needs syscalls we know will fire.
        result = run_sandboxed(
            ["true"],
            target=str(tmp_path), output=str(tmp_path),
            block_network=False, nproc_limit=0, limits={},
            writable_paths=[str(tmp_path)], readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=10,
            audit_mode=True, audit_run_dir=str(run_dir),
        )
        assert result.returncode == 0, (
            f"audit-mode target failed: rc={result.returncode}, "
            f"stderr={result.stderr[:300]!r}"
        )

    def test_audit_mode_records_openat_events(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        # The test target must be reachable inside the sandbox's
        # mount-ns. /usr is bind-mounted, so /usr/bin/python3 works;
        # sys.executable on this dev machine resolves to a user-
        # installed python under /home which mount-ns hides.
        import os.path
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")
        system_python = "/usr/bin/python3"

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        # Run a Python that opens a file — should generate at least
        # one openat record in the tracer's JSONL output. /etc is
        # already in the default mount-ns ro bind-mount list, so we
        # do NOT pass readable_paths=["/etc"] (would cause a double-
        # mount conflict — pre-existing bug, not audit-specific).
        code = (
            "import os; "
            "fd = os.open('/etc/hostname', os.O_RDONLY); "
            "os.close(fd)"
        )
        result = run_sandboxed(
            [system_python, "-c", code],
            target=str(tmp_path), output=str(tmp_path),
            block_network=False, nproc_limit=0, limits={},
            writable_paths=[str(tmp_path)],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=15,
            audit_mode=True, audit_run_dir=str(run_dir),
            # verbose=True so /etc/hostname (in the system allowlist)
            # still gets logged. Filtered audit would correctly drop
            # it because under restrict_reads=False, that read
            # wouldn't have been blocked anyway.
            audit_verbose=True,
        )
        # Target should run to completion.
        assert result.returncode == 0, (
            f"audit-mode target failed: rc={result.returncode}, "
            f"stderr={result.stderr[:300]!r}"
        )

        # Tracer wrote some openat records to the JSONL file.
        jsonl = run_dir / tracer_mod._DENIALS_FILENAME
        assert jsonl.exists(), \
            "tracer didn't write any audit records — handshake broken?"

        records = [json.loads(line) for line in
                   jsonl.read_text().splitlines() if line]
        # Don't assert exact count (Python startup does many opens)
        # but DO assert at least one openat with audit=True. Skip
        # control-plane records (audit_summary, *_budget_exceeded
        # markers) which don't have a `syscall` field.
        openats = [r for r in records if r.get("syscall") == "openat"]
        assert len(openats) > 0, (
            f"expected at least one openat audit record, got: {records!r}"
        )
        for r in openats:
            assert r["audit"] is True
            assert r["type"] == "write"  # openat → write per taxonomy


class TestAuditModeMultiProcess:
    """TRACEFORK / TRACEVFORK / TRACECLONE in the SEIZE options means
    the kernel auto-attaches the tracer to every fork/clone descendant
    of the original target. Without these options, audit signal would
    be limited to the root process — most of a `make -j N` build's
    work would go dark.

    This test runs a Python target that forks several children, each
    opening a distinct file, and asserts the JSONL contains records
    from MORE THAN ONE PID."""

    def test_multi_process_target_audits_all_children(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        # Target: fork 3 children, each opens /etc/hostname, then
        # parent reaps. Tracer should attach to each child via
        # TRACEFORK and produce records bearing distinct PIDs.
        # Uses audit_verbose=True so the filter doesn't drop the
        # /etc opens (which would be allowed under enforcement) —
        # we want EVERY traced openat surfaced for this test, since
        # we're measuring TRACEFORK auto-attach, not the filter.
        code = """
import os
for _ in range(3):
    if os.fork() == 0:
        try:
            fd = os.open('/etc/hostname', os.O_RDONLY)
            os.close(fd)
        finally:
            os._exit(0)
for _ in range(3):
    os.wait()
"""
        result = run_sandboxed(
            ["/usr/bin/python3", "-c", code],
            target=str(tmp_path), output=str(tmp_path),
            block_network=False, nproc_limit=0, limits={},
            writable_paths=[str(tmp_path)], readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=20,
            audit_mode=True, audit_run_dir=str(run_dir),
            audit_verbose=True,
        )
        assert result.returncode == 0, (
            f"multi-process target failed: rc={result.returncode}, "
            f"stderr={result.stderr[:300]!r}"
        )

        jsonl = run_dir / tracer_mod._DENIALS_FILENAME
        assert jsonl.exists()
        records = [
            json.loads(line) for line in
            jsonl.read_text().splitlines() if line
        ]
        # Records should bear MULTIPLE distinct target_pids — proves
        # TRACEFORK/CLONE auto-attached the children. Skip
        # control-plane records (audit_summary, *_budget_exceeded
        # markers) which don't have a target_pid.
        traced_pids = {r["target_pid"] for r in records
                        if "target_pid" in r}
        # Without TRACEFORK only one PID would ever appear. We expect
        # at least the parent + one child (in practice, parent + 3
        # since python forked 3 children), but the assertion just
        # pins "multiple" since exact count varies (the kernel may
        # still be in the SECCOMP-stop window for some children when
        # the parent's wait completes).
        assert len(traced_pids) >= 2, (
            f"expected audit records from multiple PIDs (TRACEFORK "
            f"auto-attach), got only {traced_pids}"
        )


class TestAuditModeTracerDeath:
    """If the tracer dies mid-trace, PTRACE_O_EXITKILL ensures the
    kernel SIGKILLs all tracees immediately. Without that option,
    surviving tracees would SIGSYS-die on their next traced syscall —
    same outcome but slower and noisier.

    Direct test: spawn our own sleeper child, SEIZE it with the same
    option set the tracer uses, kill the SEIZE'r, verify sleeper
    dies. Bypasses run_sandboxed's full path so we don't need to
    coordinate with the sandbox's tracer; verifies the kernel
    contract directly.
    """

    def test_exitkill_takes_effect_on_tracer_death(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        # Yama scope 1 requires the SEIZE'r to be an ancestor of the
        # tracee. Layout:
        #   test process (us)
        #     └── seizer (forked from us)
        #             └── sleeper (forked from seizer)
        # The seizer SEIZEs the sleeper (its own descendant — Yama
        # permitted). Then we SIGKILL the seizer, and EXITKILL should
        # cascade SIGKILL to the sleeper. The test process's role is
        # just to coordinate — it never attaches to anyone.
        #
        # Communication: sleeper PID is reported back to test process
        # via a pipe so we know what to watch for.

        pipe_r, pipe_w = os.pipe()
        seizer_pid = os.fork()
        if seizer_pid == 0:
            # === seizer ===
            os.close(pipe_r)
            try:
                # Fork the sleeper as our descendant.
                sleeper_pid = os.fork()
                if sleeper_pid == 0:
                    # === sleeper (grandchild of test process) ===
                    os.close(pipe_w)
                    try:
                        time.sleep(60)
                    finally:
                        os._exit(0)
                # === seizer parent ===
                # Brief settle so the sleeper is actually running.
                time.sleep(0.05)
                # Attach with the production option set (TRACESECCOMP +
                # TRACEEXIT + TRACEFORK/VFORK/CLONE + EXITKILL).
                if not tracer_mod._ptrace_seize(sleeper_pid):
                    os._exit(2)
                # Tell test process the sleeper PID.
                os.write(pipe_w, f"{sleeper_pid}\n".encode())
                os.close(pipe_w)
                # Block forever — test process will SIGKILL us to
                # exercise EXITKILL.
                while True:
                    time.sleep(1)
            except BaseException:
                os._exit(3)

        # === test process ===
        os.close(pipe_w)
        sleeper_pid = None
        try:
            # Read sleeper PID from seizer (with timeout).
            import select
            r, _, _ = select.select([pipe_r], [], [], 5.0)
            if not r:
                pytest.fail("seizer didn't report sleeper PID — SEIZE "
                            "may have failed (Yama scope 3?)")
            data = os.read(pipe_r, 64).decode().strip()
            sleeper_pid = int(data)
        finally:
            os.close(pipe_r)

        try:
            # Verify sleeper IS being traced by our seizer.
            with open(f"/proc/{sleeper_pid}/status") as f:
                status = f.read()
            tracer_attached = None
            for line in status.split("\n"):
                if line.startswith("TracerPid:"):
                    tracer_attached = int(line.split()[1])
                    break
            assert tracer_attached == seizer_pid, (
                f"sleeper TracerPid={tracer_attached}, expected "
                f"{seizer_pid} — SEIZE didn't take"
            )

            # Kill the seizer. EXITKILL should cascade SIGKILL to
            # the sleeper essentially immediately.
            os.kill(seizer_pid, signal.SIGKILL)
            os.waitpid(seizer_pid, 0)

            # Sleeper should die very shortly after; poll for up to
            # 5s. If still alive after that window, EXITKILL didn't
            # take.
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    pid_, status = os.waitpid(sleeper_pid, os.WNOHANG)
                except ChildProcessError:
                    # Already reaped (race with kernel); pass.
                    return
                if pid_ != 0:
                    # Verify it died by SIGKILL specifically.
                    assert os.WIFSIGNALED(status) and \
                        os.WTERMSIG(status) == signal.SIGKILL, (
                            f"sleeper died but not by SIGKILL "
                            f"(status={status:#x})"
                        )
                    return
                time.sleep(0.05)
            # Sleeper still alive after 5s — EXITKILL didn't take.
            try:
                os.kill(sleeper_pid, signal.SIGKILL)
                os.waitpid(sleeper_pid, 0)
            except Exception:
                pass
            pytest.fail(
                "EXITKILL didn't cascade — sleeper survived tracer "
                "death for >5s (would eventually SIGSYS-die on next "
                "traced syscall, but EXITKILL promises immediate kill)"
            )
        except BaseException:
            # Best-effort cleanup if anything raised mid-test.
            for pid in (seizer_pid, sleeper_pid):
                if pid is None:
                    continue
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
                try:
                    os.waitpid(pid, os.WNOHANG)
                except Exception:
                    pass
            raise


class TestSandboxAuditProfile:
    """Public-API exercise of the `--sandbox audit` profile. Goes
    through context.sandbox()'s profile resolution, not the lower-
    level _spawn.run_sandboxed direct call. Verifies the profile is
    wired end-to-end: profile→audit_mode flag→seccomp filter swap +
    tracer subprocess fork."""

    def test_audit_profile_runs_target_and_records_events(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")

        from core.sandbox.context import sandbox

        out = tmp_path / "out"
        out.mkdir()
        with sandbox(
            target=str(tmp_path), output=str(out),
            profile="full", audit=True, audit_verbose=True,
        ) as run:
            r = run(
                ["/usr/bin/python3", "-c",
                 "import os; fd = os.open('/etc/hostname', os.O_RDONLY); os.close(fd)"],
                capture_output=True, text=True, timeout=15,
            )
        assert r.returncode == 0, (
            f"audit profile target failed: rc={r.returncode}, "
            f"stderr={r.stderr[:300]!r}"
        )

        # Tracer JSONL fired into output dir (which is what context.py
        # passes as audit_run_dir).
        jsonl = out / tracer_mod._DENIALS_FILENAME
        assert jsonl.exists(), \
            "audit profile didn't produce tracer JSONL"
        records = [
            json.loads(line) for line in jsonl.read_text().splitlines()
            if line
        ]
        # At least one openat record for /etc/hostname (could also
        # appear for python startup paths).
        openats = [r for r in records if r.get("syscall") == "openat"]
        assert len(openats) > 0
        for r in openats:
            assert r["audit"] is True


class TestAuditModeDegradesWhenPtraceBlocked:
    """When the ptrace probe reports unavailable, audit mode degrades:
    seccomp filter installed WITHOUT SCMP_ACT_TRACE (target wouldn't
    survive otherwise), no tracer fork. Workflow continues."""

    def test_degrade_does_not_fork_tracer(self, monkeypatch, tmp_path):
        if not probes.check_net_available():
            pytest.skip("user namespaces not available")
        if not probes.check_mount_available():
            pytest.skip("mount-ns blocked by apparmor sysctl")
        from core.sandbox._spawn import mount_ns_available
        if not mount_ns_available():
            pytest.skip("uidmap package not installed")

        # Force ptrace probe to report unavailable.
        from core.sandbox import state
        monkeypatch.setattr(state, "_ptrace_available_cache", False)

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        # `true` should still run to completion under degraded audit.
        result = run_sandboxed(
            ["true"],
            target=str(tmp_path), output=str(tmp_path),
            block_network=False, nproc_limit=0, limits={},
            writable_paths=[str(tmp_path)], readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=10,
            audit_mode=True, audit_run_dir=str(run_dir),
        )
        assert result.returncode == 0

        # No JSONL: tracer didn't run.
        jsonl = run_dir / tracer_mod._DENIALS_FILENAME
        assert not jsonl.exists(), \
            "ptrace-degraded audit mode shouldn't have produced JSONL"
