"""Failure-mode tests for audit-mode sandbox.

Probe paths that "should never happen" but DO under degraded
environments: disk full, run dir missing, target dies early, back-to-
back sandboxes, audit profile combined with disabled flag, etc.

Goal: verify graceful degradation, no resource leaks, no hangs.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

import pytest

from core.sandbox import probes
from core.sandbox import ptrace_probe
from core.sandbox import proxy as proxy_mod
from core.sandbox import tracer as tracer_mod
from core.sandbox._spawn import run_sandboxed
from core.sandbox.context import sandbox


pytestmark = [
    pytest.mark.skipif(
        not tracer_mod._is_supported_arch(),
        reason=f"tracer doesn't support {platform.machine()}",
    ),
]


def _audit_prereqs_ok() -> tuple:
    if not probes.check_net_available():
        return False, "user namespaces not available"
    if not ptrace_probe.check_ptrace_available():
        return False, "ptrace not permitted"
    if not probes.check_mount_available():
        return False, "mount-ns blocked"
    return True, ""


class TestAuditWithDisabled:
    """`disabled=True` overrides any profile, including audit. Verify
    the audit machinery (tracer fork, seccomp filter, ref-count) is
    NOT engaged when the sandbox is effectively disabled."""

    def test_audit_profile_with_disabled_does_not_engage(
            self, tmp_path):
        # disabled=True forces effectively_disabled=True → profile
        # becomes 'none' → audit_mode field is False → no tracer.
        out = tmp_path / "out"
        out.mkdir()
        with sandbox(
            target=str(tmp_path), output=str(out),
            audit=True, disabled=True,
        ) as run:
            r = run(["true"], capture_output=True, text=True, timeout=5)
        assert r.returncode == 0
        # No JSONL — tracer wasn't engaged.
        jsonl = out / tracer_mod._DENIALS_FILENAME
        assert not jsonl.exists(), (
            "audit machinery wrongly engaged under disabled=True — "
            "unnecessary tracer fork + ptrace cost"
        )


class TestBackToBackAuditSandboxes:
    """Run multiple audit sandboxes sequentially in the same process.
    Ref-count must return to zero between calls; tracer subprocesses
    must not leak; proxy gate must return to enforcing between calls."""

    def test_sequential_audit_sandboxes_clean_state(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        # Reset proxy singleton so ref-count starts fresh.
        proxy_mod._reset_for_tests()
        try:
            # Three back-to-back audit-mode sandboxes WITHOUT
            # use_egress_proxy (ref-count not engaged) — exercises
            # tracer-fork lifecycle only.
            for i in range(3):
                run_dir = tmp_path / f"run{i}"
                run_dir.mkdir()
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
                    f"iter {i}: rc={result.returncode}"
                )
        finally:
            proxy_mod._reset_for_tests()


class TestAuditRunDirFailures:
    """audit_run_dir validation — bad paths must fail at start, not
    after attaching to the target."""

    def test_audit_run_dir_must_be_provided(self, tmp_path):
        # Missing audit_run_dir → ValueError BEFORE any fork.
        with pytest.raises(ValueError, match="audit_run_dir"):
            run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=True,  # audit_run_dir omitted
            )


class TestAuditWithoutPtraceAvailable:
    """When the ptrace probe says no, audit mode degrades gracefully:
    no tracer fork, no SCMP_ACT_TRACE in seccomp, target runs to
    completion under regular enforcement. Tracer's per-syscall hook
    cannot fire because no tracer is attached."""

    def test_no_jsonl_when_probe_negative(self, monkeypatch, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        from core.sandbox import state
        # Force probe negative.
        monkeypatch.setattr(state, "_ptrace_available_cache", False)

        run_dir = tmp_path / "run"
        run_dir.mkdir()
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
        jsonl = run_dir / tracer_mod._DENIALS_FILENAME
        assert not jsonl.exists()


class TestTracerJsonlFailureModes:
    """Tracer's _write_record must not raise on disk-full / read-only
    fs / etc. Failures return False; further records still attempted
    (next iteration could succeed if condition transient)."""

    def test_write_record_to_readonly_dir_returns_false(self, tmp_path):
        # Skip if running as root (root bypasses POSIX permissions).
        if os.geteuid() == 0:
            pytest.skip("running as root bypasses W_OK check")
        ro = tmp_path / "ro"
        ro.mkdir()
        ro.chmod(0o500)
        try:
            ok = tracer_mod._write_record(
                ro, "openat", 257, [0]*6, target_pid=1, path="/x",
            )
            assert ok is False
        finally:
            ro.chmod(0o700)

    def test_write_record_failure_logs_at_debug(
            self, tmp_path, caplog, monkeypatch):
        # Force the write path to fail and verify we get a debug log.
        def boom(*a, **k):
            raise OSError("simulated disk full")
        monkeypatch.setattr(os, "open", boom)

        import logging as _l
        with caplog.at_level(_l.DEBUG, logger="core.sandbox.tracer"):
            ok = tracer_mod._write_record(
                tmp_path, "openat", 257, [0]*6, target_pid=1, path="/x",
            )
        # OSError caught by tracer's broad except — returns False
        assert ok is False
        # Debug log line about the failure
        assert any("write_record failed" in r.message
                   for r in caplog.records), (
            f"expected debug log on write failure: "
            f"{[r.message for r in caplog.records]}"
        )


class TestRedactionInTracerRecord:
    """Tracer's _write_record now applies redact_secrets — paths and
    cmd values are scrubbed of URL-shaped credentials. Pin parity
    with summary.record_denial."""

    def test_url_credential_in_path_redacted(self, tmp_path):
        # Hypothetical: a target opens a file whose path includes
        # a URL with embedded credentials. Should be scrubbed.
        creds_path = "https://user:hunter2@example.com/secret"
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1,
            path=creds_path,
        )
        records = [
            json.loads(line) for line in
            (tmp_path / tracer_mod._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        r = records[0]
        # Password redacted from path field.
        assert "hunter2" not in r["path"], \
            f"raw credential leaked into path: {r['path']!r}"
        # And from cmd field too.
        assert "hunter2" not in r["cmd"], \
            f"raw credential leaked into cmd: {r['cmd']!r}"

    def test_clean_path_passes_through(self, tmp_path):
        clean = "/etc/hostname"
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1, path=clean,
        )
        records = [
            json.loads(line) for line in
            (tmp_path / tracer_mod._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        # Non-URL paths preserved verbatim.
        assert records[0]["path"] == clean

    def test_bearer_substring_in_path_NOT_redacted(self, tmp_path):
        # Path-specific redactor (redact_url_secrets_only) intentionally
        # SKIPS the Bearer/Basic auth-header patterns because they
        # generate false positives in filesystem paths. A path like
        # `/tmp/Bearer abc...` is a filename that happens to contain
        # the substring "Bearer", NOT an HTTP authorization header.
        # The previous behaviour (apply redact_secrets unconditionally)
        # would have wrongly redacted this filename.
        bearer = "Bearer " + "a" * 30  # >20 char threshold
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1,
            path=f"/tmp/{bearer}",
        )
        records = [
            json.loads(line) for line in
            (tmp_path / tracer_mod._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        # Filename preserved verbatim — no false-positive redaction.
        assert "a" * 30 in records[0]["path"], (
            f"path-redactor wrongly stripped Bearer-shaped filename "
            f"substring: got path={records[0]['path']!r}"
        )

    def test_basic_substring_in_path_NOT_redacted(self, tmp_path):
        # Same false-positive avoidance for the Basic auth pattern.
        basic = "Basic " + "Z" * 20
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1,
            path=f"/var/{basic}.cache",
        )
        records = [
            json.loads(line) for line in
            (tmp_path / tracer_mod._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        assert "Z" * 20 in records[0]["path"]


class TestTracerSecurityProperties:
    """Adversarial inputs from the traced target — paths with control
    characters, terminal escapes, NUL bytes, very long values. Tracer
    output must remain operator-safe (no terminal injection, no JSON
    parse failures, no panics)."""

    def test_terminal_escape_in_path_is_json_escaped(self, tmp_path):
        # A target opens a path containing CSI escape sequences. JSON
        # encoding with ensure_ascii=True must render the bytes as
        # \uXXXX so an operator catting the JSON sees no live escape.
        evil = "\x1b[2J\x1b[H\x1b[31mPWNED\x1b[0m"
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1,
            path=f"/tmp/{evil}",
        )
        raw_bytes = (tmp_path / tracer_mod._DENIALS_FILENAME).read_bytes()
        # No raw ESC bytes in on-disk JSON — encoded as 
        assert b"\x1b" not in raw_bytes, (
            f"raw terminal escape in JSONL — operator catting "
            f"the file would see live terminal escapes:\n{raw_bytes!r}"
        )
        # JSON should still parse correctly
        records = [
            json.loads(line) for line in raw_bytes.decode().splitlines()
            if line
        ]
        # Decoded path: with the Q7 fix (escape_nonprintable applied
        # before JSON encoding), the original ESC bytes are now
        # represented as literal "\\x1b" text. This is the OPERATOR-
        # SAFE form — surviving a `jq -r '.path'` round-trip without
        # injecting raw terminal escapes.
        assert "\x1b" not in records[0]["path"]
        assert "\\x1b" in records[0]["path"]
        assert "PWNED" in records[0]["path"]

    def test_path_control_chars_escaped_before_json(self, tmp_path):
        # Q7 regression: a hostile target opens a path with control
        # characters. JSON encoding with ensure_ascii=True escapes them
        # to \uXXXX in the on-disk file, BUT operators using
        # `jq -r '.path'` decode the escape and would feed raw bytes
        # to their terminal — escape injection. Defense: tracer
        # applies escape_nonprintable BEFORE JSON encoding so the
        # post-decode string is still escape-safe text.
        evil = "/tmp/\x1b[31mPWNED\x1b[0m"
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1, path=evil,
        )
        records = [
            json.loads(line) for line in
            (tmp_path / tracer_mod._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        # After JSON decode, the path field must NOT contain raw \x1b
        # bytes — escape_nonprintable converted them to "\\x1b" text,
        # which is safe even when piped through `jq -r '.path'`.
        assert "\x1b" not in records[0]["path"], (
            f"raw ESC byte in decoded path field — terminal injection "
            f"risk via `jq -r '.path' < sandbox-summary.json`: "
            f"{records[0]['path']!r}"
        )
        # The escape is preserved as text:
        assert "\\x1b" in records[0]["path"]
        assert "PWNED" in records[0]["path"]
        # cmd field gets the same treatment (it embeds path).
        assert "\x1b" not in records[0]["cmd"]

    def test_null_byte_in_path_is_handled(self, tmp_path):
        # Linux paths can't contain NUL (kernel rejects). But if a
        # malicious target somehow gets one through, our JSONL must
        # not break.
        weird = "/tmp/before\x00after"
        tracer_mod._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1, path=weird,
        )
        raw = (tmp_path / tracer_mod._DENIALS_FILENAME).read_bytes()
        # Must still be valid JSON
        records = [
            json.loads(line) for line in raw.decode().splitlines() if line
        ]
        assert len(records) == 1


class TestZombieReapingOnFailure:
    """Pre-existing path: if a parent-side error fires after the target
    child fork but before any nested handler reaped it (e.g.,
    BrokenPipeError on os.write(p_go_w, b"G")), the BaseException
    branch must reap the target child or it becomes a zombie."""

    def test_kill_and_reap_in_baseexception_is_idempotent(self, tmp_path):
        # Indirect verification: the audit_run_dir-validation path
        # raises ValueError BEFORE any fork, so this test exercises
        # the "no child to reap" leg of the BaseException cleanup.
        # The kill-and-reap must not raise if child_pid == -1
        # (uninitialised fork) or already reaped.
        with pytest.raises(ValueError):
            run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
                audit_mode=True,  # missing audit_run_dir → ValueError
            )
        # If the cleanup logic on this path tried to reap a
        # nonexistent child, we'd see an exception escape; we caught
        # only ValueError above, so test passes only if no other
        # exception leaked.

    def test_no_zombie_after_disabled_audit(self, tmp_path):
        # This exercises the SUCCESS path through run_sandboxed with
        # audit_mode=False. Just verifies cleanup happens — useful
        # baseline so a zombie from the audit path would show up
        # as a NEW process count in the suite.
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)

        before = _count_self_children()
        for _ in range(3):
            r = run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[str(tmp_path)], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=10,
                audit_mode=False, audit_run_dir=None,
            )
            assert r.returncode == 0
        after = _count_self_children()
        # Allow a small transient (test framework children, etc.)
        assert after - before <= 2, (
            f"zombie leak: child count grew from {before} to {after}"
        )


def _count_self_children() -> int:
    """Count current process's child PIDs via /proc/self/task/*/children."""
    if not os.path.isdir("/proc/self/task"):
        pytest.skip("/proc not available")
    total = 0
    for tid in os.listdir("/proc/self/task"):
        try:
            with open(f"/proc/self/task/{tid}/children") as f:
                total += len(f.read().split())
        except (FileNotFoundError, PermissionError):
            continue
    return total


class TestWarnOnceTypoDefense:
    """Finding NN: state.warn_once used getattr() with no fallback,
    so a typo'd flag name would raise an opaque AttributeError from
    inside state.py — call site has to dig through stack frames to
    find the typo. Defensive: emit a clear, named error pointing to
    the offending flag."""

    def test_typo_in_flag_name_raises_clear_error(self):
        from core.sandbox import state
        with pytest.raises(AttributeError, match="warn_once"):
            state.warn_once("_definitely_not_a_real_flag_xyz")

    def test_real_flag_still_works(self):
        from core.sandbox import state
        # Use one of the audit-related flags. Reset first so the
        # first call returns True.
        state._audit_warned_no_spawn = False
        assert state.warn_once("_audit_warned_no_spawn") is True
        # Second call returns False.
        assert state.warn_once("_audit_warned_no_spawn") is False


class TestStaleAuditConfigSweep:
    """Finding MM: audit-config tempfiles in /tmp/raptor-audit-cfg-*
    leak when the parent process gets SIGKILL'd mid-audit (OOM, etc.).
    The normal lifecycle paths unlink them, but SIGKILL bypasses
    finally blocks. Sweep on first engaged-audit per process."""

    def test_sweep_removes_same_uid_stale_files(self, tmp_path):
        # Create some fake stale config files (own UID).
        from core.sandbox._spawn import _sweep_stale_audit_configs
        # Put them in /tmp where the sweep looks.
        import tempfile
        stale_paths = []
        for _ in range(3):
            fd, p = tempfile.mkstemp(
                prefix="raptor-audit-cfg-test-", suffix=".json", dir="/tmp",
            )
            os.write(fd, b"{}")
            os.close(fd)
            stale_paths.append(p)
        try:
            # Now sweep — same-UID files matching the glob should go.
            _sweep_stale_audit_configs()
            for p in stale_paths:
                assert not os.path.exists(p), (
                    f"sweep didn't remove same-UID stale file: {p}"
                )
        finally:
            # In case sweep failed, clean up.
            for p in stale_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_sweep_is_idempotent_when_nothing_to_clean(self):
        from core.sandbox._spawn import _sweep_stale_audit_configs
        # Should be a no-op (the prior test's tempfiles, if any,
        # already cleaned up). Just verify no exception.
        _sweep_stale_audit_configs()
        # Run again — still no-op
        _sweep_stale_audit_configs()


class TestAuditConfigWriteFailureHandling:
    """Finding LL: audit-config file is mkstemp'd in /tmp, JSON
    written, then handed to the tracer subprocess via execvpe argv.
    If the write fails (disk full, EIO, partial write), the tracer
    would later read an empty/partial file → JSONDecodeError → exit
    1 → parent times out waiting for ready signal → audit silently
    disabled. Worse: operator gets an ambiguous 'tracer failed to
    attach' error rather than the actual cause.

    Fix: write loops until done; any partial-write/EIO unlinks the
    file, propagates the error immediately, and clears the engaged
    state so the parent's audit cleanup paths don't double-unlink.
    """

    def test_partial_write_propagates_oserror(self, monkeypatch, tmp_path):
        from core.sandbox import _spawn
        from core.sandbox import probes
        if not probes.check_net_available():
            pytest.skip()
        if not probes.check_mount_available():
            pytest.skip()

        # Patch os.write to return 0 on the audit-config fd → simulates
        # disk-full mid-write. Need to be careful not to break OTHER
        # writes (the spawn flow uses many).
        original_write = os.write
        sentinel_paths = []

        def selective_write(fd, data):
            # Only intercept writes to the audit-config tempfile.
            # Use /proc/self/fd/<fd> to check the symlink target.
            try:
                target = os.readlink(f"/proc/self/fd/{fd}")
                if "raptor-audit-cfg-" in target:
                    sentinel_paths.append(target)
                    return 0  # simulate disk-full
            except OSError:
                pass
            return original_write(fd, data)
        monkeypatch.setattr(os, "write", selective_write)

        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(OSError, match="audit-config"):
            _spawn.run_sandboxed(
                ["true"],
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[str(tmp_path)], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=10,
                audit_mode=True, audit_run_dir=str(out),
            )
        # Confirm the tempfile got unlinked despite the failure.
        for p in sentinel_paths:
            assert not os.path.exists(p), (
                f"audit-config tempfile leaked after write failure: {p}"
            )


class TestAuditMissingOutputBehaviour:
    """Finding KK + agentic-pass discovery: handling depends on origin
    of the audit signal:
      - Per-call kwarg `audit=True` + no output= → ValueError (caller
        explicitly asked for audit on a call with no output dir; that's
        an operator-level mistake worth surfacing).
      - CLI flag `--audit` + no output= → silently demote audit for
        this call only (operator's intent is process-wide; internal
        helper sandboxes without output should NOT block the workflow).
        Discovered by the real agentic-pass against /tmp/vulns where
        scanner's git-init helper sandbox has no output dir but
        CLI-flag audit got applied to it, killing the workflow."""

    def test_explicit_kwarg_audit_no_output_raises(self):
        from core.sandbox.context import sandbox
        with sandbox(audit=True) as run:
            with pytest.raises(ValueError, match="output="):
                run(["true"])

    def test_cli_flag_audit_no_output_silently_demotes(self, monkeypatch):
        # CLI --audit set, but THIS sandbox call has no output= →
        # don't kill the workflow; just skip audit for this call.
        from core.sandbox import state, context as ctx
        monkeypatch.setattr(state, "_cli_sandbox_audit", True)
        # Call sandbox WITHOUT explicit audit= kwarg — just CLI flag.
        # Should NOT raise on the run() call.
        with ctx.sandbox() as run:
            try:
                # Run a trivial command — may fail on this host for
                # other reasons (mount-ns), but the audit-validation
                # ValueError must NOT fire.
                run(["true"], capture_output=True, text=True, timeout=5)
            except ValueError as e:
                if "output=" in str(e):
                    pytest.fail(
                        "CLI --audit + no output= should silently "
                        "demote audit for THIS call, not raise — "
                        "internal helper sandboxes break under audit "
                        "otherwise (real agentic-pass discovery)"
                    )
                # Other ValueError unrelated to audit: re-raise
                raise
            except (RuntimeError, OSError):
                pass  # mount-ns / other infra failures OK

    def test_audit_kwarg_with_output_no_run_calls_OK(self):
        # Ref-count observation tests construct sandbox without
        # calling run() — must keep working.
        from core.sandbox.context import sandbox
        with sandbox(audit=True) as run:
            pass

    def test_audit_kwarg_with_output_run_succeeds_validation(self, tmp_path):
        from core.sandbox.context import sandbox
        out = tmp_path / "out"
        out.mkdir()
        with sandbox(audit=True, output=str(out)) as run:
            try:
                run(["true"], capture_output=True, text=True, timeout=5)
            except (ValueError, RuntimeError, OSError):
                pass


class TestAuditDegradationWarning:
    """Real agentic-pass discovery: the degradation warning at line ~935
    of context.py was checking the original `audit_mode` instead of
    `nonlocal_audit_mode` (the per-call effective state). For internal
    helper sandboxes that we ALREADY silently demote at line ~620,
    this caused a misleading "spawn-path unavailable" warning to fire
    even when spawn IS available — the call simply didn't need audit.

    The fix gates the warning on `nonlocal_audit_mode` (the demoted
    value) so internal helpers no longer trigger it. Additionally,
    the warning text now distinguishes the actual root cause
    (mount-ns blocked vs pass_fds= vs input=) so operators get a
    pointer to the correct fix."""

    def test_no_warning_for_demoted_internal_helper(self, monkeypatch, caplog):
        """CLI --audit + sandbox call with no target/output → audit is
        silently demoted, NO degradation warning fires. The call's
        omission of target/output is a deliberate caller choice
        (helper sandbox), not an audit prereq failure."""
        import logging
        from core.sandbox import state, context as ctx
        # Simulate CLI --audit set process-wide.
        monkeypatch.setattr(state, "_cli_sandbox_audit", True)
        # Reset warn-once so the test is independent of suite ordering.
        monkeypatch.setattr(state, "_audit_warned_no_spawn", False)
        caplog.set_level(logging.WARNING, logger="core.sandbox.context")
        # Helper-style call: no target, no output. Equivalent to
        # raptor_agentic.py's git-init invocation.
        with ctx.sandbox() as run:
            try:
                run(["true"], capture_output=True, text=True, timeout=5)
            except (RuntimeError, OSError, ValueError):
                pass
        # Assert the misleading warning did NOT fire for this call.
        for rec in caplog.records:
            if "spawn-path unavailable" in rec.getMessage() or \
                    "mount-ns" in rec.getMessage():
                pytest.fail(
                    f"degradation warning fired for an internal helper "
                    f"call that was already silently demoted: "
                    f"{rec.getMessage()!r}"
                )

    def test_warning_text_distinguishes_mount_ns_vs_pass_fds(
            self, monkeypatch):
        """The warning message picks the precise reason for the spawn
        ineligibility: 'mount-ns blocked' (host sysctl) vs 'pass_fds='
        / 'input=' (call kwargs). Operator gets actionable fix."""
        from core.sandbox import context as ctx_mod
        # Read the source to confirm all three reason strings are
        # present — a structural-drift defense (so a future refactor
        # that drops one branch is caught even without exercising it).
        src = (Path(ctx_mod.__file__)).read_text()
        assert "mount-ns blocked by host" in src, (
            "mount-ns degradation reason missing from context.py")
        assert "pass_fds=" in src, (
            "pass_fds degradation reason missing from context.py")
        assert "input=" in src, (
            "input= degradation reason missing from context.py")


class TestAuditRunDirKwarg:
    """audit_run_dir= decouples 'where audit JSONL goes' from 'what
    Landlock restricts writes to'. Required for callers like the
    codeql analyze sandbox calls, where writes legitimately go to
    paths that can't be enumerated in writable_paths (~/.codeql
    cache, the database dir during analysis, etc.) but the operator
    still wants audit signal.

    Without this kwarg, the only way to get audit signal was via
    output=, which forced Landlock to restrict writes to
    ['/tmp', output] — silently breaking any tool that writes
    elsewhere.
    """

    def test_audit_run_dir_alone_satisfies_explicit_audit(self, tmp_path):
        """`audit=True` + `audit_run_dir=` (no output) → no ValueError.
        Previously raised because output was the only accepted target."""
        from core.sandbox.context import sandbox
        out = tmp_path / "audit_signal"
        out.mkdir()
        # Constructing sandbox(audit=True, audit_run_dir=...) without
        # output= must NOT raise at run-time.
        with sandbox(audit=True, audit_run_dir=str(out)) as run:
            try:
                run(["true"], capture_output=True, text=True, timeout=5)
            except ValueError as e:
                # The specific ValueError we're guarding against
                # mentions output=/audit_run_dir=.
                if ("output=" in str(e) and "audit_run_dir=" in str(e)):
                    pytest.fail(
                        "audit_run_dir= alone should satisfy the audit "
                        "target requirement; got ValueError"
                    )
                raise
            except (RuntimeError, OSError):
                # Other infrastructure errors (mount-ns missing, etc.)
                # are unrelated to the kwarg contract being tested.
                pass

    def test_audit_no_target_at_all_still_raises_for_explicit(self):
        """audit=True with NEITHER output= NOR audit_run_dir= must
        still raise — that's the original case 1, unchanged."""
        from core.sandbox.context import sandbox
        with sandbox(audit=True) as run:
            with pytest.raises(ValueError) as exc_info:
                run(["true"])
            # Error message must mention BOTH options so operators
            # see they have a choice.
            msg = str(exc_info.value)
            assert "output=" in msg
            assert "audit_run_dir=" in msg

    def test_audit_run_dir_does_not_add_to_writable_paths(
            self, tmp_path, monkeypatch):
        """Critical contract: passing audit_run_dir= MUST NOT extend
        Landlock's writable_paths. That's the whole point of the
        kwarg — if codeql analyze writes to ~/.codeql, we don't want
        Landlock to additionally restrict it to ['/tmp', audit_dir].

        Verify by inspecting the writable_paths value computed in the
        sandbox setup. We capture it via a monkeypatch on _spawn's
        run_sandboxed entry point — the kwargs that arrive there tell
        us exactly what Landlock will see.
        """
        from core.sandbox import context as ctx
        from core.sandbox import _spawn as _spawn_mod
        captured = {}

        def fake_run_sandboxed(*args, **kwargs):
            captured["writable_paths"] = list(kwargs.get("writable_paths") or [])
            captured["audit_run_dir"] = kwargs.get("audit_run_dir")
            # Return a dummy successful CompletedProcess shape.
            import subprocess
            return subprocess.CompletedProcess(args=args, returncode=0,
                                               stdout="", stderr="")

        # Force the spawn path so writable_paths is meaningful.
        # mount_ns_available() checks ONLY for newuidmap binaries —
        # not the apparmor sysctl. The actual spawn-eligibility gate
        # in context.py also requires check_mount_available() (sysctl
        # check). CI runners on Ubuntu have the binaries but
        # apparmor_restrict_unprivileged_userns=1, so the spawn path
        # silently degrades to subprocess+preexec and the fake
        # run_sandboxed never gets called → KeyError on `captured`.
        # Skip if either gate fails so the assertion is sound.
        from core.sandbox.probes import check_mount_available
        if not (_spawn_mod.mount_ns_available()
                and check_mount_available()):
            pytest.skip("mount-ns not available (binaries OR sysctl) "
                        "— spawn path won't engage")
        monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_run_sandboxed)

        target = tmp_path / "tgt"; target.mkdir()
        audit_dir = tmp_path / "audit_only"; audit_dir.mkdir()
        with ctx.sandbox(audit=True, target=str(target),
                        audit_run_dir=str(audit_dir)) as run:
            run(["true"])

        wp = captured["writable_paths"]
        assert "/tmp" in wp
        assert str(audit_dir) not in wp, (
            f"audit_run_dir leaked into writable_paths {wp}; this "
            f"would cause Landlock to restrict writes to the audit "
            f"dir, defeating the kwarg's purpose"
        )
        # And audit_run_dir SHOULD have been threaded through.
        assert captured["audit_run_dir"] == str(audit_dir)

    def test_output_alone_still_works_as_audit_target(self, tmp_path):
        """Backward-compat: when output= is set without explicit
        audit_run_dir=, audit JSONL still lands at output (the
        pre-existing behaviour). audit_run_dir= is a NEW option,
        not a replacement."""
        from core.sandbox import context as ctx
        from core.sandbox import _spawn as _spawn_mod
        from core.sandbox.probes import check_mount_available
        # mount_ns_available() alone is insufficient — see comment in
        # test_audit_run_dir_does_not_add_to_writable_paths above.
        if not (_spawn_mod.mount_ns_available()
                and check_mount_available()):
            pytest.skip("mount-ns not available (binaries OR sysctl)")
        captured = {}

        def fake_run_sandboxed(*args, **kwargs):
            captured["audit_run_dir"] = kwargs.get("audit_run_dir")
            import subprocess
            return subprocess.CompletedProcess(args=args, returncode=0,
                                               stdout="", stderr="")

        import pytest as _pt
        monkey = _pt.MonkeyPatch()
        try:
            monkey.setattr(_spawn_mod, "run_sandboxed", fake_run_sandboxed)
            target = tmp_path / "tgt"; target.mkdir()
            out = tmp_path / "out"; out.mkdir()
            with ctx.sandbox(audit=True, target=str(target),
                            output=str(out)) as run:
                run(["true"])
            assert captured["audit_run_dir"] == str(out), (
                "output= must still be used as the audit target when "
                "audit_run_dir= isn't supplied (backward-compat)"
            )
        finally:
            monkey.undo()


class TestAuditAcquireOrdering:
    """Finding I: the proxy audit ref-count must be acquired AT THE
    YIELD, not earlier in setup. If acquire happened in the middle
    of setup, an exception in subsequent setup code would leave the
    count incremented forever (the contextmanager's try/finally only
    fires after a successful yield).

    The fix is structural: acquire is deferred until immediately
    before yield, so every code path that reaches acquire is
    guaranteed to also reach the matching release in finally.
    Pin the structure so a future refactor doesn't accidentally
    re-introduce the gap."""

    def test_acquire_happens_immediately_before_yield(self):
        # Read the source file and verify the acquire call sits
        # between the `try:` that wraps the yield and the `yield run`
        # itself — no other meaningful code can fail between them.
        import inspect
        from core.sandbox import context as ctx
        src = inspect.getsource(ctx.sandbox)
        # Find the exact two lines and assert ordering.
        lines = src.splitlines()
        acquire_lines = [
            i for i, line in enumerate(lines)
            if "acquire_audit_log_only" in line
        ]
        yield_lines = [
            i for i, line in enumerate(lines)
            if line.strip() == "yield run"
        ]
        try_lines = [
            i for i, line in enumerate(lines)
            if line.strip() == "try:"
        ]
        finally_lines = [
            i for i, line in enumerate(lines)
            if line.strip() == "finally:"
        ]
        assert acquire_lines, "no acquire_audit_log_only call found"
        assert yield_lines, "no yield run found"

        # Acquire must be BEFORE the yield (obviously), and there
        # must be a finally clause AFTER the yield that handles
        # release. The acquire-yield gap must be small (≤10 lines)
        # to keep the leak window minimal.
        last_acquire = max(acquire_lines)
        last_yield = max(yield_lines)
        assert last_acquire < last_yield, (
            "acquire must precede yield"
        )
        gap = last_yield - last_acquire
        assert gap < 10, (
            f"acquire is {gap} lines before yield — too far. Setup "
            f"code between acquire and yield could raise and leak "
            f"the ref-count. Move acquire closer to yield."
        )

        # There must be a finally block AFTER the yield (for release).
        post_yield_finally = [f for f in finally_lines if f > last_yield]
        assert post_yield_finally, (
            "no finally block after yield — release on exit is "
            "not guaranteed"
        )


class TestAuditComposesWithDebugProfile:
    """The flag-based refactor's headline new capability:
    `--sandbox debug --audit` runs the target with debug-profile
    seccomp (permits ptrace) AND attaches the audit tracer. Operators
    running gdb/rr under /crash-analysis can simultaneously see what
    enforcement WOULD have blocked. Pre-refactor this combination
    didn't exist (audit and debug were mutually exclusive profiles)."""

    def test_debug_plus_audit_runs_and_audits(self, tmp_path):
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")

        from core.sandbox.context import sandbox

        out = tmp_path / "out"
        out.mkdir()
        # Target under debug + audit + verbose. Under debug seccomp,
        # ptrace and friends are PERMITTED (so /crash-analysis still
        # works). Tracer still attaches and audits the broader
        # blocklist + filesystem layer.
        with sandbox(
            target=str(tmp_path), output=str(out),
            profile="debug",
            audit=True, audit_verbose=True,
        ) as run:
            r = run(
                ["/usr/bin/python3", "-c", "pass"],
                capture_output=True, text=True, timeout=15,
            )
        assert r.returncode == 0, (
            f"debug+audit target failed: rc={r.returncode}, "
            f"stderr={r.stderr[:300]!r}"
        )

        # Tracer JSONL exists: tracer was engaged despite debug profile.
        jsonl = out / tracer_mod._DENIALS_FILENAME
        assert jsonl.exists(), (
            "debug+audit didn't produce audit JSONL — refactor broke "
            "the new debug+audit composition"
        )
        # Records present (verbose mode logs everything).
        records = [
            json.loads(line) for line in
            jsonl.read_text().splitlines() if line
        ]
        assert len(records) > 0, "verbose mode should log records"
        for r in records:
            assert r["audit"] is True


class TestAuditWithExistingSandboxFlows:
    """Audit profile must compose with existing sandbox features —
    --no-sandbox precedence, run_trusted protection, CLI override
    behaviour, etc."""

    def test_no_sandbox_overrides_audit_profile(self, tmp_path):
        # disabled=True (== --no-sandbox at CLI) must defeat the
        # audit profile entirely — no tracer, no JSONL.
        from core.sandbox.context import sandbox
        out = tmp_path / "out"
        out.mkdir()
        with sandbox(
            target=str(tmp_path), output=str(out),
            audit=True, disabled=True,
        ) as run:
            r = run(["true"], capture_output=True, text=True, timeout=5)
        assert r.returncode == 0
        # Critical: no audit signal because disabled took precedence.
        jsonl = out / tracer_mod._DENIALS_FILENAME
        assert not jsonl.exists()

    def test_cli_audit_overrides_library(
            self, monkeypatch, tmp_path):
        # CLI's `--audit` flag must engage audit even if library
        # code didn't pass `audit=True`. Prompt-injection-safe
        # contract: target repo can't disable audit if operator
        # asked for it.
        from core.sandbox import state, context as ctx
        ok, reason = _audit_prereqs_ok()
        if not ok:
            pytest.skip(reason)
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")

        monkeypatch.setattr(state, "_cli_sandbox_audit", True)
        # Also force --verbose so the empty `pass` script produces
        # records (under filtered audit, /usr/lib/python opens are
        # in the system allowlist and don't fire).
        monkeypatch.setattr(state, "_cli_sandbox_audit_verbose", True)
        out = tmp_path / "out"
        out.mkdir()
        # Library code passes audit=False (default), but CLI flag wins.
        with ctx.sandbox(
            target=str(tmp_path), output=str(out),
            profile="full",  # library doesn't request audit
        ) as run:
            r = run(["/usr/bin/python3", "-c", "pass"],
                    capture_output=True, text=True, timeout=15)
        assert r.returncode == 0
        # CLI's --audit took effect: tracer JSONL exists.
        jsonl = out / tracer_mod._DENIALS_FILENAME
        assert jsonl.exists(), (
            "CLI --audit was ignored — prompt-injection safety violation"
        )

    def test_audit_kwarg_with_disabled_kwarg_does_not_acquire_proxy(self):
        # Finding D: per-call audit=True + disabled=True must NOT
        # acquire the proxy audit ref-count (sandbox is effectively
        # disabled, so audit-mode is incoherent and silently no-ops).
        from core.sandbox.context import sandbox
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])
            assert proxy_inst._audit_count == 0
            with sandbox(
                audit=True, disabled=True,
                use_egress_proxy=True,
                proxy_hosts=["api.example.com"],
            ) as run:
                # disabled=True wins; audit silently no-ops; no acquire.
                assert proxy_inst._audit_count == 0, (
                    f"audit-mode wrongly engaged with disabled=True: "
                    f"count={proxy_inst._audit_count}"
                )
            assert proxy_inst._audit_count == 0
        finally:
            proxy_mod._reset_for_tests()

    def test_audit_kwarg_with_profile_none_does_not_acquire_proxy(self):
        # Same defense: per-call profile="none" (without disabled) is
        # also "no enforcement", so audit must no-op.
        from core.sandbox.context import sandbox
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])
            with sandbox(
                audit=True, profile="none",
                use_egress_proxy=True,
                proxy_hosts=["api.example.com"],
            ) as run:
                assert proxy_inst._audit_count == 0
            assert proxy_inst._audit_count == 0
        finally:
            proxy_mod._reset_for_tests()

    def test_audit_acquires_proxy_only_when_proxy_engaged(self):
        # use_egress_proxy=False → no proxy → no acquire on the
        # singleton. Verify ref-count stays zero across an audit
        # sandbox lifecycle when proxy isn't engaged.
        from core.sandbox.context import sandbox
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])
            assert proxy_inst._audit_count == 0

            with sandbox(audit=True, use_egress_proxy=False) as run:
                # Proxy not engaged by THIS sandbox; count unchanged.
                assert proxy_inst._audit_count == 0

            assert proxy_inst._audit_count == 0
        finally:
            proxy_mod._reset_for_tests()


class TestProxyAuditAcquireReleaseIntegration:
    """End-to-end: sandbox() context with audit=True +
    use_egress_proxy=True must acquire on entry and release on exit,
    even if the sandboxed run raises."""

    def test_acquire_release_via_sandbox_context(self):
        # Start with a clean proxy
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])
            assert proxy_inst._audit_count == 0

            with sandbox(
                audit=True,
                use_egress_proxy=True,
                proxy_hosts=["api.example.com"],
            ) as run:
                assert proxy_inst._audit_count == 1
                assert proxy_inst._audit_log_only is True

            assert proxy_inst._audit_count == 0
            assert proxy_inst._audit_log_only is False
        finally:
            proxy_mod._reset_for_tests()

    def test_release_runs_even_on_exception_inside_context(self):
        proxy_mod._reset_for_tests()
        try:
            proxy_inst = proxy_mod.get_proxy(["api.example.com"])

            with pytest.raises(RuntimeError, match="simulated"):
                with sandbox(
                    audit=True,
                    use_egress_proxy=True,
                    proxy_hosts=["api.example.com"],
                ) as run:
                    assert proxy_inst._audit_count == 1
                    raise RuntimeError("simulated workflow failure")

            # Cleanup ran despite the exception
            assert proxy_inst._audit_count == 0
            assert proxy_inst._audit_log_only is False
        finally:
            proxy_mod._reset_for_tests()
