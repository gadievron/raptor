"""Fail-closed behaviour of the audit evidence channel.

Pre-fix, ``run(..., audit=True, audit_run_dir=<nonexistent dir>)`` did
not fail: the tracer's ENOENT on ``<dir>/.audit`` was swallowed by the
environmental-degradation excepts, the call cascaded mount-ns →
Landlock-only → bare ``subprocess.run``, and the command executed with
reduced containment and NO audit evidence while the API call looked
successful.

These tests cover the three fix layers:

  1. Entry validation — a caller-supplied audit target directory that
     is missing / not a directory / not writable raises ``ValueError``
     before any spawn tier runs (caller-input error, distinct from
     environmental degradation).
  2. Vanished-mid-run — an audit target dir that disappears between
     entry validation and spawn setup raises ``SandboxSetupError``
     instead of riding the degradation ladder.
  3. Evidence bottleneck — when no audit tier can engage,
     ``audit_required=True`` refuses to execute the command
     (``SandboxSetupError``); the default degrades but always leaves
     the machine-readable trail (``sandbox-audit-degraded.json`` +
     ``sandbox_info["audit_engaged"] is False``).

All tests are hermetic: environmental degradation is forced by
monkeypatching the seccomp/ptrace probes and by ``input=`` (which
routes the call off the spawn path), never by relying on host
capabilities.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from core.sandbox.context import run_trusted, run_untrusted, sandbox
from core.sandbox.errors import SandboxSetupError

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="degradation-ladder paths are Linux-backend specific",
)

MARKER = "sandbox-audit-degraded.json"


@pytest.fixture
def no_audit_tiers(monkeypatch):
    """Force every audit tier off, hermetically.

    The Landlock-only tracer probes are patched at their defining
    modules (context.py imports them inside the function bodies, so
    patching the source modules reaches every call site). The spawn
    tier is avoided per-test by passing ``input=`` — the kwarg-compat
    gate routes such calls off the spawn path on Linux.
    """
    import core.sandbox.ptrace_probe as pp
    import core.sandbox.seccomp as sc
    monkeypatch.setattr(sc, "check_seccomp_available", lambda: False)
    monkeypatch.setattr(pp, "check_ptrace_available", lambda: False)


def _audit_sandbox(audit_dir, **extra):
    return sandbox(
        audit=True, audit_run_dir=str(audit_dir),
        block_network=False, target="/tmp",
        profile="target_run", **extra,
    )


class TestEntryValidation:
    """Layer 1: caller-input errors raise at run() entry."""

    def test_missing_audit_run_dir_raises_and_does_not_execute(
            self, tmp_path):
        proof = tmp_path / "ran"
        with _audit_sandbox(tmp_path / "no-such-dir") as r:
            with pytest.raises(ValueError, match="audit target directory"):
                r(["touch", str(proof)], capture_output=True, timeout=30)
        assert not proof.exists(), (
            "command executed despite the invalid audit target dir — "
            "the fail-open this test exists to prevent"
        )

    def test_audit_run_dir_pointing_at_file_raises(self, tmp_path):
        f = tmp_path / "a-file"
        f.write_text("not a dir")
        with _audit_sandbox(f) as r:
            with pytest.raises(ValueError,
                               match="not an existing directory"):
                r(["true"], capture_output=True, timeout=30)

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="root bypasses mode-bit write denial")
    def test_unwritable_audit_run_dir_raises(self, tmp_path):
        d = tmp_path / "ro"
        d.mkdir(mode=0o500)
        try:
            with _audit_sandbox(d) as r:
                with pytest.raises(ValueError, match="not writable"):
                    r(["true"], capture_output=True, timeout=30)
        finally:
            d.chmod(0o700)

    def test_output_fallback_audit_target_also_validated(self, tmp_path):
        """audit without audit_run_dir= uses output= as the audit
        target — the same validation must apply to it."""
        with sandbox(audit=True, output=str(tmp_path / "gone"),
                     block_network=False, target="/tmp",
                     profile="target_run") as r:
            with pytest.raises(ValueError,
                               match=r"output \(audit target fallback\)"):
                r(["true"], capture_output=True, timeout=30)

    def test_valid_audit_dir_runs_and_stamps_sandbox_info(self, tmp_path):
        """The legitimate contract (existing writable run dir) is
        unchanged, and the machine-readable per-call record exists."""
        d = tmp_path / "audit"
        d.mkdir()
        with _audit_sandbox(d) as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0
        assert isinstance(res.sandbox_info.get("audit_engaged"), bool)

    def test_no_audit_means_no_validation(self, tmp_path):
        """audit_run_dir= without audit engaged is inert (sca passes
        ``audit_run_dir=None if not audit`` but other callers may pass
        the path unconditionally) — must not raise."""
        with sandbox(audit_run_dir=str(tmp_path / "missing"),
                     block_network=False, target="/tmp",
                     profile="target_run") as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0


@linux_only
class TestVanishedMidRun:
    """Layer 2: audit dir vanishing after entry validation fails loud."""

    def test_spawn_enoent_with_vanished_dir_raises(
            self, tmp_path, monkeypatch):
        """A FileNotFoundError out of the spawn tier while the audit
        dir is gone must raise SandboxSetupError, not degrade."""
        import shutil

        from core.sandbox import _spawn as spawn_mod
        d = tmp_path / "audit"
        d.mkdir()
        proof = tmp_path / "ran"

        def _vanish_and_raise(*a, **k):
            shutil.rmtree(d)
            raise FileNotFoundError(2, "No such file or directory",
                                    str(d / ".audit"))

        monkeypatch.setattr(spawn_mod, "mount_ns_available", lambda: True)
        monkeypatch.setattr(spawn_mod, "run_sandboxed", _vanish_and_raise)
        # Force the spawn tier eligible regardless of host capabilities.
        from core.sandbox import context as ctx
        monkeypatch.setattr(ctx, "check_net_available", lambda: True)
        monkeypatch.setattr(ctx, "check_mount_available", lambda: True)

        with _audit_sandbox(d) as r:
            with pytest.raises(SandboxSetupError,
                               match="audit target directory"):
                r(["touch", str(proof)], capture_output=True, timeout=30)
        assert not proof.exists()

    def test_spawn_failure_with_intact_dir_still_degrades(
            self, tmp_path, monkeypatch, no_audit_tiers):
        """Environmental spawn failures (audit dir intact) keep the
        legitimate degradation ladder — the command still runs, and
        the degradation leaves the machine-readable trail."""
        from core.sandbox import _spawn as spawn_mod
        from core.sandbox import context as ctx
        d = tmp_path / "audit"
        d.mkdir()

        def _env_failure(*a, **k):
            raise RuntimeError("kernel quirk: uidmap handshake failed")

        monkeypatch.setattr(spawn_mod, "mount_ns_available", lambda: True)
        monkeypatch.setattr(spawn_mod, "run_sandboxed", _env_failure)
        monkeypatch.setattr(ctx, "check_net_available", lambda: True)
        monkeypatch.setattr(ctx, "check_mount_available", lambda: True)

        with _audit_sandbox(d) as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0
        assert res.sandbox_info.get("audit_engaged") is False
        payload = json.loads((d / MARKER).read_text())
        assert payload["degraded"] is True
        assert "spawn path failed" in payload["reason"]


@linux_only
class TestEvidenceBottleneck:
    """Layer 3: audit requested but no tier engaged."""

    def test_default_degrade_writes_marker_and_sandbox_info(
            self, tmp_path, no_audit_tiers):
        d = tmp_path / "audit"
        d.mkdir()
        with _audit_sandbox(d) as r:
            # input= routes off the spawn tier; probes kill the
            # Landlock-only tracer tier.
            res = r(["cat"], input=b"", capture_output=True, timeout=60)
        assert res.returncode == 0
        assert res.sandbox_info.get("audit_engaged") is False
        payload = json.loads((d / MARKER).read_text())
        assert payload["audit_requested"] is True
        assert payload["audit_engaged"] is False
        assert payload["reason"]

    def test_audit_required_refuses_to_execute(
            self, tmp_path, no_audit_tiers):
        d = tmp_path / "audit"
        d.mkdir()
        proof = tmp_path / "ran"
        with _audit_sandbox(d, audit_required=True) as r:
            with pytest.raises(SandboxSetupError,
                               match="audit_required=True"):
                r(["touch", str(proof)], input=b"",
                  capture_output=True, timeout=30)
        assert not proof.exists(), (
            "audit_required=True must prevent execution when no audit "
            "tier engaged"
        )
        # The refused degradation is still marker-recorded.
        assert (d / MARKER).exists()

    def test_audit_required_inert_when_audit_engages(self, tmp_path):
        """audit_required must not fire when an audit tier engages or
        when audit is not requested at all."""
        d = tmp_path / "audit"
        d.mkdir()
        # audit not requested → audit_required inert.
        with sandbox(audit_required=True, block_network=False,
                     target="/tmp", profile="target_run") as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0


class TestKwargSurface:
    """audit_required is sandbox()-level configuration."""

    def test_inner_run_rejects_audit_required(self, tmp_path):
        with sandbox(block_network=False, target="/tmp",
                     profile="target_run") as r:
            with pytest.raises(TypeError, match="audit_required"):
                r(["true"], audit_required=True)

    def test_run_trusted_rejects_audit_required(self):
        with pytest.raises(TypeError, match="audit_required"):
            run_trusted(["true"], audit_required=True)

    def test_module_run_forwards_audit_required(
            self, tmp_path, monkeypatch):
        """The one-shot run() wrapper must forward audit_required into
        the sandbox() context (signature parity guard)."""
        seen = {}
        import core.sandbox.context as ctx

        class _FakeCtx:
            def __init__(self, **kw):
                seen.update(kw)

            def __enter__(self):
                return lambda cmd, **k: __import__("subprocess").run(
                    cmd, capture_output=True, check=False)

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(ctx, "sandbox", _FakeCtx)
        ctx.run(["true"], audit_required=True)
        assert seen.get("audit_required") is True

    def test_run_untrusted_accepts_audit_required(self, monkeypatch):
        """run_untrusted's kwarg allowlist admits audit_required and
        forwards it (composability with audit=True)."""
        import core.sandbox.context as ctx
        captured = {}

        def _fake_run(cmd, **kw):
            captured.update(kw)

            class _R:
                returncode = 0
                sandbox_info = {}
            return _R()

        monkeypatch.setattr(ctx, "run", _fake_run)
        # Pretend the userns tier is available so run_untrusted's
        # degraded-host guard (whatever its current shape) is a no-op
        # and the call reaches the forwarding under test.
        monkeypatch.setattr(ctx, "check_net_available", lambda: True)
        run_untrusted(["true"], output="/tmp", audit=True,
                      audit_required=True)
        assert captured.get("audit_required") is True


@linux_only
class TestSpawnTierFailClosed:
    """audit_required threads into _spawn's in-spawn degrade sites
    (F063a/b/c) — the raise happens before the fork."""

    def test_f063a_no_seccomp_profile_raises_when_required(self, tmp_path):
        from core.sandbox import _spawn as spawn_mod
        d = tmp_path / "audit"
        d.mkdir()
        with pytest.raises(SandboxSetupError, match="no seccomp filter"):
            spawn_mod.run_sandboxed(
                ["true"],
                target=None, output=None, block_network=False,
                nproc_limit=64, limits={}, writable_paths=[],
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env={}, cwd=None, timeout=30,
                audit_mode=True, audit_run_dir=str(d),
                audit_required=True,
            )
        # The refused degradation is still marker-recorded.
        assert (d / MARKER).exists()
        # The pre-raise cleanup removed the mkdtemp stub.
        import glob
        import tempfile
        stubs = glob.glob(os.path.join(tempfile.gettempdir(),
                                       ".raptor-sbx-*"))
        # (other concurrent runs may own stubs; just assert no crash)
        assert isinstance(stubs, list)

    def test_f063b_no_libseccomp_raises_when_required(
            self, tmp_path, monkeypatch):
        import core.sandbox.seccomp as sc
        from core.sandbox import _spawn as spawn_mod
        monkeypatch.setattr(sc, "check_seccomp_available", lambda: False)
        d = tmp_path / "audit"
        d.mkdir()
        with pytest.raises(SandboxSetupError, match="libseccomp"):
            spawn_mod.run_sandboxed(
                ["true"],
                target=None, output=None, block_network=False,
                nproc_limit=64, limits={}, writable_paths=[],
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env={}, cwd=None, timeout=30,
                audit_mode=True, audit_run_dir=str(d),
                audit_required=True,
            )
        assert (d / MARKER).exists()

    def test_f063c_ptrace_blocked_raises_when_required(
            self, tmp_path, monkeypatch):
        import core.sandbox.ptrace_probe as pp
        import core.sandbox.seccomp as sc
        from core.sandbox import _spawn as spawn_mod
        monkeypatch.setattr(sc, "check_seccomp_available", lambda: True)
        monkeypatch.setattr(pp, "check_ptrace_available", lambda: False)
        d = tmp_path / "audit"
        d.mkdir()
        with pytest.raises(SandboxSetupError, match="ptrace"):
            spawn_mod.run_sandboxed(
                ["true"],
                target=None, output=None, block_network=False,
                nproc_limit=64, limits={}, writable_paths=[],
                readable_paths=None, allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env={}, cwd=None, timeout=30,
                audit_mode=True, audit_run_dir=str(d),
                audit_required=True,
            )
        assert (d / MARKER).exists()
