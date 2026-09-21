"""audit_run_dir-only calls must not have the Landlock-only audit
lane invent a filesystem policy.

The documented contract: pass audit_run_dir alone for "audit signal
without a writable-path restriction" (codeql analyze is the live
caller — it writes to ~/.codeql caches and database dirs that cannot
be safely enumerated as writable). Pre-fix, the Landlock-only audit
branch seeded "/tmp" into the writable list even when the call
carried NO policy at all, engaging a write-nowhere-except-/tmp
ruleset — "--audit" broke the workload on exactly the
userns-restricted hosts this lane serves.
"""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-only audit lane is Linux-only")


def _lane_ready() -> bool:
    from core.sandbox.landlock import check_landlock_available
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return (check_landlock_available() and check_ptrace_available()
            and check_seccomp_available())


def _force_landlock_only_lane(monkeypatch):
    """Route the call onto the Landlock-only subprocess dispatch: no
    mount tier, and a no-namespace-needing call shape (the u24/u26
    class where the operator's audit-requested codeql-style call
    cannot take the spawn ladder)."""
    from core.sandbox import context as _ctx
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: False)


def _spy_landlock_builder(monkeypatch):
    """Record every Landlock ruleset the run builds. The audit branch
    imports the builder from .landlock; the plain baseline goes
    through .preexec's module-level import — patch both homes."""
    from core.sandbox import landlock as _landlock_mod
    from core.sandbox import preexec as _preexec_mod
    calls: list[dict] = []
    real = _landlock_mod._make_landlock_preexec

    def spy(writable_paths, allowed_tcp_ports=None, **kw):
        calls.append({"writable": list(writable_paths),
                      "ports": allowed_tcp_ports, **kw})
        return real(writable_paths, allowed_tcp_ports, **kw)

    monkeypatch.setattr(_landlock_mod, "_make_landlock_preexec", spy)
    monkeypatch.setattr(_preexec_mod, "_make_landlock_preexec", spy)
    return calls


def test_audit_run_dir_only_call_builds_no_landlock_policy(
        tmp_path, monkeypatch):
    """The pure contract shape: audit signal, no writable-path
    restriction, no network policy — NO Landlock ruleset at all."""
    if not _lane_ready():
        pytest.skip("landlock/ptrace/libseccomp unavailable")
    from core.sandbox import context as _ctx
    _force_landlock_only_lane(monkeypatch)
    calls = _spy_landlock_builder(monkeypatch)
    run_dir = tmp_path / "auditdir"
    run_dir.mkdir()
    r = _ctx.run(["sh", "-c", "echo audit-only-ok"],
                 audit=True, audit_run_dir=str(run_dir),
                 block_network=False,
                 capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "audit-only-ok" in r.stdout
    assert calls == [], (
        f"a no-policy audit call built a Landlock ruleset: {calls}")


def test_degraded_net_deny_carries_no_invented_fs_policy(
        tmp_path, monkeypatch):
    """block_network on the degraded host still arms the Landlock
    TCP-connect deny — but with the caller's (empty) writable set,
    never an invented \"/tmp\" one. Per the builder's contract a
    net-only deny handles ONLY the net access."""
    if not _lane_ready():
        pytest.skip("landlock/ptrace/libseccomp unavailable")
    from core.sandbox import context as _ctx
    _force_landlock_only_lane(monkeypatch)
    # netns unavailable too: that is what arms the degraded
    # Landlock TCP-connect deny for a block_network call (with netns
    # available the call takes the mountless spawn lane instead).
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
    calls = _spy_landlock_builder(monkeypatch)
    run_dir = tmp_path / "auditdir"
    run_dir.mkdir()
    r = _ctx.run(["sh", "-c", "echo net-deny-ok"],
                 audit=True, audit_run_dir=str(run_dir),
                 block_network=True,
                 capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert calls, "degraded net deny should still build a ruleset"
    for call in calls:
        assert call["writable"] == [], (
            f"invented writable policy on the audit lane: {call}")
        assert call.get("deny_all_tcp_connect"), call
