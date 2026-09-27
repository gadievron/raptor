"""No recursive-DNS escape through the TCP-only Landlock fallback.

Routing tests run on any host without executing a payload. The Linux
integration test checks kernel enforcement without sending external traffic.
"""

import errno
import socket
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.errors import SandboxSetupError


@pytest.fixture
def fallback(monkeypatch):
    from core.sandbox import _spawn, probes

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(context, "check_net_available", lambda: False)
    monkeypatch.setattr(context, "check_mount_available", lambda: False)
    monkeypatch.setattr(context, "check_landlock_available", lambda: True)
    monkeypatch.setattr(context, "_get_landlock_abi", lambda: 4)
    monkeypatch.setattr(context, "check_seccomp_available", lambda: True)
    monkeypatch.setattr(_spawn, "mount_ns_available", lambda: False)
    monkeypatch.setattr(probes, "check_unshare_engages", lambda flags: (True, ""))
    built = []

    def build(*args, **kwargs):
        built.append(kwargs)
        return None

    monkeypatch.setattr(context, "_make_preexec_fn", build)
    monkeypatch.setattr(
        context.subprocess, "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    return built


@pytest.mark.parametrize("ports", [None, [443]])
def test_construction_fallback_blocks_udp(fallback, ports):
    with context.sandbox(block_network=True, allowed_tcp_ports=ports):
        pass
    assert fallback[-1]["seccomp_block_udp"] is True


@pytest.mark.parametrize("waived", [False, True])
def test_missing_seccomp_refuses_full_profile(fallback, monkeypatch, waived):
    monkeypatch.setattr(context, "check_seccomp_available", lambda: False)
    if waived:
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    with pytest.raises(SandboxSetupError, match="UDP/DNS block"):
        with context.sandbox(block_network=True, profile="full"):
            pass
    assert not fallback


def test_network_only_accepts_without_udp_block(fallback):
    """network-only has no seccomp — the gate returns early and the
    Landlock TCP deny engages without a UDP block."""
    with context.sandbox(block_network=True, profile="network-only"):
        pass
    assert fallback[-1]["seccomp_block_udp"] is False


def test_explicit_network_optout_keeps_existing_semantics(fallback):
    with context.sandbox(block_network=True, degraded_net_deny=False):
        pass
    assert fallback[-1]["seccomp_block_udp"] is False


@pytest.mark.parametrize("available", [True, False])
def test_runtime_demotion_rechecks_udp_filter(fallback, monkeypatch, available):
    from core.sandbox import _spawn

    monkeypatch.setattr(context, "check_net_available", lambda: True)

    def fail_spawn(*args, **kwargs):
        raise OSError("forced namespace setup failure")

    monkeypatch.setattr(_spawn, "run_sandboxed", fail_spawn)
    monkeypatch.setattr(context, "check_seccomp_available", lambda: available)
    if available:
        result = context.run(["true"], block_network=True, capture_output=True)
        assert result.sandbox_info["degraded_net_deny"] is True
        assert fallback[-1]["seccomp_block_udp"] is True
    else:
        with pytest.raises(SandboxSetupError, match="UDP/DNS block"):
            context.run(["true"], block_network=True, capture_output=True)


@pytest.mark.parametrize("demote", [False, True])
def test_audit_fallback_keeps_udp_enforcing(fallback, monkeypatch, tmp_path, demote):
    from core.sandbox import _landlock_audit, _spawn, landlock, ptrace_probe, seccomp

    monkeypatch.setattr(context, "check_net_available", lambda: demote)

    def fail_spawn(*args, **kwargs):
        raise OSError("forced namespace setup failure")

    monkeypatch.setattr(_spawn, "run_sandboxed", fail_spawn)
    monkeypatch.setattr(seccomp, "check_seccomp_available", lambda: True)
    monkeypatch.setattr(ptrace_probe, "check_ptrace_available", lambda: True)
    monkeypatch.setattr(landlock, "_make_landlock_preexec", lambda *a, **kw: None)
    filters = []

    def build_filter(*args, **kwargs):
        filters.append(kwargs)
        return None

    monkeypatch.setattr(seccomp, "_make_seccomp_preexec", build_filter)
    monkeypatch.setattr(
        _landlock_audit, "run_landlock_audit",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    result = context.run(
        ["true"], block_network=True, audit=True, audit_run_dir=str(tmp_path),
        capture_output=True,
    )
    assert result.sandbox_info["audit_engaged"] is True
    assert filters[-1]["block_udp"] is True
    assert filters[-1]["audit_mode"] is True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux kernel enforcement")
@pytest.mark.parametrize("flags", [0, 0x80000, 0x800])  # Linux CLOEXEC / NONBLOCK
@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_live_fallback_denies_dns_datagram_creation(monkeypatch, family, flags):
    from core.sandbox.landlock import check_landlock_available, _get_landlock_abi
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_landlock_available() and _get_landlock_abi() >= 4
            and check_seccomp_available()):
        pytest.skip("requires Landlock TCP policy and seccomp")
    monkeypatch.setattr(context, "check_net_available", lambda: False)
    monkeypatch.setattr(context, "check_mount_available", lambda: False)
    payload = f"""
import errno, socket
try:
    socket.socket({int(family)}, {int(socket.SOCK_DGRAM | flags)})
except OSError as exc:
    assert exc.errno == {errno.EPERM}, exc
else:
    raise AssertionError('UDP DNS channel remains open')
"""
    result = context.run(
        [sys.executable, "-c", payload], block_network=True,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.sandbox_info["degraded_net_deny"] is True
