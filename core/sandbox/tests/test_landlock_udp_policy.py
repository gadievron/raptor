"""ABI10 policy construction controls; these do not prove kernel enforcement."""

import os
import sys

import pytest

from core.sandbox import landlock
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux Landlock ABI")


@pytest.mark.parametrize("abi,deny_udp,ports,tcp_deny,expected", [
    (9, True, None, True, 0x2),
    (10, True, None, True, 0xE),
    (11, True, None, True, 0xE),
    (10, False, None, True, 0x2),
    (10, True, [443], False, 0xE),
    (10, False, [443], False, 0x2),
    (10, True, None, False, 0xC),
])
def test_requested_udp_rights_reach_ruleset_attributes(
        abi, deny_udp, ports, tcp_deny, expected):
    private = module_function_view(
        landlock, bindings={"_get_landlock_abi": lambda: abi})
    apply = private._make_landlock_preexec(
        [], allowed_tcp_ports=ports, deny_all_tcp_connect=tcp_deny,
        deny_all_udp=deny_udp, fail_raise=True)
    cells = dict(zip(apply.__code__.co_freevars, apply.__closure__))
    seen = []
    rules = []

    class Libc:
        def syscall(self, number, *args):
            if number == landlock._SYS_LANDLOCK_CREATE:
                attr = args[0]._obj
                seen.append((attr.handled_access_fs, attr.handled_access_net))
                return 800
            if number == landlock._SYS_LANDLOCK_ADD_RULE:
                rule = args[2]._obj
                if args[1] == landlock._LL_RULE_NET_PORT:
                    rules.append((rule.port, rule.allowed_access))
                else:
                    assert args[1] == landlock._LL_RULE_PATH_BENEATH
                return 0
            assert number == landlock._SYS_LANDLOCK_RESTRICT
            return 0

        def prctl(self, *args):
            return 0

    cells["_libc"].cell_contents = Libc()
    closed = []
    def close_owned(fd):
        if fd != 800:
            os.close(fd)
        closed.append(fd)

    cells["_os_close"].cell_contents = close_owned
    apply()
    expected_fs = private._write_mask_for_abi(abi) if ports else 0
    assert seen == [(expected_fs, expected)]
    assert rules == ([(443, 0x2)] if ports else [])
    assert closed.count(800) == 1
    for fd in set(closed) - {800}:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("abi", [9, 10, 11])
@pytest.mark.parametrize("block_udp", [False, True])
def test_preexec_forwards_resolved_policy_without_old_kernel_engagement(
        abi, block_udp):
    from core.sandbox import preexec

    landlock_calls = []
    seccomp_calls = []

    def landlock_builder(*args, **kwargs):
        landlock_calls.append((args, kwargs))
        return lambda: None

    def seccomp_builder(*args, **kwargs):
        seccomp_calls.append((args, kwargs))
        return lambda: None

    private = module_function_view(preexec, bindings={
        "check_landlock_available": lambda: True,
        "_get_landlock_abi": lambda: abi,
        "_make_landlock_preexec": landlock_builder,
        "_make_seccomp_preexec": seccomp_builder,
    })
    private._make_preexec_fn(
        {}, seccomp_profile="default", seccomp_block_udp=block_udp)
    assert len(landlock_calls) == int(block_udp and abi >= 10)
    if landlock_calls:
        assert landlock_calls[0][1]["deny_all_udp"] is True
        assert landlock_calls[0][1]["deny_all_tcp_connect"] is False
    assert len(seccomp_calls) == 1
    assert seccomp_calls[0][1]["block_udp"] is block_udp


@pytest.mark.parametrize("profile", [None, "none", "default"])
@pytest.mark.parametrize("available", [False, True])
def test_abi10_never_waives_degraded_seccomp_requirement(profile, available):
    from core.sandbox import context
    from core.sandbox.errors import SandboxSetupError

    private = module_function_view(context, bindings={
        "check_seccomp_available": lambda: available,
        "_get_landlock_abi": lambda: 10,
    })
    if profile and profile != "none" and available:
        private._require_degraded_udp_filter(profile)
    else:
        with pytest.raises(SandboxSetupError, match="required seccomp"):
            private._require_degraded_udp_filter(profile)


@pytest.mark.parametrize("stage", ["create", "prctl", "restrict"])
def test_requested_udp_install_failure_is_loud_and_closes_owned_ruleset(stage):
    private = module_function_view(
        landlock, bindings={"_get_landlock_abi": lambda: 10})
    apply = private._make_landlock_preexec(
        [], deny_all_udp=True, fail_raise=True)
    cells = dict(zip(apply.__code__.co_freevars, apply.__closure__))
    seen = []
    closed = []
    diagnostics = []

    class Libc:
        def syscall(self, number, *args):
            if number == landlock._SYS_LANDLOCK_CREATE:
                seen.append(args[0]._obj.handled_access_net)
                return -1 if stage == "create" else 800
            assert number == landlock._SYS_LANDLOCK_RESTRICT
            return -1 if stage == "restrict" else 0

        def prctl(self, *args):
            return -1 if stage == "prctl" else 0

    cells["_libc"].cell_contents = Libc()
    cells["_os_close"].cell_contents = closed.append
    cells["_os_write"].cell_contents = lambda fd, data: diagnostics.append((fd, data))
    with pytest.raises(landlock.LandlockInstallError):
        apply()
    assert seen == [0xC]
    assert closed == ([] if stage == "create" else [800])
    assert diagnostics


@pytest.mark.parametrize("block_network", [False, True])
def test_initial_context_preserves_resolved_udp_intent(tmp_path, block_network):
    from contextlib import contextmanager
    from core.sandbox import context

    calls = []

    def preexec_builder(*args, **kwargs):
        calls.append(kwargs)
        return lambda: None

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "check_net_available": lambda: False,
        "check_mount_available": lambda: False,
        "check_landlock_available": lambda: True,
        "_get_landlock_abi": lambda: 10,
        "check_seccomp_available": lambda: True,
        "_make_preexec_fn": preexec_builder,
    })
    with contextmanager(private.sandbox)(
            block_network=block_network, profile="full",
            output=str(tmp_path)):
        pass  # Construction only: no target, kernel operation or namespace claim.
    assert calls
    assert all(call["seccomp_block_udp"] is block_network for call in calls)


@pytest.mark.parametrize("block_network", [False, True])
def test_audit_context_forwards_resolved_udp_intent_before_dispatch(
        tmp_path, block_network):
    import builtins
    from contextlib import contextmanager
    from types import SimpleNamespace
    from core.sandbox import context, seccomp

    class PolicyCaptured(BaseException):
        pass

    captured = []

    def capture_policy(*args, **kwargs):
        captured.append(kwargs)
        raise PolicyCaptured

    private_landlock = module_function_view(landlock, bindings={
        "_make_landlock_preexec": capture_policy,
    })
    private_seccomp = module_function_view(seccomp, bindings={
        "check_seccomp_available": lambda: True,
        "_make_seccomp_preexec": lambda *args, **kwargs: lambda: None,
    })

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "landlock":
            return private_landlock
        if level == 1 and name == "seccomp":
            return private_seccomp
        if level == 1 and name == "ptrace_probe":
            return SimpleNamespace(check_ptrace_available=lambda: True)
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "check_net_available": lambda: False,
        "check_mount_available": lambda: False,
        "check_landlock_available": lambda: True,
        "_get_landlock_abi": lambda: 10,
        "check_seccomp_available": lambda: True,
        "_make_preexec_fn": lambda *args, **kwargs: lambda: None,
    }, import_hook=import_local)
    with pytest.raises(PolicyCaptured):
        with contextmanager(private.sandbox)(
                block_network=block_network, profile="full",
                output=str(tmp_path), audit=True,
                audit_run_dir=str(tmp_path)) as run:
            run(["/bin/true"], capture_output=True, text=True)
    assert len(captured) == 1
    assert captured[0]["deny_all_udp"] is block_network
    assert captured[0]["deny_all_tcp_connect"] is block_network


def test_runtime_namespace_demotion_rebuilds_udp_denial_before_dispatch(tmp_path):
    import builtins
    from contextlib import contextmanager
    from types import SimpleNamespace
    from core.sandbox import context, probes, _spawn

    class DemotionCaptured(BaseException):
        pass

    calls = []
    spawn_attempts = []

    def preexec_builder(*args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("seccomp_block_udp"):
            raise DemotionCaptured
        return lambda: None

    def refuse_spawn(*args, **kwargs):
        spawn_attempts.append(True)
        raise RuntimeError("owned namespace setup refusal")

    private_spawn = module_function_view(_spawn, bindings={
        "run_sandboxed": refuse_spawn,
        "mount_ns_available": lambda: True,
    })
    private_probes = module_function_view(probes, bindings={
        "check_unshare_engages": lambda *args, **kwargs: (True, ""),
    })

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "_spawn":
            return private_spawn
        if level == 1 and not name and "_spawn" in fromlist:
            return SimpleNamespace(_spawn=private_spawn)
        if level == 1 and name == "probes":
            return private_probes
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "check_net_available": lambda: True,
        "check_mount_available": lambda: True,
        "check_landlock_available": lambda: True,
        "_get_landlock_abi": lambda: 10,
        "check_seccomp_available": lambda: True,
        "_make_preexec_fn": preexec_builder,
    }, import_hook=import_local)
    with pytest.raises(DemotionCaptured):
        with contextmanager(private.sandbox)(
                block_network=True, profile="full", target=str(tmp_path),
                output=str(tmp_path)) as run:
            run(["/bin/true"], capture_output=True, text=True)
    assert spawn_attempts
    assert calls[-1]["seccomp_block_udp"] is True
    assert calls[-1]["deny_all_tcp_connect"] is True
    assert all(not call["seccomp_block_udp"] for call in calls[:-1])
