"""Capability skip-guards for feature-assuming sandbox tests.

The feature-matrix harness (core/sandbox/scripts/feature-matrix/) runs
this suite on hosts that GENUINELY lack kernel sandbox features —
Landlock faked to ENOSYS, unprivileged user namespaces denied. Tests
that exercise a capability (rather than the degradation behaviour in
its absence) fail there by hitting the sandbox's own designed
refusals: SandboxSetupError fail-closed gates, Landlock install
fail-raise, the block_network refusal. Those failures are noise that
buries real degradation regressions.

These markers make degraded lanes report honestly: the designed
outcome for a feature-exercising test on a feature-less host is a SKIP
with the missing capability named; a FAILURE is signal. On
feature-complete hosts (every other CI tier) the conditions are all
False and the marks are inert — nothing is skipped that ran before.

Availability comes from the sandbox's own once-per-process cached
probes — the same verdicts the production degradation lattice keys on,
so a test skips exactly where production refuses.
"""

import sys

import pytest


def _landlock_available() -> bool:
    from core.sandbox.landlock import check_landlock_available
    return check_landlock_available()


def _userns_available() -> bool:
    # check_net_available is the user-namespace foundation probe the
    # context layer keys `use_sandbox` on.
    from core.sandbox.probes import check_net_available
    return check_net_available()


def _mount_ns_available() -> bool:
    from core.sandbox.probes import check_mount_available
    return check_mount_available()


requires_landlock = pytest.mark.skipif(
    not _landlock_available(),
    reason="requires Landlock: exercises confinement that the sandbox "
           "refuses (by design) on Landlock-less kernels",
)

requires_userns = pytest.mark.skipif(
    not _userns_available(),
    reason="requires unprivileged user namespaces: exercises the "
           "namespace backend, which the sandbox refuses (by design) "
           "on this host",
)

requires_mount = pytest.mark.skipif(
    not _mount_ns_available(),
    reason="requires mount namespace: exercises isolation that needs "
           "newuidmap/newgidmap (uidmap package) on non-root hosts",
)


def pid1_userns_owner_is_invoker() -> bool:
    """True when pid 1's user namespace is OWNED by the invoking uid —
    i.e. this process runs inside a self-owned nested user namespace
    (test container, pid-namespaced battery) whose init is our own
    process tree, not the root-owned system init.

    Tests that use pid 1 as their FOREIGN-namespace refusal subject
    cannot construct that posture here: the ownership check they
    expect to refuse legitimately accepts a namespace the invoker
    owns. Lazy (call it inside the test), so no probe cost rides
    module import.

    Mirrors the gidmap helper's own check: ``NS_GET_OWNER_UID`` on
    ``/proc/1/ns/user``. On a normal host an unprivileged process
    cannot even open pid 1's ns/user — that open refusal IS the
    foreign-namespace posture, so any OSError reports False.
    """
    import array
    import fcntl
    import os

    ns_get_owner_uid = 0xB704  # _IO(0xb7, 0x4) — linux/nsfs.h
    try:
        fd = os.open("/proc/1/ns/user", os.O_RDONLY)
    except OSError:
        return False
    try:
        owner = array.array("I", [0])
        fcntl.ioctl(fd, ns_get_owner_uid, owner, True)
    except OSError:
        return False
    finally:
        os.close(fd)
    return owner[0] == os.getuid()


def _network_block_enforceable() -> bool:
    # sandbox()'s default profile requests block_network=True, which is
    # fail-closed: with no namespace backend (userns) AND no Landlock
    # ABI v4+ for the degraded TCP-connect deny, sandbox() refuses the
    # run (SandboxSetupError) rather than let the requested network
    # policy evaporate. Tests that run a default-profile sandbox for an
    # unrelated subject hit that designed refusal on such hosts.
    if sys.platform == "darwin":
        # The refusal is Linux-only (context.py gates it on the
        # platform); darwin's backend is seatbelt and these tests keep
        # running there.
        return True
    if _userns_available():
        return True
    from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
    return check_landlock_available() and _get_landlock_abi() >= 4


requires_network_block_backend = pytest.mark.skipif(
    not _network_block_enforceable(),
    reason="requires a network-block backend (user namespaces or "
           "Landlock ABI v4+): the default profile's block_network=True "
           "is refused (by design) when neither deny lane can engage",
)
