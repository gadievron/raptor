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


def pidns_isolation_available() -> bool:
    """True when the sandbox's namespace backend — and with it the
    PID-namespace hiding of host pids — can engage on this host.

    Mirrors production exactly: ``core.sandbox.context`` derives
    ``use_sandbox`` (Linux) from ``check_net_available()`` (the
    user-namespace foundation probe), and every namespace lane —
    the PID-namespace unshare included — hangs off that verdict.
    When it is False the sandbox runs in the Landlock-only posture:
    host processes stay VISIBLE in ``/proc`` (enumeration and
    world-readable entries like ``cmdline``), but out-of-domain
    ``/proc/<pid>/environ`` / ``mem`` reads are still denied by the
    sandbox's own Landlock ptrace scoping — the Landlock domain
    gates the kernel's ptrace-mode access checks those files
    require, on any Yama setting (Yama gates only ptrace ATTACH,
    never the READ check environ opens use). What the posture loses
    is PID hiding, so a test guarding the PID-namespace hiding
    behaviour has nothing to measure and skips on this verdict with
    the posture named.

    Lazy (call it inside the test) so no probe cost rides module
    import.
    """
    return _userns_available()


# Own-pid ceiling below which the /proc/<own-pid> denial oracle is
# unfalsifiable: the sandbox's fresh PID namespace re-allocates pids
# from 1, so a probe pid this small can name the sandbox's OWN
# processes instead of a hidden host process. Why not lower: every
# spawn provably allocates pids 1 (the namespace init shim) and 2 (the
# target command), and pipeline-shaped targets have been observed
# allocating pids up to 8 — any lower ceiling reds the oracle on those
# spawns. Why not higher: a single-command spawn allocates at
# most a handful of pids, and every increment above that ceiling
# silences the guard on runners that legitimately hold a small pid in
# a long-lived namespace (fresh containers), where the oracle is valid.
SANDBOX_PIDNS_PID_COLLISION_CEILING = 8


def own_pid_collides_with_sandbox_pidns() -> bool:
    """True when this process's own pid is small enough to be
    re-allocated inside a sandbox's fresh PID namespace.

    Only possible when the test process itself runs inside a nested
    pid namespace (an ``unshare -Upf``-wrapped battery, a fresh
    container) — on a host's init pid namespace an unprivileged test
    runner never holds a single-digit pid. When it fires, a
    ``/proc/<own-pid>`` probe inside the sandbox can resolve to the
    sandbox's own init shim or target, so "the read failed" no longer
    distinguishes PID-namespace isolation from pid collision — and
    "the read succeeded" no longer proves a host leak (the shim's
    environ image is the parent's execve image with credential values
    zeroed — see ``core.sandbox._spawn._scrub_env_image_values``).
    Lazy: the pid must be the RUNTIME pid of the process executing the
    test (xdist workers fork after import).
    """
    import os
    return os.getpid() <= SANDBOX_PIDNS_PID_COLLISION_CEILING


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
