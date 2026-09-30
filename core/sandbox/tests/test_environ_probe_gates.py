"""Regression pins for the host-pid environ test's oracle gates.

The e2e test ``test_proc_host_pid_environ_blocked_under_restrict_reads``
skips through two truthful gates in ``core.sandbox.tests.capability``:
one keyed on the SAME probe production derives the namespace backend
from, one keyed on the runtime pid's collision range inside a fresh
sandbox PID namespace. These pins hold the gates to their contracts in
both directions — a gate that widens silently would skip the guard on
hosts where it is valid; one that narrows would red the nested-userns
battery envelope again.
"""

import os

import pytest

from core.sandbox.tests import capability


class TestPidnsIsolationAvailableGate:
    """The gate mirrors production's namespace-backend verdict exactly."""

    def test_false_when_userns_probe_false(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        import core.sandbox.probes as probes_mod
        monkeypatch.setattr(probes_mod, "check_net_available",
                            lambda: False)
        assert capability.pidns_isolation_available() is False

    def test_true_when_userns_probe_true(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        import core.sandbox.probes as probes_mod
        monkeypatch.setattr(probes_mod, "check_net_available",
                            lambda: True)
        assert capability.pidns_isolation_available() is True


class TestOwnPidCollisionGate:
    """Ceiling pinned in both directions.

    Collides below-or-at the ceiling (the sandbox's fresh PID
    namespace provably allocates 1 and 2 on every spawn, with headroom
    for spawn-lane helpers); never fires above it, so runners with
    ordinary host pids keep running the guard.
    """

    @pytest.mark.parametrize("pid", [1, 2,
                                     capability.
                                     SANDBOX_PIDNS_PID_COLLISION_CEILING])
    def test_collides_at_or_below_ceiling(
            self, monkeypatch: pytest.MonkeyPatch, pid: int) -> None:
        monkeypatch.setattr(os, "getpid", lambda: pid)
        assert capability.own_pid_collides_with_sandbox_pidns() is True

    @pytest.mark.parametrize(
        "pid",
        [capability.SANDBOX_PIDNS_PID_COLLISION_CEILING + 1, 300, 123456])
    def test_valid_above_ceiling(
            self, monkeypatch: pytest.MonkeyPatch, pid: int) -> None:
        monkeypatch.setattr(os, "getpid", lambda: pid)
        assert capability.own_pid_collides_with_sandbox_pidns() is False

    def test_ceiling_is_a_small_spawn_scale_number(self) -> None:
        # Direction pins for the constant itself: must cover the two
        # pids every spawn allocates (init shim + target), must stay
        # an order of magnitude below the kernel's RESERVED_PIDS=300
        # floor above which real-host userspace pids live — a ceiling
        # at or above it would skip the guard on ordinary hosts.
        assert capability.SANDBOX_PIDNS_PID_COLLISION_CEILING >= 2
        assert capability.SANDBOX_PIDNS_PID_COLLISION_CEILING < 300
