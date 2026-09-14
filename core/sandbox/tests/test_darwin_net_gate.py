"""block_network on a seatbelt-less macOS host must refuse, not warn.

The Linux side converted "no layer can enforce the requested network
block" from warn-and-run into a fail-closed refusal; the block was
scoped ``!= darwin``, so a trusted ``block_network=True`` run on a Mac
where sandbox-exec is missing or fails its smoke test silently kept
FULL host network behind the once-per-process "Sandbox unavailable"
warning — while run()'s docstring promised the refusal. macOS is the
STRONGER case for refusing: there is no Landlock fallback layer there
at all.

The gate stays a capability-axis refusal in context.py (tiers.py's
design notes keep per-axis enforceability out of the containment
lattice); the same two acceptance levers apply as on Linux:
``degraded_net_deny=False`` per call and
``RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1`` host-wide.

Uses the established fake-darwin patching pattern from
test_context_backend_dispatch.py; the Linux arm's behaviour is pinned
by test_degraded_net_deny_failclosed.py and unchanged.
"""

from __future__ import annotations

import logging
import sys
from unittest import mock

import pytest

from core.sandbox import context
from core.sandbox.errors import SandboxSetupError


@pytest.fixture
def darwin_no_seatbelt():
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                           return_value=False), \
         mock.patch.object(context, "check_mount_available",
                           return_value=False), \
         mock.patch.object(context, "check_net_available",
                           return_value=False):
        yield


def test_block_network_refuses_without_seatbelt(darwin_no_seatbelt):
    with pytest.raises(SandboxSetupError) as ei, \
            context.sandbox(block_network=True):
        pass
    msg = str(ei.value)
    assert "no layer can enforce" in msg
    assert "seatbelt" in msg
    assert "degraded_net_deny=False" in msg  # names the escape hatch
    # The remedy must be macOS-shaped, not the Linux userns text.
    assert "apparmor" not in msg.lower()


def test_allowed_tcp_ports_named_in_the_refusal(darwin_no_seatbelt):
    with pytest.raises(SandboxSetupError) as ei, \
            context.sandbox(block_network=True, allowed_tcp_ports=[443]):
        pass
    assert "allowed_tcp_ports" in str(ei.value)


def test_per_call_opt_out_still_runs(darwin_no_seatbelt):
    # degraded_net_deny=False is the caller's conscious acceptance of
    # open egress — the context must engage, not raise.
    with context.sandbox(block_network=True,
                         degraded_net_deny=False) as run:
        assert callable(run)


def test_operator_waiver_downgrades_to_loud_warning(
        darwin_no_seatbelt, monkeypatch, caplog):
    # The warning is warn_once-gated: an earlier consumer anywhere in
    # the same process eats the once and this assertion goes latent.
    # Own the latch state regardless of suite order.
    from core.sandbox import state
    state.reset_warn_once("_degraded_net_open_override_warned")
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    with caplog.at_level(logging.WARNING, logger="core.sandbox.context"), \
            context.sandbox(block_network=True) as run:
        assert callable(run)
    assert any("NETWORK UNRESTRICTED" in rec.getMessage()
               for rec in caplog.records), (
        "the waiver must name what is being accepted")


def test_seatbelt_available_engages_without_refusal():
    # The gate keys on enforceability, not platform: with seatbelt
    # live, block_network rides the SBPL (deny network*) and no
    # refusal fires.
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                           return_value=True), \
         mock.patch.object(context, "check_mount_available",
                           return_value=False), \
         mock.patch.object(context, "check_net_available",
                           return_value=False), \
         context.sandbox(block_network=True) as run:
        assert callable(run)


def test_strict_still_gets_its_own_all_requirements_abort(
        darwin_no_seatbelt):
    # strict defers to its own gate so ONE abort names every unmet
    # strict requirement — the net gate must not pre-empt it.
    with pytest.raises(SandboxSetupError, match="strict"), \
            context.sandbox(profile="strict", block_network=True):
        pass
