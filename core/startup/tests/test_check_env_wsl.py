"""Tests for the WSL section of core.startup.init.check_env().

The section is messaging-only: on a WSL host the env parts gain a
``WSL`` fact and the warning list gains the ``wsl_advisories`` lines
(built from the sandbox probe results check_env already gathered).
Off WSL, check_env output is byte-identical to before the section
existed. Cross-platform — the kernel probes are mocked so the tests
run on any CI host.
"""

from __future__ import annotations

import sys
from contextlib import ExitStack
from unittest import mock

import pytest

from core.startup import init as startup_init

pytestmark = pytest.mark.wsl


def _linux_sandbox_mocks(stack: ExitStack, *, landlock_ok: bool) -> None:
    """Pin the Linux sandbox probe results check_env consumes."""
    stack.enter_context(mock.patch.object(sys, "platform", "linux"))
    stack.enter_context(mock.patch(
        "core.sandbox.check_net_available", return_value=True))
    stack.enter_context(mock.patch(
        "core.sandbox.check_mount_available", return_value=True))
    stack.enter_context(mock.patch(
        "core.sandbox.check_landlock_available", return_value=landlock_ok))
    stack.enter_context(mock.patch(
        "core.sandbox.check_seccomp_available", return_value=True))
    if landlock_ok:
        stack.enter_context(mock.patch(
            "core.sandbox._get_landlock_abi", return_value=4))


def test_wsl_host_gets_part_and_advisories():
    lines = ["WSL: advisory one", "WSL: advisory two"]
    with ExitStack() as stack:
        _linux_sandbox_mocks(stack, landlock_ok=False)
        stack.enter_context(mock.patch(
            "core.startup.wsl.is_wsl", return_value=True))
        advisories = stack.enter_context(mock.patch(
            "core.startup.wsl.wsl_advisories", return_value=list(lines)))
        parts, warnings = startup_init.check_env(set())

    assert "WSL" in parts
    for line in lines:
        assert line in warnings
    # The advisory builder receives the probe result check_env
    # gathered — never a re-probe.
    advisories.assert_called_once_with(False)


def test_wsl_advisories_see_landlock_present():
    with ExitStack() as stack:
        _linux_sandbox_mocks(stack, landlock_ok=True)
        stack.enter_context(mock.patch(
            "core.startup.wsl.is_wsl", return_value=True))
        advisories = stack.enter_context(mock.patch(
            "core.startup.wsl.wsl_advisories", return_value=[]))
        parts, _warnings = startup_init.check_env(set())

    assert "WSL" in parts
    advisories.assert_called_once_with(True)


def test_non_wsl_host_unchanged():
    with ExitStack() as stack:
        _linux_sandbox_mocks(stack, landlock_ok=True)
        stack.enter_context(mock.patch(
            "core.startup.wsl.is_wsl", return_value=False))
        advisories = stack.enter_context(mock.patch(
            "core.startup.wsl.wsl_advisories"))
        parts, warnings = startup_init.check_env(set())

    assert "WSL" not in parts
    assert not any("WSL" in w for w in warnings)
    advisories.assert_not_called()
