"""Cross-platform tests for the Linux/macOS backend dispatch in
``core.sandbox.context``.

These tests don't actually execute sandboxed processes; they patch
``sys.platform`` and the spawn modules and assert the right backend
is selected. The behavioural side (writes blocked, audit JSONL
produced, etc.) is covered by test_macos_spawn.py and
test_e2e_sandbox.py; this file is purely about the dispatch.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from core.sandbox import context, state


@pytest.fixture
def reset_caches():
    """Make sure the platform / availability caches don't leak
    between tests in this file."""
    state._seatbelt_available_cache = None
    state._mount_available_cache = None
    state._mount_ns_available_cache = None
    yield
    state._seatbelt_available_cache = None
    state._mount_available_cache = None
    state._mount_ns_available_cache = None


def test_check_seatbelt_available_returns_false_on_linux(reset_caches):
    """Sanity: on a Linux dev box this MUST return False without
    even attempting to invoke /usr/bin/sandbox-exec (which doesn't
    exist there). The probe short-circuits on platform check."""
    if sys.platform == "darwin":
        pytest.skip("Linux-only sanity check")
    assert context.check_seatbelt_available() is False


def test_dispatch_picks_macos_backend_on_darwin(reset_caches):
    """When sys.platform == "darwin" AND seatbelt is available, the
    spawn dispatch must route through _macos_spawn.run_sandboxed,
    NOT _spawn.run_sandboxed.

    Patching strategy: ``from . import _macos_spawn as _macos_mod``
    inside the function resolves via ``core.sandbox.__dict__`` once
    the submodule is loaded — patching ``sys.modules`` doesn't reach
    that attribute, so we patch ``run_sandboxed`` on the real
    submodule object directly. Same trick for ``core.sandbox._spawn``.
    """
    from core.sandbox import _macos_spawn as macos_mod
    from core.sandbox import _spawn as linux_mod

    fake_macos_result = mock.MagicMock()
    fake_macos_result.returncode = 0
    fake_macos_result.stderr = b""
    fake_macos_result.sandbox_info = {"backend": "macos-seatbelt"}

    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=True), \
         mock.patch.object(context, "check_mount_available",
                            return_value=False), \
         mock.patch.object(context, "check_net_available",
                            return_value=True), \
         mock.patch.object(macos_mod, "run_sandboxed",
                            return_value=fake_macos_result) as macos_run, \
         mock.patch.object(linux_mod, "run_sandboxed",
                            return_value=fake_macos_result) as linux_run:
        from core.sandbox.context import sandbox
        with sandbox(target="/tmp/some_target") as run:
            run(["/usr/bin/true"], capture_output=True)

    # macOS backend was called; Linux backend was NOT.
    assert macos_run.called, (
        "Darwin dispatch failed to route through _macos_spawn"
    )
    assert not linux_run.called, (
        "Darwin dispatch incorrectly invoked Linux _spawn"
    )


def test_dispatch_picks_linux_backend_on_linux(reset_caches):
    """Inverse: on Linux, the dispatch must use _spawn (or the
    Landlock-only subprocess fallback), NEVER _macos_spawn."""
    from core.sandbox import _macos_spawn as macos_mod
    from core.sandbox import _spawn as linux_mod

    fake_linux_result = mock.MagicMock()
    fake_linux_result.returncode = 0
    fake_linux_result.stderr = b""
    fake_linux_result.sandbox_info = {"backend": "mount-ns"}

    with mock.patch.object(sys, "platform", "linux"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=False), \
         mock.patch.object(context, "check_mount_available",
                            return_value=True), \
         mock.patch.object(context, "check_net_available",
                            return_value=True), \
         mock.patch.object(macos_mod, "run_sandboxed") as macos_run, \
         mock.patch.object(linux_mod, "run_sandboxed",
                            return_value=fake_linux_result), \
         mock.patch.object(linux_mod, "mount_ns_available",
                            return_value=True):
        from core.sandbox.context import sandbox
        with sandbox(target="/tmp", output="/tmp") as run:
            try:
                run(["/usr/bin/true"], capture_output=True)
            except Exception:
                # The fake _spawn doesn't simulate the full chain
                # perfectly; we only care about WHICH backend was
                # invoked, not the result.
                pass

    assert not macos_run.called, (
        "Linux dispatch incorrectly invoked _macos_spawn"
    )


def test_use_seatbelt_false_when_seatbelt_unavailable(reset_caches):
    """Even on Darwin, if check_seatbelt_available() returns False
    (sandbox-exec missing or smoke test failed), use_seatbelt must
    be False — the dispatch then falls back to the bare subprocess
    path with rlimits only."""
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=False), \
         mock.patch.object(context, "check_net_available",
                            return_value=False):
        # Sandbox unavailable entirely → no backend; subprocess.run
        # path with rlimits only. Just verify no crash.
        from core.sandbox.context import sandbox
        with sandbox() as run:
            with mock.patch("subprocess.run") as sub_run:
                sub_run.return_value = mock.MagicMock(
                    returncode=0, stderr=b"", stdout=b"",
                    sandbox_info={},
                )
                run(["/usr/bin/true"])
        assert sub_run.called


def test_use_seatbelt_does_not_depend_on_check_net_available(reset_caches):
    """Regression catch: an earlier dispatch wired use_sandbox to
    check_net_available() (Linux unshare probe) AND THEN used the
    result to gate use_seatbelt. On macOS check_net_available()
    returns False (no unshare binary), so use_seatbelt was always
    False even when sandbox-exec worked — silently degrading to
    bare subprocess.run. The fix routes use_sandbox per-platform
    via check_seatbelt_available() on Darwin. This test asserts
    that with seatbelt available + net unavailable (the actual
    macOS state), the seatbelt backend IS used."""
    fake_macos_result = mock.MagicMock()
    fake_macos_result.returncode = 0
    fake_macos_result.stderr = b""
    fake_macos_result.sandbox_info = {"backend": "macos-seatbelt"}

    from core.sandbox import _macos_spawn as macos_mod
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=True), \
         mock.patch.object(context, "check_net_available",
                            return_value=False), \
         mock.patch.object(context, "check_mount_available",
                            return_value=False), \
         mock.patch.object(macos_mod, "run_sandboxed",
                            return_value=fake_macos_result) as macos_run:
        from core.sandbox.context import sandbox
        with sandbox(target="/tmp/some_target") as run:
            run(["/usr/bin/true"], capture_output=True)

    assert macos_run.called, (
        "seatbelt dispatch failed when check_net_available() returned "
        "False — this is the actual state on every macOS host."
    )


def test_macos_does_not_resolve_unshare(reset_caches):
    """Regression catch: even when use_seatbelt is engaged, an earlier
    code path unconditionally built a Linux `unshare`-prefixed command
    in the run() function (used only for the Landlock-only fallback).
    The construction itself called _resolve_sandbox_binary("unshare")
    which raises FileNotFoundError on macOS — crashing every sandbox
    call that hits the dispatch with block_network/restrict_reads/
    use_mount True (i.e. nearly every run_untrusted call). Fixed by
    vetoing need_unshare when use_seatbelt is True."""
    from core.sandbox import _macos_spawn as macos_mod
    fake_macos_result = mock.MagicMock()
    fake_macos_result.returncode = 0
    fake_macos_result.stderr = b""
    fake_macos_result.sandbox_info = {"backend": "macos-seatbelt"}

    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=True), \
         mock.patch.object(context, "check_net_available",
                            return_value=False), \
         mock.patch.object(context, "check_mount_available",
                            return_value=False), \
         mock.patch.object(macos_mod, "run_sandboxed",
                            return_value=fake_macos_result), \
         mock.patch("core.sandbox.probes._resolve_sandbox_binary",
                     side_effect=FileNotFoundError("unshare")):
        from core.sandbox.context import sandbox
        # block_network=True + restrict_reads=True is the typical
        # run_untrusted path that previously crashed on macOS.
        with sandbox(target="/tmp/x", output="/tmp/x",
                      block_network=True, restrict_reads=True) as run:
            run(["/usr/bin/true"], capture_output=True)
    # If _resolve_sandbox_binary was called, the mock would have
    # raised; the sandbox() call would have propagated. Reaching
    # here means the seatbelt path correctly skipped the unshare
    # construction.


def test_audit_degrade_reason_macos_branch(reset_caches):
    """The audit-degraded helper has a Darwin-specific branch that
    fires when seatbelt is unavailable. Verify it produces a macOS-
    sensible message rather than the Linux apparmor one."""
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch.object(context, "check_seatbelt_available",
                            return_value=False):
        reason, instr = context._audit_degrade_reason(
            None, None, None, None, {},
        )
        assert "sandbox-exec" in reason or "seatbelt" in reason.lower()
        # Must NOT mention apparmor (Linux-specific).
        assert "apparmor" not in reason.lower()
