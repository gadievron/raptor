"""check_child_unix_sockets_available — transport pre-flight verdict.

The helper answers one question for in-sandbox unix-socket servers
(the persistent Ghidra worker): can the sandboxed CHILD create AF_UNIX
sockets, or must the parent hand it an inherited socketpair half? Its
verdict must mirror the spawn path's own gating (namespace lane +
connect-scoping supervisor) and stay fail-closed: a false positive
boot-loops the child against EPERM, a false negative only picks the
transport that works on every lane.
"""

from __future__ import annotations

import sys

from core.sandbox import probes


class TestDarwin:
    def test_darwin_always_capable(self, monkeypatch):
        # Seatbelt does not filter socket creation.
        monkeypatch.setattr(sys, "platform", "darwin")
        assert probes.check_child_unix_sockets_available() is True


class TestLinux:
    def test_no_namespace_lane_means_incapable(self, monkeypatch):
        # The nested-sandbox host class from the field failure: the
        # namespace lane cannot engage, every child lands on the
        # preexec seccomp lane, which denies socket(AF_UNIX)
        # unconditionally — the worker dies at bind with EPERM.
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            probes, "check_mount_available", lambda: False,
        )
        assert probes.check_child_unix_sockets_available() is False

    def test_namespace_lane_without_unix_scope_incapable(
        self, monkeypatch,
    ):
        # Even on the namespace lane, allow_unix_sockets stays
        # disabled (fail-closed) without the connect-scoping
        # supervisor — the verdict must track that gate.
        import core.sandbox._unix_scope as unix_scope
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            probes, "check_mount_available", lambda: True,
        )
        monkeypatch.setattr(
            unix_scope, "probe_unix_scope", lambda: False,
        )
        assert probes.check_child_unix_sockets_available() is False

    def test_namespace_lane_with_unix_scope_capable(self, monkeypatch):
        import core.sandbox._unix_scope as unix_scope
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            probes, "check_mount_available", lambda: True,
        )
        monkeypatch.setattr(
            unix_scope, "probe_unix_scope", lambda: True,
        )
        assert probes.check_child_unix_sockets_available() is True


class TestPackageExport:
    def test_exported_from_core_sandbox(self):
        import core.sandbox as sandbox_pkg
        assert (
            sandbox_pkg.check_child_unix_sockets_available
            is probes.check_child_unix_sockets_available
        )
        assert (
            "check_child_unix_sockets_available" in sandbox_pkg.__all__
        )
