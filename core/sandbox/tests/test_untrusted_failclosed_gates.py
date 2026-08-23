"""Fail-closed preflight gates for the untrusted/strict contracts.

Two silent-degradation seams:

- On macOS, _require_userns_or_optin returned False unconditionally
  ("the seatbelt tier provides the isolation contract there") without
  verifying seatbelt actually engages — with sandbox-exec missing or
  smoke-failing, run_untrusted's default profile warned once and ran
  attacker-derived code as a bare subprocess. Only strict aborted.
- strict's preflight checked namespaces/mount only; with libseccomp
  absent the filter builder returns None and both spawn paths run
  filterless (AF_UNIX blocklist, io_uring/keyring/bpf, UDP block all
  gone) under a profile sold as fail-closed.
"""

import sys
import tempfile
import unittest
from unittest.mock import patch

import core.sandbox.context as ctx
from core.sandbox.errors import SandboxSetupError


class TestDarwinUntrustedGate(unittest.TestCase):
    """Unit-level: the darwin arm of _require_userns_or_optin."""

    def _call(self):
        return ctx._require_userns_or_optin("run_untrusted()",
                                            restrict_reads=True)

    def test_darwin_with_seatbelt_available_is_exempt(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=True):
            self.assertFalse(self._call())

    def test_darwin_without_seatbelt_fails_closed(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": ""}):
            with self.assertRaises(SandboxSetupError):
                self._call()

    def test_darwin_operator_override_engages_degraded_mode(self):
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": "1"}):
            self.assertFalse(self._call())


class TestStrictRequiresSeccomp(unittest.TestCase):
    def setUp(self):
        if sys.platform != "linux":
            self.skipTest("Linux strict gate")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_strict_aborts_when_libseccomp_unavailable(self):
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            with self.assertRaises(SandboxSetupError) as cm:
                with ctx.sandbox(profile="strict",
                                 target=self.tmp.name,
                                 output=self.tmp.name):
                    pass
            self.assertIn("seccomp", str(cm.exception).lower())

    def test_full_profile_still_degrades_gracefully(self):
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            # construction must not raise for the degrading profile
            with ctx.sandbox(profile="full", target=self.tmp.name,
                             output=self.tmp.name):
                pass

    def test_strict_names_seccomp_even_when_mount_ns_also_missing(self):
        """CI-runner condition: with mount-ns ALSO unavailable, the
        mount refusal used to fire first and the libseccomp gate's
        diagnostic was unobservable. The strict abort must aggregate
        every unmet requirement into ONE message naming all of them —
        an operator on a doubly-degraded host fixes everything in one
        round-trip instead of discovering the gates serially."""
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False), \
             patch.object(ctx, "check_mount_available",
                          return_value=False), \
             patch("core.sandbox.probes.mount_unavailable_reason",
                   return_value=("mount-ns blocked by host (simulated)",
                                 "re-enable unprivileged mount "
                                 "namespaces on this host.")):
            with self.assertRaises(SandboxSetupError) as cm:
                with ctx.sandbox(profile="strict",
                                 target=self.tmp.name,
                                 output=self.tmp.name):
                    pass
            text = str(cm.exception).lower()
            self.assertIn("unmet requirements", text)
            self.assertIn("mount-namespace", text)
            self.assertIn("seccomp", text)

    def test_strict_single_missing_requirement_message_unchanged(self):
        """With ONLY libseccomp missing the abort keeps the exact
        single-requirement phrasing (no aggregation preamble)."""
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            if not ctx.check_mount_available():
                self.skipTest("mount-ns unavailable on this host")
            with self.assertRaises(SandboxSetupError) as cm:
                with ctx.sandbox(profile="strict",
                                 target=self.tmp.name,
                                 output=self.tmp.name):
                    pass
            text = str(cm.exception)
            self.assertIn(
                "sandbox profile 'strict' requires a seccomp filter",
                text)
            self.assertNotIn("unmet requirements", text)


if __name__ == "__main__":
    unittest.main()


class TestUntrustedRequiresSeccomp(unittest.TestCase):
    """The untrusted preflight must refuse to run attacker-derived
    code FILTERLESS: with libseccomp absent, the AF_UNIX blocklist,
    escape-primitive blocks and send-flag argument rules all silently
    vanish — previously only strict aborted; run_untrusted degraded
    with a warning."""

    def _call(self):
        return ctx._require_userns_or_optin("run_untrusted()",
                                            restrict_reads=True)

    def test_linux_without_libseccomp_fails_closed(self):
        if sys.platform != "linux":
            self.skipTest("Linux gate")
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": ""}):
            with self.assertRaises(SandboxSetupError) as cm:
                self._call()
            self.assertIn("seccomp", str(cm.exception).lower())

    def test_operator_override_engages_degraded_mode(self):
        if sys.platform != "linux":
            self.skipTest("Linux gate")
        with patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False), \
             patch.dict(ctx.os.environ,
                        {"RAPTOR_ALLOW_DEGRADED_UNTRUSTED": "1"}):
            self._call()  # must not raise

    def test_darwin_arm_untouched_by_seccomp_gate(self):
        """macOS has no libseccomp; the seatbelt arm must return
        before the seccomp gate is consulted."""
        with patch.object(ctx.sys, "platform", "darwin"), \
             patch.object(ctx, "check_seatbelt_available",
                          return_value=True), \
             patch.object(ctx._seccomp, "check_seccomp_available",
                          return_value=False):
            self.assertFalse(self._call())


class TestStartNewSessionIsContract(unittest.TestCase):
    """setsid detachment is part of the untrusted-execution contract:
    without it /dev/tty resolves to the operator's controlling
    terminal and a sandboxed target polls their keystrokes. The
    hardened helpers previously ACCEPTED start_new_session=False
    through their kwargs allowlist — forwarding the suppression the
    setsid rationale comment says requires sandbox() — so any
    internal caller could reopen the channel. Both helpers must
    refuse the kwarg via TypeError, like block_network."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="raptor-snsg-")
        self.addCleanup(self._tmp.cleanup)
        # The host-capability preflight is irrelevant to the kwarg
        # contract — neutralise it so the tests are hermetic on
        # namespace-less CI hosts.
        p = patch.object(ctx, "_require_userns_or_optin",
                         lambda *a, **k: False)
        p.start()
        self.addCleanup(p.stop)

    def test_run_untrusted_refuses_false(self):
        with self.assertRaises(TypeError) as cm:
            ctx.run_untrusted(["/bin/true"], target=self._tmp.name,
                              start_new_session=False)
        self.assertIn("start_new_session", str(cm.exception))

    def test_run_untrusted_refuses_even_true(self):
        # Policy is fixed, not negotiable — accepting the harmless
        # spelling would keep the kwarg discoverable and one default
        # change away from regressing.
        with self.assertRaises(TypeError):
            ctx.run_untrusted(["/bin/true"], target=self._tmp.name,
                              start_new_session=True)

    def test_run_untrusted_networked_refuses_false(self):
        with self.assertRaises(TypeError) as cm:
            ctx.run_untrusted_networked(
                ["/bin/true"], proxy_hosts=["example.com"],
                target=self._tmp.name, start_new_session=False)
        self.assertIn("start_new_session", str(cm.exception))
