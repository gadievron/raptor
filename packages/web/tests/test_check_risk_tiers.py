"""Risk-tiered checks vs the scope receipt.

A passive receipt means benign observation only: checks that send
crafted probe values (attack-shaped headers, metadata-service URLs,
login attempts) must not fire, and state-touching checks need the
intrusive tier.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.web.checks import registry


class TestDeclaredTiers(unittest.TestCase):
    def test_every_check_declares_a_known_tier(self):
        for cls in registry.unauthenticated() + registry.authenticated():
            self.assertIn(
                getattr(cls, "risk", "passive"),
                ("passive", "active", "intrusive"),
                cls.__name__,
            )

    def test_attack_shaped_probes_are_not_passive(self):
        """The concrete probes the passive receipt must exclude:
        X-Forwarded-Host injection, password-reset poisoning, metadata
        SSRF payloads, credential probes."""
        from packages.web.checks.authentication import (
            AccountEnumerationCheck,
            BruteForceProtectionCheck,
            DefaultCredentialsCheck,
        )
        from packages.web.checks.host_header import (
            HostHeaderInjectionCheck,
            PasswordResetPoisoningCheck,
        )
        from packages.web.checks.ssrf import (
            BlindSsrfHeaderCheck,
            SsrfParameterCheck,
        )

        for cls in (
            HostHeaderInjectionCheck, SsrfParameterCheck,
            BlindSsrfHeaderCheck, AccountEnumerationCheck,
            DefaultCredentialsCheck,
        ):
            self.assertNotEqual(cls.risk, "passive", cls.__name__)
        # State-touching probes need the intrusive tier: lockouts and
        # password-reset emails hit real users.
        self.assertEqual(BruteForceProtectionCheck.risk, "intrusive")
        self.assertEqual(PasswordResetPoisoningCheck.risk, "intrusive")

    def test_header_inspection_stays_passive(self):
        from packages.web.checks.headers import CspCheck, HstsCheck

        self.assertEqual(CspCheck.risk, "passive")
        self.assertEqual(HstsCheck.risk, "passive")


class TestReceiptGating(unittest.TestCase):
    def _scanner(self, tmpdir: str, approval_level: str):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            return WebScanner(
                "https://t.example", None, Path(tmpdir),
                approval_level=approval_level,
            )

    def test_passive_receipt_excludes_active_and_intrusive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, "passive")
            allowed = scanner._authorized_checks(registry.unauthenticated())
            self.assertTrue(allowed)
            for cls in allowed:
                self.assertEqual(
                    getattr(cls, "risk", "passive"), "passive", cls.__name__,
                )

    def test_active_receipt_excludes_only_intrusive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, "active")
            allowed = scanner._authorized_checks(registry.unauthenticated())
            risks = {getattr(cls, "risk", "passive") for cls in allowed}
            self.assertIn("active", risks)
            self.assertNotIn("intrusive", risks)

    def test_intrusive_receipt_allows_everything(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, "intrusive")
            allowed = scanner._authorized_checks(registry.unauthenticated())
            self.assertEqual(
                len(allowed), len(registry.unauthenticated()),
            )

    def test_access_control_phase_denied_under_passive(self):
        from packages.web.discovery import DiscoveryResult

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, "passive")
            scanner.session = None
            self.assertEqual(
                scanner._phase_access_control(DiscoveryResult(), {}), [],
            )
            self.assertNotIn("access_control", scanner._phases_completed)


if __name__ == "__main__":
    unittest.main()
