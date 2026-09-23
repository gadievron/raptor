"""Risk-tiered checks vs the scope receipt.

A passive receipt means benign observation only: checks that send
crafted probe values (attack-shaped headers, metadata-service URLs,
login attempts) must not fire, and state-touching checks need the
intrusive tier.
"""

from __future__ import annotations

import ast
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


class TestSessionGatedChecksRegisterAuthenticated(unittest.TestCase):
    """A check whose run() self-skips without an authenticated session
    is structurally vacuous when registered on the unauthenticated set:
    Phase 4 hardcodes session=None and Phase 5 runs only requires_auth
    checks, so it returns [] on every pipeline invocation while
    coverage reads covered. Mechanical derivation over the registry so
    the NEXT session-gated check cannot re-open the hole.

    Detection is AST-shape, not a regex over spellings: an ``if`` whose
    test mentions ``session`` in ANY form (bare name, boolean
    combination, ``is None``, ``not (session and ...)``,
    ``getattr(session, ...)``) and whose body bails out with an empty
    result is a session gate."""

    @staticmethod
    def _mentions_session(node: "ast.expr") -> bool:
        return any(
            isinstance(sub, ast.Name) and sub.id == "session"
            for sub in ast.walk(node)
        )

    @staticmethod
    def _bails_out_empty(body: "list[ast.stmt]") -> bool:
        """The gate body's exit returns nothing usable: ``return``,
        ``return None``, or ``return []``."""
        for stmt in body:
            if not isinstance(stmt, ast.Return):
                continue
            value = stmt.value
            if value is None:
                return True
            if isinstance(value, ast.List) and not value.elts:
                return True
            if isinstance(value, ast.Constant) and value.value is None:
                return True
        return False

    @classmethod
    def _session_gates(cls, func) -> bool:
        import inspect
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
        return any(
            isinstance(node, ast.If)
            and cls._mentions_session(node.test)
            and cls._bails_out_empty(node.body)
            for node in ast.walk(tree)
        )

    def test_session_gate_implies_requires_auth_registration(self):
        gated = []
        for cls in registry.all():
            if self._session_gates(cls.run):
                gated.append(cls)
                self.assertTrue(
                    cls.requires_auth,
                    f"{cls.__name__} ({cls.check_id}) gates its body on "
                    "the session but is registered unauthenticated — it "
                    "can never fire in the pipeline",
                )
        # The sweep itself must be alive: the known session-gated
        # checks have to be seen by the derivation.
        self.assertGreaterEqual(len(gated), 3)

    def test_detector_catches_every_gate_spelling(self):
        """The shapes a regex over 'if not session' missed."""

        def run_boolean_combination(self, client, target_url,
                                    session=None, discovery=None):
            if not (session and session.authenticated):
                return []
            return ["finding"]

        def run_getattr_spelling(self, client, target_url,
                                 session=None, discovery=None):
            if not getattr(session, "authenticated", False):
                return []
            return ["finding"]

        def run_canonical(self, client, target_url,
                          session=None, discovery=None):
            if not session or not session.authenticated:
                return []
            return ["finding"]

        def run_is_none(self, client, target_url,
                        session=None, discovery=None):
            if session is None:
                return
            return ["finding"]

        for gate in (run_boolean_combination, run_getattr_spelling,
                     run_canonical, run_is_none):
            self.assertTrue(self._session_gates(gate), gate.__name__)

    def test_detector_ignores_optional_session_enrichment(self):
        """A check that merely does MORE with a session is functional
        without one — it must not be forced onto the auth arm."""

        def run_enrichment(self, client, target_url,
                           session=None, discovery=None):
            findings = ["base"]
            if session and session.authenticated:
                findings.append("extra")
            return findings

        self.assertFalse(self._session_gates(run_enrichment))

    def test_cache_deception_runs_on_the_authenticated_arm(self):
        from packages.web.checks.cache import CacheDeceptionCheck

        self.assertIn(CacheDeceptionCheck, registry.authenticated())
        self.assertNotIn(CacheDeceptionCheck, registry.unauthenticated())


class TestLandscapeCountsOnlyRunnableChecks(unittest.TestCase):
    """Coverage truth: the research landscape must count a check only
    when THIS run can execute it — not merely because it is
    registered."""

    def _scanner(self, tmpdir: str, approval_level: str = "active"):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            return WebScanner(
                "https://t.example", None, Path(tmpdir),
                approval_level=approval_level,
            )

    def test_requires_auth_checks_are_not_runnable_without_a_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            scanner.session = None
            ids = scanner._runnable_check_ids()
            self.assertNotIn("V5.1.13", ids)

            scanner.session = object()  # any live session
            self.assertIn("V5.1.13", scanner._runnable_check_ids())

    def test_receipt_excluded_tiers_are_not_runnable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, approval_level="passive")
            scanner.session = None
            ids = scanner._runnable_check_ids()
            # Active-tier checks and the Phase-6 fuzzing capability are
            # both outside a passive receipt.
            self.assertNotIn("V5.1.12", ids)
            self.assertNotIn("V5.2.1", ids)
            # Passive checks remain covered.
            self.assertIn("V14.4.1", ids)

    def test_active_receipt_keeps_the_fuzzing_capability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir, approval_level="active")
            scanner.session = None
            self.assertIn("V5.2.1", scanner._runnable_check_ids())


if __name__ == "__main__":
    unittest.main()


class TestTierContractHolds(unittest.TestCase):
    def test_state_persisting_prototype_pollution_is_intrusive(self):
        # A successful probe mutates Object.prototype until the target
        # restarts — the declared intrusive definition.
        from packages.web.checks.prototype_pollution import (
            ServerSidePrototypePollutionCheck,
        )

        self.assertEqual(ServerSidePrototypePollutionCheck.risk, "intrusive")

    def test_passive_stack_trace_check_sends_only_benign_paths(self):
        from packages.web.checks.information import StackTraceCheck

        self.assertEqual(getattr(StackTraceCheck, "risk", "passive"), "passive")

        paths: list[str] = []

        class _Recorder:
            def get(self, path, **kwargs):
                paths.append(path)
                from types import SimpleNamespace
                return SimpleNamespace(status_code=404, text="")

        StackTraceCheck().run(_Recorder(), "https://t.example")
        self.assertTrue(paths)
        for path in paths:
            self.assertFalse(
                any(ch in path for ch in "<>\"'"),
                f"attack-shaped probe path under the passive tier: {path}",
            )
