"""Scanner wiring for the browser phases (no real Chromium needed)."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.web.browser import RenderedPage, XssExecutionProof
from packages.web.models import WebFinding


def _finding(**kwargs) -> WebFinding:
    defaults = dict(
        id="WEB-0001", title="XSS", severity="high", confidence="medium",
        status="needs_review", url="https://t.example/echo?q=1",
        evidence="reflected", description="", recommendation="",
        vuln_type="xss", asvs_category="V5", check_id="V5.3.1",
        target_url="https://t.example/echo",
        affected_parameters=["q"],
    )
    defaults.update(kwargs)
    return WebFinding(**defaults)


class TestBrowserPhases(unittest.TestCase):
    def _scanner(self, tmpdir: str):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            scanner = WebScanner(
                "https://t.example", None, Path(tmpdir), browser=True,
            )
        scanner.execution_policy = MagicMock()
        return scanner

    @contextmanager
    def _engine(self, scanner, engine):
        fake = MagicMock()
        fake.__enter__ = MagicMock(return_value=engine)
        fake.__exit__ = MagicMock(return_value=None)
        with patch.object(scanner, "_browser_engine", return_value=fake), \
                patch("packages.web.browser.browser_available",
                      return_value=True):
            yield

    def test_rendered_crawl_merges_additively(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            engine = MagicMock()
            engine.blocked_requests = 2
            engine.rendered_crawl.return_value = [RenderedPage(
                url="https://t.example/",
                links=["https://t.example/js-only",
                       "https://t.example/known"],
                forms=[{
                    "action": "https://t.example/js-form",
                    "method": "POST",
                    "inputs": {"jsfield": {"type": "text"}},
                }],
            )]
            crawl_data = {
                "discovered_urls": ["https://t.example/known"],
                "discovered_forms": [],
                "discovered_parameters": ["old"],
            }
            with self._engine(scanner, engine):
                scanner._phase_browser_crawl(crawl_data)

            self.assertIn(
                "https://t.example/js-only", crawl_data["discovered_urls"],
            )
            self.assertEqual(
                crawl_data["discovered_urls"].count("https://t.example/known"),
                1,
            )
            self.assertEqual(len(crawl_data["discovered_forms"]), 1)
            self.assertEqual(
                crawl_data["discovered_parameters"], ["old", "jsfield"],
            )
            self.assertIn("browser_crawl", scanner._phases_completed)

    def test_execution_proof_upgrades_xss_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            finding = _finding()
            engine = MagicMock()
            proof = XssExecutionProof(
                url=finding.target_url, parameter="q",
                payload="<img …>", tokens=["tok"],
                screenshot=f"{tmpdir}/xss.png",
            )
            # First call: the finding probe. Later calls: fragment
            # probes over crawled pages — no DOM sinks.
            engine.prove_xss.side_effect = [proof] + [None] * 20
            with self._engine(scanner, engine):
                new = scanner._phase_browser_xss(
                    [finding], {"discovered_urls": []},
                )

            self.assertEqual(new, [])
            self.assertEqual(finding.status, "confirmed")
            self.assertEqual(finding.confidence, "high")
            self.assertEqual(finding.oracle_signal, "xss_executed_in_dom")
            self.assertIn("Execution proof", finding.evidence)
            self.assertIn("xss.png", finding.evidence)

    def test_fragment_sink_becomes_new_dom_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            engine = MagicMock()
            proof = XssExecutionProof(
                url="https://t.example/app", parameter="#fragment",
                payload="<img …>", tokens=["tok"],
            )
            engine.prove_xss.side_effect = [None, proof]
            with self._engine(scanner, engine):
                new = scanner._phase_browser_xss(
                    [], {"discovered_urls": ["https://t.example/app"]},
                )

            self.assertEqual(len(new), 1)
            self.assertEqual(new[0].attack_vector, "dom_fragment")
            self.assertEqual(new[0].status, "confirmed")
            self.assertEqual(new[0].cwe_id, "CWE-79")

    def test_policy_denial_skips_browser_phases(self):
        from packages.web.execution_policy import WebPolicyError

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            scanner.execution_policy.authorize.side_effect = WebPolicyError(
                "passive only",
            )
            crawl_data: dict = {"discovered_urls": []}
            scanner._phase_browser_crawl(crawl_data)
            new = scanner._phase_browser_xss([_finding()], crawl_data)

            self.assertEqual(new, [])
            self.assertNotIn("browser_crawl", scanner._phases_completed)
            self.assertNotIn("browser_xss", scanner._phases_completed)

    def test_browser_off_by_default(self):
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner("https://t.example", None, Path(tmpdir))
            self.assertFalse(scanner.use_browser)


if __name__ == "__main__":
    unittest.main()
