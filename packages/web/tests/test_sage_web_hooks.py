"""SAGE web-scan hooks: per-target priors, hint-tier contract."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.sage.hooks import (
    _web_domain,
    recall_context_for_web_scan,
    store_web_scan_observations,
)

_TARGET = "https://app.example.test:8443"


class TestWebDomain(unittest.TestCase):
    def test_domain_is_url_keyed_and_stable(self):
        self.assertEqual(_web_domain(_TARGET), _web_domain(_TARGET))
        self.assertTrue(_web_domain(_TARGET).startswith("raptor-web-"))
        self.assertNotEqual(
            _web_domain(_TARGET), _web_domain("https://other.example"),
        )


class TestRecall(unittest.TestCase):
    def test_no_client_degrades_to_empty(self):
        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertEqual(recall_context_for_web_scan(_TARGET), [])

    def test_recall_queries_target_domain_and_methodology(self):
        client = MagicMock()
        client.query.side_effect = [
            [{"content": "sqli confirmed at /search", "confidence": 0.9}],
            [{"content": "verify with replay", "confidence": 0.8}],
        ]
        with patch("core.sage.hooks._get_client", return_value=client):
            rows = recall_context_for_web_scan(_TARGET)

        self.assertEqual(len(rows), 2)
        domains = [
            call.kwargs["domain_tag"] for call in client.query.call_args_list
        ]
        self.assertEqual(domains[0], _web_domain(_TARGET))
        self.assertEqual(domains[1], "raptor-methodology")
        self.assertIn("app.example.test:8443", client.query.call_args_list[0].kwargs["text"])

    def test_query_failure_degrades_to_empty(self):
        client = MagicMock()
        client.query.side_effect = RuntimeError("sidecar down")
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertEqual(recall_context_for_web_scan(_TARGET), [])


class TestStore(unittest.TestCase):
    def _store(self, client, **kwargs):
        defaults = dict(
            fingerprint={"server": "nginx/1.24", "framework": "Django"},
            findings=[
                {"vuln_type": "sqli", "url": f"{_TARGET}/search?q=1",
                 "confirmed": True},
                {"vuln_type": "xss", "url": f"{_TARGET}/echo",
                 "status": "needs_review"},
            ],
            refuted_probes=[
                {"vuln_type": "xss", "endpoint": f"{_TARGET}/echo"},
            ],
            wordlist_stats={"common.txt": 12},
        )
        defaults.update(kwargs)
        with patch("core.sage.hooks._get_client", return_value=client):
            store_web_scan_observations(_TARGET, **defaults)

    def test_no_client_is_a_noop(self):
        self._store(None)  # must not raise

    def test_store_emits_bounded_observation_rows(self):
        client = MagicMock()
        client.propose.return_value = True
        self._store(client)

        contents = [
            call.kwargs["content"] for call in client.propose.call_args_list
        ]
        self.assertEqual(len(contents), 4)
        joined = "\n".join(contents)
        self.assertIn("fingerprint: framework=Django, server=nginx/1.24",
                      joined)
        confirmed_rows = [
            content for content in contents
            if content.startswith("Confirmed vulnerability classes")
        ]
        self.assertEqual(len(confirmed_rows), 1)
        self.assertIn("sqli at /search", confirmed_rows[0])
        # The unconfirmed xss finding must NOT appear as confirmed —
        # asserted against the confirmed row itself, not a substring
        # heuristic over the joined blob.
        self.assertNotIn("xss", confirmed_rows[0])
        self.assertIn("common.txt: 12 hit(s)", joined)
        # Hint-tier contract stated ON the stored row, so any future
        # consumer reading it back sees the boundary.
        self.assertIn("never suppression", joined)
        domains = {
            call.kwargs["domain_tag"]
            for call in client.propose.call_args_list
        }
        self.assertEqual(domains, {_web_domain(_TARGET)})

    def test_empty_run_stores_nothing(self):
        client = MagicMock()
        self._store(
            client, fingerprint={}, findings=[], refuted_probes=[],
            wordlist_stats={},
        )
        client.propose.assert_not_called()


class TestScannerWiring(unittest.TestCase):
    def _scanner(self, tmpdir: str):
        from packages.web.scanner import WebScanner

        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            return WebScanner(_TARGET, None, Path(tmpdir))

    def test_priors_attach_to_fuzzer_as_hint_tier(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            scanner.fuzzer = MagicMock()
            rows = [{"content": "sqli likely", "confidence": 0.9}]
            with patch(
                "core.sage.hooks.recall_context_for_web_scan",
                return_value=rows,
            ):
                scanner._sage_attach_priors()
            scanner.fuzzer.set_sage_prior_recall.assert_called_once()
            text, passed_rows = scanner.fuzzer.set_sage_prior_recall.call_args.args
            self.assertIn("sqli likely", text)
            self.assertEqual(passed_rows, rows)

    def test_no_rows_leaves_fuzzer_untouched(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            scanner.fuzzer = MagicMock()
            with patch(
                "core.sage.hooks.recall_context_for_web_scan",
                return_value=[],
            ):
                scanner._sage_attach_priors()
            scanner.fuzzer.set_sage_prior_recall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
