"""Probe-value hygiene: hostname-exact redirect detection, HTML
filtering regexp tolerance, and the shared probe-host constant."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from packages.web.checks.base import PROBE_HOST
from packages.web.checks.oauth import OAuthOpenRedirectCheck


def _redirect_response(location: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"Location": location}
    resp.text = ""
    return resp


class TestOauthRedirectHostnameExact(unittest.TestCase):
    def _run(self, location: str):
        client = MagicMock()
        client.get.return_value = _redirect_response(location)
        results = OAuthOpenRedirectCheck().run(
            client, "https://t.example",
            discovery={"urls": ["https://t.example/oauth/authorize?x=1"]},
        )
        return [r for r in results if not r.passed]

    def test_actual_redirect_to_probe_host_is_flagged(self):
        self.assertTrue(self._run(f"https://{PROBE_HOST}/callback?code=1"))

    def test_probe_host_reflected_in_query_is_not_flagged(self):
        """Substring matching fired on mere reflection; hostname-exact
        must not."""
        self.assertFalse(self._run(
            f"https://t.example/login?next=https%3A%2F%2F{PROBE_HOST}%2Fcb",
        ))
        self.assertFalse(self._run(
            f"https://t.example/login?next={PROBE_HOST}",
        ))

    def test_prefix_and_suffix_host_tricks_are_not_flagged(self):
        self.assertFalse(self._run(f"https://{PROBE_HOST}.attacker.example/"))
        self.assertFalse(self._run(f"https://x{PROBE_HOST}/"))

    def test_scheme_relative_redirect_to_probe_host_is_flagged(self):
        self.assertTrue(self._run(f"//{PROBE_HOST}/callback"))


class TestInlineScriptEndTag(unittest.TestCase):
    def test_whitespace_before_gt_still_terminates(self):
        """A `</script >` end tag must terminate the inline block, or
        everything after it (including attacker-shaped markup) is
        swallowed into the script text."""
        from packages.web.discovery.js_routes import extract_js_routes

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<script>fetch('/api/one')</script >"
            "<script type='text/javascript'>fetch('/api/two')</script\t>"
            # Per the HTML spec, junk after the end-tag name is ignored
            # by browsers — the tag still terminates the script.
            "<script>fetch('/api/three')</script\t\n bar>"
            "<script>fetch('/api/four')</script>"
        )
        resp.content = resp.text.encode()
        client.get.return_value = resp

        urls = extract_js_routes(client, "https://t.example")
        self.assertIn("https://t.example/api/one", urls)
        self.assertIn("https://t.example/api/two", urls)
        self.assertIn("https://t.example/api/three", urls)
        self.assertIn("https://t.example/api/four", urls)


class TestProbeHostSingleSource(unittest.TestCase):
    def test_checks_share_the_constant(self):
        from packages.web.checks import cache, host_header

        self.assertEqual(host_header._ATTACKER_HOST, PROBE_HOST)
        self.assertEqual(cache._PROBE_VALUE, PROBE_HOST)
        self.assertTrue(PROBE_HOST.endswith(".example.com"))


if __name__ == "__main__":
    unittest.main()


class TestSmugglingVariants(unittest.TestCase):
    """Probe shapes + per-variant signals, exchange stubbed (no wire)."""

    def _run(self, exchanges):
        from packages.web.checks.cache import RequestSmugglingCheck

        check = RequestSmugglingCheck()
        calls = []

        def fake_exchange(host, port, use_tls, request_text):
            calls.append(request_text)
            return exchanges[len(calls) - 1]

        check._raw_exchange = fake_exchange
        results = check.run(MagicMock(), "https://t.example")
        return results, calls

    def test_all_three_variants_probe_with_correct_framing(self):
        results, calls = self._run([(None, 0.0)] * 3)
        self.assertEqual(results, [])
        self.assertEqual(len(calls), 3)
        clte, tecl, clzero = calls
        self.assertIn("Content-Length: 6", clte)
        self.assertIn("Transfer-Encoding: chunked", clte)
        self.assertIn("Content-Length: 3", tecl)
        self.assertIn("SMUGGLED", tecl)
        self.assertNotIn("Transfer-Encoding", clzero)
        self.assertIn("raptor-clzero-probe", clzero)
        # CL.0's declared length must exactly cover its embedded prefix.
        prefix = clzero.split("\r\n\r\n", 1)[1]
        import re
        declared = int(re.search(r"Content-Length: (\d+)", clzero).group(1))
        self.assertEqual(declared, len(prefix))

    def test_tecl_stall_flags_with_variant_named(self):
        results, _ = self._run([
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),  # CL.TE clean
            ("", 5.0),  # TE.CL: server sat on the ambiguous framing
        ])
        self.assertEqual(len(results), 1)
        self.assertIn("TE.CL", results[0].evidence)
        self.assertEqual(results[0].confidence, "low")

    def test_fast_400_rejection_is_not_a_signal(self):
        # An immediate 400 for a CL+TE request is the RECOMMENDED
        # rejection of the ambiguity — flagging it marked every
        # hardened proxy as a smuggling prerequisite.
        results, _ = self._run([
            ("HTTP/1.1 400 Bad Request\r\n\r\n", 0.1),
            ("HTTP/1.1 400 Bad Request\r\n\r\n", 0.1),
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),
        ])
        self.assertEqual(results, [])

    def test_digits_in_headers_or_body_are_not_a_status_line(self):
        # 'Content-Length: 2400' and echoed request lines must never
        # satisfy the signals: only real response status lines count.
        results, _ = self._run([
            ("HTTP/1.1 200 OK\r\nContent-Length: 2400\r\n\r\nx", 0.05),
            ("HTTP/1.1 200 OK\r\nContent-Length: 2400\r\n\r\nx", 0.05),
            # Error page quoting the request line: one status line only.
            ("HTTP/1.1 200 OK\r\n\r\nbad: GET /raptor-clzero-probe HTTP/1.1", 0.1),
        ])
        self.assertEqual(results, [])

    def test_clzero_double_response_flags(self):
        results, _ = self._run([
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),
            ("HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n", 0.3),
        ])
        self.assertEqual(len(results), 1)
        self.assertIn("CL.0", results[0].evidence)
        self.assertIn("second request", results[0].evidence)

    def test_slow_400_is_not_a_signal(self):
        results, _ = self._run([
            ("HTTP/1.1 400 Bad Request\r\n\r\n", 3.0),
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),
            ("HTTP/1.1 200 OK\r\n\r\nok", 0.1),
        ])
        self.assertEqual(results, [])


class TestSurfaceCoverageArtifact(unittest.TestCase):
    def test_coverage_web_json_written_from_request_history(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from packages.web.models import WebFinding
        from packages.web.scanner import WebScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                scanner = WebScanner("https://t.example", None, Path(tmpdir))
            scanner.client.request_history = [
                {"method": "GET", "url": "https://t.example/a?x=1",
                 "status_code": 200},
                {"method": "GET", "url": "https://t.example/a?x=2",
                 "status_code": 200},
                {"method": "POST", "url": "https://t.example/login",
                 "status_code": 302},
                {"method": "GET", "url": "https://t.example/missing",
                 "status_code": 404},
            ]
            finding = WebFinding(
                id="WEB-0001", title="t", severity="high",
                confidence="high", status="confirmed",
                url="https://t.example/a", evidence="e", description="d",
                recommendation="r", vuln_type="sqli",
                asvs_category="V5", check_id="V5.2.1",
            )

            scanner._write_surface_coverage([finding])

            record = json.loads(
                (Path(tmpdir) / "coverage-web.json").read_text(),
            )
            self.assertEqual(record["requests_in_window"], 4)
            self.assertEqual(record["distinct_paths_probed"], 3)
            self.assertEqual(record["by_method"], {"GET": 3, "POST": 1})
            self.assertEqual(
                record["by_status_class"],
                {"2xx": 2, "3xx": 1, "4xx": 1},
            )
            self.assertEqual(record["finding_paths"], ["/a"])
            self.assertIn("no knowable", record["note"])


class TestContextMapRendererContract(unittest.TestCase):
    def test_web_map_carries_the_fields_diagram_labels_from(self):
        """/diagram labels entry points from id/path/method and sinks
        from sink_details id/operation — without them the web map
        rendered as '?' and 'unknown' nodes."""
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from packages.web.discovery import DiscoveryResult

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("packages.web.scanner.WebClient"), patch(
                "packages.web.scanner.WebCrawler"
            ):
                from packages.web.scanner import WebScanner

                scanner = WebScanner("https://t.example", None, Path(tmpdir))
            cmap = scanner._build_web_context_map({
                "discovered_urls": ["https://t.example/search?q=1"],
                "discovered_forms": [{
                    "action": "https://t.example/login", "method": "POST",
                    "inputs": {"user": {"type": "text"}},
                }],
                "discovered_parameters": ["q"],
            }, DiscoveryResult())

        for ep in cmap["entry_points"]:
            self.assertTrue(ep["id"].startswith("EP-"))
            self.assertTrue(ep["path"])
            self.assertIn(ep["method"], ("GET", "POST"))
        self.assertEqual(
            [s["id"] for s in cmap["sink_details"]], ["SINK-001"],
        )
        self.assertIn("parameter 'q'", cmap["sink_details"][0]["operation"])

        from packages.diagram.context_map import generate

        mermaid = generate(cmap)
        self.assertIn('EP-001["GET https://t.example/search', mermaid)
        self.assertIn("parameter 'q'", mermaid)
        self.assertNotIn('"?', mermaid)
        self.assertNotIn("unknown", mermaid)
