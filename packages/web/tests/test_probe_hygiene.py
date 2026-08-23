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
        )
        resp.content = resp.text.encode()
        client.get.return_value = resp

        urls = extract_js_routes(client, "https://t.example")
        self.assertIn("https://t.example/api/one", urls)
        self.assertIn("https://t.example/api/two", urls)


class TestProbeHostSingleSource(unittest.TestCase):
    def test_checks_share_the_constant(self):
        from packages.web.checks import cache, host_header

        self.assertEqual(host_header._ATTACKER_HOST, PROBE_HOST)
        self.assertEqual(cache._PROBE_VALUE, PROBE_HOST)
        self.assertTrue(PROBE_HOST.endswith(".example.com"))


if __name__ == "__main__":
    unittest.main()
