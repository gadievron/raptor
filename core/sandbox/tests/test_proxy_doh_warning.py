"""DoH-provider warning: the proxy warns when an allowlisted host is a
known DNS-over-HTTPS provider, since a sandboxed child could use it to
bypass DNS controls."""

import logging
import unittest

from core.sandbox.proxy import EgressProxy, _KNOWN_DOH_PROVIDERS


class TestDoHProviderWarning(unittest.TestCase):
    def setUp(self):
        self._proxies: list[EgressProxy] = []

    def tearDown(self):
        for p in self._proxies:
            p.stop(drain_timeout=0)

    def _make(self, hosts):
        p = EgressProxy(hosts)
        self._proxies.append(p)
        return p

    def test_warns_on_doh_host_at_construction(self):
        with self.assertLogs("core.sandbox.proxy", level=logging.WARNING) as cm:
            self._make(["example.com", "dns.google"])
        self.assertTrue(
            any("DNS-over-HTTPS" in msg and "dns.google" in msg
                for msg in cm.output),
            cm.output,
        )

    def test_no_warning_without_doh_host(self):
        with self.assertRaises(AssertionError):
            with self.assertLogs("core.sandbox.proxy", level=logging.WARNING):
                self._make(["example.com", "api.anthropic.com"])

    def test_warns_on_add_hosts(self):
        p = self._make(["example.com"])
        with self.assertLogs("core.sandbox.proxy", level=logging.WARNING) as cm:
            p.add_hosts(["cloudflare-dns.com"])
        self.assertTrue(
            any("DNS-over-HTTPS" in msg and "cloudflare-dns.com" in msg
                for msg in cm.output),
            cm.output,
        )

    def test_known_providers_nonempty(self):
        self.assertGreater(len(_KNOWN_DOH_PROVIDERS), 10)


if __name__ == "__main__":
    unittest.main()
