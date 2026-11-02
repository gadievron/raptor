"""Offline boundary and snapshot refresh regression tests."""
import io
import runpy
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.domains.public_suffix import (
    InvalidHostname, PSL_PATH, domain_boundary, host_matches_anchor, load_suffix_rules,
    parse_suffix_list, registrable_domain, same_registrable_domain,
)


class TestPublicSuffix(unittest.TestCase):
    def test_tenant_boundaries(self):
        for suffix in ('up.railway.app', 'surge.sh', 's3.amazonaws.com',
                       'github.io', 'vercel.app', 'pages.dev', 'com.sg', 'co.uk'):
            with self.subTest(suffix=suffix):
                self.assertEqual(registrable_domain('sub.victim.' + suffix),
                                 'victim.' + suffix)
                self.assertNotEqual(registrable_domain('victim.' + suffix),
                                    registrable_domain('attacker.' + suffix))

    def test_wildcard_and_exception(self):
        self.assertEqual(registrable_domain('sub.victim.foo.ck'), 'victim.foo.ck')
        self.assertEqual(registrable_domain('sub.www.ck'), 'www.ck')
        self.assertIsNone(registrable_domain('foo.ck'))

    def test_normalization(self):
        self.assertEqual(registrable_domain('SUB.Example.COM.'), 'example.com')
        self.assertEqual(registrable_domain('faß.de'), 'xn--fa-hia.de')
        self.assertNotEqual(registrable_domain('faß.de'), registrable_domain('fass.de'))
        self.assertEqual(registrable_domain('www.食狮.公司.cn'), 'xn--85x722f.xn--55qx5d.cn')

    def test_suffix_and_unknown_tld(self):
        self.assertIsNone(registrable_domain('github.io'))
        self.assertIsNone(registrable_domain('com'))
        self.assertEqual(registrable_domain('sub.example.test'), 'example.test')

    def test_ip_literals(self):
        self.assertEqual(registrable_domain('192.0.2.1'), '192.0.2.1')
        self.assertEqual(registrable_domain('2001:db8::1'), '2001:db8::1')

    def test_rejects_invalid_hosts_before_loading_rules(self):
        for host in ("a." * 16000 + "example.com", "a" * 64 + ".com",
                     "", ".", "example..com", "example.com..", "-bad.com",
                     "bad-.com", "bad_label.com", "é" * 60 + ".com"):
            with self.subTest(length=len(host)), patch(
                    'core.domains.public_suffix.load_suffix_rules') as load:
                with self.assertRaises(InvalidHostname):
                    registrable_domain(host)
                load.assert_not_called()

    def test_dns_length_boundaries(self):
        host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        self.assertEqual(len(host), 253)
        self.assertEqual(registrable_domain(host), "c" * 63 + "." + "d" * 61)
        self.assertEqual(registrable_domain(host + "."), registrable_domain(host))
        with self.assertRaises(InvalidHostname):
            registrable_domain(host + "e")

    def test_boundary_provenance(self):
        cases = [
            ("sub.example.com", "psl", "com", "example.com"),
            ("cdn.victim.github.io", "psl", "github.io", "victim.github.io"),
            ("sub.victim.foo.ck", "psl", "*.ck", "victim.foo.ck"),
            ("sub.www.ck", "psl", "!www.ck", "www.ck"),
            ("api.team.internal", "default", None, "team.internal"),
            ("api.office.local", "default", None, "office.local"),
            ("buildserver", "default", None, None),
            ("localhost", "default", None, None),
            ("192.0.2.1", "ip", None, "192.0.2.1"),
        ]
        for host, source, rule, domain in cases:
            with self.subTest(host=host):
                result = domain_boundary(host)
                self.assertEqual((result.source, result.rule, result.registrable_domain),
                                 (source, rule, domain))

    def test_private_dns_underscores_require_opt_in(self):
        host = "api.service_name.internal"
        with self.assertRaises(InvalidHostname):
            domain_boundary(host)
        result = domain_boundary(host, allow_underscores=True)
        self.assertEqual(result.registrable_domain, "service_name.internal")
        self.assertEqual(result.source, "default")
        with self.assertRaises(InvalidHostname):
            domain_boundary("a." * 16000 + host, allow_underscores=True)

    def test_rules_are_immutable_and_cached(self):
        rules = load_suffix_rules()
        self.assertIs(rules, load_suffix_rules())
        self.assertIsInstance(rules.exact, frozenset)
        self.assertIsInstance(rules.wildcard, frozenset)
        self.assertIsInstance(rules.exceptions, frozenset)
        with self.assertRaises(FrozenInstanceError):
            rules.exact = frozenset()

    def test_invalid_snapshot(self):
        snapshot = PSL_PATH.read_text(encoding='utf-8')
        for invalid in ('', snapshot.split('// ===BEGIN PRIVATE DOMAINS===')[0],
                        snapshot + '\n railway.app\n', snapshot + '\nbad*rule\n'):
            with self.subTest(), self.assertRaises(ValueError):
                parse_suffix_list(invalid)

    def test_missing_snapshot_raises_without_fallback(self):
        load_suffix_rules.cache_clear()
        try:
            with patch.object(Path, 'read_text', side_effect=OSError('missing')):
                with self.assertRaises(OSError):
                    registrable_domain('example.com')
        finally:
            load_suffix_rules.cache_clear()


class TestHostPolicy(unittest.TestCase):
    def test_known_tenants_and_exact_grants(self):
        for suffix in ('github.io', 's3.amazonaws.com', 'surge.sh', 'up.railway.app',
                       'foo.ck', 'com.sg'):
            with self.subTest(suffix=suffix):
                anchor = 'victim.' + suffix
                self.assertTrue(host_matches_anchor('sub.' + anchor, anchor))
                self.assertFalse(host_matches_anchor('attacker.' + suffix, anchor))
                self.assertTrue(host_matches_anchor('attacker.' + suffix, anchor,
                                                    extra_hosts=['attacker.' + suffix]))
                self.assertFalse(host_matches_anchor('sub.attacker.' + suffix, anchor,
                                                     extra_hosts=['attacker.' + suffix]))
        self.assertTrue(host_matches_anchor('sub.www.ck', 'www.ck'))

    def test_unknown_local_ip_and_public_suffix_grants_are_exact(self):
        for anchor, other in [('api.office.local', 'db.office.local'),
                              ('api.team.internal', 'db.team.internal'),
                              ('localhost', 'sub.localhost'),
                              ('buildserver', 'sub.buildserver'),
                              ('192.0.2.1', '192.0.2.2'),
                              ('github.io', 'tenant.github.io')]:
            with self.subTest(anchor=anchor):
                self.assertTrue(host_matches_anchor(anchor, anchor))
                self.assertFalse(host_matches_anchor(other, anchor))
                self.assertFalse(same_registrable_domain(anchor, other))
                self.assertTrue(host_matches_anchor(other, anchor, extra_hosts=[other]))
        self.assertTrue(host_matches_anchor('API.OFFICE.LOCAL.', 'api.office.local'))

    def test_policy_errors_cannot_be_mistaken_for_allowed_or_denied(self):
        for error in (OSError('missing'), ValueError('invalid')):
            with self.subTest(error=type(error).__name__), patch(
                    'core.domains.public_suffix.load_suffix_rules', side_effect=error):
                with self.assertRaises(type(error)):
                    host_matches_anchor('localhost', 'localhost')
                with self.assertRaises(type(error)):
                    same_registrable_domain('192.0.2.1', '192.0.2.1')
        with self.assertRaises(InvalidHostname):
            host_matches_anchor('service_name.internal', 'service_name.internal')


class TestRefresh(unittest.TestCase):
    def refresh(self, data, destination):
        script = Path(__file__).resolve().parents[3] / '.github/scripts/refresh_public_suffix_list.py'
        main = runpy.run_path(str(script))['main']
        with patch.dict(main.__globals__, DEST=destination,
                        urlopen=lambda *a, **k: io.BytesIO(data)):
            main()

    def test_invalid_refresh_preserves_snapshot(self):
        with TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'snapshot.dat'
            destination.write_bytes(b'last known good')
            for data in (b'invalid', b'x' * 4_000_001):
                with self.subTest(size=len(data)), self.assertRaises(ValueError):
                    self.refresh(data, destination)
                self.assertEqual(destination.read_bytes(), b'last known good')

    def test_valid_refresh(self):
        with TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'snapshot.dat'
            data = PSL_PATH.read_bytes()
            self.refresh(data, destination)
            self.assertEqual(destination.read_bytes(), data)
            self.assertEqual(list(Path(tmp).iterdir()), [destination])


if __name__ == '__main__':
    unittest.main()
