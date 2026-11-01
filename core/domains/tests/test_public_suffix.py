"""Offline boundary and snapshot refresh regression tests."""
import io
import runpy
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.domains.public_suffix import (
    PSL_PATH, load_suffix_rules, parse_suffix_list, registrable_domain,
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
