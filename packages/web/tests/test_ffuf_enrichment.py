"""Phase 2a ffuf config enrichment (auth reuse + fingerprint tuning)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.web.discovery import DiscoveryResult
from packages.web.discovery.wordlists import (
    recommend_extensions,
    select_wordlist,
)
from packages.web.ffuf import FfufConfig
from packages.web.scanner import WebScanner


class TestWordlistHelpers(unittest.TestCase):
    def test_extensions_follow_fingerprint(self):
        exts = recommend_extensions(
            {"framework": "PHP/Laravel", "server": "Apache/2.4"}
        )
        self.assertIn(".php", exts)
        self.assertIn(".bak", exts)  # server product known -> backup pair

        self.assertEqual(recommend_extensions({}), ())

    def test_wordlist_selection_prefers_fingerprint_then_generic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "sub").mkdir()
            (root / "sub" / "Common-PHP-Filenames.txt").write_text(
                "index.php\n", encoding="utf-8"
            )
            (root / "common.txt").write_text("admin\n", encoding="utf-8")

            php = select_wordlist({"framework": "PHP"}, root)
            self.assertIsNotNone(php)
            self.assertEqual(php.name, "Common-PHP-Filenames.txt")

            generic = select_wordlist({"framework": "Elixir"}, root)
            self.assertIsNotNone(generic)
            self.assertEqual(generic.name, "common.txt")

        self.assertIsNone(select_wordlist({}, root))  # dir gone


class TestConfigEnrichment(unittest.TestCase):
    def _scanner(self, tmpdir: str, **kwargs) -> WebScanner:
        with patch("packages.web.scanner.WebClient"), patch(
            "packages.web.scanner.WebCrawler"
        ):
            scanner = WebScanner("http://example.com", None, Path(tmpdir), **kwargs)
        return scanner

    def test_session_cookies_flow_into_ffuf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "w.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            scanner = self._scanner(
                tmpdir, ffuf_config=FfufConfig(wordlist=wordlist),
            )
            scanner.session = MagicMock(
                authenticated=True, mode="form", token=None,
            )
            scanner.client.get_cookies.return_value = {"sid": "s3cret"}

            enriched = scanner._enriched_ffuf_config(DiscoveryResult())

            self.assertEqual(enriched.cookies, ("sid=s3cret",))

    def test_operator_values_always_win(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "w.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            explicit = FfufConfig(
                wordlist=wordlist,
                cookies=("mine=1",),
                extensions=(".zip",),
            )
            scanner = self._scanner(tmpdir, ffuf_config=explicit)
            scanner.session = MagicMock(
                authenticated=True, mode="form", token=None,
            )
            scanner.client.get_cookies.return_value = {"sid": "s3cret"}
            discovery = DiscoveryResult()
            discovery.fingerprint = {"framework": "PHP"}

            enriched = scanner._enriched_ffuf_config(discovery)

            self.assertEqual(enriched.cookies, ("mine=1",))
            self.assertEqual(enriched.extensions, (".zip",))

    def test_bearer_session_becomes_authorization_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "w.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            scanner = self._scanner(
                tmpdir, ffuf_config=FfufConfig(wordlist=wordlist),
            )
            scanner.session = MagicMock(
                authenticated=True, mode="bearer", token="tok-42",
            )

            enriched = scanner._enriched_ffuf_config(DiscoveryResult())

            self.assertEqual(
                enriched.headers, ("Authorization: Bearer tok-42",)
            )

    def test_wordlist_dir_activates_ffuf_by_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "lists"
            root.mkdir()
            (root / "common.txt").write_text("admin\n", encoding="utf-8")
            scanner = self._scanner(tmpdir, ffuf_wordlist_dir=root)

            enriched = scanner._enriched_ffuf_config(DiscoveryResult())

            self.assertIsNotNone(enriched)
            self.assertEqual(enriched.wordlist, root / "common.txt")

    def test_no_config_and_no_dir_keeps_ffuf_off(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = self._scanner(tmpdir)
            self.assertIsNone(scanner._enriched_ffuf_config(DiscoveryResult()))


if __name__ == "__main__":
    unittest.main()
