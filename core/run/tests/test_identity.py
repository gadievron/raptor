"""Tests for core.run.identity — the operator/finder identity (#485 WHO)."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.run.identity import load_finder_identity


class TestLoadFinderIdentity(unittest.TestCase):

    def _write(self, d, obj):
        p = Path(d) / "identity.json"
        p.write_text(json.dumps(obj))
        return p

    def test_full_identity_allowlisted(self):
        # name/handle/url kept; anything else dropped.
        with TemporaryDirectory() as d:
            p = self._write(d, {"name": "Jane Doe", "handle": "@jane",
                                "url": "https://x", "secret": "drop-me"})
            self.assertEqual(
                load_finder_identity(p),
                {"name": "Jane Doe", "handle": "@jane", "url": "https://x"})

    def test_name_only(self):
        with TemporaryDirectory() as d:
            self.assertEqual(
                load_finder_identity(self._write(d, {"name": "Jane"})),
                {"name": "Jane"})

    def test_no_usable_name_is_unset(self):
        # No default "Raptor User": a nameless / blank / non-string name = unset.
        with TemporaryDirectory() as d:
            self.assertIsNone(load_finder_identity(self._write(d, {"handle": "@x"})))
            self.assertIsNone(load_finder_identity(self._write(d, {"name": "   "})))
            self.assertIsNone(load_finder_identity(self._write(d, {"name": 123})))
            self.assertIsNone(load_finder_identity(self._write(d, {})))

    def test_absent_file_is_none(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_finder_identity(Path(d) / "nope.json"))

    def test_malformed_is_none(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "identity.json"
            p.write_text("not json{")
            self.assertIsNone(load_finder_identity(p))
            p.write_text(json.dumps(["a", "list"]))  # not a dict
            self.assertIsNone(load_finder_identity(p))

    def test_strips_whitespace(self):
        with TemporaryDirectory() as d:
            self.assertEqual(
                load_finder_identity(self._write(d, {"name": "  Jane  ",
                                                     "handle": "  @j  "})),
                {"name": "Jane", "handle": "@j"})

    # --- adversarial: who is publish-bound, so no injection/spoof/DoS ---

    def test_rejects_control_and_format_chars(self):
        # Null bytes / ANSI escapes / unicode bidi-override / zero-width must
        # not reach a published identity (terminal injection, spoofing).
        with TemporaryDirectory() as d:
            for bad in ("Jane\x00Doe", "Jane\x1b[31mDoe", "Jane‮Doe",
                        "a​b"):
                self.assertIsNone(
                    load_finder_identity(self._write(d, {"name": bad})),
                    f"control/format char should reject: {bad!r}")

    def test_keeps_legitimate_unicode_name(self):
        # Real non-ASCII names are fine — only control/format chars are rejected.
        with TemporaryDirectory() as d:
            self.assertEqual(
                load_finder_identity(self._write(d, {"name": "José 李"})),
                {"name": "José 李"})

    def test_length_caps(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(
                load_finder_identity(self._write(d, {"name": "x" * 500})))
            # over-long handle dropped; usable name kept
            self.assertEqual(
                load_finder_identity(self._write(d, {"name": "Jane",
                                                     "handle": "h" * 500})),
                {"name": "Jane"})

    def test_oversize_file_rejected(self):
        # A huge (or huge-symlinked) file must not be read on the hot start path.
        with TemporaryDirectory() as d:
            p = Path(d) / "big.json"
            p.write_text('{"name":"' + ("A" * (70 * 1024)) + '"}')
            self.assertIsNone(load_finder_identity(p))


if __name__ == "__main__":
    unittest.main()
