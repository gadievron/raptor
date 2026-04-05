"""Tests for core.json utilities."""

import json
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json, load_json_with_comments, save_json


class TestLoadJson(unittest.TestCase):

    def test_loads_valid(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"key": "value"}')
            self.assertEqual(load_json(p), {"key": "value"})

    def test_missing_file(self):
        self.assertIsNone(load_json("/nonexistent/path.json"))

    def test_invalid_json(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{not valid")
            self.assertIsNone(load_json(p))

    def test_empty_file(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "empty.json"
            p.write_text("")
            self.assertIsNone(load_json(p))

    def test_accepts_string_path(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"a": 1}')
            self.assertEqual(load_json(str(p)), {"a": 1})

    def test_strict_raises_on_invalid(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{not valid")
            with self.assertRaises(Exception):
                load_json(p, strict=True)

    def test_strict_returns_none_for_missing(self):
        self.assertIsNone(load_json("/nonexistent/path.json", strict=True))


class TestLoadJsonWithComments(unittest.TestCase):

    def test_strips_comments(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('// comment\n{"key": "value"}\n')
            self.assertEqual(load_json_with_comments(p), {"key": "value"})

    def test_inline_not_stripped(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{"url": "https://example.com"}\n')
            result = load_json_with_comments(p)
            self.assertEqual(result["url"], "https://example.com")

    def test_all_comments(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text("// only comments\n// nothing else\n")
            self.assertIsNone(load_json_with_comments(p))

    def test_missing_file(self):
        self.assertIsNone(load_json_with_comments("/nonexistent/path.json"))


class TestSaveJson(unittest.TestCase):

    def test_saves_and_loads(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            save_json(p, {"key": [1, 2, 3]})
            self.assertTrue(p.exists())
            data = json.loads(p.read_text())
            self.assertEqual(data, {"key": [1, 2, 3]})

    def test_creates_parent_dirs(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "sub" / "dir" / "out.json"
            save_json(p, {"a": 1})
            self.assertTrue(p.exists())

    def test_serializes_path(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            save_json(p, {"path": Path("/tmp/test")})
            data = json.loads(p.read_text())
            self.assertEqual(data["path"], "/tmp/test")

    def test_serializes_datetime(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            dt = datetime(2026, 4, 5, 12, 0, 0)
            save_json(p, {"ts": dt})
            data = json.loads(p.read_text())
            self.assertEqual(data["ts"], "2026-04-05T12:00:00")

    def test_serializes_unknown_type(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            save_json(p, {"items": {1, 2, 3}})
            data = json.loads(p.read_text())
            # set → str fallback
            self.assertIsInstance(data["items"], str)

    def test_pretty_printed(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            save_json(p, {"a": 1})
            text = p.read_text()
            self.assertIn("\n", text)
            self.assertIn("  ", text)


if __name__ == "__main__":
    unittest.main()
