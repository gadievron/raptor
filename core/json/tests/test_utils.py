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

    def test_inline_trailing_comment(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{\n  "ram": 4096 // override default\n}\n')
            self.assertEqual(load_json_with_comments(p), {"ram": 4096})

    def test_inline_comment_preserves_url_in_string(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{"url": "https://example.com"} // a comment\n')
            result = load_json_with_comments(p)
            self.assertEqual(result["url"], "https://example.com")

    def test_escaped_quote_in_string(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{"msg": "say \\"hello\\""} // note\n')
            result = load_json_with_comments(p)
            self.assertEqual(result["msg"], 'say "hello"')

    def test_escaped_backslash_before_closing_quote(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            # File content: {"p": "C:\\"} // comment
            # JSON value is C:\  (one backslash)
            p.write_text('{"p": "C:\\\\"} // comment\n')
            result = load_json_with_comments(p)
            self.assertEqual(result["p"], "C:\\")

    def test_comment_above_and_inline(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text(
                '// top comment\n'
                '{\n'
                '  // key comment\n'
                '  "a": 1, // inline\n'
                '  "b": 2\n'
                '}\n'
            )
            self.assertEqual(load_json_with_comments(p), {"a": 1, "b": 2})

    def test_hash_full_line_comment(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('# a comment\n{"key": "value"}\n')
            self.assertEqual(load_json_with_comments(p), {"key": "value"})

    def test_hash_inline_comment(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{\n  "ram": 4096 # override\n}\n')
            self.assertEqual(load_json_with_comments(p), {"ram": 4096})

    def test_hash_inside_string_preserved(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{"color": "#fff"}\n')
            result = load_json_with_comments(p)
            self.assertEqual(result["color"], "#fff")

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

    def test_concurrent_threads_same_path_no_torn_writes(self):
        """REGRESSION: two threads in the same process saving the same
        path must not share a tempfile path. Earlier code used a
        deterministic ``.~<name>.tmp`` suffix; both threads opened the
        same path with O_TRUNC, the second clobbering the first's
        partial write and leaving a torn file that fails json.loads.

        With pid+tid in the suffix, each writer has its own tmpfile;
        the final atomic rename is last-writer-wins, but every reader
        sees a fully-formed file.
        """
        import threading as _threading

        with TemporaryDirectory() as d:
            p = Path(d) / "hot.json"
            barrier = _threading.Barrier(8)
            errors: list[BaseException] = []

            def writer(i: int) -> None:
                try:
                    barrier.wait()
                    for n in range(50):
                        save_json(p, {"writer": i, "n": n})
                except BaseException as e:
                    errors.append(e)

            threads = [_threading.Thread(target=writer, args=(i,))
                       for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(errors, [], f"writer raised: {errors}")
            # Whatever the final winner is, the file MUST parse cleanly.
            data = json.loads(p.read_text())
            self.assertIn("writer", data)
            self.assertIn(data["writer"], range(8))


if __name__ == "__main__":
    unittest.main()
