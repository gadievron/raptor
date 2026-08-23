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
            target = Path(d) / "target"
            save_json(p, {"path": target})
            data = json.loads(p.read_text())
            self.assertEqual(data["path"], str(target))

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


class TestOrjsonBackend(unittest.TestCase):
    """Verify load/save work with both stdlib json and orjson backends."""

    def test_load_roundtrip_stdlib(self):
        import core.json.utils as u
        saved = u._orjson
        try:
            u._orjson = None
            with TemporaryDirectory() as d:
                p = Path(d) / "data.json"
                p.write_text('{"a": 1, "b": [2, 3]}')
                self.assertEqual(load_json(p), {"a": 1, "b": [2, 3]})
        finally:
            u._orjson = saved

    def test_save_roundtrip_stdlib(self):
        import core.json.utils as u
        saved = u._orjson
        try:
            u._orjson = None
            with TemporaryDirectory() as d:
                p = Path(d) / "out.json"
                save_json(p, {"x": 1, "path": Path("/tmp")})
                result = json.loads(p.read_text())
                self.assertEqual(result["x"], 1)
                self.assertEqual(result["path"], "/tmp")
        finally:
            u._orjson = saved

    def test_load_roundtrip_orjson(self):
        import core.json.utils as u
        if u._orjson is None:
            self.skipTest("orjson not installed")
        with TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"a": 1, "b": [2, 3]}')
            self.assertEqual(load_json(p), {"a": 1, "b": [2, 3]})

    def test_save_roundtrip_orjson(self):
        import core.json.utils as u
        if u._orjson is None:
            self.skipTest("orjson not installed")
        with TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            save_json(p, {"x": 1, "path": Path("/tmp")})
            result = json.loads(p.read_text())
            self.assertEqual(result["x"], 1)
            self.assertEqual(result["path"], "/tmp")

    def test_non_finite_rejected_both_backends(self):
        import core.json.utils as u
        for backend_name, override in [("stdlib", None), ("orjson", u._orjson)]:
            saved = u._orjson
            try:
                u._orjson = override
                with TemporaryDirectory() as d:
                    p = Path(d) / "nan.json"
                    p.write_text('{"val": NaN}')
                    result = load_json(p)
                    self.assertIsNone(result, f"NaN should be rejected ({backend_name})")
            finally:
                u._orjson = saved

    def test_allow_non_finite_falls_back_to_stdlib(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "nan.json"
            p.write_text('{"val": NaN}')
            result = load_json(p, allow_non_finite=True)
            self.assertIsNotNone(result)

    def test_save_rejects_non_finite_floats_both_backends(self):
        """NaN/Infinity must raise ValueError on BOTH encoder paths.
        The stdlib branch already had allow_nan=False; orjson would
        silently serialise them as null — behaviour depended on which
        library was installed."""
        import core.json.utils as u
        payloads = [
            {"val": float("nan")},
            {"val": float("inf")},
            {"val": float("-inf")},
            {"nested": [1, {"deep": (float("nan"),)}]},
            {float("inf"): "non-finite key"},
        ]
        backends = [("stdlib", None)]
        if u._orjson is not None:
            backends.append(("orjson", u._orjson))
        for backend_name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                with TemporaryDirectory() as d:
                    for i, payload in enumerate(payloads):
                        p = Path(d) / f"bad-{i}.json"
                        with self.assertRaises(
                            ValueError,
                            msg=f"{backend_name}: {payload!r}",
                        ):
                            save_json(p, payload)
                        self.assertFalse(
                            p.exists(),
                            f"{backend_name}: no partial file on reject",
                        )
            finally:
                u._orjson = saved

    def test_save_accepts_finite_floats_both_backends(self):
        import core.json.utils as u
        for override in [None, u._orjson]:
            saved = u._orjson
            try:
                u._orjson = override
                with TemporaryDirectory() as d:
                    p = Path(d) / "ok.json"
                    save_json(p, {"val": 1.5, "list": [0.0, -2.25]})
                    self.assertEqual(
                        json.loads(p.read_text()),
                        {"val": 1.5, "list": [0.0, -2.25]},
                    )
            finally:
                u._orjson = saved

    def test_save_datetime_both_backends(self):
        import core.json.utils as u
        dt = datetime(2026, 1, 15, 12, 0, 0)
        for override in [None, u._orjson]:
            saved = u._orjson
            try:
                u._orjson = override
                with TemporaryDirectory() as d:
                    p = Path(d) / "dt.json"
                    save_json(p, {"ts": dt})
                    result = json.loads(p.read_text())
                    self.assertIn("2026", result["ts"])
            finally:
                u._orjson = saved


class TestLoads(unittest.TestCase):
    """Public string-level loads: budget gate, backends, hardening."""

    def _both_backends(self):
        import core.json.utils as u
        backends = [("stdlib", None)]
        if u._orjson is not None:
            backends.append(("orjson", u._orjson))
        return u, backends

    def test_parses_str_and_bytes_both_backends(self):
        from core.json import loads
        u, backends = self._both_backends()
        for name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                self.assertEqual(loads('{"a": 1}'), {"a": 1}, name)
                self.assertEqual(loads(b'{"a": 1}'), {"a": 1}, name)
            finally:
                u._orjson = saved

    def test_bom_tolerated_both_backends(self):
        from core.json import loads
        u, backends = self._both_backends()
        for name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                self.assertEqual(loads("\ufeff" + '{"a": 1}'), {"a": 1}, name)
                self.assertEqual(
                    loads(b'\xef\xbb\xbf{"a": 1}'), {"a": 1}, name)
            finally:
                u._orjson = saved

    def test_budget_breach_raises_and_warns(self):
        from core.json import JsonBudgetExceededError, loads
        payload = '{"a": "' + "x" * 64 + '"}'
        with self.assertLogs("core.json.utils", level="WARNING") as cm:
            with self.assertRaises(JsonBudgetExceededError):
                loads(payload, max_bytes=16)
        self.assertTrue(
            any("refusing to parse" in line for line in cm.output))
        # The subclass contract: plain ValueError handlers catch it.
        self.assertTrue(issubclass(JsonBudgetExceededError, ValueError))

    def test_budget_gate_runs_before_parse(self):
        from core.json import JsonBudgetExceededError, loads
        # Malformed AND oversize: the budget error proves the gate
        # fired before any parse attempt.
        with self.assertRaises(JsonBudgetExceededError):
            loads("{" * 64, max_bytes=16)

    def test_under_budget_parses(self):
        from core.json import loads
        self.assertEqual(loads('{"a": 1}', max_bytes=8), {"a": 1})

    def test_non_finite_rejected_both_backends(self):
        from core.json import loads
        u, backends = self._both_backends()
        for name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                with self.assertRaises(ValueError, msg=name):
                    loads('{"v": NaN}')
            finally:
                u._orjson = saved

    def test_allow_non_finite_falls_back_to_stdlib(self):
        import math

        from core.json import loads
        result = loads('{"v": NaN}', allow_non_finite=True)
        self.assertTrue(math.isnan(result["v"]))

    def test_malformed_raises(self):
        from core.json import loads
        with self.assertRaises(ValueError):
            loads("{not json")

    def test_budget_error_shared_with_bounded_helpers(self):
        import core.json.bounded as b
        from core.json import JsonBudgetExceededError
        self.assertIs(b.JsonBudgetExceededError, JsonBudgetExceededError)


class TestOrjsonBigIntDivergence(unittest.TestCase):
    """Pin the documented big-int divergence between the two backends.

    orjson parses integer literals outside ``[-2**63, 2**64 - 1]`` as
    lossy floats; stdlib json returns exact arbitrary-precision ints.
    There is no cheap guard (orjson raises nothing — see the
    ``_loads`` docstring), so the divergence is pinned here: if a
    future orjson release changes this behaviour, or someone tightens
    ``_loads``, these assertions flag it for a deliberate decision.
    """

    U64_MAX = 2**64 - 1
    I64_MIN = -(2**63)

    def _load(self, d: str, literal: str):
        # Resolve load_json through the module object at call time —
        # the module-level import would go stale when a sibling test
        # (test_f046_lazy_reexports) resets sys.modules, making the
        # _orjson override in these tests a no-op on the old module.
        import core.json.utils as u
        p = Path(d) / "n.json"
        p.write_text(f'{{"n": {literal}}}')
        data = u.load_json(p)
        assert data is not None
        return data["n"]

    def test_orjson_coerces_out_of_range_ints_to_float(self):
        import core.json.utils as u
        if u._orjson is None:
            self.skipTest("orjson not installed")
        with TemporaryDirectory() as d:
            for literal in (
                str(self.U64_MAX + 1),
                str(self.I64_MIN - 1),
                str(2**100),
            ):
                val = self._load(d, literal)
                self.assertIsInstance(val, float, literal)
                self.assertEqual(val, float(int(literal)), literal)

    def test_orjson_exact_inside_64_bit_range(self):
        import core.json.utils as u
        if u._orjson is None:
            self.skipTest("orjson not installed")
        with TemporaryDirectory() as d:
            for n in (self.U64_MAX, self.I64_MIN, 0, 2**63 - 1):
                val = self._load(d, str(n))
                self.assertIsInstance(val, int, str(n))
                self.assertEqual(val, n)

    def test_stdlib_exact_at_any_width(self):
        import core.json.utils as u
        saved = u._orjson
        try:
            u._orjson = None
            with TemporaryDirectory() as d:
                for n in (self.U64_MAX + 1, self.I64_MIN - 1, 2**100):
                    val = self._load(d, str(n))
                    self.assertIsInstance(val, int, str(n))
                    self.assertEqual(val, n)
        finally:
            u._orjson = saved

    def test_bounded_helpers_stay_stdlib_exact(self):
        """core.json.bounded is the documented escape hatch for
        big-int-identity callers — it must never grow the fast path."""
        from core.json.bounded import load_json_bounded, loads_bounded
        n = 2**100
        self.assertEqual(loads_bounded(f'{{"n": {n}}}', max_bytes=64)["n"], n)
        with TemporaryDirectory() as d:
            p = Path(d) / "n.json"
            p.write_text(f'{{"n": {n}}}')
            self.assertEqual(
                load_json_bounded(p, max_bytes=64)["n"], n)


class TestLoadJsonMaxBytes(unittest.TestCase):
    """Byte budget: st_size gate BEFORE any read."""

    def test_under_budget_parses(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"key": "value"}')
            self.assertEqual(
                load_json(p, max_bytes=1024), {"key": "value"})

    def test_exact_size_parses(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"a": 1}')
            size = p.stat().st_size
            self.assertEqual(load_json(p, max_bytes=size), {"a": 1})

    def test_oversize_returns_none(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "big.json"
            p.write_text('{"pad": "' + "x" * 100 + '"}')
            self.assertIsNone(load_json(p, max_bytes=10))

    def test_oversize_strict_raises(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "big.json"
            p.write_text('{"pad": "' + "x" * 100 + '"}')
            with self.assertRaises(ValueError):
                load_json(p, strict=True, max_bytes=10)

    def test_oversize_never_read(self):
        # The gate must fire on stat alone — a FIFO would block any
        # read attempt forever, so returning promptly proves no read
        # happened. Instead of a FIFO (fragile in CI), assert on the
        # cheaper contract: a file of valid JSON over budget is
        # rejected even though a read+parse would have succeeded.
        with TemporaryDirectory() as d:
            p = Path(d) / "valid-but-big.json"
            p.write_text(json.dumps({"k": "v" * 1000}))
            self.assertIsNone(load_json(p, max_bytes=100))

    def test_default_unbounded_unchanged(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "big.json"
            p.write_text(json.dumps({"k": "v" * 100_000}))
            self.assertEqual(load_json(p)["k"], "v" * 100_000)

    def test_missing_file_still_none(self):
        self.assertIsNone(
            load_json("/nonexistent/path.json", max_bytes=10))
        self.assertIsNone(
            load_json("/nonexistent/path.json", strict=True, max_bytes=10))


if __name__ == "__main__":
    unittest.main()
