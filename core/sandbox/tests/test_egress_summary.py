"""Tests for core.sandbox.egress_summary."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.sandbox.egress_summary import (
    EGRESS_SUMMARY_FILE,
    finalize_egress_summary,
    summarise_egress,
)


def _write_events(tmp: Path, events: list[dict]) -> None:
    path = tmp / "proxy-events.jsonl"
    path.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )


class TestSummariseEgress(unittest.TestCase):

    def test_no_events_file_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(summarise_egress(Path(td)))

    def test_empty_events_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "proxy-events.jsonl").write_text("", encoding="utf-8")
            self.assertIsNone(summarise_egress(Path(td)))

    def test_allowed_connections_counted(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "pypi.org", "port": 443, "result": "allowed",
                 "bytes_c2u": 100, "bytes_u2c": 200},
                {"host": "pypi.org", "port": 443, "result": "allowed",
                 "bytes_c2u": 50, "bytes_u2c": 300},
            ])
            s = summarise_egress(td)
            self.assertIsNotNone(s)
            self.assertEqual(s["total_connections"], 2)
            self.assertEqual(s["allowed"], 2)
            self.assertEqual(s["denied"], 0)
            self.assertEqual(s["failed"], 0)
            self.assertEqual(s["unique_hosts"], 1)
            self.assertEqual(s["total_bytes_out"], 150)
            self.assertEqual(s["total_bytes_in"], 500)

    def test_denied_connections_counted(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "evil.com", "port": 443, "result": "denied_host",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "pypi.org", "port": 443, "result": "allowed",
                 "bytes_c2u": 10, "bytes_u2c": 20},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["allowed"], 1)
            self.assertEqual(s["denied"], 1)
            self.assertEqual(s["failed"], 0)
            self.assertEqual(s["unique_hosts"], 2)
            host_map = {e["host"]: e for e in s["hosts"]}
            self.assertEqual(host_map["evil.com"]["denied"], 1)
            self.assertIn("denied_host", host_map["evil.com"]["reasons"])

    def test_would_deny_counted_as_denied(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "audit.com", "port": 443, "result": "would_deny_host",
                 "bytes_c2u": 0, "bytes_u2c": 0},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["denied"], 1)
            self.assertEqual(s["failed"], 0)
            host_map = {e["host"]: e for e in s["hosts"]}
            self.assertIn("would_deny_host", host_map["audit.com"]["reasons"])

    def test_infrastructure_failures_counted_separately(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "flaky.com", "port": 443, "result": "dns_failed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "down.com", "port": 443, "result": "upstream_failed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "slow.com", "port": 443, "result": "timed_out",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "bad.com", "port": 443, "result": "bad_request",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "err.com", "port": 443, "result": "handler_error",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "full.com", "port": 443, "result": "refused_capacity",
                 "bytes_c2u": 0, "bytes_u2c": 0},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["denied"], 0)
            self.assertEqual(s["failed"], 6)
            self.assertEqual(s["allowed"], 0)
            self.assertEqual(s["total_connections"], 6)
            host_map = {e["host"]: e for e in s["hosts"]}
            self.assertIn("dns_failed", host_map["flaky.com"]["reasons"])
            self.assertIn("upstream_failed", host_map["down.com"]["reasons"])

    def test_control_plane_events_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "pypi.org", "port": 443, "result": "allowed",
                 "bytes_c2u": 10, "bytes_u2c": 20},
                {"result": "buffer_overflow", "host": None, "port": None},
                {"result": "parser_jail_degraded", "host": None, "port": None},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["total_connections"], 1)

    def test_only_control_plane_events_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"result": "buffer_overflow", "host": None, "port": None},
            ])
            self.assertIsNone(summarise_egress(Path(td)))

    def test_multiple_hosts_sorted(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "zz.com", "port": 443, "result": "allowed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "aa.com", "port": 443, "result": "allowed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["hosts"][0]["host"], "aa.com")
            self.assertEqual(s["hosts"][1]["host"], "zz.com")

    def test_corrupt_lines_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            path = Path(td) / "proxy-events.jsonl"
            path.write_text(
                '{"host":"ok.com","port":443,"result":"allowed","bytes_c2u":0,"bytes_u2c":0}\n'
                'NOT JSON\n'
                '{"host":"ok2.com","port":443,"result":"allowed","bytes_c2u":0,"bytes_u2c":0}\n',
                encoding="utf-8",
            )
            s = summarise_egress(Path(td))
            self.assertEqual(s["total_connections"], 2)

    def test_mixed_denied_and_failed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "ok.com", "port": 443, "result": "allowed",
                 "bytes_c2u": 10, "bytes_u2c": 20},
                {"host": "evil.com", "port": 443, "result": "denied_host",
                 "bytes_c2u": 0, "bytes_u2c": 0},
                {"host": "flaky.com", "port": 443, "result": "dns_failed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
            ])
            s = summarise_egress(td)
            self.assertEqual(s["allowed"], 1)
            self.assertEqual(s["denied"], 1)
            self.assertEqual(s["failed"], 1)
            self.assertEqual(s["total_connections"], 3)


class TestFinalizeEgressSummary(unittest.TestCase):

    def test_writes_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "pypi.org", "port": 443, "result": "allowed",
                 "bytes_c2u": 10, "bytes_u2c": 20},
            ])
            result = finalize_egress_summary(td)
            self.assertIsNotNone(result)
            out = td / EGRESS_SUMMARY_FILE
            self.assertTrue(out.exists())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["total_connections"], 1)
            self.assertEqual(data["failed"], 0)

    def test_no_events_no_file(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            result = finalize_egress_summary(td)
            self.assertIsNone(result)
            self.assertFalse((td / EGRESS_SUMMARY_FILE).exists())

    def test_never_raises(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_events(td, [
                {"host": "x.com", "port": 443, "result": "allowed",
                 "bytes_c2u": 0, "bytes_u2c": 0},
            ])
            with patch("core.sandbox.egress_summary.summarise_egress",
                        side_effect=RuntimeError("boom")):
                result = finalize_egress_summary(td)
            self.assertIsNone(result)

    def test_symlink_not_followed_on_read(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            real = td / "real-events.jsonl"
            real.write_text(
                '{"host":"x.com","port":443,"result":"allowed",'
                '"bytes_c2u":0,"bytes_u2c":0}\n',
                encoding="utf-8",
            )
            link = td / "proxy-events.jsonl"
            link.symlink_to(real)
            self.assertIsNone(summarise_egress(td))


if __name__ == "__main__":
    unittest.main()
