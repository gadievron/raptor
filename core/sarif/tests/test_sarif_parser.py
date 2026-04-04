#!/usr/bin/env python3
"""Tests for SARIF parser reliability fixes."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


class TestSarifSizeGuard(unittest.TestCase):
    """Test that oversized SARIF files are rejected."""

    def test_rejects_file_over_100mib(self):
        """Size guard rejects files exceeding 100 MiB."""
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "big.sarif"
            path.write_text('{"runs": []}')

            original_stat = path.stat
            call_count = [0]

            def fake_stat(self_path, **kwargs):
                # Only fake the size check (second stat call), not exists()
                call_count[0] += 1
                real = original_stat(**kwargs)
                if call_count[0] >= 2:
                    mock_result = MagicMock()
                    mock_result.st_size = 200 * 1024 * 1024
                    mock_result.st_mode = real.st_mode
                    return mock_result
                return real

            from unittest.mock import patch
            with patch.object(type(path), 'stat', fake_stat):
                result = parse_sarif_findings(path)

            self.assertEqual(result, [])

    def test_accepts_normal_file(self):
        """Normal SARIF files are parsed correctly."""
        from core.sarif.parser import parse_sarif_findings

        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "test finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.c"},
                            "region": {"startLine": 1}
                        }
                    }],
                    "level": "error"
                }]
            }]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "normal.sarif"
            path.write_text(json.dumps(sarif_data))

            result = parse_sarif_findings(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["rule_id"], "test-rule")

    def test_rejects_nonexistent_file(self):
        from core.sarif.parser import parse_sarif_findings

        result = parse_sarif_findings(Path("/nonexistent/file.sarif"))
        self.assertEqual(result, [])

    def test_rejects_invalid_json(self):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.sarif"
            path.write_text("not json{{{")

            result = parse_sarif_findings(path)
            self.assertEqual(result, [])


class TestLoadSarif(unittest.TestCase):
    """Test load_sarif — the single I/O entry point for SARIF files."""

    def test_returns_dict_for_valid_file(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "valid.sarif"
            path.write_text('{"version": "2.1.0", "runs": []}')

            result = load_sarif(path)
            self.assertIsInstance(result, dict)
            self.assertEqual(result["version"], "2.1.0")

    def test_returns_none_for_nonexistent(self):
        from core.sarif.parser import load_sarif

        self.assertIsNone(load_sarif(Path("/nonexistent.sarif")))

    def test_returns_none_for_invalid_json(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.sarif"
            path.write_text("{broken")

            self.assertIsNone(load_sarif(path))

    def test_returns_none_for_non_object(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "array.sarif"
            path.write_text('[1, 2, 3]')

            self.assertIsNone(load_sarif(path))


class TestMergeSarif(unittest.TestCase):
    """Test merge_sarif — combines multiple SARIF files."""

    def test_merges_runs(self):
        from core.sarif.parser import merge_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.sarif"
            p2 = Path(tmpdir) / "b.sarif"
            p1.write_text(json.dumps({"runs": [{"results": [{"ruleId": "r1"}]}]}))
            p2.write_text(json.dumps({"runs": [{"results": [{"ruleId": "r2"}]}]}))

            merged = merge_sarif([str(p1), str(p2)])
            self.assertEqual(len(merged["runs"]), 2)

    def test_skips_invalid_files(self):
        from core.sarif.parser import merge_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            good = Path(tmpdir) / "good.sarif"
            good.write_text(json.dumps({"runs": [{"results": []}]}))

            merged = merge_sarif([str(good), "/nonexistent.sarif"])
            self.assertEqual(len(merged["runs"]), 1)

    def test_empty_input(self):
        from core.sarif.parser import merge_sarif

        merged = merge_sarif([])
        self.assertEqual(merged["runs"], [])


class TestSarifHelpers(unittest.TestCase):
    """Test get_tool_name and get_rules helpers."""

    def test_get_tool_name(self):
        from core.sarif.parser import get_tool_name

        run = {"tool": {"driver": {"name": "Semgrep OSS"}}}
        self.assertEqual(get_tool_name(run), "Semgrep OSS")

    def test_get_tool_name_missing(self):
        from core.sarif.parser import get_tool_name

        self.assertEqual(get_tool_name({}), "unknown")

    def test_get_rules(self):
        from core.sarif.parser import get_rules

        run = {"tool": {"driver": {"rules": [
            {"id": "rule-1", "shortDescription": {"text": "test"}},
            {"id": "rule-2"},
        ]}}}
        rules = get_rules(run)
        self.assertEqual(len(rules), 2)
        self.assertIn("rule-1", rules)
        self.assertIn("rule-2", rules)

    def test_get_rules_empty(self):
        from core.sarif.parser import get_rules

        self.assertEqual(get_rules({}), {})

    def test_get_rules_skips_no_id(self):
        from core.sarif.parser import get_rules

        run = {"tool": {"driver": {"rules": [
            {"id": "valid"},
            {"shortDescription": {"text": "no id"}},
        ]}}}
        rules = get_rules(run)
        self.assertEqual(len(rules), 1)
        self.assertIn("valid", rules)


if __name__ == "__main__":
    unittest.main()
