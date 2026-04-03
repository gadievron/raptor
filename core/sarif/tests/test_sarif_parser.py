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


if __name__ == "__main__":
    unittest.main()
