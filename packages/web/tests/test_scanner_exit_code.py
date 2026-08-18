#!/usr/bin/env python3
"""Exit-code contract for the web scanner CLI.

A completed scan must exit 0 even when vulnerabilities were found: raptor.py's
lifecycle wrapper records any non-zero exit as a failed run, so exiting 1 on
findings would mark every successful vuln-finding scan as status=failed.

Requires bs4 and requests — skipped if missing.
"""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

try:
    import packages.web.scanner as scanner_mod
    HAS_WEB_DEPS = True
except ImportError:
    HAS_WEB_DEPS = False


@unittest.skipUnless(HAS_WEB_DEPS, "bs4/requests not installed")
class TestScannerExitCode(unittest.TestCase):
    """main() exit codes reflect scan completion, not finding count."""

    def _run_main(self, total_vulnerabilities: int) -> int:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "discovery": {"total_pages": 1, "total_parameters": 1},
            "total_vulnerabilities": total_vulnerabilities,
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            argv = ["scanner.py", "--url", "http://example.com",
                    "--out", tmpdir]
            with patch.object(scanner_mod, "WebScanner",
                              return_value=mock_scanner), \
                 patch("packages.llm_analysis.get_client", return_value=None), \
                 patch("sys.argv", argv):
                return scanner_mod.main()

    def test_completed_scan_with_findings_exits_zero(self):
        self.assertEqual(self._run_main(total_vulnerabilities=3), 0)

    def test_completed_scan_without_findings_exits_zero(self):
        self.assertEqual(self._run_main(total_vulnerabilities=0), 0)
