"""SAGE build-reliability memory must record zero-finding runs.

Regression: run_autonomous_workflow early-returned on
total_findings == 0 before reaching store_codeql_build_reliability, so
the "no_findings" outcome branch was dead code and only "success" runs
were ever recorded.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import raptor_codeql


def _make_args(**overrides):
    base = {
        "repo": "/tmp/some-repo",
        "out": None,
        "codeql_cli": None,
        "languages": None,
        "build_command": None,
        "force": False,
        "extended": False,
        "min_files": 1,
        "traced_build": False,
        "scan_only": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class BuildReliabilityOutcomeTests(unittest.TestCase):

    def _run_with_findings(self, total_findings: int) -> MagicMock:
        scan_result = SimpleNamespace(
            success=True, total_findings=total_findings,
        )
        agent = MagicMock()
        agent.run_autonomous_analysis.return_value = scan_result
        store = MagicMock()
        with patch.object(raptor_codeql, "CodeQLAgent", return_value=agent), \
             patch.object(raptor_codeql, "store_codeql_build_reliability",
                          store):
            raptor_codeql.run_autonomous_workflow(_make_args())
        return store

    def test_zero_findings_records_no_findings_outcome(self):
        store = self._run_with_findings(0)
        store.assert_called_once()
        kwargs = store.call_args.kwargs
        self.assertEqual(kwargs["auto_detect_outcome"], "no_findings")
        self.assertEqual(kwargs["analyses_completed"], 0)


if __name__ == "__main__":
    unittest.main()
