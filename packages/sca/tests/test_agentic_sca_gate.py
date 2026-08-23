"""The mechanical SCA phase must not run when --sca requests the deep phase.

With --sca, dependency findings used to be produced twice (the always-on
mechanical subprocess phase plus the opt-in deep run_sca phase) and both
totals were added into total_findings, double-counting dependency vulns
and feeding them into the pipeline via two channels.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from raptor_agentic import _should_run_mechanical_sca


class TestMechanicalScaGate(unittest.TestCase):

    def test_runs_when_agent_present_and_no_deep_sca(self):
        self.assertTrue(_should_run_mechanical_sca("/path/to/agent", False))

    def test_skipped_when_deep_sca_requested(self):
        # Deep --sca analyses the same dependency set; running both
        # would double-count dependency findings.
        self.assertFalse(_should_run_mechanical_sca("/path/to/agent", True))

    def test_skipped_when_agent_missing(self):
        self.assertFalse(_should_run_mechanical_sca(None, False))
        self.assertFalse(_should_run_mechanical_sca(None, True))


if __name__ == "__main__":
    unittest.main()
