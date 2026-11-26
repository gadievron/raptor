"""The Semgrep non-timeout failure branch must leave a durable marker.

The timeout branch writes ``.semgrep_timeout`` precisely because absent
``semgrep_*.json`` files are ambiguous — they look indistinguishable
from "scan was disabled". A Semgrep crash (rc=2, OOM-kill, ...) in a
mixed run (CodeQL also running) used to print one stderr line
mid-stream and complete "green" with all Semgrep findings missing and
no artifact recording why. These tests pin the ``.semgrep_failed``
marker write in the generic failure branch and its surfacing at the
completion site (run summary line + run metadata ``extra``).

Source-text assertions, matching ``TimeoutMessageAccuracyTests`` in
``test_phase_timeout.py``: the branch only runs with a live Semgrep
subprocess, so the structural pin is the hermetic form.
"""

from __future__ import annotations

import unittest
from pathlib import Path

# parents[3] climbs:
#   [0] packages/autonomous/tests/
#   [1] packages/autonomous/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_AGENTIC = REPO_ROOT / "raptor_agentic.py"


class SemgrepFailureMarkerTests(unittest.TestCase):

    def _source(self) -> str:
        return RAPTOR_AGENTIC.read_text(encoding="utf-8")

    def test_generic_failure_branch_writes_marker(self) -> None:
        """The ``elif rc != -1`` branch writes ``.semgrep_failed`` with
        the exit code, mirroring the timeout branch's marker."""
        src = self._source()
        branch_at = src.index("elif rc != -1:")
        collect_at = src.index("# ---- Collect CodeQL results ----")
        branch = src[branch_at:collect_at]
        self.assertIn('out_dir / ".semgrep_failed"', branch)
        self.assertIn('"exit_code": rc', branch)

    def test_completion_surfaces_marker(self) -> None:
        """The completion site re-surfaces the marker: a summary line
        the operator reads, and the run metadata ``extra`` record."""
        src = self._source()
        self.assertIn('completion_extra["semgrep_failed"]', src)
        self.assertIn("exclude Semgrep findings", src)


if __name__ == "__main__":
    unittest.main()
