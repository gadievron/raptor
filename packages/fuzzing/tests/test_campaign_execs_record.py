"""Strategy-outcome records carry the campaign's real exec count.

Both ``store_fuzzing_strategy_outcome`` call sites previously
hardcoded ``execs=0``, so cross-run strategy memory could never weigh
throughput — a strategy that ran millions of execs finding nothing
and one that barely executed looked identical.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_FUZZING = REPO_ROOT / "raptor_fuzzing.py"


class _FakeRunner:
    def __init__(self, stats):
        self._stats = stats

    def get_stats(self):
        return self._stats


class CampaignExecsTests(unittest.TestCase):

    def _campaign_execs(self):
        import sys
        sys.path.insert(0, str(REPO_ROOT))
        try:
            from raptor_fuzzing import _campaign_execs
        finally:
            sys.path.remove(str(REPO_ROOT))
        return _campaign_execs

    def test_reads_execs_done(self):
        fn = self._campaign_execs()
        self.assertEqual(fn(_FakeRunner({"execs_done": "123456"})), 123456)

    def test_absent_or_junk_degrade_to_zero(self):
        fn = self._campaign_execs()
        self.assertEqual(fn(_FakeRunner({})), 0)
        self.assertEqual(fn(_FakeRunner({"execs_done": "N/A"})), 0)

    def test_no_outcome_record_hardcodes_zero_execs(self):
        """Every store_fuzzing_strategy_outcome call passes a computed
        execs value, never the literal 0."""
        tree = ast.parse(RAPTOR_FUZZING.read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "store_fuzzing_strategy_outcome"):
                continue
            for kw in node.keywords:
                if (kw.arg == "execs"
                        and isinstance(kw.value, ast.Constant)):
                    offenders.append(node.lineno)
        self.assertEqual(
            offenders, [],
            "store_fuzzing_strategy_outcome with a constant execs at "
            f"line(s) {offenders} — strategy memory needs the real "
            "campaign throughput",
        )


if __name__ == "__main__":
    unittest.main()
