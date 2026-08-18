"""Tests for raptor_fuzzing._clamp_parallel.

The --parallel help text promises a tuning.json ceiling
(max_fuzz_parallel); pre-fix the raw value flowed straight into
range(parallel_jobs), so --parallel 64 started 64 AFL instances
regardless of the configured ceiling.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import raptor_fuzzing


class ClampParallelTests(unittest.TestCase):

    def _with_ceiling(self, ceiling: int, requested: int) -> int:
        fake = SimpleNamespace(max_fuzz_parallel=ceiling)
        with patch("core.tuning.get_tuning", return_value=fake):
            return raptor_fuzzing._clamp_parallel(requested)

    def test_within_ceiling_passes_through(self):
        self.assertEqual(self._with_ceiling(ceiling=4, requested=2), 2)
        self.assertEqual(self._with_ceiling(ceiling=4, requested=4), 4)

    def test_above_ceiling_is_clamped(self):
        self.assertEqual(self._with_ceiling(ceiling=4, requested=64), 4)

    def test_tuning_unavailable_falls_back_to_requested(self):
        with patch("core.tuning.get_tuning",
                   side_effect=RuntimeError("no tuning")):
            self.assertEqual(raptor_fuzzing._clamp_parallel(8), 8)


if __name__ == "__main__":
    unittest.main()
