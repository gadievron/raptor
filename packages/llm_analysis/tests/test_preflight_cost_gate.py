"""Tests for the shared pre-flight cost gate.

The gate (catalog load -> scorecard estimate -> print estimate ->
compare cap -> fail_run -> abort) used to be implemented twice: once in
raptor.py and once inline in libexec/raptor-run-lifecycle, and the two
copies had already drifted (stdout vs stderr for the estimate line).
raptor._preflight_cost_gate is now the single implementation, with an
estimate_stream parameter so the lifecycle script can keep its stdout
single-line OUTPUT_DIR= for parsers.
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import raptor  # noqa: E402


class PreflightCostGateTests(unittest.TestCase):

    def _run_gate(self, cost_high: float, cap: float, stream=None) -> bool:
        entry = SimpleNamespace(typical_findings_count=10)
        est = SimpleNamespace(cost_high=cost_high)
        with patch("core.run.target_types.load", return_value=entry), \
             patch("core.run.estimator.estimate_from_scorecard",
                   return_value=est), \
             patch("core.run.estimator.format_estimate",
                   return_value="Estimated cost: $x-$y"), \
             patch.object(raptor, "fail_run") as fail_run:
            fired = raptor._preflight_cost_gate(
                "/tmp/target", cap, Path("/tmp/out"),
                estimate_stream=stream,
            )
        self.fail_run_mock = fail_run
        return fired

    def test_gate_fires_when_estimate_exceeds_cap(self):
        stream = io.StringIO()
        self.assertTrue(self._run_gate(cost_high=100.0, cap=50.0,
                                       stream=stream))
        self.fail_run_mock.assert_called_once()

    def test_gate_passes_when_estimate_within_cap(self):
        stream = io.StringIO()
        self.assertFalse(self._run_gate(cost_high=10.0, cap=50.0,
                                        stream=stream))
        self.fail_run_mock.assert_not_called()

    def test_estimate_line_routed_to_given_stream(self):
        stream = io.StringIO()
        self._run_gate(cost_high=10.0, cap=50.0, stream=stream)
        self.assertIn("Estimated cost", stream.getvalue())


class LifecycleUsesSharedGateTests(unittest.TestCase):
    """The lifecycle script must delegate, not carry its own copy."""

    def test_lifecycle_delegates_to_raptor_gate(self):
        src = (REPO_ROOT / "libexec" / "raptor-run-lifecycle").read_text(
            encoding="utf-8"
        )
        self.assertIn("from raptor import _preflight_cost_gate", src)
        # The drifted inline copy is gone.
        self.assertNotIn("estimate_from_scorecard", src)
        self.assertNotIn("PROVIDER_DEFAULT_MODELS", src)


class SentinelAfterGateTests(unittest.TestCase):
    """OUTPUT_DIR= must print AFTER the failable pre-flight cost gate.

    Callers treat the sentinel as "the run started, write here"; a gate
    refusal after the sentinel hands them a directory belonging to a
    failed run. Pinned at source level for both entry points so the
    ordering cannot silently regress.
    """

    @staticmethod
    def _order(src: str, first: str, second: str) -> None:
        i, j = src.index(first), src.index(second)
        assert i < j, f"{first!r} must appear before {second!r}"

    def test_lifecycle_gate_precedes_sentinel(self):
        src = (REPO_ROOT / "libexec" / "raptor-run-lifecycle").read_text(
            encoding="utf-8"
        )
        self._order(src, "from raptor import _preflight_cost_gate",
                    'print(f"OUTPUT_DIR={out_dir}")')

    def test_raptor_py_gate_precedes_sentinel(self):
        src = (REPO_ROOT / "raptor.py").read_text(encoding="utf-8")
        # Scope to the lifecycle-start block: the gate call site, then
        # the sentinel print.
        self._order(src, "if _preflight_cost_gate(target, max_cost_usd",
                    'print(f"OUTPUT_DIR={out_dir}", flush=True)')

    def test_raptor_py_sentinel_is_last_start_block_line(self):
        """License/start-line informational prints precede the sentinel."""
        src = (REPO_ROOT / "raptor.py").read_text(encoding="utf-8")
        sentinel = src.index('print(f"OUTPUT_DIR={out_dir}", flush=True)')
        for marker in ("detect_target_license", "format_start_line"):
            assert src.index(marker) < sentinel, (
                f"{marker} should print before the OUTPUT_DIR sentinel"
            )


if __name__ == "__main__":
    unittest.main()
