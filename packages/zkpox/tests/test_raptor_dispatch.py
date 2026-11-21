"""Tests for the raptor.py 'zkpox' mode dispatch.

Pins the five raptor.py integration sites so a future refactor can't
silently drop one of them.

Ported from Daniel Cuthbert's feat/zkpox-sp1-tier3 reland (70ea7e608).
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # raptor-integration root


class TestZkpoxModeDispatch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.raptor_py = Path(__file__).parents[3] / "raptor.py"
        cls.raptor_src = cls.raptor_py.read_text()

    def test_mode_zkpox_function_exists(self):
        """The function `mode_zkpox(args)` must exist in raptor.py."""
        self.assertIn("def mode_zkpox(args:", self.raptor_src,
                      "raptor.py must define mode_zkpox(args)")

    def test_mode_handlers_dict_includes_zkpox(self):
        """`mode_handlers = { ..., 'zkpox': mode_zkpox, ... }` — must be
        present for BOTH the real-dispatch and show_mode_help dicts."""
        occurrences = self.raptor_src.count("'zkpox': mode_zkpox")
        self.assertGreaterEqual(
            occurrences, 2,
            "both the real-dispatch and show_mode_help mode_handlers dicts "
            "must route 'zkpox' → mode_zkpox",
        )

    def test_all_modes_set_includes_zkpox(self):
        """show_mode_help's all_modes set must list zkpox so
        `python3 raptor.py help zkpox` is not reported Unknown."""
        self.assertRegex(
            self.raptor_src,
            r"all_modes = set\(mode_scripts\.keys\(\)\) \| \{[^}]*'zkpox'[^}]*\}",
            "all_modes must include 'zkpox'",
        )

    def test_help_epilog_lists_zkpox(self):
        """`python3 raptor.py --help` must mention zkpox."""
        self.assertRegex(
            self.raptor_src,
            r"zkpox\s+- Zero-knowledge proof of exploit",
            "_HELP_EPILOG must list zkpox as an available mode",
        )

    def test_mode_zkpox_delegates_prove_to_lifecycle(self):
        """mode_zkpox should delegate prove to _run_with_lifecycle — consistent
        with sibling modes (scan, agentic, codeql)."""
        match = re.search(
            r"def mode_zkpox\(.*?\)(.*?)(?=\ndef |\Z)",
            self.raptor_src,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "mode_zkpox function not found")
        body = match.group(1)
        self.assertIn("_run_with_lifecycle", body,
                      "mode_zkpox must use _run_with_lifecycle for consistent "
                      "project/output-dir handling")
        self.assertIn('"zkpox"', body,
                      "mode_zkpox must pass 'zkpox' as the command name "
                      "(matters for run-metadata classification)")


if __name__ == "__main__":
    unittest.main()
