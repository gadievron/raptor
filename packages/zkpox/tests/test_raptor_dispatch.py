"""Tests for the raptor.py 'zkpox' mode dispatch (ZKPoX Tier 2/3 reland).

The integration adds `mode_zkpox()` to raptor.py and wires it into the
mode-dispatch sites. These tests pin those wire-ups so a future refactor
can't silently drop one of them.

UPSTREAM IMPACT TESTED:
- mode_zkpox function (the actual dispatcher)
- real-dispatch mode_handlers dict (controls `python3 raptor.py zkpox`)
- show_mode_help special-mode handlers (controls `python3 raptor.py help zkpox`)
- all_modes set (so `help zkpox` is not "Unknown mode")
- _HELP_EPILOG (controls `python3 raptor.py --help` output)
- lifecycle helper usage (project/output-dir handling)
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

    def test_mode_zkpox_uses_lifecycle_helper(self):
        """mode_zkpox should delegate to _run_with_lifecycle, not bare
        subprocess — consistent with sibling modes (scan, agentic, codeql)."""
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


class TestZkpoxProvingStackGuard(unittest.TestCase):
    """The Tier 2/3 proving-stack guard must live in the subcommand
    handlers, not in main() — so --help and the dependency-free tiers
    stay usable on hosts without the SP1 toolchain."""

    @classmethod
    def setUpClass(cls):
        cls.src = (Path(__file__).parents[3] / "raptor_zkpox.py").read_text()

    def test_main_does_not_call_require_proving_stack(self):
        """main() must not guard eagerly — that broke --help on bare hosts."""
        match = re.search(
            r"def main\(.*?\)(.*?)(?=\n(?:def |if __name__))",
            self.src,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "main() not found")
        self.assertNotIn("require_proving_stack", match.group(1),
                         "main() must not call require_proving_stack eagerly")

    def test_no_stale_zkpox_require_call(self):
        """The pre-reland `zkpox.require()` (no such symbol) must be gone."""
        self.assertNotIn("zkpox.require()", self.src,
                         "zkpox.require() is not a real symbol; the guard is "
                         "zkpox.require_proving_stack()")

    def test_prove_and_verify_guard_proving_stack(self):
        """cmd_prove and cmd_verify must each call require_proving_stack."""
        for fn in ("cmd_prove", "cmd_verify"):
            with self.subTest(fn=fn):
                match = re.search(
                    rf"def {fn}\(.*?\)(.*?)(?=\ndef )",
                    self.src,
                    re.DOTALL,
                )
                self.assertIsNotNone(match, f"{fn} not found")
                self.assertIn("require_proving_stack", match.group(1),
                              f"{fn} must guard the Tier 2/3 proving stack")


if __name__ == "__main__":
    unittest.main()
