"""Tests for FEAT-R-006: raptor.py 'openant' mode dispatch.

The integration adds `mode_openant()` to raptor.py and wires it into 4
sites. These tests pin those wire-ups so a future refactor can't silently
drop one of them.

UPSTREAM IMPACT TESTED:
- mode_handlers dict (controls `python3 raptor.py openant`)
- mode_scripts dict (controls `python3 raptor.py help openant`)
- _HELP_EPILOG (controls `python3 raptor.py --help` output)
- mode_openant function (the actual dispatcher)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # raptor-integration root


class TestFeatR006OpenantModeDispatch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.raptor_py = Path(__file__).parents[3] / "raptor.py"
        cls.raptor_src = cls.raptor_py.read_text()

    def test_mode_openant_function_exists(self):
        """The function `mode_openant(args)` must exist in raptor.py."""
        self.assertIn("def mode_openant(args:", self.raptor_src,
                      "raptor.py must define mode_openant(args)")

    def test_mode_handlers_dict_includes_openant(self):
        """`mode_handlers = { ..., 'openant': mode_openant, ... }`"""
        self.assertIn("'openant': mode_openant", self.raptor_src,
                      "mode_handlers must route 'openant' → mode_openant")

    def test_mode_scripts_dict_includes_openant(self):
        """show_mode_help() must know about openant."""
        self.assertIn("'openant': script_root / \"raptor_openant.py\"",
                       self.raptor_src,
                       "mode_scripts in show_mode_help must include openant")

    def test_help_epilog_lists_openant(self):
        """`python3 raptor.py --help` must mention openant."""
        # The epilog has a line like "openant     - OpenAnt..."
        self.assertRegex(
            self.raptor_src,
            r"openant\s+- OpenAnt",
            "_HELP_EPILOG must list openant as an available mode",
        )

    def test_mode_openant_uses_lifecycle_helper(self):
        """mode_openant should delegate to _run_with_lifecycle, not bare
        subprocess — consistent with sibling modes (scan, agentic, codeql)."""
        # Find mode_openant body and check it calls _run_with_lifecycle
        import re
        match = re.search(
            r"def mode_openant\(.*?\)(.*?)(?=\ndef |\Z)",
            self.raptor_src,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "mode_openant function not found")
        body = match.group(1)
        self.assertIn("_run_with_lifecycle", body,
                      "mode_openant must use _run_with_lifecycle for "
                      "consistent project/output-dir handling")
        self.assertIn("\"openant\"", body,
                      "mode_openant must pass 'openant' as the command name "
                      "(matters for run-metadata classification — BUG-R-009)")


class TestFeatR005OpenantFlagsInAgentic(unittest.TestCase):
    """raptor_agentic.py must declare the 5 OpenAnt flags."""

    @classmethod
    def setUpClass(cls):
        cls.agentic_py = Path(__file__).parents[3] / "raptor_agentic.py"
        cls.src = cls.agentic_py.read_text()

    def test_all_5_openant_flags_declared(self):
        for flag in ["--openant", "--openant-only", "--openant-core",
                     "--openant-model", "--openant-level"]:
            with self.subTest(flag=flag):
                self.assertIn(flag, self.src,
                              f"raptor_agentic.py must declare {flag}")

    def test_phase1b_block_present(self):
        """Phase 1b block runs OpenAnt scan + dedup + merge."""
        self.assertIn("PHASE 1b: OPENANT SEMANTIC SCAN", self.src,
                      "Phase 1b OpenAnt block must be present")
        self.assertIn("openant_extra_findings", self.src,
                      "openant_extra_findings variable must be populated")
        self.assertIn("deduplicate_with_sarif", self.src,
                      "Phase 1b must dedup against SARIF findings")

    def test_openant_only_skips_scanners(self):
        """--openant-only must turn off Semgrep and CodeQL."""
        self.assertIn("openant_only", self.src)
        # Find lines that gate run_semgrep and run_codeql on openant_only
        self.assertIn("not _openant_only", self.src,
                      "run_semgrep and run_codeql must be gated by "
                      "'and not _openant_only'")


if __name__ == "__main__":
    unittest.main()
