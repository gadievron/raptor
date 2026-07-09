#!/usr/bin/env python3
"""Tests for crash analyser exception handling."""

import re
import unittest
from pathlib import Path

# Anchor to this test file rather than the runtime CWD; pytest can be
# invoked from anywhere (IDE, sub-package run, tooling that chdir's).
# parents[2] = packages/binary_analysis/.
_CRASH_ANALYSER = (
    Path(__file__).resolve().parents[1] / "crash_analyser.py"
)


class TestCrashAnalyserExceptionHandling(unittest.TestCase):
    """Test that crash analyser uses specific exception types."""

    def test_no_bare_except(self):
        """No bare except: clauses in crash_analyser.py."""
        source = _CRASH_ANALYSER.read_text()
        bare_excepts = re.findall(r'^\s*except\s*:', source, re.MULTILINE)
        self.assertEqual(len(bare_excepts), 0,
                        f"Found {len(bare_excepts)} bare except: clauses")

    def test_broad_except_exception_count_stable(self):
        """Track broad except Exception: count so new ones are flagged."""
        source = _CRASH_ANALYSER.read_text()
        broad_excepts = re.findall(r'^\s*except Exception\b', source, re.MULTILINE)
        self.assertLessEqual(len(broad_excepts), 15,
                            f"Found {len(broad_excepts)} broad except Exception: clauses "
                            f"(was 15; new ones should use specific types)")


if __name__ == "__main__":
    unittest.main()
