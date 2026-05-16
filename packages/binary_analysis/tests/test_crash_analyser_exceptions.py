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

    def test_no_broad_except_exception(self):
        """No broad except Exception: — all should be specific types."""
        source = _CRASH_ANALYSER.read_text()
        broad_excepts = re.findall(r'^\s*except Exception\s*:', source, re.MULTILINE)
        self.assertEqual(len(broad_excepts), 0,
                        f"Found {len(broad_excepts)} broad except Exception: clauses "
                        f"(should use specific types like OSError, subprocess.SubprocessError)")


if __name__ == "__main__":
    unittest.main()
