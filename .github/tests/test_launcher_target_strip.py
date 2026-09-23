"""bin/raptor's TARGET control-strip covers the full control class.

The prompt-building strip used ``tr -d '\\000-\\010\\012-\\037'``,
keeping TAB (\\011) and DEL (\\177) while the caller-dir gate one
screen below refuses the full ``[[:cntrl:]]`` class — an
inconsistency, not a bypass, but the two lanes classify the same
byte class and must agree. The test runs the launcher's own strip
line verbatim, so a regressed range fails here.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"


class TestTargetControlStrip(unittest.TestCase):
    def _strip_line(self) -> str:
        for line in _LAUNCHER.read_text(encoding="utf-8").splitlines():
            if line.startswith("_target_clean=$(printf"):
                return line
        raise AssertionError("TARGET strip line not found in bin/raptor")

    def test_strip_covers_full_c0_range_and_del(self):
        line = self._strip_line()
        # Byte-level behavioural pin of the launcher's own line: TAB,
        # DEL, ESC, and newline all stripped; printable text kept.
        script = (
            "TARGET=$'a\\tb\\x7fc\\x1bd\\ne'\n"
            f"{line}\n"
            "printf '%s' \"$_target_clean\"\n"
        )
        out = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            timeout=30, check=True,
        )
        self.assertEqual(out.stdout, "abcde")

    def test_range_spelling_matches_cntrl_class(self):
        line = self._strip_line()
        m = re.search(r"tr -d '([^']+)'", line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "\\000-\\037\\177")


if __name__ == "__main__":
    unittest.main()
