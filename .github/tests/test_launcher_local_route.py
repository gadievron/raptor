"""bin/raptor _raptor_local_route command list must stay in sync with raptor.py.

The local route dispatches analysis commands to ``python3 raptor.py`` when
claude is absent or ``RAPTOR_NO_CLAUDE`` is set.  Its command list is a curated
subset of raptor.py's ``mode_handlers`` — deliberately excluding modes that
need LLM credentials or are utility-only (describe, doctor, frida).

If a mode is added to raptor.py, this test forces a conscious decision:
add it to _raptor_local_route (local-capable) or to _EXCLUDED_FROM_LOCAL
(needs credentials / utility-only).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

_EXCLUDED_FROM_LOCAL = {"describe", "doctor", "frida"}


def _local_route_commands() -> set[str]:
    text = (_REPO / "bin" / "raptor").read_text(encoding="utf-8")
    m = re.search(
        r"_raptor_local_route\(\)\s*\{.*?case\s+\"\$\{1:-\}\"\s+in"
        r"\s+([a-z|]+)\)",
        text, re.DOTALL,
    )
    if not m:
        raise AssertionError("could not find _raptor_local_route case pattern")
    return set(m.group(1).split("|"))


def _raptor_py_modes() -> set[str]:
    text = (_REPO / "raptor.py").read_text(encoding="utf-8")
    block_start = text.index("# Route to appropriate mode")
    block = text[block_start:text.index("if mode not in mode_handlers", block_start)]
    return set(re.findall(r"'(\w+)':", block))


class TestLocalRouteSync(unittest.TestCase):

    def test_local_route_is_subset_of_raptor_py_modes(self):
        local = _local_route_commands()
        modes = _raptor_py_modes()
        extra = local - modes
        self.assertFalse(extra,
            f"_raptor_local_route lists commands not in raptor.py mode_handlers: {extra}")

    def test_every_mode_is_either_local_or_excluded(self):
        local = _local_route_commands()
        modes = _raptor_py_modes()
        unaccounted = modes - local - _EXCLUDED_FROM_LOCAL
        self.assertFalse(unaccounted,
            f"raptor.py mode(s) {unaccounted} not in _raptor_local_route and not in "
            f"_EXCLUDED_FROM_LOCAL — add to one or the other")

    def test_excluded_modes_actually_exist(self):
        modes = _raptor_py_modes()
        phantom = _EXCLUDED_FROM_LOCAL - modes
        self.assertFalse(phantom,
            f"_EXCLUDED_FROM_LOCAL names modes not in raptor.py: {phantom} — "
            f"remove stale entries")


if __name__ == "__main__":
    unittest.main()
