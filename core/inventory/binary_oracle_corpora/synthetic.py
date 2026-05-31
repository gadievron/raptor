"""Synthetic-fixture corpus driver.

Uses the in-tree fixture at
``core/inventory/tests/fixtures/binary_oracle/`` with hand-labeled
expected verdicts. No external deps; validates the precision harness
end-to-end on known-correct cases and acts as a fast classifier sanity
check.

The fold case (``folded_a``/``folded_b``) depends on whether an ICF-
capable linker is available; the driver asks the fixture's Makefile
which mode it built in and adjusts the expected verdict accordingly.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal

from ..binary_oracle import Classification

FIXTURE_DIR = (Path(__file__).resolve().parents[1] / "tests" / "fixtures"
               / "binary_oracle")


@dataclass
class _SyntheticDriver:
    name: str = "synthetic"
    description: str = (
        "In-tree fixture (8 functions, hand-labeled verdicts) — fast "
        "classifier sanity check, no external deps.")
    mode: Literal["synthetic"] = "synthetic"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        # Build the fixture (idempotent — make checks timestamps).
        subprocess.run(["make", "-s", "demo"], cwd=FIXTURE_DIR, check=True)
        binary = FIXTURE_DIR / "demo"
        icf_mode = subprocess.run(
            ["make", "-s", "print-icf-mode"], cwd=FIXTURE_DIR,
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        folded_verdict: Classification = (
            "folded" if icf_mode != "none" else "symbol_present"
        )
        expected: Dict[str, Classification] = {
            "live_called":                "symbol_present",
            "live_address_taken_target":  "symbol_present",
            "inlined_only":               "inlined",
            "inlined_only_user":          "symbol_present",
            "dead_static_unused":         "absent",
            "dead_extern_unused":         "absent",
            "folded_a":                   folded_verdict,
            "folded_b":                   folded_verdict,
            "volatile_call_target":       "symbol_present",
            "indirect_caller":            "symbol_present",
        }
        return {
            "o2_binary":            binary,
            "candidate_functions":  list(expected.keys()),
            "expected":             expected,
        }


driver = _SyntheticDriver()
