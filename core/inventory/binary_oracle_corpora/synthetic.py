"""Synthetic-fixture corpus driver.

Uses the in-tree fixture at
``core/inventory/tests/fixtures/binary_oracle/`` with hand-labeled
expected verdicts. No external deps; validates the precision harness
end-to-end on known-correct cases and acts as a fast classifier sanity
check.

The fold case (``folded_a``/``folded_b``) checks the actual binary
to see if both symbols share the same address (i.e. the linker's ICF
pass actually merged them). This is more robust than checking the
Makefile's ICF-mode flag, which only tests linker capability — some
linker versions report ICF support but don't fold all eligible pairs.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal

from ..binary_oracle import Classification

FIXTURE_DIR = (Path(__file__).resolve().parents[1] / "tests" / "fixtures"
               / "binary_oracle")


def _symbols_share_address(binary: Path, name_a: str, name_b: str) -> bool:
    """Check whether two symbols share the same address in the binary."""
    proc = subprocess.run(
        ["nm", str(binary)], capture_output=True, text=True)
    if proc.returncode != 0:
        return False
    addrs: Dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            addrs[parts[2]] = parts[0]
    addr_a = addrs.get(name_a)
    addr_b = addrs.get(name_b)
    return addr_a is not None and addr_a == addr_b


@dataclass
class _SyntheticDriver:
    name: str = "synthetic"
    description: str = (
        "In-tree fixture (8 functions, hand-labeled verdicts) — fast "
        "classifier sanity check, no external deps.")
    mode: Literal["synthetic"] = "synthetic"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        subprocess.run(["make", "-s", "demo"], cwd=FIXTURE_DIR, check=True)
        binary = FIXTURE_DIR / "demo"
        folded_verdict: Classification = (
            "folded" if _symbols_share_address(binary, "folded_a", "folded_b")
            else "symbol_present"
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
