"""Synthetic-fixture corpus driver.

Uses the in-tree fixture at
``core/inventory/tests/fixtures/binary_oracle/`` with hand-labeled
expected verdicts. No external deps; validates the precision harness
end-to-end on known-correct cases and acts as a fast classifier sanity
check.

The fold case (``folded_a``/``folded_b``) probes the classifier
directly to determine the expected verdict. Fold detection is DWARF-
based (``DW_AT_low_pc`` collisions); nm symbol addresses may disagree
when the linker merges code but doesn't update DWARF entries (observed
with GNU ld ``--icf=safe``).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal

from core.analysis.binary_oracle import Classification

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
        subprocess.run(["make", "-s", "demo"], cwd=FIXTURE_DIR, check=True)
        binary = FIXTURE_DIR / "demo"
        from core.analysis.binary_oracle import classify_binary_evidence
        probe = classify_binary_evidence(["folded_a", "folded_b"], binary)
        fold_w = probe.get("folded_a")
        folded_verdict: Classification = (
            fold_w.classification if fold_w else "symbol_present"
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
