"""z3 layering driftguard.

There is exactly one ``z3`` module per interpreter, and when angr is
installed claripy's exact pin owns its version. RAPTOR's own SMT
consumers (``core/smt_solver``, ``packages/exploit_feasibility``)
import ``z3`` themselves and are verified version-tolerant; this
substrate must observe z3's API ONLY through angr/claripy, or a
version skew would couple two layers that are deliberately
independent. Two sanctioned exceptions: the presence probe in
``_availability`` (importability check via __import__, no import
statement) and ``_budget`` (sets/restores the global z3 timeout
parameter — budget enforcement, not solving).
"""
from __future__ import annotations

import re
from pathlib import Path

_Z3_IMPORT = re.compile(r"^\s*(?:import z3\b|from z3\b)", re.MULTILINE)


def test_core_symbolic_never_imports_z3_directly():
    pkg = Path(__file__).resolve().parents[1]
    offenders = [
        str(p.relative_to(pkg))
        for p in pkg.rglob("*.py")
        if p.name != "_budget.py"
        and _Z3_IMPORT.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        f"core/symbolic must reach z3 only through angr/claripy; "
        f"direct imports found in: {offenders}"
    )
