"""Drift guard for the core.binary.inspect adoption sweep.

Pins the swept binutils invocations to the sandboxed substrate
(import-or-fail style, same pattern as packages/llm_analysis/tests/
test_preflight_cost_gate.py): the consumers must import the inspect
wrappers and must not re-grow raw ``run_trusted`` invocations of the
allowlisted read-only inspection tools against target binaries.

Deliberately NOT swept:

* ``core/analysis/binary_oracle*`` — corpus-precision-validated;
  keeps its own ``_run``/``_stream`` per the substrate's docstring.
  Pinned below: it must NOT silently start importing the substrate.
* crash_analyser's ``addr2line`` call — the address operand follows
  the ``-e <binary>`` flag, and ``inspect_binary`` both appends the
  binary last and derives the sandbox target from its final operand;
  converting needs a substrate extension first.
* crash_analyser's macOS ``otool`` calls — not an allowlisted tool.
* analyzer.py's ``ldd`` (executes the loader), ``ROPgadget`` /
  one_gadget (not read-only binutils) and ``uname`` (host probe).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_INSPECT_ADOPTERS = [
    "packages/binary_analysis/crash_analyser.py",
    "packages/exploit_feasibility/analyzer.py",
    "packages/exploit_feasibility/constants.py",
]

# A re-grown raw invocation: run_trusted/_run_trusted with an
# allowlisted inspection tool as argv[0].
_HAND_ROLLED = re.compile(
    r"""_?run_trusted\(\s*\n?\s*\[\s*['"](readelf|nm|objdump|strings|"""
    r"""c\+\+filt|file)['"]"""
)


@pytest.mark.parametrize("rel_path", _INSPECT_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "from core.binary.inspect import" in src, (
        f"{rel_path} must route binutils inspection through "
        "core.binary.inspect"
    )


@pytest.mark.parametrize("rel_path", _INSPECT_ADOPTERS)
def test_no_raw_binutils_invocation(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    hits = _HAND_ROLLED.findall(src)
    assert not hits, (
        f"{rel_path} re-grew raw run_trusted binutils invocations "
        f"({hits}); use core.binary.inspect"
    )


def test_binary_oracle_stays_independent():
    """The oracle keeps its own corpus-validated execution path; a
    silent convergence would invalidate its precision claims."""
    for py in (REPO_ROOT / "core" / "analysis").glob("binary_oracle*.py"):
        src = py.read_text(encoding="utf-8")
        assert "core.binary.inspect" not in src, (
            f"{py.name} must not import core.binary.inspect (see "
            "substrate docstring — the oracle is the template, not a "
            "consumer)"
        )
