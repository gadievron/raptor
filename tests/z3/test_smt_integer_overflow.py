"""Tests for packages.codeql.smt_integer_overflow (CWE-190 SMT analyzer).

Covers the arithmetic sinks, overflow predicates, type-inference width
selection, and the pipeline wiring against the actual raptor_testbench.c
golden case.

All tests are skipped automatically when z3-solver is not installed.
"""

import os
import sys
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import pytest

# tests/z3/test_smt_integer_overflow.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

z3 = pytest.importorskip("z3")

from packages.codeql import smt_integer_overflow as m  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTBENCH_C = REPO_ROOT / "test" / "data" / "testbench" / "raptor_testbench.c"


# ---------------------------------------------------------------------------
# Dataflow stand-ins (match smt_sanitizer tests, avoid DataflowPath import)
# ---------------------------------------------------------------------------

@dataclass
class Step:
    file_path: str = "x.c"
    line: int = 1
    column: int = 1
    snippet: str = ""
    label: str = ""


@dataclass
class Path_:
    source: Step
    sink: Step
    intermediate_steps: List[Step]
    sanitizers: List[str] = field(default_factory=list)
    rule_id: str = "r"
    message: str = "m"


def _path(sink_snippet: str, *intermediate: str) -> Path_:
    return Path_(
        source=Step(snippet=""),
        sink=Step(snippet=sink_snippet),
        intermediate_steps=[Step(snippet=s, label=f"s{i}") for i, s in enumerate(intermediate)],
    )


# ---------------------------------------------------------------------------
# Fixture: enable SMT and reset width/signedness env around each test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _smt_env(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_ENABLED", "1")
    monkeypatch.delenv("RAPTOR_SMT_WIDTH", raising=False)
    monkeypatch.delenv("RAPTOR_SMT_SIGNED", raising=False)
    yield


# ---------------------------------------------------------------------------
# Arithmetic extraction
# ---------------------------------------------------------------------------

def test_extract_malloc_add():
    exprs = m._extract_arith_from_snippet("buf = malloc(n + 1);")
    assert len(exprs) == 1
    assert exprs[0].op == "+" and exprs[0].context == "malloc"
    assert (exprs[0].width, exprs[0].signed) == (64, False)   # size_t default


def test_extract_assign_infers_width_from_type():
    exprs = m._extract_arith_from_snippet("unsigned int alloc_size = size + 100;")
    assert len(exprs) == 1
    assert exprs[0].declared_type.strip() == "unsigned int"
    assert (exprs[0].width, exprs[0].signed) == (32, False)


def test_extract_signed_int_assign():
    exprs = m._extract_arith_from_snippet("int delta = a - b;")
    assert len(exprs) == 1
    assert (exprs[0].width, exprs[0].signed) == (32, True)
    assert exprs[0].op == "-"


def test_extract_no_arith_returns_empty():
    assert m._extract_arith_from_snippet("strcpy(dst, src);") == []


def test_extract_calloc_first_and_second_arg():
    exprs = m._extract_arith_from_snippet("buf = calloc(n + 1, sizeof(T));")
    # n + 1 is modelable; "sizeof(T)" alone is not a binary arithmetic term.
    assert any(e.op == "+" and e.context == "calloc" for e in exprs)


# ---------------------------------------------------------------------------
# Overflow detection - SAT cases
# ---------------------------------------------------------------------------

def test_malloc_add_unbounded_is_sat():
    r = m.analyze_integer_overflow(_path("buf = malloc(n + 1);"), ".")
    assert r.overflow_found is True
    assert r.operation == "+"
    assert "malloc" in r.contexts
    assert r.overflow_input is not None
    # n near 2**64-1 (size_t max)
    assert r.overflow_input["n"] >= (1 << 63)


def test_malloc_mul_unbounded_is_sat():
    r = m.analyze_integer_overflow(_path("buf = malloc(n * 8);"), ".")
    assert r.overflow_found is True
    assert r.operation == "*"
    # n * 8 overflows at bv64-unsigned when n >= 2**61
    assert r.overflow_input["n"] >= (1 << 60)


def test_memcpy_size_overflow_is_sat():
    r = m.analyze_integer_overflow(_path("memcpy(dst, src, len + 1);"), ".")
    assert r.overflow_found is True
    # len == SIZE_MAX is the canonical witness
    assert r.overflow_input["len"] == (1 << 64) - 1


def test_signed_int_subtraction_underflow_is_sat():
    r = m.analyze_integer_overflow(_path("int delta = a - b;"), ".")
    assert r.overflow_found is True
    assert r.operation == "-"
    assert "bv32-signed" in r.reasoning


def test_sizeof_operand_modelled_as_small_constant():
    r = m.analyze_integer_overflow(_path("buf = malloc(n * sizeof(T));"), ".")
    assert r.overflow_found is True
    # _sizeof_T should appear as an implicit variable bounded to [1, 65536]
    assert "_sizeof_T" in r.overflow_input
    assert 1 <= r.overflow_input["_sizeof_T"] <= (1 << 16)


# ---------------------------------------------------------------------------
# Overflow detection - UNSAT (guards prove safety)
# ---------------------------------------------------------------------------

def test_bounded_malloc_is_unsat():
    r = m.analyze_integer_overflow(
        _path("buf = malloc(n * 8);",
              "if (n > 1000) return -1;"),
        ".",
    )
    assert r.overflow_found is False
    assert r.overflow_input is None
    assert "no overflow reachable" in r.reasoning


def test_bounded_assign_unsigned_int_is_unsat():
    r = m.analyze_integer_overflow(
        _path("unsigned int alloc_size = size + 100;",
              "if (size > 1000) return -1;"),
        ".",
    )
    assert r.overflow_found is False
    assert "bv32-unsigned" in r.reasoning


# ---------------------------------------------------------------------------
# Width / signedness sensitivity
# ---------------------------------------------------------------------------

def test_width_from_declared_type_overrides_env(monkeypatch):
    # Env says 64-bit, but declared 'unsigned int' should force bv32-unsigned
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "64")
    r = m.analyze_integer_overflow(_path("unsigned int alloc_size = size + 100;"), ".")
    assert r.overflow_found is True
    assert "bv32-unsigned" in r.reasoning


def test_env_default_used_when_no_type_hint(monkeypatch):
    # No assignment type -> malloc fallback is size_t (bv64-unsigned) regardless of env
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "32")
    r = m.analyze_integer_overflow(_path("buf = malloc(n + 1);"), ".")
    # malloc context forces size_t semantics, so bv64-unsigned wins over env
    assert r.overflow_found is True
    assert "bv64-unsigned" in r.reasoning


# ---------------------------------------------------------------------------
# Fallthrough cases
# ---------------------------------------------------------------------------

def test_no_arithmetic_returns_none():
    r = m.analyze_integer_overflow(_path("strcpy(dst, src);"), ".")
    assert r.overflow_found is None
    assert r.smt_available is True
    assert "no modellable binary arithmetic" in r.reasoning


def test_disabled_returns_none():
    os.environ["RAPTOR_SMT_ENABLED"] = "0"
    try:
        r = m.analyze_integer_overflow(_path("buf = malloc(n + 1);"), ".")
        assert r.overflow_found is None
        assert r.smt_available is False
    finally:
        os.environ["RAPTOR_SMT_ENABLED"] = "1"


# ---------------------------------------------------------------------------
# Golden integration: raptor_testbench.c vuln_integer_overflow
# ---------------------------------------------------------------------------

def test_testbench_vuln_integer_overflow_is_detected():
    """The testbench's CWE-190 pattern must be flagged by the analyzer.

    Extracts the exact sink line (`unsigned int alloc_size = size + 100;`)
    from test/data/testbench/raptor_testbench.c, feeds it as a synthetic
    DataflowPath, and asserts overflow reachability.
    """
    assert TESTBENCH_C.exists(), f"testbench missing at {TESTBENCH_C}"
    src = TESTBENCH_C.read_text()

    # Find the literal sink line; guards against drift if the testbench is edited.
    sink_re = re.compile(r'^\s*(unsigned\s+int\s+alloc_size\s*=\s*size\s*\+\s*100\s*;)',
                         re.MULTILINE)
    match = sink_re.search(src)
    assert match is not None, "testbench no longer contains the expected CWE-190 sink"
    sink_line = match.group(1)

    r = m.analyze_integer_overflow(_path(sink_line), ".")
    assert r.overflow_found is True
    assert r.operation == "+"
    assert "bv32-unsigned" in r.reasoning
    # Witness must be close to UINT32_MAX - 99 so that size + 100 wraps
    assert r.overflow_input["size"] >= ((1 << 32) - 100)


def test_testbench_sink_becomes_unsat_with_realistic_guard():
    """Same testbench sink, but with an upstream guard bounding size tightly
    enough that the analyzer must prove overflow is unreachable."""
    sink = "unsigned int alloc_size = size + 100;"
    guard = "if (size > 1000) return -1;"
    r = m.analyze_integer_overflow(_path(sink, guard), ".")
    assert r.overflow_found is False
    assert "bv32-unsigned" in r.reasoning
