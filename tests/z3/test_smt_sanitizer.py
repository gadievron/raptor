"""Tests for packages.codeql.smt_sanitizer bitvector modeling.

Covers the cases the bitvector migration needs to handle correctly:
  - upper / lower / range / null sanitizer bypass with concrete inputs
  - multi-variable dataflow (independent constraints)
  - genuine UNSAT (sanitizers proven effective)
  - signed vs unsigned mode, 32-bit vs 64-bit width
  - disabled / z3-absent fallthrough

All tests are skipped automatically when z3-solver is not installed.
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import pytest

# tests/z3/test_smt_sanitizer.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

z3 = pytest.importorskip("z3")

from packages.codeql import smt_sanitizer as s  # noqa: E402


# ---------------------------------------------------------------------------
# Dataflow stand-ins (avoid importing DataflowPath to sidestep logger setup)
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


def _path(*snippets: str) -> Path_:
    return Path_(
        source=Step(snippet="// src"),
        sink=Step(),
        intermediate_steps=[Step(snippet=sn, label=f"s{i}") for i, sn in enumerate(snippets)],
    )


# ---------------------------------------------------------------------------
# Fixture: enable SMT and reset mode env vars around each test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _smt_env(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_ENABLED", "1")
    monkeypatch.delenv("RAPTOR_SMT_WIDTH", raising=False)
    monkeypatch.delenv("RAPTOR_SMT_SIGNED", raising=False)
    yield


# ---------------------------------------------------------------------------
# Mode helpers
# ---------------------------------------------------------------------------

def test_default_mode_is_bv64_signed():
    assert s._bv_width() == 64
    assert s._is_signed() is True
    assert s._mode_tag() == "bv64-signed"


def test_width_env_override(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "32")
    assert s._bv_width() == 32


def test_invalid_width_falls_back_to_64(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "17")
    assert s._bv_width() == 64
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "notanumber")
    assert s._bv_width() == 64


def test_signed_env_override(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_SIGNED", "unsigned")
    assert s._is_signed() is False
    monkeypatch.setenv("RAPTOR_SMT_SIGNED", "signed")
    assert s._is_signed() is True


# ---------------------------------------------------------------------------
# Bypass-side cases (attacker should be able to pass through)
# ---------------------------------------------------------------------------

def test_upper_bound_bypass_sat():
    r = s.analyze_sanitizers(_path("if (len > 100) return -1;"), ".")
    assert r.bypass_found is True
    assert r.bypass_input == {"len": 100}   # boundary is a valid bypass witness
    assert "bv64-signed" in r.reasoning


def test_overlap_bypass_between_opposing_bounds():
    r = s.analyze_sanitizers(
        _path("if (len > 100) return -1;", "if (len < 50) return -1;"),
        ".",
    )
    assert r.bypass_found is True
    v = r.bypass_input["len"]
    assert 50 <= v <= 100   # any witness in the gap is acceptable


def test_multi_variable_independent_constraints():
    r = s.analyze_sanitizers(
        _path("if (len > 100) return -1;", "if (strlen(buf) < 10) return -1;"),
        ".",
    )
    assert r.bypass_found is True
    assert r.bypass_input["len"] <= 100
    assert r.bypass_input["buf"] >= 10


def test_range_guard_bypass_in_range():
    r = s.analyze_sanitizers(_path("if (n < 0 || n > 5) return -1;"), ".")
    assert r.bypass_found is True
    assert 0 <= r.bypass_input["n"] < 5


def test_null_guard_bypass_is_nonzero():
    r = s.analyze_sanitizers(_path("if (!ptr) return -1;"), ".")
    assert r.bypass_found is True
    assert r.bypass_input["ptr"] != 0


# ---------------------------------------------------------------------------
# Unsat cases (sanitizers proven effective)
# ---------------------------------------------------------------------------

def test_contradictory_bypass_is_unsat():
    # Guard 1: if(x > 100) -> bypass x <= 100
    # Guard 2: if(x < 200) -> bypass x >= 200
    # Joint bypass is unsat -> sanitizers effective.
    r = s.analyze_sanitizers(
        _path("if (x > 100) return -1;", "if (x < 200) return -1;"),
        ".",
    )
    assert r.bypass_found is False
    assert r.bypass_input is None
    assert "sanitizers effective" in r.reasoning


# ---------------------------------------------------------------------------
# Width / signedness modes
# ---------------------------------------------------------------------------

def test_unsigned_mode_upper_bound_still_sat(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_SIGNED", "unsigned")
    r = s.analyze_sanitizers(_path("if (len > 100) return -1;"), ".")
    assert r.bypass_found is True
    assert 0 <= r.bypass_input["len"] <= 100
    assert "bv64-unsigned" in r.reasoning


def test_bv32_signed_mode(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_WIDTH", "32")
    r = s.analyze_sanitizers(_path("if (len > 100) return -1;"), ".")
    assert r.bypass_found is True
    assert "bv32-signed" in r.reasoning


def test_signed_mode_reports_negative_witnesses():
    # Null guard bypass is any non-zero value. Under signed reinterpretation,
    # the solver may pick a high-bit-set value which must render as negative.
    r = s.analyze_sanitizers(_path("if (!ptr) return -1;"), ".")
    assert r.bypass_found is True
    val = r.bypass_input["ptr"]
    # In signed bv64, witnesses lie in [-2**63, 2**63)
    assert -(1 << 63) <= val < (1 << 63)
    assert val != 0


def test_unsigned_mode_witnesses_are_nonnegative(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_SIGNED", "unsigned")
    r = s.analyze_sanitizers(_path("if (!ptr) return -1;"), ".")
    assert r.bypass_found is True
    assert r.bypass_input["ptr"] >= 0


# ---------------------------------------------------------------------------
# Disabled / absent fallthrough
# ---------------------------------------------------------------------------

def test_disabled_returns_none_result(monkeypatch):
    monkeypatch.setenv("RAPTOR_SMT_ENABLED", "0")
    r = s.analyze_sanitizers(_path("if (len > 100) return -1;"), ".")
    assert r.bypass_found is None
    assert r.smt_available is False
