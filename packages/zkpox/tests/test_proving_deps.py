"""Tests for ``packages.zkpox.proving_deps`` — the Tier 2/3
proving-stack availability gate.

The gate ships ahead of the prover itself (#470): its job is to
let the dependency-free tiers stay importable and to give the
future prove/verify entry points + their slow tests one canonical
"is the stack here?" check.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# packages/zkpox/tests/test_proving_deps.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import packages.zkpox.proving_deps as pd  # noqa: E402
from packages.zkpox import (  # noqa: E402
    ProvingStackUnavailable,
    proving_stack_available,
    require_proving_stack,
)


def test_available_returns_bool():
    """Whatever the host has, the probe returns a bool and doesn't
    raise."""
    pd.proving_stack_available.cache_clear()
    assert isinstance(proving_stack_available(), bool)


def test_available_false_when_binary_missing(monkeypatch):
    pd.proving_stack_available.cache_clear()
    monkeypatch.setattr(pd.shutil, "which", lambda _b: None)
    assert proving_stack_available() is False
    pd.proving_stack_available.cache_clear()


def test_available_true_when_all_binaries_present(monkeypatch):
    pd.proving_stack_available.cache_clear()
    monkeypatch.setattr(pd.shutil, "which", lambda b: f"/usr/bin/{b}")
    assert proving_stack_available() is True
    pd.proving_stack_available.cache_clear()


def test_available_is_cached(monkeypatch):
    """lru_cache: the probe runs once per process. Pin it so a
    future contributor doesn't add a per-call subprocess thinking
    it's cheap."""
    pd.proving_stack_available.cache_clear()
    calls = {"n": 0}

    def counting_which(_b):
        calls["n"] += 1
        return None

    monkeypatch.setattr(pd.shutil, "which", counting_which)
    proving_stack_available()
    proving_stack_available()
    assert calls["n"] == len(pd._PROVING_BINARIES)  # one sweep, not two
    pd.proving_stack_available.cache_clear()


# ----------------------------------------------------------------------
# require_proving_stack guard
# ----------------------------------------------------------------------


def test_require_raises_when_unavailable(monkeypatch):
    monkeypatch.setattr(pd, "proving_stack_available", lambda: False)
    with pytest.raises(ProvingStackUnavailable) as e:
        require_proving_stack()
    msg = str(e.value)
    # Actionable: names the missing stack + reassures lower tiers work
    assert "SP1" in msg or "RISC-V" in msg
    assert "0/1" in msg and "1.5" in msg


def test_require_passes_when_available(monkeypatch):
    monkeypatch.setattr(pd, "proving_stack_available", lambda: True)
    # Must not raise
    require_proving_stack()


# ----------------------------------------------------------------------
# Import-cheapness invariant (the whole reason this module exists)
# ----------------------------------------------------------------------


def test_zkpox_import_pulls_no_heavy_deps():
    """Importing packages.zkpox must not import SP1 / RISC-V / etc.
    The gate probes by PATH lookup, never by importing the stack at
    module load. Guard: the proving_deps module's only imports are
    stdlib (functools, shutil)."""
    import ast
    src = (REPO / "packages" / "zkpox" / "proving_deps.py").read_text()
    tree = ast.parse(src)
    imported_top = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_top.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_top.add(node.module.split(".")[0])
    # only stdlib — no sp1/risc-v/age/tle/etc at module scope
    assert imported_top <= {"__future__", "functools", "shutil"}
