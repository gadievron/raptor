"""Tests for core.symbolic.load_binary + BinaryInfo.

Uses the overflow-marker fixture (conftest) — the smallest non-PIE
target with a known ``win`` symbol. Compiling it takes ~200ms per
test which is acceptable at unit-test scope.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("angr")  # suite asserts real-angr behaviour

from core.symbolic.tests.conftest import (
    OVERFLOW_MARKER_SOURCE,
    compile_fixture,
)


def _compile_m0(tmp_path: Path) -> Path:
    """Compile the overflow-marker fixture; skips without gcc."""
    return compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)


def test_load_binary_returns_binary_info(tmp_path: Path):
    from core.symbolic import BinaryInfo, load_binary

    binary = _compile_m0(tmp_path)
    info = load_binary(binary)

    assert isinstance(info, BinaryInfo)
    assert info.path == binary
    assert info.arch_name == "AMD64"
    assert info.bits == 64
    assert info.entry_point > 0
    assert isinstance(info.symbols, dict)


def test_load_binary_captures_win_symbol(tmp_path: Path):
    """The fixture exports a ``win`` symbol — the BinaryInfo snapshot
    must include it. Regression pin: if angr's symbol filtering
    changes and starts dropping user-defined ``T`` symbols, this
    test catches it."""
    from core.symbolic import load_binary

    binary = _compile_m0(tmp_path)
    info = load_binary(binary)
    assert "win" in info.symbols
    assert info.symbols["win"] > 0
    assert "main" in info.symbols


def test_load_binary_detects_non_pie(tmp_path: Path):
    """The fixture is compiled with -no-pie — is_pie must read False."""
    from core.symbolic import load_binary

    binary = _compile_m0(tmp_path)
    info = load_binary(binary)
    assert info.is_pie is False


def test_load_binary_missing_file_raises():
    from core.symbolic import load_binary

    with pytest.raises(FileNotFoundError):
        load_binary(Path("/no/such/binary/anywhere"))


def test_load_binary_non_elf_raises(tmp_path: Path):
    """Loading a text file (not an ELF) must fail with ValueError,
    not a random angr error."""
    from core.symbolic import load_binary

    text_file = tmp_path / "not-an-elf.txt"
    text_file.write_text("this is not an ELF")
    with pytest.raises(ValueError, match="failed to load"):
        load_binary(text_file)


def test_load_binary_symbols_snapshot_is_immutable_by_convention(tmp_path: Path):
    """BinaryInfo is a frozen dataclass. Mutating its .symbols dict
    would corrupt subsequent readers. Callers should treat it as
    read-only; verify frozen semantics catch reassignment attempts."""
    from core.symbolic import load_binary

    binary = _compile_m0(tmp_path)
    info = load_binary(binary)
    # Reassignment blocked by frozen=True
    with pytest.raises((AttributeError, TypeError)):
        info.entry_point = 0  # type: ignore[misc]
    # The dict itself is mutable (dicts don't freeze inside frozen
    # dataclasses); callers must NOT mutate it. Not enforceable at
    # dataclass level — documented in the type docstring.
