"""Tests for the angr-free (pyelftools) fallback path of load_binary.

Callers gate on ``except (FileNotFoundError, ValueError)`` (the
pre-gate in ``detect_shape``), so the fallback must translate
elftools' ``ELFError`` — a direct Exception subclass — into the
documented ValueError instead of letting it escape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("elftools")


def _force_no_angr(monkeypatch: pytest.MonkeyPatch) -> None:
    import core.symbolic._availability as availability

    monkeypatch.setattr(availability, "angr_available", lambda: False)


def test_fallback_non_elf_raises_valueerror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.symbolic import load_binary

    _force_no_angr(monkeypatch)
    garbage = tmp_path / "not-an-elf.bin"
    garbage.write_bytes(b"garbage, definitely not ELF")
    with pytest.raises(ValueError, match="failed to load"):
        load_binary(garbage)


def test_fallback_missing_file_still_filenotfound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.symbolic import load_binary

    _force_no_angr(monkeypatch)
    with pytest.raises(FileNotFoundError):
        load_binary(Path("/no/such/binary/anywhere"))
