"""Tests for the shared bounded-read helper used by SCA parsers."""

from __future__ import annotations

import logging
from pathlib import Path

from packages.sca.parsers._safe_read import read_bounded


def _write(tmp_path: Path, body: bytes, name: str = "f.txt") -> Path:
    p = tmp_path / name
    p.write_bytes(body)
    return p


def test_small_file_returns_text(tmp_path: Path) -> None:
    p = _write(tmp_path, b"hello world\n")
    assert read_bounded(p) == "hello world\n"


def test_file_at_exact_max_reads_ok(tmp_path: Path) -> None:
    p = _write(tmp_path, b"x" * 100)
    assert read_bounded(p, max_bytes=100) == "x" * 100


def test_file_one_byte_over_max_refuses(
    tmp_path: Path, caplog,
) -> None:
    """File whose stat'd size exceeds max → None + warning. The
    bound is in-process defence-in-depth; the OS sandbox is the
    backstop, but the helper turns the OOM into a clean
    'treating as unparseable' verdict."""
    p = _write(tmp_path, b"x" * 101)
    with caplog.at_level(logging.WARNING):
        assert read_bounded(p, max_bytes=100) is None
    assert any("refusing to read" in r.message for r in caplog.records)


def test_missing_file_returns_none(tmp_path: Path, caplog) -> None:
    """Defensive: a file we can't stat (gone, perm denied) is treated
    as unparseable, not as a fatal error."""
    p = tmp_path / "does-not-exist"
    with caplog.at_level(logging.DEBUG):
        assert read_bounded(p) is None


def test_non_utf8_decodes_with_replacement(tmp_path: Path) -> None:
    """Adversarial byte sequences (or legitimate non-UTF-8 manifests)
    don't crash — invalid bytes become U+FFFD. The caller's regex /
    JSON parse handles U+FFFD as gracefully as it handles other
    unparseable content."""
    p = _write(tmp_path, b"valid\xff\xfeinvalid")
    text = read_bounded(p)
    assert text is not None
    assert "valid" in text
    assert "�" in text  # replacement char


def test_default_cap_is_50_mb() -> None:
    """Pin the default. Changing it is a deliberate decision —
    if you're widening the cap, document why in the module
    docstring; if narrowing, audit existing manifests that
    might exceed it."""
    from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES
    assert _MAX_PARSER_BYTES == 50 * 1024 * 1024


def test_bound_violation_does_not_partially_read(
    tmp_path: Path, caplog,
) -> None:
    """Refuses entirely on bound violation — doesn't return a
    silently-truncated prefix that would parse as a different
    (smaller, attacker-shaped) manifest."""
    p = _write(tmp_path, b"valid prefix\n" + b"x" * 200)
    with caplog.at_level(logging.WARNING):
        result = read_bounded(p, max_bytes=100)
    assert result is None, (
        "must not return a truncated prefix; that would let an "
        "attacker craft an oversized manifest whose first 100 bytes "
        "parse to a different / weaker spec than the actual contents"
    )
