"""Token-map parsing stays bounded on hostile repo files.

Two pump shapes from the hostile-input doctrine:

1. OVERSIZED FILE — the per-unit read is capped (``MAX_UNIT_CHARS``);
   an over-budget file degrades the unit to a parse failure ("file
   exceeds parse budget"), never to a truncated parse whose missing
   tail could hide the check (false absence) and never to an
   unbounded buffer.
2. BRACE PUMP — K planted function definitions used to trigger a
   per-function forward rescan toward the file tail (quadratic);
   the single-pass brace table keeps parsing linear while matching
   the same bodies.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from core.concepts import token_map
from core.concepts.token_map import _parse_php_unit, build_token_map

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def test_oversized_file_degrades_to_parse_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_map, "MAX_UNIT_CHARS", 1024)
    entry = tmp_path / "big.php"
    entry.write_text(
        "<?php om_verify_request_stamp();\n" + ("x" * 4096) + "\n",
    )
    unit = _parse_php_unit(entry, tmp_path)
    assert unit.parse_ok is False
    assert unit.parse_error == "file exceeds parse budget"
    # End-to-end: the entry degrades to unknown, never to a verdict
    # computed over a truncated prefix.
    payload = build_token_map(
        MODEL, [{"entry": "big.php", "file": "big.php"}], tmp_path,
    )
    (rec,) = payload["entries"]
    assert rec["status"] == "unknown"
    assert "parse budget" in rec["reason"]


def test_within_budget_file_parses_normally(tmp_path: Path) -> None:
    entry = tmp_path / "ok.php"
    entry.write_text(
        "<?php\nfunction helper() { om_verify_request_stamp(); }\n"
        "helper();\n",
    )
    unit = _parse_php_unit(entry, tmp_path)
    assert unit.parse_ok is True
    assert set(unit.functions) == {"helper"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
def test_fifo_unit_refused_without_hanging(tmp_path: Path) -> None:
    trap = tmp_path / "trap.php"
    os.mkfifo(trap)
    unit = _parse_php_unit(trap, tmp_path)
    assert unit.parse_ok is False
    assert unit.parse_error.startswith("unreadable")


def test_nested_function_pump_completes_linearly(tmp_path: Path) -> None:
    count = 1500
    opens = "".join(f"function f{i}() {{ " for i in range(count))
    entry = tmp_path / "pump.php"
    entry.write_text("<?php\n" + opens + ("} " * count) + "\n")
    started = time.monotonic()
    unit = _parse_php_unit(entry, tmp_path)
    elapsed = time.monotonic() - started
    assert unit.parse_ok is True
    assert len(unit.functions) == count
    # Linear parsing finishes in well under a second; the old
    # per-function rescan took multiple seconds at this size. The
    # generous margin keeps the pin stable on slow CI machines.
    assert elapsed < 5.0


def test_unbalanced_braces_still_fail_closed(tmp_path: Path) -> None:
    entry = tmp_path / "broken.php"
    entry.write_text("<?php\nfunction f() { if (1) {\n")
    unit = _parse_php_unit(entry, tmp_path)
    assert unit.parse_ok is False
    assert "unbalanced braces in function f" == unit.parse_error
