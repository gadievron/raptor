r"""CRLF-checkout equivalence for the attribution source fallback.

``findings._enclosing_from_source`` reads ``newline=""`` (raw-byte
line model) and indexes through ``split_lines``, so the finding's
line number — a ``\n``-only count from the reporting tool — lands on
the same source line the tool saw.  Both halves of that pairing are
load-bearing: a universal-newline read turns a planted bare ``\r``
into a line break BEFORE ``split_lines`` runs, shifting every
subsequent index and resolving a confident wrong enclosing name.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.audit.findings import (
    _enclosing_from_source,
    resolve_function_attribution,
)

_PY_BODY_LF = (
    "def alpha():\n"
    "    return 1\n"
    "\n"
    "def bravo():\n"
    "    x = compute()\n"
    "    return x\n"
)


def _twin_trees(tmp_path: Path) -> tuple[Path, Path]:
    lf = tmp_path / "lf"
    crlf = tmp_path / "crlf"
    for root, data in (
        (lf, _PY_BODY_LF.encode()),
        (crlf, _PY_BODY_LF.replace("\n", "\r\n").encode()),
    ):
        root.mkdir()
        (root / "mod.py").write_bytes(data)
    return lf, crlf


def test_enclosing_name_crlf_equivalence(tmp_path: Path) -> None:
    lf, crlf = _twin_trees(tmp_path)
    got_lf = _enclosing_from_source(lf, "mod.py", 5)
    got_crlf = _enclosing_from_source(crlf, "mod.py", 5)
    assert got_lf == got_crlf == "bravo"


def test_bare_cr_does_not_shift_line_indexing(tmp_path: Path) -> None:
    r"""A bare ``\r`` planted inside a string literal must stay inside
    its line: under a universal-newline read it becomes a break and
    the walk resolves the attacker-chosen ``evil`` name instead."""
    root = tmp_path / "t"
    root.mkdir()
    (root / "mod.py").write_bytes(
        b'def real():\n    s = "X\rdef evil():"\n    do_bad()\n'
    )
    assert _enclosing_from_source(root, "mod.py", 3) == "real"


def test_resolver_fallback_crlf_equivalence(tmp_path: Path) -> None:
    """End to end through ``resolve_function_attribution``: the file
    is itemised but neither the claim nor the line resolves against
    the checklist, so the source fallback decides — identically on
    both checkouts."""
    checklist: dict[str, Any] = {
        "files": [{
            "path": "mod.py",
            "items": [{
                "name": "unrelated",
                "kind": "function",
                "line_start": 100,
                "line_end": 120,
            }],
        }],
    }
    lf, crlf = _twin_trees(tmp_path)
    results = [
        resolve_function_attribution(
            checklist, "mod.py", "compute", 5, target_path=root,
        )
        for root in (lf, crlf)
    ]
    assert results[0] == results[1] == ("bravo", "corrected")
