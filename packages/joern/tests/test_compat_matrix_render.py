"""Terminal-safety oracles for the compat-matrix render lanes.

Release tags, asset names, and per-step values derive from the GitHub
releases API and downloaded artifacts — the matrix rows, the pin
confirmation line, and the FAILURES summary must escape them. These
unit tests are the revert oracle for the three site fixes (`tag_name`
is outside the writer-gate detector's vocabulary, so the gate alone
cannot hold these sites).
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

_SCRIPT = (Path(__file__).resolve().parents[3]
           / "packages" / "joern" / "scripts" / "compat_matrix.py")

HOSTILE_TAG = "v9.9\x1b[2J\x9b.1"
RAW = ("\x1b", "\x9b")


def _load():
    loader = SourceFileLoader("compat_matrix_render_test", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_format_row_escapes_hostile_tag_and_steps():
    mod = _load()
    out = mod._format_row(
        HOSTILE_TAG, {"pass": False, "unzip": "boom \x1b]0;evil\x07"},
    )
    for raw in RAW + ("\x07",):
        assert raw not in out
    assert "v9.9" in out and "boom" in out


def test_pin_line_escapes_hostile_tag_and_asset():
    mod = _load()
    out = mod._pin_line(HOSTILE_TAG, "cli\x9b.zip", "ab" * 32)
    for raw in RAW:
        assert raw not in out
    assert "pinned" in out and "cli" in out


def test_summary_line_escapes_hostile_failure_tags():
    mod = _load()
    rows = [
        ("v1.0.0", {"pass": True}),
        (HOSTILE_TAG, {"pass": False}),
    ]
    out = mod._summary_line(rows)
    for raw in RAW:
        assert raw not in out
    assert "FAILURES" in out and "1/2" in out
