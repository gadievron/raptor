"""The CodeQL-failure stderr tail is relayed to the operator terminal.

CodeQL error lines quote target file paths, and file names may
legally carry ESC/C1 bytes — a hostile repo can therefore put raw
terminal control sequences into the relayed lines. Every other
child-output relay in raptor_agentic.py routes through
``sanitise_for_terminal``; the tail must too.
"""

from __future__ import annotations

import sys
from pathlib import Path

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_agentic():
    if str(_RAPTOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor_agentic
    return raptor_agentic


def test_codeql_stderr_tail_lines_render_inert(capsys):
    agentic = _import_agentic()
    tail_printer = getattr(agentic, "_print_codeql_stderr_tail", None)
    assert tail_printer is not None, (
        "codeql stderr relay has no escaping chokepoint"
    )
    tail_printer("db create failed: path\x1b]0;pwned\x07.c\nsecond line")
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "pwned" in out  # content survives, escaped
    assert "second line" in out


def test_codeql_stderr_tail_keeps_language_hint(capsys):
    agentic = _import_agentic()
    tail_printer = getattr(agentic, "_print_codeql_stderr_tail", None)
    assert tail_printer is not None, (
        "codeql stderr relay has no escaping chokepoint"
    )
    tail_printer("No CodeQL-supported languages detected")
    out = capsys.readouterr().out
    assert "--languages" in out  # the actionable hint still prints


def test_codeql_stderr_tail_empty_prints_nothing(capsys):
    agentic = _import_agentic()
    tail_printer = getattr(agentic, "_print_codeql_stderr_tail", None)
    assert tail_printer is not None, (
        "codeql stderr relay has no escaping chokepoint"
    )
    tail_printer("")
    assert capsys.readouterr().out == ""
