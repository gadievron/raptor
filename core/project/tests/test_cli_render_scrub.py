"""/project render surfaces print finding-derived text (LLM-authored,
or restored verbatim by /project import) — hostile bytes must be
escaped at the print sites."""

from __future__ import annotations

from core.project.cli import _print_code_findings, _print_correlate_counts

HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"
RAW = ("\x1b", "\x07", "\x9b", "‮")


def _finding(**over) -> dict:
    base = {
        "id": "F-1",
        "file": f"src/{HOSTILE}.c",
        "function": "main",
        "line": 10,
        "vuln_type": f"overflow{HOSTILE}",
        "status": "confirmed",
        "reasoning": f"because {HOSTILE} of taint",
        "proof_source": f"argv{HOSTILE}",
        "proof_sink": f"strcpy{HOSTILE}",
    }
    base.update(over)
    return base


def test_code_findings_table_and_detail_escaped(capsys):
    _print_code_findings([_finding()], detailed=True)
    out = capsys.readouterr().out
    assert "verflow" in out  # title_case_type may capitalise
    for raw in RAW:
        assert raw not in out


def test_correlate_counts_are_int_only(capsys):
    # The header helper coerces every value — a foreign string in a
    # count slot raises rather than rendering.
    _print_correlate_counts({
        "runs": 2, "total_unique_findings": 5,
        "disagreements": 1, "new_findings": 0,
        "potentially_resolved": 0,
    })
    out = capsys.readouterr().out
    assert "Runs: 2" in out and "Disagreements: 1" in out

    import pytest
    with pytest.raises((ValueError, TypeError)):
        _print_correlate_counts({"runs": HOSTILE,
                                 "total_unique_findings": 1})
