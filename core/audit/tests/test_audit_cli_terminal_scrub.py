"""Terminal-escape scrubbing on the raptor-audit CLI lanes that
interpolate target-derived (file:function keys) or LLM-authored
(hypothesis) text.

The critique report round-trips taint through a stats dict and a
tuple-in-list container before printing — no foreign key name is
visible at the sink — so the print sites themselves must escape.
The record gate errors print the same file:function values cmd_sweep
already escapes.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"

HOSTILE_FN = "fn\x1b[2J\x9bpwn"
HOSTILE_HYP = "if \x1b]0;evil\x07 reaches sink, CWE-787"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_scrub", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_scrub", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _append_log(out_dir: Path, entries: list[dict]) -> None:
    log = out_dir / ".audit-log.jsonl"
    with log.open("a", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def test_critique_escapes_hostile_key_and_hypothesis(
    tmp_path: Path, capsys,
) -> None:
    cli = _load_cli()
    key = f"src/a.c:{HOSTILE_FN}"
    _append_log(tmp_path, [
        # A reviewed finding with an LLM-authored hypothesis and no
        # rule → lands in the Mode 2 gaps table; one sweep → also in
        # the low-coverage table.
        {"key": key, "action": "sweep", "tool": "semgrep"},
        {"key": key, "status": "finding",
         "hypothesis": HOSTILE_HYP, "evidence_tool": "semgrep"},
        # A suspicious function → untried-tools table.
        {"key": f"src/b.c:{HOSTILE_FN}", "status": "suspicious"},
    ])
    rc = cli.cmd_critique(SimpleNamespace(out=str(tmp_path)))
    assert rc == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x9b" not in out
    assert "\x07" not in out
    # Content still present, escaped.
    assert "src/a.c" in out and "src/b.c" in out


def test_record_gate_error_escapes_hostile_function(
    tmp_path: Path, capsys,
) -> None:
    """G5 fires (no context breadcrumb) — the error text embeds the
    file:function key and the copy-paste hint embeds file/function;
    both must be escaped."""
    cli = _load_cli()
    target = tmp_path / "tree"
    target.mkdir()
    args = SimpleNamespace(
        out=str(tmp_path),
        target=str(target),
        file="src/a.c",
        function=HOSTILE_FN,
        status="clean",
        body="looked fine",
        line_start=None,
        line_end=None,
        cwe=None,
        strategies=None,
        evidence_tool=None,
        hypothesis=None,
        vuln_type=None,
        related_to=None,
        reach_via=None,
    )
    rc = cli.cmd_record(args)
    assert rc == 1
    err = capsys.readouterr().err
    assert "G5 READ-FIRST" in err
    assert "\x1b" not in err
    assert "\x9b" not in err
