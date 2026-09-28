"""raptor-review ``tools``: the per-item could-not-run query surface.

The audit trail records exactly which mechanical channels could not
speak for a function — ``refutation_gate_engagement`` rows carry
per-gate engaged/blocked_on records, ``substrate_skip`` rows carry
tool + reason, and review-journal rows carry ``tools_skipped`` — but
no operator surface exposed them per item; the counts in the report
were a dead end. These tests pin the query surface.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = REPO_ROOT / "libexec" / "raptor-review"
    mod = types.ModuleType("raptor_review_cli_toolruns")
    mod.__file__ = str(script)
    code = compile(script.read_text(), str(script), "exec")
    exec(code, mod.__dict__)
    return mod


_cli = _load_cli()


def _write_audit_log(run: Path, rows: list[dict[str, Any]]) -> None:
    (run / ".audit-log.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8",
    )


def _append_journal(run: Path, **kw: Any) -> None:
    from core.coverage.journal import ReviewJournalEntry, append_entry
    base: dict[str, Any] = {
        "run_id": "t", "file": "binary:lib.so", "source_hash": "",
    }
    base.update(kw)
    append_entry(run, ReviewJournalEntry(**base))


def _gate_row(function: str, gates: list[dict[str, Any]],
              phase: str = "review") -> dict[str, Any]:
    return {
        "action": "refutation_gate_engagement",
        "phase": phase,
        "key": f"binary:lib.so:{function}:0",
        "file": "binary:lib.so",
        "function": function,
        "gates": gates,
    }


def _seed_toolrun_records(run: Path) -> None:
    _write_audit_log(run, [
        _gate_row("FUN_00250bc0", [
            {"gate": "smt-refutation", "engaged": False,
             "blocked_on": "no solver model for the pattern class"},
            {"gate": "taint-corroboration", "engaged": True,
             "blocked_on": None},
        ]),
        {
            "action": "substrate_skip",
            "key": "binary:lib.so:FUN_0036b4c0",
            "file": "binary:lib.so",
            "function": "FUN_0036b4c0",
            "tool": "codeql",
            "reason": "target language outside the tier's model",
        },
    ])
    _append_journal(run, ts="2026-01-01T00:00:01+00:00",
                    function="FUN_00777000", verdict="clean",
                    tools_skipped=["joern"])


class TestToolsCommand:
    def test_lists_could_not_run_channels_per_function(
        self, tmp_path: Path, capsys,
    ) -> None:
        _seed_toolrun_records(tmp_path)
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path)))
        out = capsys.readouterr().out
        # Blocked gate: function, gate name, status, blocked_on.
        assert "FUN_00250bc0" in out
        assert "smt-refutation" in out
        assert "blocked" in out
        assert "no solver model for the pattern class" in out
        # The engaged gate at the same site stays visible with its
        # status — engaged/blocked is a per-gate fact, not a filter.
        assert "taint-corroboration" in out
        assert "engaged" in out
        # Substrate skip: tool + reason.
        assert "FUN_0036b4c0" in out
        assert "codeql" in out
        assert "target language outside the tier's model" in out
        # Journal-recorded review-time skip.
        assert "FUN_00777000" in out
        assert "joern" in out

    def test_fully_engaged_functions_are_counted_not_listed(
        self, tmp_path: Path, capsys,
    ) -> None:
        _write_audit_log(tmp_path, [
            _gate_row("FUN_ok", [
                {"gate": "smt-refutation", "engaged": True,
                 "blocked_on": None},
            ]),
        ])
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path)))
        out = capsys.readouterr().out
        assert "FUN_ok" not in out
        assert "1" in out  # engaged-only functions are summarised

    def test_latest_gate_row_per_site_and_phase_wins(
        self, tmp_path: Path, capsys,
    ) -> None:
        # A later engagement row for the same site+phase supersedes
        # the earlier one (append order = time order): a gate that
        # eventually engaged must not keep reporting its stale block.
        _write_audit_log(tmp_path, [
            _gate_row("FUN_retry", [
                {"gate": "smt-refutation", "engaged": False,
                 "blocked_on": "solver timeout"},
            ]),
            _gate_row("FUN_retry", [
                {"gate": "smt-refutation", "engaged": True,
                 "blocked_on": None},
            ]),
        ])
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path)))
        out = capsys.readouterr().out
        assert "solver timeout" not in out
        assert "FUN_retry" not in out  # fully engaged → summarised

    def test_raw_json_carries_full_rows(
        self, tmp_path: Path, capsys,
    ) -> None:
        _seed_toolrun_records(tmp_path)
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path), raw=True))
        rows = json.loads(capsys.readouterr().out)
        by_status = {r["status"] for r in rows}
        assert by_status >= {"engaged", "blocked", "skipped"}
        blocked = [r for r in rows if r["status"] == "blocked"]
        assert blocked and blocked[0]["function"] == "FUN_00250bc0"
        assert blocked[0]["channel"] == "smt-refutation"
        assert blocked[0]["reason"] == \
            "no solver model for the pattern class"

    def test_output_escaped_at_render(self, tmp_path: Path, capsys) -> None:
        # Display integrity: gate names / reasons / function names
        # come from run artifacts a hostile target can influence —
        # OSC/ESC, raw C1 controls (0x85 NEL, 0x9b CSI, 0x9d OSC,
        # 0x90 DCS), and bidi overrides (U+202E RLO, U+2066 LRI)
        # must render inert. The seam (``sanitise_string``) escapes
        # C1 to ``\xHH`` text and drops bidi controls.
        _write_audit_log(tmp_path, [
            _gate_row("FUN_evil\x1b]0;pwned\x07\x85", [
                {"gate": "smt\x1b[31m-refutation\x9d", "engaged": False,
                 "blocked_on": "bad \x1bP payload \x9b\x90 ‮dab⁦ bytes"},
            ]),
        ])
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path)))
        out = capsys.readouterr().out
        assert "FUN_evil" in out  # the row DID render
        for raw in ("\x1b", "\x07", "\x85", "\x9b", "\x9d", "\x90",
                    "‮", "⁦"):
            assert raw not in out
        assert "\\x9b" in out   # C1 escaped to inert text, not dropped
        assert "bytes" in out   # content around bidi survives

    def test_empty_run_says_so(self, tmp_path: Path, capsys) -> None:
        _cli.cmd_tools(argparse.Namespace(out=str(tmp_path)))
        out = capsys.readouterr().out
        assert "No tool/gate engagement records" in out

    def test_subcommand_registered_in_cli(self, tmp_path: Path) -> None:
        # End-to-end through the real parser: "tools" must be a known
        # command (not swallowed by the bare-path → show fallback).
        _seed_toolrun_records(tmp_path)
        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "libexec" / "raptor-review"),
             "tools", "--out", str(tmp_path)],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        assert "smt-refutation" in proc.stdout
