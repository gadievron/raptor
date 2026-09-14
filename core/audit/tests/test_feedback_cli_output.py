"""`feedback` reports journal corrections, not annotation writes.

Post-migration the importer appends review-journal correction
entries and only READS annotations (human-note veto); the CLI output
still claimed "annotation(s) updated" — machinery must not claim to
write /annotate content.

The console lines must also reflect the actual refereed transition:
a referee-demoted finding lands on ``suspicious``, never ``clean``,
and the output groups by referee outcome (demoted-to-suspicious /
downgraded-to-clean / upgraded / corroborated) instead of one
"Downgraded ... → clean" line covering both downgrade kinds.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    now_iso,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_fbout", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_fbout", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_feedback_output_names_journal_not_annotations(tmp_path, capsys):
    mod = _load_cli()
    report = tmp_path / "findings.json"
    report.write_text(json.dumps({"findings": []}))
    ann_dir = tmp_path / "annotations"
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    rc = mod.cmd_feedback(SimpleNamespace(
        validation_report=str(report),
        annotations_dir=str(ann_dir),
        audit_out=str(out_dir),
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "journal correction(s)" in captured.out
    assert "annotation(s) updated" not in captured.out


def _seed(out_dir: Path, function: str, verdict: str,
          evidence_tools: list[str] | None = None) -> None:
    append_entry(out_dir, ReviewJournalEntry(
        ts=now_iso(),
        run_id="test",
        file="src/vuln.c",
        function=function,
        verdict=verdict,
        source_hash="",
        body="prior review",
        evidence_tools=list(evidence_tools or []),
    ))


def test_feedback_output_groups_by_referee_outcome(tmp_path, capsys):
    """Mixed outcomes: each console line binds to its transition.

    - tool-evidenced finding, LLM-only ruled_out → demoted to
      suspicious (the referee blocks the clean downgrade);
    - LLM-tier finding, ruled_out → downgraded to clean;
    - clean prior, confirmed → upgraded to finding;
    - finding prior, confirmed → corroborated.
    """
    mod = _load_cli()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _seed(out_dir, "tool_backed_fn", "finding",
          evidence_tools=["joern:flow"])
    _seed(out_dir, "llm_tier_fn", "finding",
          evidence_tools=["llm-claimed:manual review"])
    _seed(out_dir, "missed_fn", "clean")
    _seed(out_dir, "corroborated_fn", "finding")

    report = tmp_path / "findings.json"
    report.write_text(json.dumps([
        {"file": "src/vuln.c", "function": "tool_backed_fn",
         "ruling": {"status": "ruled_out", "disqualifier": "D-1",
                    "reason": "looks like test code"}},
        {"file": "src/vuln.c", "function": "llm_tier_fn",
         "ruling": {"status": "ruled_out", "disqualifier": "D-0",
                    "reason": "hypothesis wrong"}},
        {"file": "src/vuln.c", "function": "missed_fn",
         "ruling": {"status": "confirmed"}},
        {"file": "src/vuln.c", "function": "corroborated_fn",
         "ruling": {"status": "confirmed"}},
    ]))
    ann_dir = tmp_path / "annotations"

    rc = mod.cmd_feedback(SimpleNamespace(
        validation_report=str(report),
        annotations_dir=str(ann_dir),
        audit_out=str(out_dir),
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "Downgraded to clean: 1" in captured.out
    assert "Demoted to suspicious: 1" in captured.out
    assert "LLM-only ruling" in captured.out
    assert "Upgraded: 1 (clean → finding)" in captured.out
    assert "Corroborated: 1" in captured.out
    # The referee-demoted row must not be folded into a "→ clean"
    # label — that transition never happened.
    assert "finding/suspicious → clean" not in captured.out


def test_feedback_output_suspicious_only(tmp_path, capsys):
    """A run whose only downgrade was referee-demoted prints no
    clean-downgrade line at all."""
    mod = _load_cli()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _seed(out_dir, "tool_backed_fn", "finding",
          evidence_tools=["semgrep"])

    report = tmp_path / "findings.json"
    report.write_text(json.dumps([
        {"file": "src/vuln.c", "function": "tool_backed_fn",
         "ruling": {"status": "ruled_out", "disqualifier": "D-3",
                    "reason": "hedged"}},
    ]))
    ann_dir = tmp_path / "annotations"

    rc = mod.cmd_feedback(SimpleNamespace(
        validation_report=str(report),
        annotations_dir=str(ann_dir),
        audit_out=str(out_dir),
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "Demoted to suspicious: 1" in captured.out
    assert "Downgraded to clean" not in captured.out
    assert "→ clean" not in captured.out
