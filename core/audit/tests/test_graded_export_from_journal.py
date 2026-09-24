"""Journal-derived findings-graded.json for in-session audit runs.

Contract under test: a run whose review pass produced suspicious/dark
items but ZERO findings must still emit findings-graded.json — the
downstream /validate import and cross-run dedup read that artifact,
and a suspicious record that never reaches it is invisible to every
later adjudication pass (it then gets re-discovered as "novel").
"""

from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.audit.findings_export import export_graded_from_journal
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER_PATH = REPO_ROOT / "libexec" / "raptor-validation-helper"


def _entry(file: str, function: str, verdict: str, **kw) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(), run_id="run1", file=file, function=function,
        verdict=verdict, source_hash="", **kw,
    )


def _journal(tmp_path: Path, entries: list[ReviewJournalEntry]) -> Path:
    for e in entries:
        append_entry(tmp_path, e)
    return tmp_path


def test_only_suspicious_run_emits_graded_artifact(tmp_path):
    _journal(tmp_path, [
        _entry("mod/handler.ext", "interstitial:1-60", "suspicious",
               line_start=1, line_end=60,
               body="Executed taint rule confirms source-to-sink flow",
               evidence_tools=["semgrep"], cwe="CWE-79"),
        _entry("lib/util.src", "helper", "clean"),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded is not None
    path = tmp_path / "findings-graded.json"
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["stats"]["total"] == 1
    rec = data["findings"][0]
    assert rec["status"] == "suspicious"
    assert rec["file"] == "mod/handler.ext"
    assert rec["function"] == "interstitial:1-60"
    assert rec["vuln_type"] == "CWE-79"
    assert "taint rule" in rec["hypothesis"]


def test_dark_entries_export_with_needs_validation(tmp_path):
    _journal(tmp_path, [
        _entry("a.c", "f", "dark", line_start=10,
               body="tool-blind auth bypass hypothesis"),
    ])
    graded = export_graded_from_journal(tmp_path)
    rec = graded["findings"][0]
    assert rec["status"] == "dark"
    assert rec["needs_validation"] is True


def test_latest_verdict_wins(tmp_path):
    # A corrective re-emission (suspicious -> clean) removes the
    # record from the export; the stale suspicious row must not ride.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious"),
        _entry("a.c", "f", "clean"),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["stats"]["total"] == 0
    assert (tmp_path / "findings-graded.json").exists()


def test_existing_export_never_overwritten(tmp_path):
    (tmp_path / "findings-graded.json").write_text(
        json.dumps({"findings": [{"id": "x"}], "stats": {"total": 1}}))
    _journal(tmp_path, [_entry("a.c", "f", "suspicious")])
    assert export_graded_from_journal(tmp_path) is None
    data = json.loads((tmp_path / "findings-graded.json").read_text())
    assert data["findings"] == [{"id": "x"}]


def test_no_journal_writes_nothing(tmp_path):
    assert export_graded_from_journal(tmp_path) is None
    assert not (tmp_path / "findings-graded.json").exists()


def test_export_carries_journal_derivation_marker(tmp_path):
    # The reconstruction is not the orchestrator's outcome-based
    # export: the container AND each record say so, so consumers (and
    # cross-run merges that lift records out of the container) can
    # weigh the evidence chains accordingly.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", body="review body"),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["source"] == "review-journal"
    assert graded["derivation"]["unverified_rows"] == 0
    rec = graded["findings"][0]
    assert rec["provenance"]["derivation"] == "journal"


def test_unstamped_row_exports_without_tool_receipts(tmp_path):
    # The journal lives in the target-writable run dir: a hand-written
    # row claiming tool receipts must not mint confirmed_by receipts
    # or confidence=high — receipts require a verifying row MAC (the
    # in-session record gate enforced tool grounding at record time,
    # and the MAC proves this install's writer recorded the row in
    # some run).
    import json as _json
    row = {
        "ts": now_iso(), "run_id": "run1", "file": "a.c",
        "function": "f", "verdict": "finding", "source_hash": "",
        "line_start": 5, "line_end": 30, "cwe": "CWE-89",
        "evidence_tools": ["codeql", "semgrep"],
        "body": "claims a tool-confirmed flow",
        "schema_version": 1,
    }
    (tmp_path / "review-journal.jsonl").write_text(
        _json.dumps(row) + "\n")
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["unverified_rows"] == 1
    rec = graded["findings"][0]
    assert rec["discovery"]["confirmed_by"] == []
    assert rec["discovery"]["evidence_tool"] == "none"
    assert rec["confidence"] != "high"


def test_stamped_row_keeps_tool_receipts(tmp_path):
    # Control: a row the journal writer recorded (MAC verifies) keeps
    # its journaled evidence stamp — the receipts were correlated at
    # record time.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", line_start=5,
               body="executed rule confirms flow",
               evidence_tools=["semgrep"], cwe="CWE-79"),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["unverified_rows"] == 0
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "semgrep"


@pytest.fixture(scope="module")
def helper_module():
    """Import the validate helper CLI (no .py suffix)."""
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_validation_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_later_import_sees_the_graded_record(tmp_path, helper_module):
    """End of the hand-off: the /validate findings import recognises
    the journal-derived container shape."""
    _journal(tmp_path, [
        _entry("mod/handler.ext", "interstitial:1-60", "suspicious",
               line_start=1, body="confirmed flow",
               evidence_tools=["semgrep"]),
    ])
    export_graded_from_journal(tmp_path)
    data = json.loads((tmp_path / "findings-graded.json").read_text())
    container, note = helper_module._coerce_findings_container(data)
    assert container is not None
    assert len(container["findings"]) == 1
    assert container["findings"][0]["file"] == "mod/handler.ext"
