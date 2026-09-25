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


def _entry(file: str, function: str, verdict: str,
           run_id: str = "run1", **kw) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(), run_id=run_id, file=file, function=function,
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
    # Control: a row the journal writer recorded IN THIS RUN (MAC
    # verifies and the MAC-covered run_id names the exporting run
    # dir) keeps its journaled evidence stamp — the receipts were
    # correlated at record time.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", run_id=tmp_path.name,
               line_start=5, body="executed rule confirms flow",
               evidence_tools=["semgrep"], cwe="CWE-79"),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["unverified_rows"] == 0
    assert graded["derivation"]["foreign_run_rows"] == 0
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "semgrep"
    assert "receipt_scope" not in rec["provenance"]


def test_replayed_row_from_sibling_run_exports_without_receipts(tmp_path):
    # A writer-minted row byte-copied across run dirs still verifies
    # under the install-scoped MAC, but its MAC-covered run_id names
    # the ORIGIN run — the receipt run-scope gate strips its tool
    # receipts (and the high confidence they mint) in the destination.
    run_a = tmp_path / "runA"
    run_b = tmp_path / "runB"
    run_a.mkdir()
    run_b.mkdir()
    _journal(run_a, [
        _entry("a.c", "target", "suspicious", run_id="runA",
               line_start=5, body="genuine sweep-backed suspicion",
               evidence_tools=["semgrep"], cwe="CWE-89"),
    ])
    line = (run_a / "review-journal.jsonl").read_text()
    (run_b / "review-journal.jsonl").write_text(line)
    graded = export_graded_from_journal(run_b)
    assert graded["derivation"]["unverified_rows"] == 0
    assert graded["derivation"]["foreign_run_rows"] == 1
    rec = graded["findings"][0]
    assert rec["discovery"]["confirmed_by"] == []
    assert rec["discovery"]["evidence_tool"] == "none"
    assert rec["confidence"] != "high"
    # The origin run still exports its own row with full receipts.
    graded_a = export_graded_from_journal(run_a)
    assert graded_a["findings"][0]["discovery"]["evidence_tool"] \
        == "semgrep"


def test_replayed_tampered_row_still_detected(tmp_path):
    # Field-tamper detection is unchanged by the run-scope gate: an
    # edited replay demotes to the unverified tier, not the foreign
    # tier.
    import json as _json
    run_a = tmp_path / "runA"
    run_b = tmp_path / "runB"
    run_a.mkdir()
    run_b.mkdir()
    _journal(run_a, [
        _entry("a.c", "target", "finding", run_id="runB",
               line_start=5, evidence_tools=["codeql"]),
    ])
    row = _json.loads((run_a / "review-journal.jsonl").read_text())
    row["line_start"] = 999   # edit AFTER stamping; run_id even matches
    (run_b / "review-journal.jsonl").write_text(_json.dumps(row) + "\n")
    graded = export_graded_from_journal(run_b)
    assert graded["derivation"]["unverified_rows"] == 1
    assert graded["derivation"]["foreign_run_rows"] == 0
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "none"


def test_relative_out_dir_keeps_same_run_receipts(tmp_path, monkeypatch):
    # Fail-direction pin: a relative out_dir spelling ("." from
    # --out .) has Path(".").name == "" — unresolved, that identity
    # demoted every SAME-RUN row to the foreign tier. The identity is
    # resolved first.
    run = tmp_path / "runX"
    run.mkdir()
    _journal(run, [
        _entry("a.c", "f", "suspicious", run_id="runX",
               line_start=5, evidence_tools=["semgrep"]),
    ])
    monkeypatch.chdir(run)
    graded = export_graded_from_journal(Path("."))
    assert graded["derivation"]["foreign_run_rows"] == 0
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "semgrep"
    assert "receipt_scope" not in rec["provenance"]


def test_relative_out_dir_never_run_scopes_unattributed_rows(
        tmp_path, monkeypatch):
    # The other inverted direction: with an empty identity, a
    # run_id="" row compared EQUAL and graded run-scoped — receipts
    # with no marker. It must stay in the marked grandfather tier.
    run = tmp_path / "runY"
    run.mkdir()
    _journal(run, [
        _entry("a.c", "f", "suspicious", run_id="",
               line_start=5, evidence_tools=["semgrep"]),
    ])
    monkeypatch.chdir(run)
    graded = export_graded_from_journal(Path("."))
    assert graded["derivation"]["unscoped_run_rows"] == 1
    rec = graded["findings"][0]
    assert rec["provenance"]["receipt_scope"] == "install"


def test_unattributed_verified_row_grandfathers_with_marker(tmp_path):
    # A verified row with NO run attribution (legacy writer stamped
    # run_id="") keeps its receipts — stripping every legacy receipt
    # would regress honest old exports — but the grandfather is
    # marked per record and counted per container so downstream can
    # weigh it.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", run_id="",
               line_start=5, evidence_tools=["semgrep"]),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["unscoped_run_rows"] == 1
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "semgrep"
    assert rec["provenance"]["receipt_scope"] == "install"


def test_unattributed_sentinel_row_grandfathers_at_install_tier(tmp_path):
    # The record CLI's documented no-attribution sentinel is the
    # OTHER spelling of run_id="": rows stamped before the CLI
    # resolved a relative --out spelling all carry it. It says "this
    # row names no run", not "this row names another run" — the
    # marked install tier, never the foreign arm's receipt strip and
    # replay warning.
    from core.coverage.journal import RUN_ID_UNATTRIBUTED

    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", run_id=RUN_ID_UNATTRIBUTED,
               line_start=5, evidence_tools=["semgrep"]),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["foreign_run_rows"] == 0
    assert graded["derivation"]["unscoped_run_rows"] == 1
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "semgrep"
    # Never run-scoped either: the grandfather stays visibly marked.
    assert rec["provenance"]["receipt_scope"] == "install"


def test_tampered_sentinel_row_still_demotes_to_unverified(tmp_path):
    # The sentinel tier sits BEHIND the integrity check: an edited
    # sentinel row demotes to the unverified arm, receipts stripped —
    # the grandfather never launders a tampered row.
    from core.coverage.journal import RUN_ID_UNATTRIBUTED

    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", run_id=RUN_ID_UNATTRIBUTED,
               line_start=5, evidence_tools=["semgrep"]),
    ])
    journal = tmp_path / "review-journal.jsonl"
    row = json.loads(journal.read_text())
    row["line_start"] = 999
    journal.write_text(json.dumps(row) + "\n")
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["unverified_rows"] == 1
    assert graded["derivation"]["unscoped_run_rows"] == 0
    assert graded["findings"][0]["discovery"]["evidence_tool"] == "none"


def test_sentinel_lookalike_run_id_stays_foreign(tmp_path):
    # Exact match only: anything that is not the sentinel (or empty)
    # is a run attribution, and one that does not name THIS run keeps
    # failing toward the foreign arm — the grandfather widens nothing
    # for named runs.
    _journal(tmp_path, [
        _entry("a.c", "f", "suspicious", run_id="cli-record-2",
               line_start=5, evidence_tools=["semgrep"]),
    ])
    graded = export_graded_from_journal(tmp_path)
    assert graded["derivation"]["foreign_run_rows"] == 1
    assert graded["derivation"]["unscoped_run_rows"] == 0
    assert graded["findings"][0]["discovery"]["evidence_tool"] == "none"


def _load_record_cli():
    loader = SourceFileLoader(
        "raptor_audit_cli_export_roundtrip",
        str(REPO_ROOT / "libexec" / "raptor-audit"))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_export_roundtrip", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_record_out_dot_round_trips_with_receipts(tmp_path, monkeypatch):
    # Producer↔consumer identity pin: `record --out .` from inside
    # the run dir must stamp the RESOLVED basename — the exact
    # identity the export compares against — so the run's own record
    # round-trips run-scoped with receipts intact (no install marker,
    # no foreign arm). Unresolved, the producer stamped the
    # no-attribution sentinel for every relative --out spelling.
    from types import SimpleNamespace

    from core.audit.record import append_audit_log

    mod = _load_record_cli()
    out_dir = tmp_path / "runQ"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "int foo(char *p) { return p[0]; }\n")
    append_audit_log(out_dir, {
        "action": "context", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
    })
    append_audit_log(out_dir, {
        "action": "sweep", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
        "tool": "dynamic:crash", "outcome": "confirmed",
    })
    monkeypatch.chdir(out_dir)
    rc = mod.cmd_record(SimpleNamespace(
        out=".", target=str(target), file="src/a.c", function="foo",
        status="finding", body="dynamic crash replay output",
        line_start=None, line_end=None, cwe=None, strategies=None,
        evidence_tool="dynamic:crash",
        hypothesis="if input reaches memcpy unbounded, CWE-787",
        vuln_type="buffer_overflow", related_to=None,
        reach_via="exported API",
    ))
    assert rc == 0
    row = json.loads(
        (out_dir / "review-journal.jsonl").read_text().splitlines()[-1])
    assert row["run_id"] == "runQ"
    graded = export_graded_from_journal(Path("."))
    assert graded["derivation"]["foreign_run_rows"] == 0
    assert graded["derivation"]["unscoped_run_rows"] == 0
    rec = graded["findings"][0]
    assert rec["discovery"]["evidence_tool"] == "dynamic:crash"
    # Run-scoped, not grandfathered: no install marker.
    assert "receipt_scope" not in rec["provenance"]


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
