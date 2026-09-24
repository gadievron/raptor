"""``raptor-audit resume`` journal-completeness gate.

Every spend decision on a resume — the drift gate, the own-run $0
reuse import, the journal spend floor — reads the review journal.
A journal the loader cannot load COMPLETELY (over the retained-entry
budget with nothing prunable) previously read as EMPTY, so the resume
saw zero prior verdicts and re-reviewed the entire run at full price.
The gate refuses such a resume up front, naming the compaction remedy;
a journal whose excess is duplicate re-emission rows (the
resume-segment shape) prunes losslessly at load and passes.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import core.coverage.journal as journal_mod
from core.audit.resume import save_run_config
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso
from core.run.metadata import RUN_METADATA_FILE


def _load_cli():
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_cli_jgate_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_jgate_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _mk_resumable_run(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    out = tmp_path / "audit_run"
    out.mkdir()
    (out / RUN_METADATA_FILE).write_text(json.dumps({
        "command": "audit",
        "status": "interrupted",
        "target_path": str(target),
        "timestamp": "2026-09-20T00:00:00+00:00",
    }))
    save_run_config(out, {"version": 1, "target_path": str(target)})
    (out / "checklist.json").write_text('{"files": []}')
    return out


def _entry(i: int, **kwargs) -> ReviewJournalEntry:
    e = ReviewJournalEntry(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="abc123",
    )
    for k, v in kwargs.items():
        setattr(e, k, v)
    return e


def _resume_args(out: Path) -> SimpleNamespace:
    return SimpleNamespace(
        out_dir=str(out), allow_drift=False, reopen=False,
        max_cost=None, max_time=None, max_workers=None,
        no_supervisor_bound=True,
    )


def test_incomplete_journal_refuses_resume_with_remedy(
    tmp_path, monkeypatch, capsys,
):
    mod = _load_cli()
    out = _mk_resumable_run(tmp_path)
    # Distinct live rows: nothing prunable, so an over-budget journal
    # loads incomplete and the gate must refuse.
    append_entry(out, _entry(1))
    append_entry(out, _entry(2))
    size = (out / "review-journal.jsonl").stat().st_size
    monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size - 1)

    rc = mod.cmd_resume(_resume_args(out))
    assert rc == 1
    err = capsys.readouterr().err
    assert "journal compact" in err
    assert "refusing" in err.lower()


def test_prunable_journal_passes_gate(tmp_path, monkeypatch):
    mod = _load_cli()
    out = _mk_resumable_run(tmp_path)
    append_entry(out, _entry(1, cost_usd=0.5))
    for _ in range(6):
        append_entry(
            out,
            _entry(1, reused=True, reused_from_run="run-0", cost_usd=0.0),
        )
    size = (out / "review-journal.jsonl").stat().st_size
    monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size // 2)

    # Stop deterministically right AFTER the gate: the next step in
    # cmd_resume is the drift gate.
    import core.audit.resume as resume_mod

    class _Sentinel(Exception):
        pass

    def _boom(*a, **k):
        raise _Sentinel

    monkeypatch.setattr(resume_mod, "compute_drift", _boom)
    try:
        mod.cmd_resume(_resume_args(out))
    except _Sentinel:
        passed_gate = True
    else:
        passed_gate = False
    assert passed_gate, "gate refused a losslessly-prunable journal"


def test_segment_start_auto_compacts_oversized_journal(
    tmp_path, monkeypatch,
):
    """Per-segment re-emission is load-bearing (verdict_reuse: each
    run carries a complete record), so resume keeps re-emitting — and
    instead auto-compacts at the segment boundary once the journal
    passes the threshold. The newest row per identity survives; the
    original is backed up."""
    mod = _load_cli()
    out = _mk_resumable_run(tmp_path)
    append_entry(out, _entry(1, cost_usd=0.5))
    for _ in range(6):
        append_entry(
            out,
            _entry(1, reused=True, reused_from_run="run-0", cost_usd=0.0),
        )
    journal = out / "review-journal.jsonl"
    before = journal.stat().st_size
    # Threshold derives from the loader budget at call time; setting
    # the budget to the file size puts the threshold at half of it
    # (over -> auto-compact) while the loader still reads complete.
    monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", before)

    import core.audit.resume as resume_mod

    class _Sentinel(Exception):
        pass

    def _boom(*a, **k):
        raise _Sentinel

    monkeypatch.setattr(resume_mod, "compute_drift", _boom)
    try:
        mod.cmd_resume(_resume_args(out))
    except _Sentinel:
        pass
    assert journal.stat().st_size < before
    backup = out / "review-journal.jsonl.pre-compact"
    assert backup.stat().st_size == before
    # The run's asserted state is intact: one reused row survives
    # alongside the $-bearing live row.
    entries = journal_mod.load_entries(out)
    assert sum(1 for e in entries if e.reused) == 1
    assert any(e.cost_usd == 0.5 for e in entries)


def test_segment_start_under_threshold_untouched(tmp_path, monkeypatch):
    mod = _load_cli()
    out = _mk_resumable_run(tmp_path)
    append_entry(out, _entry(1))
    journal = out / "review-journal.jsonl"
    before = journal.read_bytes()

    import core.audit.resume as resume_mod

    class _Sentinel(Exception):
        pass

    def _boom(*a, **k):
        raise _Sentinel

    monkeypatch.setattr(resume_mod, "compute_drift", _boom)
    try:
        mod.cmd_resume(_resume_args(out))
    except _Sentinel:
        pass
    assert journal.read_bytes() == before
    assert not (out / "review-journal.jsonl.pre-compact").exists()
