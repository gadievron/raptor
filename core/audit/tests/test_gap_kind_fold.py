"""Kind-aware gap folding: finding-grade journal entries never suppress.

/agentic's per-finding analyses land in the same journal/index as
/audit's function reviews. Analysing one scanner finding is not a
function review, so those entries must not satisfy the gap fold —
regardless of hash verifiability, verdict-reuse mode, or which entry
is newest. Function-grade (/audit) entries keep the existing hash-aware
suppression and reuse semantics.
"""

from __future__ import annotations

from core.audit.gaps import compute_gaps
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [{
                "name": "check_pw",
                "kind": "function",
                "line_start": 1,
                "line_end": 5,
            }],
        }],
    }


def _entry(*, producer, run_id, verdict="clean", source_hash="", ts=None):
    return ReviewJournalEntry(
        ts=ts or now_iso(),
        run_id=run_id,
        file="auth.c",
        function="check_pw",
        verdict=verdict,
        source_hash=source_hash,
        line_start=1,
        line_end=5,
        producer=producer,
    )


def _project_with(tmp_path, *entries):
    project = tmp_path / "project"
    run_dir = project / "run1"
    run_dir.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        append_entry(run_dir, entry)
    merge_into_index(project, run_dir)
    return project


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestFindingGradeNeverSuppresses:
    def test_agentic_index_entry_does_not_suppress(self, tmp_path):
        """Hash-less (unverifiable) agentic entry: pre-kind-gate this
        silently suppressed the gap. It must resurface."""
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(producer="agentic", run_id="run1"),
        )
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_hash_verified_agentic_entry_does_not_reuse(self, tmp_path):
        """Hash-verified agentic entry with reuse enabled: must neither
        suppress nor land in the reuse sink."""
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with(
            tmp_path,
            _entry(producer="agentic", run_id="run1", source_hash=stored),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project, reuse_sink=sink,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert sink == {}

    def test_legacy_agentic_run_id_does_not_suppress(self, tmp_path):
        """Legacy entries without the producer stamp resolve via the
        run_id prefix heuristic."""
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(producer=None, run_id="agentic_20260101"),
        )
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_agentic_entry_in_own_run_journal_does_not_suppress(
        self, tmp_path,
    ):
        """Per-run fold (out_dir journal): a finding-grade entry in the
        run's own journal must not mark the function reviewed."""
        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        append_entry(out_dir, _entry(producer="agentic", run_id="run1"))
        gaps = compute_gaps(_checklist(target), [], out_dir=out_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestFunctionGradeKeepsSemantics:
    def test_audit_entry_still_suppresses(self, tmp_path):
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with(
            tmp_path,
            _entry(producer="audit", run_id="run1", source_hash=stored),
        )
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_newer_agentic_entry_does_not_unsuppress_audit_verdict(
        self, tmp_path,
    ):
        """The plain latest-per-function index collapse would let a
        newer finding-grade entry shadow the audit verdict; the
        function-grade collapse must keep the suppression."""
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        audit = _entry(
            producer="audit", run_id="run1", source_hash=stored,
        )
        newer = _entry(
            producer="agentic", run_id="run1", verdict="suspicious",
        )
        assert newer.ts > audit.ts
        project = _project_with(tmp_path, audit, newer)
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_audit_entry_in_own_run_journal_still_suppresses(
        self, tmp_path,
    ):
        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        append_entry(out_dir, _entry(producer="audit", run_id="run1"))
        gaps = compute_gaps(_checklist(target), [], out_dir=out_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)
