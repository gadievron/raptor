"""Hash-aware cross-run gap folding.

Prior-run reviews (project journal index) only suppress a gap when
the journaled ``source_hash`` still matches the function's current
source. A changed function resurfaces as a gap; unchanged ones stay
covered; unverifiable entries (missing hash, missing source) keep the
historical suppression behaviour.
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

_ORIGINAL_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_CHANGED_SOURCE = """\
int check_pw(const char *pw) {
    /* validation removed */
    return strcmp(pw, stored) == 0;
    (void)0;
    (void)0;
}
"""


def _write_target(tmp_path, source=_ORIGINAL_SOURCE):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(source, encoding="utf-8")
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


def _project_with_entry(tmp_path, source_hash):
    """Create a project dir whose journal index carries one prior
    review of auth.c:check_pw with *source_hash*."""
    project = tmp_path / "project"
    run_dir = project / "run1"
    run_dir.mkdir(parents=True, exist_ok=True)
    append_entry(run_dir, ReviewJournalEntry(
        ts=now_iso(),
        run_id="run1",
        file="auth.c",
        function="check_pw",
        verdict="clean",
        source_hash=source_hash,
        line_start=1,
        line_end=5,
    ))
    merge_into_index(project, run_dir)
    return project


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestHashAwareFolding:
    def test_unchanged_function_stays_covered(self, tmp_path):
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with_entry(tmp_path, stored)

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_changed_function_resurfaces_as_gap(self, tmp_path):
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with_entry(tmp_path, stored)

        # Source changes after the prior run's review.
        (target / "auth.c").write_text(_CHANGED_SOURCE, encoding="utf-8")

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps), (
            "a function whose source changed since its journaled "
            "review must be re-reviewed, not suppressed as covered"
        )

    def test_short_prefix_hash_resurfaces(self, tmp_path):
        # Contract inverted by the journal-provenance hardening:
        # the old bidirectional prefix compare let an
        # attacker-stored 1-char "hash" match ~1/16 of real hashes, so
        # the fold now requires an EXACT full-length match. A shorter
        # prefix — even a correct one — is no longer drift evidence
        # and the function resurfaces for one re-review (its fresh
        # entry re-records the full hash).
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)[:8]
        project = _project_with_entry(tmp_path, stored)

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_missing_hash_keeps_current_behaviour_covered(self, tmp_path):
        # Documented choice: entries without a source_hash (legacy
        # journals, hash-computation failures at review time) carry no
        # drift evidence. Treating them as changed would resurface
        # every legacy review at once — so they STAY covered.
        # Post journal-MAC: this leniency applies to VERIFIED rows
        # only (the fixture appends through append_entry, which
        # stamps); an UNSTAMPED empty-hash row resurfaces — see
        # test_journal_fold_provenance.
        target = _write_target(tmp_path)
        project = _project_with_entry(tmp_path, "")

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_missing_source_file_resurfaces_as_gap(self, tmp_path):
        # Checklist references the file but it is gone from disk:
        # that IS drift (compute_drift flags the same case) — the
        # prior verdict must not stand as coverage. Pre-fix this
        # folded to covered and a deleted/renamed file's verdicts
        # were reused silently.
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with_entry(tmp_path, stored)
        (target / "auth.c").unlink()

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_no_target_path_keeps_covered(self, tmp_path):
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with_entry(tmp_path, stored)
        (target / "auth.c").write_text(_CHANGED_SOURCE, encoding="utf-8")

        checklist = _checklist(target)
        checklist.pop("target_path")
        gaps = compute_gaps(checklist, [], project_dir=project)
        # Without a target path the hash cannot be recomputed — the
        # entry keeps its historical suppression.
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_error_verdicts_still_not_folded(self, tmp_path):
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        run_dir = project / "run1"
        run_dir.mkdir(parents=True)
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="auth.c",
            function="check_pw", verdict="error",
            source_hash=hash_span(target / "auth.c", 1, 5),
        ))
        merge_into_index(project, run_dir)

        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_entry_for_function_absent_from_checklist(self, tmp_path):
        # A journaled function no longer in the inventory: nothing to
        # suppress, nothing to crash on.
        target = _write_target(tmp_path)
        project = _project_with_entry(tmp_path, "abcdef123456")
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "other.c",
                "items": [{
                    "name": "unrelated", "kind": "function",
                    "line_start": 1, "line_end": 4,
                }],
            }],
        }
        gaps = compute_gaps(checklist, [], project_dir=project)
        assert _gap_keys(gaps) == {"other.c:unrelated"}

    def test_moved_function_hashes_at_current_span(self, tmp_path):
        # The function body is unchanged but shifted down the file:
        # the fold must hash the CURRENT checklist span, not the
        # journaled one.
        target = _write_target(tmp_path)
        stored = hash_span(target / "auth.c", 1, 5)
        project = _project_with_entry(tmp_path, stored)

        (target / "auth.c").write_text(
            "/* new header comment */\n" + _ORIGINAL_SOURCE,
            encoding="utf-8",
        )
        checklist = _checklist(target)
        checklist["files"][0]["items"][0]["line_start"] = 2
        checklist["files"][0]["items"][0]["line_end"] = 6

        gaps = compute_gaps(checklist, [], project_dir=project)
        assert "auth.c:check_pw" not in _gap_keys(gaps)


_TWO_SITE_SOURCE = """\
#define SSHINT(x) ((x) + 1)
int a;
#define SSHINT(x) ((x) + 2)
int b;
"""


class TestCrossRunSameNamedSites:
    """Cross-run reuse must credit every reviewed SITE of a same-named
    item: the project index stores per-site rows (span-suffixed keys)
    and the fold collapses per site, so a new run on unchanged source
    suppresses all reviewed siblings instead of re-buying N-1 of them."""

    def _setup(self, tmp_path, reviewed_lines):
        target = tmp_path / "target"
        target.mkdir()
        (target / "conf.c").write_text(_TWO_SITE_SOURCE, encoding="utf-8")
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        for line in reviewed_lines:
            append_entry(run, ReviewJournalEntry(
                ts=now_iso(), run_id="run1",
                file="conf.c", function="SSHINT",
                verdict="clean",
                source_hash=hash_span(target / "conf.c", line, line),
                line_start=line, line_end=line,
                producer="audit",
            ))
        merge_into_index(project, run)
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "conf.c",
                "language": "c",
                "items": [
                    {"name": "SSHINT", "kind": "macro",
                     "line_start": 1, "line_end": 1},
                    {"name": "SSHINT", "kind": "macro",
                     "line_start": 3, "line_end": 3},
                ],
            }],
        }
        return checklist, project

    def test_both_reviewed_sites_stay_covered(self, tmp_path):
        checklist, project = self._setup(tmp_path, [1, 3])
        gaps = compute_gaps(checklist, [], project_dir=project)
        assert [g for g in gaps if g["name"] == "SSHINT"] == [], (
            "both sites carry hash-verified prior-run reviews — "
            "resurfacing either re-buys a paid review on every re-run"
        )

    def test_unreviewed_sibling_still_surfaces(self, tmp_path):
        checklist, project = self._setup(tmp_path, [1])
        gaps = compute_gaps(checklist, [], project_dir=project)
        leftover = [g for g in gaps if g["name"] == "SSHINT"]
        assert len(leftover) == 1, (
            "one prior-run review must suppress exactly one site; "
            "the unreviewed sibling stays a gap"
        )
