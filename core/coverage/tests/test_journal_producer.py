"""Producer-kind resolution: which tool wrote a journal entry, and
whether it counts as a function-grade review.

/audit entries are function-grade (may suppress gaps, may be reused);
/agentic entries are finding-grade (one scanner finding analysed — never
a function review). The kind must resolve identically for the coverage
importer's tool label and the audit gap fold, and the function-grade
index collapse must not let a newer finding-grade entry shadow an older
audit verdict.
"""

from core.coverage.journal import (
    ReviewJournalEntry,
    entry_producer,
    is_function_grade,
    latest_function_grade_index,
    merge_into_index,
    now_iso,
)


def _entry(
    *,
    producer=None,
    run_id="audit_20260101_000000",
    verdict="clean",
    file="src/a.c",
    function="f",
    ts=None,
    strategies=None,
) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=ts or now_iso(),
        run_id=run_id,
        file=file,
        function=function,
        verdict=verdict,
        source_hash="",
        producer=producer,
        strategies=strategies or [],
    )


class TestEntryProducer:
    def test_explicit_producer_wins(self):
        assert entry_producer(_entry(producer="agentic")) == "agentic"
        assert entry_producer(_entry(producer="audit",
                                     run_id="agentic_x")) == "audit"

    def test_legacy_agentic_prefixes(self):
        assert entry_producer(_entry(run_id="agentic_20260101")) == "agentic"
        assert entry_producer(_entry(run_id="scan_20260101")) == "agentic"

    def test_legacy_default_is_audit(self):
        assert entry_producer(_entry(run_id="audit_20260101")) == "audit"
        assert entry_producer(_entry(run_id="")) == "audit"
        assert entry_producer(_entry(run_id="myproject_run")) == "audit"


class TestIsFunctionGrade:
    def test_audit_entries_are_function_grade(self):
        assert is_function_grade(_entry(producer="audit"))
        assert is_function_grade(_entry(run_id="audit_x"))

    def test_agentic_entries_are_finding_grade(self):
        assert not is_function_grade(_entry(producer="agentic"))
        assert not is_function_grade(_entry(run_id="agentic_x"))

    def test_validate_entries_are_finding_grade(self):
        """Feedback-written entries for functions no audit reviewed:
        one validated finding is not a function review."""
        assert not is_function_grade(_entry(producer="validate"))
        # Never inferred from run_id — explicit stamp only.
        assert is_function_grade(_entry(run_id="validate_20260101"))


class TestLatestFunctionGradeIndex:
    def test_finding_grade_entries_excluded(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        from core.coverage.journal import append_entry
        append_entry(run, _entry(producer="agentic", verdict="suspicious"))
        merge_into_index(project, run)

        assert latest_function_grade_index(project) == {}

    def test_newer_agentic_entry_does_not_shadow_audit_verdict(
        self, tmp_path,
    ):
        """The plain load_index collapse keeps the newest entry of any
        kind; the function-grade collapse must keep the audit verdict
        even when an /agentic analysis is more recent."""
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        from core.coverage.journal import append_entry, load_index
        audit = _entry(producer="audit", verdict="clean")
        append_entry(run, audit)
        newer = _entry(producer="agentic", verdict="suspicious")
        assert newer.ts > audit.ts
        append_entry(run, newer)
        merge_into_index(project, run)

        collapsed = latest_function_grade_index(project)
        assert set(collapsed) == {"src/a.c:f"}
        assert collapsed["src/a.c:f"].verdict == "clean"
        assert entry_producer(collapsed["src/a.c:f"]) == "audit"
        # And the shadowing premise holds on the plain collapse (the
        # two entries share model + empty-strategy index keys only when
        # producers differ on ts — assert the plain view disagrees so
        # this test fails loudly if load_index grows kind-awareness).
        plain = load_index(project)
        assert plain["src/a.c:f"].verdict == "suspicious"

    def test_multiple_functions_collapse_independently(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        from core.coverage.journal import append_entry
        append_entry(run, _entry(function="f", producer="audit"))
        append_entry(run, _entry(function="g", producer="agentic"))
        append_entry(run, _entry(function="h", run_id="audit_x"))
        merge_into_index(project, run)

        assert set(latest_function_grade_index(project)) == {
            "src/a.c:f", "src/a.c:h",
        }
