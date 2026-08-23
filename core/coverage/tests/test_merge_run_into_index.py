"""Run-level journal merge: root AND one-level tool subdirs.

Producers write journals where they run — /audit at the run root,
/agentic's analysis agent under ``autonomous/``. The run-completion
merge must pick up both, matching the one-level-subdir convention the
coverage-record loader already uses.
"""

from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_index,
    merge_run_into_index,
    now_iso,
)


def _entry(function: str, run_id: str = "agentic_1") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id=run_id,
        file="src/a.c",
        function=function,
        verdict="clean",
        source_hash="",
        producer="agentic",
    )


def test_merges_root_and_tool_subdir_journals(tmp_path):
    project = tmp_path / "project"
    run = project / "agentic_1"
    autonomous = run / "autonomous"
    autonomous.mkdir(parents=True)
    append_entry(run, _entry("root_fn"))
    append_entry(autonomous, _entry("analysed_fn"))

    merged = merge_run_into_index(project, run)

    assert merged == 2
    assert set(load_index(project)) == {
        "src/a.c:root_fn", "src/a.c:analysed_fn",
    }


def test_subdir_only_journal_still_merges(tmp_path):
    """The /agentic default: no root journal, entries in autonomous/."""
    project = tmp_path / "project"
    run = project / "agentic_1"
    autonomous = run / "autonomous"
    autonomous.mkdir(parents=True)
    append_entry(autonomous, _entry("analysed_fn"))

    assert merge_run_into_index(project, run) == 1
    assert set(load_index(project)) == {"src/a.c:analysed_fn"}


def test_no_journals_is_a_noop(tmp_path):
    project = tmp_path / "project"
    run = project / "run1"
    (run / "scan").mkdir(parents=True)

    assert merge_run_into_index(project, run) == 0
    assert load_index(project) == {}


def test_missing_run_dir_is_tolerated(tmp_path):
    assert merge_run_into_index(tmp_path, tmp_path / "gone") == 0


def test_second_level_journals_not_merged(tmp_path):
    """One level only — mirrors load_records' glob depth."""
    project = tmp_path / "project"
    run = project / "run1"
    deep = run / "autonomous" / "nested"
    deep.mkdir(parents=True)
    append_entry(deep, _entry("too_deep"))

    assert merge_run_into_index(project, run) == 0
