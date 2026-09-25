"""Run-level journal merge: root AND one-level tool subdirs.

Producers write journals where they run — /audit at the run root,
/agentic's analysis agent under ``autonomous/``. The run-completion
merge must pick up both, matching the one-level-subdir convention the
coverage-record loader already uses.
"""

import core.coverage.journal as journal_mod
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_index,
    merge_into_index,
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


class TestMergeCap:
    """The per-run merge cap counts DISTINCT index identities, not raw
    rows: the merge is latest-wins per ``index_key``, so non-latest
    siblings are collapsed (losslessly) before the cap, and duplicate
    re-emission rows can no longer crowd a distinct identity's only
    row out of the newest-N window."""

    def test_duplicates_collapse_before_cap_bites(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 3)
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        # One old distinct identity, then a newer identity re-emitted
        # three times (same index_key, monotone ts): 4 rows > cap.
        append_entry(run, _entry("old_fn"))
        for _ in range(3):
            append_entry(run, _entry("hot_fn"))

        merge_into_index(project, run)

        idx = load_index(project)
        assert "src/a.c:old_fn" in idx, (
            "duplicate rows crowded a distinct identity out of the "
            "merge window"
        )
        assert "src/a.c:hot_fn" in idx

    def test_under_cap_merges_everything_silently(
        self, tmp_path, monkeypatch, caplog,
    ):
        import logging
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 3)
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        for name in ("a_fn", "b_fn", "c_fn"):
            append_entry(run, _entry(name))

        with caplog.at_level(logging.WARNING):
            assert merge_into_index(project, run) == 3
        assert set(load_index(project)) == {
            "src/a.c:a_fn", "src/a.c:b_fn", "src/a.c:c_fn",
        }
        assert not any("merging only the newest" in r.message
                       for r in caplog.records)

    def test_over_cap_distinct_identities_truncate_loudly(
        self, tmp_path, monkeypatch, caplog,
    ):
        import logging
        monkeypatch.setattr(journal_mod, "_MAX_MERGE_ENTRIES", 2)
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        for name in ("oldest_fn", "mid_fn", "newest_fn"):
            append_entry(run, _entry(name))

        with caplog.at_level(logging.WARNING):
            merge_into_index(project, run)

        idx = load_index(project)
        assert "src/a.c:oldest_fn" not in idx
        assert "src/a.c:mid_fn" in idx
        assert "src/a.c:newest_fn" in idx
        assert any(
            "distinct entry identities" in r.message
            and "NOT reach the project index" in r.message
            for r in caplog.records
        )


def test_flock_refuses_planted_symlink_sidecar(tmp_path, caplog):
    """A planted symlink at the .lock sidecar must not be created
    through (O_NOFOLLOW): degrade to the no-lock path with a loud
    warning — same treatment as the store's coverage_store_lock."""
    import logging

    from core.coverage.journal import _flock

    victim = tmp_path / "victim"
    idx = tmp_path / "journal-index.json"
    (tmp_path / "journal-index.json.lock").symlink_to(victim)
    entered = False
    with caplog.at_level(logging.WARNING):
        with _flock(idx):
            entered = True
    assert entered
    assert not victim.exists(), "flock followed the planted symlink"
    assert any("WITHOUT cross-process lock" in r.message
               for r in caplog.records)
