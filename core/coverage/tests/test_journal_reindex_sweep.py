"""Project-wide journal reindex sweep — one command heals the index.

Live motivation: healing a skew-damaged project index took TWO manual
``journal reindex <run-dir>`` invocations, because the tampered index
rows' intact source of truth was a PRIOR run's journal — the current
run re-merged as a no-op and the broken rows stayed. The sweep form
(``journal reindex --project <name>``) re-projects EVERY run of the
project through the same single-run merge path, oldest→newest, so one
command converges the index to what the original chronological
run-completion merges would have produced.

Headline: ``TestSweepCli.test_sweep_heals_what_single_reindex_cannot``
reproduces the incident shape — intact truth in the OLDER run, index
damaged, single reindex of the newest run leaves the damage in place,
one sweep heals it.
"""

import json
from pathlib import Path

from core.coverage import journal_mac
from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    merge_run_into_index,
    now_iso,
)


def _entry(function: str = "check_pw", *, file: str = "src/a.c",
           body: str = "reviewed, no concern",
           ts: str | None = None) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=ts or now_iso(),
        run_id="run_1",
        file=file,
        function=function,
        verdict="clean",
        source_hash="deadbeef",
        body=body,
        producer="audit",
    )


def _raw_index_rows(project: Path) -> dict:
    data = json.loads(
        (project / INDEX_FILENAME).read_text(encoding="utf-8"))
    return data["entries"]


def _rewrite_journal_row(run_dir: Path, mutate) -> dict:
    """Rewrite the single-row run journal through ``mutate(row)`` and
    return the mutated row (token re-minted over the mutated shape
    unless ``mutate`` says otherwise by returning False)."""
    path = run_dir / "review-journal.jsonl"
    row = json.loads(path.read_text(encoding="utf-8").strip())
    remint = mutate(row)
    if remint is not False:
        row.pop(journal_mac.TOKEN_KEY, None)
        token = journal_mac.mint_row(row)
        assert token, "test key must be usable"
        row[journal_mac.TOKEN_KEY] = token
    path.write_text(
        json.dumps(row, separators=(",", ":")) + "\n", encoding="utf-8")
    return row


def _damage_stored_copy(project: Path, function: str) -> str:
    """Damage the index's stored copy of *function*'s row the way the
    skew event did: drop a stamped field, keep the token verbatim."""
    path = project / INDEX_FILENAME
    data = json.loads(path.read_text(encoding="utf-8"))
    matches = [k for k in data["entries"] if f":{function}:" in k]
    assert len(matches) == 1, matches
    key = matches[0]
    broken = data["entries"][key]
    assert broken.pop("body", None) is not None
    assert not journal_mac.verify_row(broken, broken[journal_mac.TOKEN_KEY])
    path.write_text(
        json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    return key


class TestMergeStats:
    """Optional ``stats`` out-param on the merge: a caller-visible
    mirror of the strip/heal log disclosures, accumulated so a sweep
    threads one dict through many merges."""

    def test_stats_reports_healed(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        assert merge_into_index(project, run) == 1
        _damage_stored_copy(project, "check_pw")

        stats: dict[str, int] = {}
        assert merge_into_index(project, run, stats=stats) == 1
        assert stats == {"stripped": 0, "healed": 1}

    def test_stats_reports_stripped(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())

        def edit(row):
            row["body"] = "edited after stamping"
            return False  # keep the stale token

        _rewrite_journal_row(run, edit)

        stats: dict[str, int] = {}
        assert merge_into_index(project, run, stats=stats) == 1
        assert stats == {"stripped": 1, "healed": 0}

    def test_stats_accumulate_across_calls(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        assert merge_into_index(project, run) == 1
        _damage_stored_copy(project, "check_pw")

        stats: dict[str, int] = {}
        merge_into_index(project, run, stats=stats)   # heals once
        merge_into_index(project, run, stats=stats)   # clean no-op
        assert stats == {"stripped": 0, "healed": 1}

    def test_merge_run_into_index_threads_stats_to_subdirs(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        sub = run / "autonomous"
        sub.mkdir(parents=True)
        append_entry(run, _entry("root_fn"))
        append_entry(sub, _entry("sub_fn"))
        assert merge_run_into_index(project, run) == 2
        _damage_stored_copy(project, "root_fn")
        _damage_stored_copy(project, "sub_fn")

        stats: dict[str, int] = {}
        assert merge_run_into_index(project, run, stats=stats) == 2
        assert stats == {"stripped": 0, "healed": 2}

    def test_omitting_stats_is_the_existing_contract(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        assert merge_into_index(project, run) == 1
        assert merge_into_index(project, run) == 0

    def test_stats_disclose_a_journal_that_yields_no_rows(self, tmp_path):
        """A non-empty journal whose every line is malformed loads as
        zero entries with only a log warning — the return value reads
        as 'nothing to merge'. The stats channel must disclose it, or
        a sweep reports the run as a clean no-op."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        (run / JOURNAL_FILENAME).write_text("{ not json\n",
                                            encoding="utf-8")
        stats: dict[str, int] = {}
        assert merge_into_index(project, run, stats=stats) == 0
        assert stats.get("unreadable") == 1

    def test_stats_disclose_a_journal_that_refuses_the_open(self, tmp_path):
        """Refused-open shape (journal path is a directory — the same
        loader arm covers permission-denied): incomplete load, zero
        rows; must reach the stats disclosure."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        (run / JOURNAL_FILENAME).mkdir()
        stats: dict[str, int] = {}
        assert merge_into_index(project, run, stats=stats) == 0
        assert stats.get("unreadable") == 1

    def test_stats_report_no_unreadable_for_absent_or_healthy(self, tmp_path):
        project = tmp_path / "project"
        run_absent = project / "run_1"
        run_absent.mkdir(parents=True)
        run_ok = project / "run_2"
        run_ok.mkdir(parents=True)
        append_entry(run_ok, _entry())
        stats: dict[str, int] = {}
        assert merge_into_index(project, run_absent, stats=stats) == 0
        assert merge_into_index(project, run_ok, stats=stats) == 1
        assert stats.get("unreadable", 0) == 0
