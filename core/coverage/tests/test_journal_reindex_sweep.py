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
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

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


@pytest.fixture()
def project_env(tmp_path, monkeypatch):
    """A real registry project whose output dir is containment-
    probeable (``coverage.json`` marks it project-shaped), so run
    pin resolution takes the same path run completion uses."""
    import core.project.project as project_mod
    registry = tmp_path / "registry"
    registry.mkdir()
    monkeypatch.setattr(project_mod, "PROJECTS_DIR", registry)
    target = tmp_path / "target"
    target.mkdir()
    proj_dir = tmp_path / "proj-out"
    manager = project_mod.ProjectManager()
    manager.create("sweeptest", str(target), output_dir=str(proj_dir))
    (proj_dir / "coverage.json").write_text("{}", encoding="utf-8")
    return SimpleNamespace(
        name="sweeptest", dir=proj_dir, manager=manager,
        registry=registry, target=target)


def _make_run(project_dir: Path, name: str) -> Path:
    run = project_dir / name
    run.mkdir(parents=True)
    return run


def _sweep(name: str):
    from core.coverage.journal_sweep import reindex_project_journals
    return reindex_project_journals(name)


def _plant_live_running_meta(run: Path, monkeypatch) -> None:
    """Stamp *run* as owned by a LIVE session: this process's real
    identity stamp (starttime + boot id checked for real), with only
    the gate's comm probe answered the way the recorded owner's
    process would answer it — the test process is pytest, not a
    claude-shaped session."""
    import core.run.metadata as metadata
    from core.project import sessions
    stamp = metadata._session_stamp(os.getpid())
    if not (stamp.get("session_start") and stamp.get("session_boot_id")):
        pytest.skip("process identity stamps unavailable here")
    monkeypatch.setattr(sessions, "_comm", lambda _pid: "claude")
    meta = {"status": "running", "session_pid": os.getpid(),
            "command": "agentic", "timestamp": now_iso(), **stamp}
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(meta), encoding="utf-8")


class TestSweepCore:
    def test_sweep_merges_every_run(self, project_env):
        run_a = _make_run(project_env.dir, "scan-20260101-000000")
        run_b = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_a, _entry("fn_a"))
        append_entry(run_b, _entry("fn_b"))

        report = _sweep(project_env.name)

        assert [o.run_name for o in report.outcomes] == [
            "scan-20260101-000000", "scan-20260102-000000"]
        assert report.total_merged == 2
        rows = _raw_index_rows(project_env.dir)
        assert len(rows) == 2

    def test_sweep_order_is_oldest_first(self, project_env):
        """Ordering pin. The one genuinely order-sensitive merge case:
        same key, EQUAL ``ts``, different bodies — the first-merged
        copy wins (an incoming row never replaces a same-``ts`` stored
        copy that verifies, nor one it cannot out-verify). Sweeping
        oldest→newest reproduces the chronology the original
        run-completion merges applied, so the index converges to the
        state it would have had absent damage: the OLDER run's copy.
        Newest→oldest would land the newer run's body instead."""
        ts = now_iso()
        run_a = _make_run(project_env.dir, "scan-20260101-000000")
        run_b = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_a, _entry("dup_fn", body="older-origin", ts=ts))
        append_entry(run_b, _entry("dup_fn", body="newer-origin", ts=ts))

        report = _sweep(project_env.name)

        assert report.total_merged == 1
        (row,) = _raw_index_rows(project_env.dir).values()
        assert row["body"] == "older-origin"

    def test_sweep_heals_prior_run_damage(self, project_env):
        """Core-level shape of the headline: intact truth in the OLDER
        run, damaged stored copy, one sweep heals it."""
        run_a = _make_run(project_env.dir, "scan-20260101-000000")
        run_b = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_a, _entry("old_fn"))
        append_entry(run_b, _entry("new_fn"))
        assert merge_into_index(project_env.dir, run_a) == 1
        assert merge_into_index(project_env.dir, run_b) == 1
        key = _damage_stored_copy(project_env.dir, "old_fn")

        report = _sweep(project_env.name)

        assert report.total_healed == 1
        row = _raw_index_rows(project_env.dir)[key]
        token = row.get(journal_mac.TOKEN_KEY)
        assert token
        assert journal_mac.verify_row(row, token)
        assert row.get("body") == "reviewed, no concern"

    def test_sweep_refuses_while_a_run_is_writing(
        self, project_env, monkeypatch,
    ):
        """Wholesale refusal BEFORE any merge when a live run owns the
        project — the sweep rewrites the shared index, and a racing
        completion merge could interleave with it. ``self_session_pid``
        is None on purpose: even this session's own runs contend."""
        from core.coverage.journal_sweep import SweepRefused
        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        _plant_live_running_meta(run, monkeypatch)

        with pytest.raises(SweepRefused) as exc:
            _sweep(project_env.name)
        assert "scan-20260101-000000" in str(exc.value)
        assert not (project_env.dir / INDEX_FILENAME).exists()

    def test_stale_running_marker_does_not_block(self, project_env):
        """Inherited stale-lock semantics: legacy metadata with no
        recorded owner pid is unverifiable — never block on what
        can't be checked (same doctrine as run-start contention)."""
        import core.run.metadata as metadata
        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        meta = {"status": "running", "timestamp": now_iso()}
        (run / metadata.RUN_METADATA_FILE).write_text(
            json.dumps(meta), encoding="utf-8")

        report = _sweep(project_env.name)
        assert report.total_merged == 1

    def test_sweep_skips_imported_runs(self, project_env):
        """Import-restored runs are quarantined wholesale, like
        ``project_run_projections`` — their journals were minted on
        the exporting machine and never re-project here."""
        from core.project.findings_utils import IMPORTED_RUN_MARKER_FILE
        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        (run / IMPORTED_RUN_MARKER_FILE).write_text(
            json.dumps({"imported": True}), encoding="utf-8")

        report = _sweep(project_env.name)

        (outcome,) = report.outcomes
        assert outcome.skipped_reason and "imported" in outcome.skipped_reason
        assert not (project_env.dir / INDEX_FILENAME).exists()

    def test_sweep_skips_runs_that_resolve_elsewhere(
        self, project_env, monkeypatch,
    ):
        """THE RUN PIN decides, per run — a run whose pin resolves to
        no project (standalone / pin-refused) or to a DIFFERENT
        project is skipped, never force-merged into this index."""
        import core.run.metadata as metadata
        run_none = _make_run(project_env.dir, "scan-20260101-000000")
        run_other = _make_run(project_env.dir, "scan-20260102-000000")
        run_ours = _make_run(project_env.dir, "scan-20260103-000000")
        for r in (run_none, run_other, run_ours):
            append_entry(r, _entry(f"fn_{r.name[-1]}"))
        elsewhere = project_env.dir.parent / "elsewhere"

        def fake_resolve(out_dir):
            out_dir = Path(out_dir).resolve()
            if out_dir == run_none.resolve():
                return None
            if out_dir == run_other.resolve():
                return elsewhere
            return project_env.dir.resolve()

        monkeypatch.setattr(
            metadata, "_journal_project_dir", fake_resolve)

        report = _sweep(project_env.name)

        by_name = {o.run_name: o for o in report.outcomes}
        assert "no project pin" in (
            by_name["scan-20260101-000000"].skipped_reason or "")
        assert "different project" in (
            by_name["scan-20260102-000000"].skipped_reason or "")
        assert by_name["scan-20260103-000000"].merged == 1
        assert len(_raw_index_rows(project_env.dir)) == 1

    def test_corrupt_index_refuses_the_sweep(self, project_env):
        """An unreadable index is the very damage class this remedy
        targets — sweeping over it must refuse loudly (naming the
        index path), never report rc-0 'nothing needed repair' while
        every merge silently declined. The refusal happens BEFORE the
        run loop; the corrupt file is left byte-identical (the
        writer's refuse-to-overwrite posture)."""
        from core.coverage.journal_sweep import SweepRefused
        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        index_path = project_env.dir / INDEX_FILENAME
        index_path.write_text("{ not json\n", encoding="utf-8")

        with pytest.raises(SweepRefused) as exc:
            _sweep(project_env.name)
        assert str(index_path) in str(exc.value)
        assert index_path.read_text(encoding="utf-8") == "{ not json\n"

    def test_unreadable_run_journal_is_disclosed_not_a_clean_no_op(
        self, project_env,
    ):
        """A run whose journal yields no rows (every line malformed)
        must surface in the report as an unreadable-journal run, not
        as a swept success with merged=0 — and it must not abort the
        other runs' re-projection."""
        run_bad = _make_run(project_env.dir, "scan-20260101-000000")
        (run_bad / JOURNAL_FILENAME).write_text("{ not json\n",
                                                encoding="utf-8")
        run_ok = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_ok, _entry())

        report = _sweep(project_env.name)

        by_name = {o.run_name: o for o in report.outcomes}
        bad = by_name["scan-20260101-000000"]
        assert bad.unreadable == 1
        assert bad.merged == 0
        assert by_name["scan-20260102-000000"].merged == 1
        assert report.unreadable_runs == 1
        assert report.total_merged == 1

    def test_permission_denied_journal_is_disclosed(self, project_env):
        """Refused-open shape via chmod 000 (skipped for root, which
        chmod does not stop)."""
        if os.geteuid() == 0:
            pytest.skip("chmod 000 does not bar root")
        run_bad = _make_run(project_env.dir, "scan-20260101-000000")
        journal = run_bad / JOURNAL_FILENAME
        journal.write_text('{"ts": "x"}\n', encoding="utf-8")
        journal.chmod(0)
        run_ok = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_ok, _entry())
        try:
            report = _sweep(project_env.name)
        finally:
            journal.chmod(0o644)

        by_name = {o.run_name: o for o in report.outcomes}
        assert by_name["scan-20260101-000000"].unreadable == 1
        assert by_name["scan-20260102-000000"].merged == 1
        assert report.unreadable_runs == 1

    def test_journal_as_directory_is_disclosed(self, project_env):
        run_bad = _make_run(project_env.dir, "scan-20260101-000000")
        (run_bad / JOURNAL_FILENAME).mkdir()
        run_ok = _make_run(project_env.dir, "scan-20260102-000000")
        append_entry(run_ok, _entry())

        report = _sweep(project_env.name)

        by_name = {o.run_name: o for o in report.outcomes}
        assert by_name["scan-20260101-000000"].unreadable == 1
        assert by_name["scan-20260102-000000"].merged == 1
        assert report.unreadable_runs == 1

    def test_unknown_project_is_a_hard_error(self, project_env):
        from core.coverage.journal_sweep import SweepRefused
        with pytest.raises(SweepRefused, match="unknown project"):
            _sweep("no-such-project")

    def test_invalid_project_name_is_a_hard_error(self, project_env):
        from core.coverage.journal_sweep import SweepRefused
        with pytest.raises(SweepRefused, match="invalid project name"):
            _sweep("../escape")

    def test_empty_project_sweeps_to_empty_report(self, project_env):
        report = _sweep(project_env.name)
        assert report.outcomes == []
        assert report.total_merged == 0
