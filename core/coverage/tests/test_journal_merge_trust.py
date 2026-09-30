"""Merge trust gate: verified stored rows refuse never-verified newer rows.

Defect (probed against the pre-fix merge, both the single-run reindex
form and the project sweep on identical fixtures): a planted
MARKER-LESS run dir inside the project tree — admitted by the legacy
containment probe — whose journal carries a FUTURE-``ts`` unstamped
row on an existing index key demoted the honest MAC-verified stored
row via plain latest-wins: the stored token vanished with the
replaced body, the row landed in the unstamped tier (no verdict
reuse), and every re-merge re-applied the demotion. ``ts`` is
self-declared writer content; a fabricated timestamp must never
outrank proven provenance.

The gate (``merge_into_index``): a stored row that POSITIVELY
verifies under this install's MAC key refuses replacement by an
incoming row that does not. Direction pins below keep every
legitimate flow intact:

* a VERIFIED newer row still replaces an older verified row (all
  locally-appended rows are stamped at ``append_entry``);
* a never-verified newer row still wins over a never-verified stored
  row (plain latest-wins — pre-MAC legacy journals keep converging);
* the same-``ts`` non-displacement and repair tie-breaks are
  untouched;
* a stored row that cannot positively verify (rotated or unusable
  key) earns no refusal authority — the merge stands down to the
  pre-gate posture rather than wedging the index on unverifiable
  state;
* incoming verification runs per row whenever a token is present —
  the merge's one-shot key-usability sample guards only the
  destructive token strip, so a stale outage sample never refuses
  an honest row that verifies.
"""

import json
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

#: Sorts above any live ``now_iso()`` stamp — the attacker's
#: self-declared "newer" timestamp.
FUTURE_TS = "2999-01-01T00:00:00.000000Z"


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


def _write_unstamped_row(run_dir: Path, entry: ReviewJournalEntry) -> None:
    """Plant *entry* as a raw journal line WITHOUT a provenance token
    — the shape any same-user writer in the project tree can mint
    (no MAC key required)."""
    row = entry.to_dict()
    assert journal_mac.TOKEN_KEY not in row
    with open(run_dir / JOURNAL_FILENAME, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")


def _single_row(project: Path) -> dict:
    (row,) = _raw_index_rows(project).values()
    return row


def _assert_verified(row: dict, body: str) -> None:
    token = row.get(journal_mac.TOKEN_KEY)
    assert token, "stored token must survive"
    assert journal_mac.verify_row(row, token)
    assert row.get("body") == body


class TestMergeTrustGate:
    def test_future_ts_unstamped_row_cannot_demote_verified_row(
        self, tmp_path,
    ):
        """HEADLINE (merge level — the single-run ``journal reindex``
        form rides this exact path): honest verified row in the index,
        planted run journal with a future-``ts`` unstamped row on the
        same key. The planted row must not merge and the stored row
        must stay verified."""
        project = tmp_path / "project"
        honest = project / "run_honest"
        honest.mkdir(parents=True)
        append_entry(honest, _entry())
        assert merge_into_index(project, honest) == 1

        planted = project / "run_planted"
        planted.mkdir()
        _write_unstamped_row(
            planted, _entry(body="planted demotion", ts=FUTURE_TS))

        assert merge_run_into_index(project, planted) == 0
        _assert_verified(_single_row(project), "reviewed, no concern")

    def test_refusal_is_disclosed_in_stats(self, tmp_path):
        """The refused replacement reaches the caller-visible stats
        channel (same contract as ``stripped``/``healed``) — a sweep
        must be able to disclose that a run's rows were refused, not
        report the run as an empty no-op."""
        project = tmp_path / "project"
        honest = project / "run_honest"
        honest.mkdir(parents=True)
        append_entry(honest, _entry())
        assert merge_into_index(project, honest) == 1

        planted = project / "run_planted"
        planted.mkdir()
        _write_unstamped_row(
            planted, _entry(body="planted demotion", ts=FUTURE_TS))

        stats: dict[str, int] = {}
        assert merge_into_index(project, planted, stats=stats) == 0
        assert stats.get("refused") == 1
        assert stats.get("stripped", 0) == 0
        assert stats.get("healed", 0) == 0

    def test_re_merge_stays_refused_and_idempotent(self, tmp_path):
        """The pre-fix demotion RE-APPLIED on every merge. Post-fix,
        re-merging the planted run is a genuine no-op: nothing merges
        and the index document does not change."""
        project = tmp_path / "project"
        honest = project / "run_honest"
        honest.mkdir(parents=True)
        append_entry(honest, _entry())
        assert merge_into_index(project, honest) == 1

        planted = project / "run_planted"
        planted.mkdir()
        _write_unstamped_row(
            planted, _entry(body="planted demotion", ts=FUTURE_TS))

        index_path = project / INDEX_FILENAME
        assert merge_run_into_index(project, planted) == 0
        after_first = index_path.read_bytes()
        assert merge_run_into_index(project, planted) == 0
        assert index_path.read_bytes() == after_first
        _assert_verified(_single_row(project), "reviewed, no concern")

    def test_verified_newer_row_still_replaces_verified_older(
        self, tmp_path,
    ):
        """Direction pin: legitimate progress is untouched — a stamped
        (verifying) newer row replaces the older verified copy, token
        intact."""
        project = tmp_path / "project"
        run_a = project / "run_a"
        run_a.mkdir(parents=True)
        append_entry(run_a, _entry(
            body="first review", ts="2026-01-01T00:00:00.000001Z"))
        assert merge_into_index(project, run_a) == 1

        run_b = project / "run_b"
        run_b.mkdir()
        append_entry(run_b, _entry(
            body="second review", ts="2026-01-01T00:00:00.000002Z"))
        assert merge_into_index(project, run_b) == 1
        _assert_verified(_single_row(project), "second review")

    def test_unverified_newer_still_wins_over_unverified_stored(
        self, tmp_path,
    ):
        """Direction pin: plain latest-wins between two never-verified
        rows is unchanged — pre-MAC legacy journals keep converging."""
        project = tmp_path / "project"
        run_a = project / "run_a"
        run_a.mkdir(parents=True)
        _write_unstamped_row(run_a, _entry(
            body="older unstamped", ts="2026-01-01T00:00:00.000001Z"))
        assert merge_into_index(project, run_a) == 1

        run_b = project / "run_b"
        run_b.mkdir()
        _write_unstamped_row(run_b, _entry(
            body="newer unstamped", ts="2026-01-01T00:00:00.000002Z"))
        assert merge_into_index(project, run_b) == 1
        row = _single_row(project)
        assert row.get("body") == "newer unstamped"
        assert journal_mac.TOKEN_KEY not in row

    def test_equal_ts_planted_row_still_never_displaces_verified(
        self, tmp_path,
    ):
        """Direction pin: the pre-existing same-``ts`` posture is
        unchanged — an incoming row never replaces a same-``ts``
        stored copy it cannot out-verify."""
        project = tmp_path / "project"
        ts = now_iso()
        honest = project / "run_honest"
        honest.mkdir(parents=True)
        append_entry(honest, _entry(ts=ts))
        assert merge_into_index(project, honest) == 1

        planted = project / "run_planted"
        planted.mkdir()
        _write_unstamped_row(planted, _entry(body="planted twin", ts=ts))
        assert merge_into_index(project, planted) == 0
        _assert_verified(_single_row(project), "reviewed, no concern")

    def test_unverifiable_stored_row_earns_no_refusal_authority(
        self, tmp_path, tmp_path_factory, monkeypatch,
    ):
        """A stored token that does not positively verify under THIS
        install's key (rotated key, foreign index) grants no refusal
        authority — the merge stands down to plain latest-wins instead
        of wedging the index on unverifiable state. (Same fail
        direction as the strip rule's key-outage posture above it: an
        unverifiable state is transient/local and must not mint
        durable authority either way.)"""
        project = tmp_path / "project"
        run_a = project / "run_a"
        run_a.mkdir(parents=True)
        append_entry(run_a, _entry(
            body="minted under old key",
            ts="2026-01-01T00:00:00.000001Z"))
        assert merge_into_index(project, run_a) == 1

        # Rotate the install key: the stored token now fails verify.
        monkeypatch.setenv(
            "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-rotated")))
        stored = _single_row(project)
        assert not journal_mac.verify_row(
            stored, stored.get(journal_mac.TOKEN_KEY))

        run_b = project / "run_b"
        run_b.mkdir()
        _write_unstamped_row(run_b, _entry(
            body="newer unstamped", ts="2026-01-01T00:00:00.000002Z"))
        assert merge_into_index(project, run_b) == 1
        assert _single_row(project).get("body") == "newer unstamped"

    def test_stale_key_outage_sample_never_refuses_verifying_row(
        self, tmp_path, monkeypatch,
    ):
        """Incoming verification is attempted per row whenever a token
        is present — it is NOT gated on the merge's one-shot
        ``key_usable()`` sample (that sample guards only the
        destructive token strip). A key that reads unusable at the
        sample but verifies by the row loop must not refuse an honest
        stamped newer row over an older verified stored copy: both of
        the gate's authority inputs observe the same live key state."""
        project = tmp_path / "project"
        run_a = project / "run_a"
        run_a.mkdir(parents=True)
        append_entry(run_a, _entry(
            body="first review", ts="2026-01-01T00:00:00.000001Z"))
        assert merge_into_index(project, run_a) == 1

        run_b = project / "run_b"
        run_b.mkdir()
        append_entry(run_b, _entry(
            body="second review", ts="2026-01-01T00:00:00.000002Z"))

        # The key itself stays fully usable (append_entry above minted
        # real, verifying tokens); only the merge's one-shot sample
        # reads False — the narrowest key-state transition.
        monkeypatch.setattr(journal_mac, "key_usable", lambda: False)
        stats: dict[str, int] = {}
        assert merge_into_index(project, run_b, stats=stats) == 1
        assert stats.get("refused", 0) == 0
        assert stats.get("stripped", 0) == 0
        _assert_verified(_single_row(project), "second review")


@pytest.fixture()
def project_env(tmp_path, monkeypatch):
    """A real registry project whose output dir is containment-
    probeable (``coverage.json`` marks it project-shaped) — the exact
    admission surface the planted marker-less dir rides."""
    import core.project.project as project_mod
    registry = tmp_path / "registry"
    registry.mkdir()
    monkeypatch.setattr(project_mod, "PROJECTS_DIR", registry)
    target = tmp_path / "target"
    target.mkdir()
    proj_dir = tmp_path / "proj-out"
    manager = project_mod.ProjectManager()
    manager.create("trusttest", str(target), output_dir=str(proj_dir))
    (proj_dir / "coverage.json").write_text("{}", encoding="utf-8")
    return SimpleNamespace(
        name="trusttest", dir=proj_dir, manager=manager,
        registry=registry, target=target)


class TestSweepTrustGate:
    """The sweep form of the probe: the planted dir is MARKER-LESS
    (no run metadata at all), admitted by the legacy containment
    probe, and reached automatically — no operator names it."""

    def test_planted_markerless_dir_cannot_demote_via_sweep(
        self, project_env,
    ):
        from core.coverage.journal_sweep import reindex_project_journals

        honest = project_env.dir / "scan-20260101-000000"
        honest.mkdir()
        append_entry(honest, _entry())

        planted = project_env.dir / "scan-20260102-000000"
        planted.mkdir()   # marker-less: no .raptor-run.json
        _write_unstamped_row(
            planted, _entry(body="planted demotion", ts=FUTURE_TS))

        report = reindex_project_journals(project_env.name)

        by_name = {o.run_name: o for o in report.outcomes}
        assert by_name["scan-20260101-000000"].merged == 1
        assert by_name["scan-20260102-000000"].merged == 0
        _assert_verified(_single_row(project_env.dir),
                         "reviewed, no concern")

        # Re-sweeping never re-applies the planted row.
        report2 = reindex_project_journals(project_env.name)
        assert report2.total_merged == 0
        _assert_verified(_single_row(project_env.dir),
                         "reviewed, no concern")

    def test_sweep_outcome_surfaces_refused(self, project_env):
        """The merge's ``stats["refused"]`` count reaches the per-run
        ``RunOutcome`` and the report total, the same channel
        ``stripped``/``healed``/``unreadable`` ride — a sweep must be
        able to say WHICH run's rows were refused, not report the run
        as an empty no-op with only a warning in the log."""
        from core.coverage.journal_sweep import reindex_project_journals

        honest = project_env.dir / "scan-20260101-000000"
        honest.mkdir()
        append_entry(honest, _entry())

        planted = project_env.dir / "scan-20260102-000000"
        planted.mkdir()
        _write_unstamped_row(
            planted, _entry(body="planted demotion", ts=FUTURE_TS))

        report = reindex_project_journals(project_env.name)

        by_name = {o.run_name: o for o in report.outcomes}
        assert by_name["scan-20260102-000000"].refused == 1
        assert by_name["scan-20260102-000000"].merged == 0
        assert by_name["scan-20260101-000000"].refused == 0
        assert report.total_refused == 1
