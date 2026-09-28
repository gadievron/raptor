"""Index-merge provenance discipline: verify-before-write + repair.

The merge round-trips journal rows through this checkout's dataclass.
That round-trip is lossy for any field the checkout does not know
(additive fields from a newer writer — the tolerant-reader contract),
so carrying the row's MAC token verbatim over the reduced copy mints
an index row every future fold reads as TAMPERED: an honest row
permanently loses verdict-reuse authority. Two rules close the class:

* verify-before-write — a token that does not verify over the exact
  dict being persisted is STRIPPED (honest-unstamped, never
  fake-tampered);
* same-``ts`` repair tie-break — a verifying incoming row replaces a
  same-key, same-``ts`` stored copy whose token is absent or failing,
  so re-merging the intact run journal heals a skew-damaged index.
"""

import json
import os
from pathlib import Path

import pytest

from core.coverage import journal_mac
from core.coverage.journal import (
    INDEX_FILENAME,
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _entry(function: str = "check_pw") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run_1",
        file="src/a.c",
        function=function,
        verdict="clean",
        source_hash="deadbeef",
        body="reviewed, no concern",
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


class TestVerifyBeforeWrite:
    def test_healthy_row_token_survives_and_verifies(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())

        assert merge_into_index(project, run) == 1

        (row,) = _raw_index_rows(project).values()
        token = row.get(journal_mac.TOKEN_KEY)
        assert token
        assert journal_mac.verify_row(row, token)

    def test_lossy_roundtrip_strips_token_instead_of_indexing_tampered(
        self, tmp_path, caplog,
    ):
        """The version-skew class, simulated forward: a newer writer
        stamped a field this checkout's dataclass does not know. The
        tolerant reader drops the field, so the token can no longer
        verify over the merged shape — the merge must strip it, not
        persist a row the fold reads as tampered."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        # Future-writer row: an unknown additive field covered by a
        # freshly minted token (mirrors body_offload before this
        # checkout learned it).
        _rewrite_journal_row(
            run, lambda row: row.__setitem__("future_field", [1, 2, 3]))

        with caplog.at_level("WARNING"):
            assert merge_into_index(project, run) == 1

        (row,) = _raw_index_rows(project).values()
        assert journal_mac.TOKEN_KEY not in row
        assert "future_field" not in row  # the round-trip IS lossy
        assert any(
            "token stripped" in r.message for r in caplog.records
        ), "the strip must be loud"

    def test_already_tampered_row_lands_unstamped_too(self, tmp_path):
        """A genuinely edited row (content changed, token stale) takes
        the same strip: the index never stores a token its own row
        cannot satisfy."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())

        def edit(row):
            row["body"] = "edited after stamping"
            return False  # keep the stale token

        _rewrite_journal_row(run, edit)

        assert merge_into_index(project, run) == 1
        (row,) = _raw_index_rows(project).values()
        assert journal_mac.TOKEN_KEY not in row

    def test_key_outage_carries_tokens_verbatim(self, tmp_path):
        """A transient unusable MAC key must not durably unstamp
        honest rows: verify cannot distinguish "no usable key" from
        "bad token", so under an outage the merge carries tokens
        verbatim (the pre-rule posture) and the rows verify again
        the moment the key is back."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())

        key_file = (Path(os.environ["XDG_DATA_HOME"])
                    / "raptor" / "journal-mac.key")
        key_file.chmod(0o644)          # group-readable keys refused
        assert not journal_mac.key_usable()
        assert merge_into_index(project, run) == 1

        (row,) = _raw_index_rows(project).values()
        token = row.get(journal_mac.TOKEN_KEY)
        assert token, "outage merge must carry the token verbatim"

        key_file.chmod(0o600)          # outage over — key restored
        assert journal_mac.key_usable()
        assert journal_mac.verify_row(row, token)


def _seed_broken_index_copy(project: Path, run: Path) -> str:
    """Project the run's single row into the index, then damage the
    STORED copy the way the skew event did: drop a stamped field,
    keep the token verbatim."""
    assert merge_into_index(project, run) == 1
    path = project / INDEX_FILENAME
    data = json.loads(path.read_text(encoding="utf-8"))
    (key,) = data["entries"]
    broken = data["entries"][key]
    assert broken.pop("body", None) is not None
    token = broken[journal_mac.TOKEN_KEY]
    assert not journal_mac.verify_row(broken, token)
    path.write_text(
        json.dumps(data, separators=(",", ":")) + "\n",
        encoding="utf-8")
    return key


class TestSameTsRepair:
    def test_verifying_copy_replaces_broken_same_ts_row(
        self, tmp_path, caplog,
    ):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        key = _seed_broken_index_copy(project, run)

        with caplog.at_level("INFO"):
            assert merge_into_index(project, run) == 1

        row = _raw_index_rows(project)[key]
        token = row.get(journal_mac.TOKEN_KEY)
        assert token
        assert journal_mac.verify_row(row, token)
        assert row.get("body") == "reviewed, no concern"
        assert any("repaired 1 row" in r.message for r in caplog.records)

    def test_remerge_of_identical_rows_is_a_noop(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())

        assert merge_into_index(project, run) == 1
        before = _raw_index_rows(project)
        assert merge_into_index(project, run) == 0
        assert _raw_index_rows(project) == before

    def test_unstamped_incoming_never_replaces_verifying_row(
        self, tmp_path,
    ):
        """No replacement authority without a verifying token: an
        unstamped same-``ts`` copy (e.g. a skewed checkout that
        stripped its own lossy token) must not evict the verified
        stored row."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        assert merge_into_index(project, run) == 1

        def strip(row):
            row.pop(journal_mac.TOKEN_KEY, None)
            return False

        _rewrite_journal_row(run, strip)

        assert merge_into_index(project, run) == 0
        (row,) = _raw_index_rows(project).values()
        assert journal_mac.TOKEN_KEY in row

    def test_broken_incoming_never_heals_broken_stored_row(
        self, tmp_path,
    ):
        """A stripped (formerly lossy) incoming row has no token, so
        it cannot claim the repair tie-break either — the stored copy
        stays until a VERIFYING copy arrives."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        key = _seed_broken_index_copy(project, run)
        # Make the incoming side lossy too (unknown stamped field →
        # strip at merge time).
        _rewrite_journal_row(
            run, lambda row: row.__setitem__("future_field", ["x"]))

        merge_into_index(project, run)

        row = _raw_index_rows(project)[key]
        token = row.get(journal_mac.TOKEN_KEY)
        assert token
        assert not journal_mac.verify_row(row, token)

    def test_older_verifying_copy_never_rewinds_newer_row(self, tmp_path):
        """The repair fires at EQUAL ``ts`` only — a verifying but
        older row must not replace a newer stored copy, broken or
        not (history is never rewound)."""
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        key = _seed_broken_index_copy(project, run)
        # Bump the STORED copy's ts past the journal row's.
        path = project / INDEX_FILENAME
        data = json.loads(path.read_text(encoding="utf-8"))
        data["entries"][key]["ts"] = "9999-12-31T23:59:59.999999Z"
        path.write_text(
            json.dumps(data, separators=(",", ":")) + "\n",
            encoding="utf-8")

        assert merge_into_index(project, run) == 0

        row = _raw_index_rows(project)[key]
        assert row["ts"].startswith("9999-")


class TestReindexCli:
    """``raptor-audit journal reindex <run-dir>`` — the operator
    remedy that re-projects a run into its pinned project's index,
    letting the same-``ts`` tie-break repair skew-damaged rows."""

    def _load_cli(self):
        import importlib.util
        from importlib.machinery import SourceFileLoader
        cli_path = str(
            Path(__file__).resolve().parents[3]
            / "libexec" / "raptor-audit",
        )
        loader = SourceFileLoader("raptor_audit_cli_reindex_test",
                                  cli_path)
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_reindex_test", loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_reindex_repairs_skew_damaged_index(
        self, tmp_path, monkeypatch, capsys,
    ):
        import core.run.metadata as metadata
        project = tmp_path / "project"
        run = project / "run_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        key = _seed_broken_index_copy(project, run)
        # Pin resolution has its own suite (core/run/tests/test_pin);
        # here the run resolves to its project directly.
        monkeypatch.setattr(
            metadata, "_journal_project_dir", lambda _rd: project)

        from types import SimpleNamespace
        cli = self._load_cli()
        rc = cli.cmd_journal(SimpleNamespace(
            journal_command="reindex", run_dir=str(run)))

        out = capsys.readouterr().out
        assert rc == 0
        assert INDEX_FILENAME in out
        assert "1 row(s) merged or repaired" in out
        row = _raw_index_rows(project)[key]
        token = row.get(journal_mac.TOKEN_KEY)
        assert token
        assert journal_mac.verify_row(row, token)

    def test_reindex_refuses_unpinned_run(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A standalone (pin-to-none) run has no project index — the
        command refuses loudly instead of guessing a parent dir."""
        import core.run.metadata as metadata
        run = tmp_path / "run_1"
        run.mkdir()
        monkeypatch.setattr(
            metadata, "_journal_project_dir", lambda _rd: None)

        from types import SimpleNamespace
        cli = self._load_cli()
        rc = cli.cmd_journal(SimpleNamespace(
            journal_command="reindex", run_dir=str(run)))

        assert rc == 1
        assert "no project" in capsys.readouterr().err

    def test_reindex_refuses_missing_dir(self, tmp_path, capsys):
        from types import SimpleNamespace
        cli = self._load_cli()
        rc = cli.cmd_journal(SimpleNamespace(
            journal_command="reindex",
            run_dir=str(tmp_path / "gone")))
        assert rc == 1
        assert "not a directory" in capsys.readouterr().err
