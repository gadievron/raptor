"""Compaction should reclaim its own scratch without multiplying unchanged journals."""

from pathlib import Path

import pytest

from core.coverage import journal_compact as compact
from core.coverage.journal import JOURNAL_FILENAME, append_entry
from core.coverage.tests.test_journal_compact import _entry, _reemission_run


@pytest.mark.parametrize("mode", ["dedup", "supersede", "slim"])
def test_unchanged_second_pass_preserves_inode_and_creates_no_archive(tmp_path, mode):
    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    kwargs = {"supersede": mode == "supersede", "slim_clean": mode == "slim"}
    compact.compact_journal(tmp_path, **kwargs)
    journal = tmp_path / JOURNAL_FILENAME
    before = journal.stat()
    backups = set(tmp_path.glob("*.pre-*"))
    stats = compact.compact_journal(tmp_path, **kwargs)
    assert journal.stat().st_ino == before.st_ino
    assert journal.stat().st_mtime_ns == before.st_mtime_ns
    assert set(tmp_path.glob("*.pre-*")) == backups
    assert stats.backup_path == ""
    assert stats.bytes_before == stats.bytes_after
    assert stats.spend_usd_before == stats.spend_usd_after


def test_compaction_does_not_sweep_legacy_unowned_temporary_file(tmp_path):
    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    active = tmp_path / ".~compact-other-shard.jsonl"
    active.write_bytes(b"another compactor's active work")
    compact.compact_journal(tmp_path)
    assert active.read_bytes() == b"another compactor's active work"


@pytest.mark.parametrize("when", ["after-read", "before-backup"])
def test_replaced_journal_is_not_overwritten_by_compaction(tmp_path, monkeypatch, when):
    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    journal = tmp_path / JOURNAL_FILENAME
    replacement = b'{"operator":"new journal"}\n'
    if when == "after-read":
        classify = compact._classify
        changed = False

        def replace(*args):
            nonlocal changed
            result = classify(*args)
            if not changed:
                changed = True
                fresh = tmp_path / "operator-new"
                fresh.write_bytes(replacement)
                fresh.replace(journal)
            return result

        monkeypatch.setattr(compact, "_classify", replace)
    else:
        backup_path = compact._backup_path

        def replace(*args):
            path = backup_path(*args)
            fresh = tmp_path / "operator-new"
            fresh.write_bytes(replacement)
            fresh.replace(journal)
            return path

        monkeypatch.setattr(compact, "_backup_path", replace)
    with pytest.raises(compact.CompactRefused):
        compact.compact_journal(tmp_path)
    assert journal.read_bytes() == replacement


def test_dangling_backup_name_does_not_block_new_archive(tmp_path):
    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    occupied = tmp_path / (JOURNAL_FILENAME + ".pre-compact")
    occupied.symlink_to(tmp_path / "absent")
    stats = compact.compact_journal(tmp_path)
    assert occupied.is_symlink()
    assert Path(stats.backup_path).name.endswith(".pre-compact.2")


@pytest.mark.parametrize("mode", ["dedup", "supersede", "slim"])
@pytest.mark.parametrize("content", ["settled", "empty", "malformed"])
def test_unchanged_journal_allocates_no_rewrite_temp(
    tmp_path, monkeypatch, mode, content
):
    if content == "settled":
        append_entry(tmp_path, _entry(1, body="small", cost_usd=0.25))
    else:
        (tmp_path / JOURNAL_FILENAME).write_bytes(
            b"" if content == "empty" else b"unparseable evidence\n"
        )
    original = (tmp_path / JOURNAL_FILENAME).read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("unchanged journal should not allocate another full copy")

    monkeypatch.setattr(compact.tempfile, "mkstemp", forbidden)
    result = compact.compact_journal(
        tmp_path, supersede=mode == "supersede", slim_clean=mode == "slim"
    )
    assert result.backup_path == ""
    assert (tmp_path / JOURNAL_FILENAME).read_bytes() == original


@pytest.mark.parametrize("kind", ["plain", "link", "fifo", "directory"])
def test_orphan_sweep_only_removes_owned_regular_current_format(tmp_path, kind):
    import os

    append_entry(tmp_path, _entry(1, body="small"))
    orphan = tmp_path / (compact._COMPACT_TMP_PREFIX + "orphan.jsonl")
    outside = tmp_path / "keep"
    outside.write_bytes(b"keep")
    if kind == "plain":
        orphan.write_bytes(b"orphan rewrite")
    elif kind == "link":
        orphan.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(orphan)
    else:
        orphan.mkdir()
    compact.compact_journal(tmp_path)
    assert os.path.lexists(orphan) is (kind != "plain")
    assert outside.read_bytes() == b"keep"


def test_orphan_sweep_has_separate_scan_and_delete_caps(tmp_path, monkeypatch):
    append_entry(tmp_path, _entry(1, body="small"))
    for number in range(6):
        (tmp_path / f"{compact._COMPACT_TMP_PREFIX}{number}.jsonl").write_bytes(
            b"orphan"
        )
    monkeypatch.setattr(compact, "_COMPACT_TMP_SWEEP_LIMIT", 2)
    compact.compact_journal(tmp_path)
    assert len(list(tmp_path.glob(compact._COMPACT_TMP_PREFIX + "*"))) == 4
    monkeypatch.setattr(compact, "_COMPACT_TMP_SCAN_LIMIT", 0)
    compact.compact_journal(tmp_path)
    assert len(list(tmp_path.glob(compact._COMPACT_TMP_PREFIX + "*"))) == 4


def test_global_writer_lock_prevents_active_temp_reaping_and_redundant_generation(
    tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Event, Lock
    from core.atomic_fs.fs_lock import artifact_lock

    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    entered, attempted, release = Event(), Event(), Event()
    guard = Lock()
    attempts = 0
    temps = []
    mkstemp = compact.tempfile.mkstemp

    @contextmanager
    def tracked_lock(*args, **kwargs):
        nonlocal attempts
        with guard:
            attempts += 1
            if attempts == 2:
                attempted.set()
        with artifact_lock(*args, **kwargs):
            yield

    def held_temp(*args, **kwargs):
        result = mkstemp(*args, **kwargs)
        temps.append(Path(result[1]))
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(compact, "artifact_lock", tracked_lock)
    monkeypatch.setattr(compact.tempfile, "mkstemp", held_temp)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(compact.compact_journal, tmp_path)
        try:
            assert entered.wait(5)
            second = pool.submit(compact.compact_journal, tmp_path)
            assert attempted.wait(5)
            assert len(temps) == 1 and temps[0].exists()
        finally:
            release.set()
        assert first.result(timeout=5).backup_path
        assert second.result(timeout=5).backup_path == ""
    assert len(temps) == 1
    assert not temps[0].exists()
    assert len(list(tmp_path.glob(JOURNAL_FILENAME + ".pre-compact*"))) == 1


def test_writer_lock_wait_respects_checkpoint_deadline(tmp_path):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from core.atomic_fs.fs_lock import artifact_lock

    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    original = (tmp_path / JOURNAL_FILENAME).read_bytes()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with artifact_lock(tmp_path / ".journal-compact", required=True):
            result = pool.submit(
                compact.compact_journal,
                tmp_path,
                deadline_monotonic=time.monotonic() + 0.05,
            )
            with pytest.raises(compact.CompactAborted, match="wall-clock"):
                result.result(timeout=2)
    assert (tmp_path / JOURNAL_FILENAME).read_bytes() == original
    assert not list(tmp_path.glob(compact._COMPACT_TMP_PREFIX + "*"))


def test_required_writer_lock_failure_refuses_before_any_rewrite(tmp_path, monkeypatch):
    from contextlib import contextmanager

    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    original = (tmp_path / JOURNAL_FILENAME).read_bytes()

    @contextmanager
    def refused(*args, **kwargs):
        assert kwargs["required"] is True
        raise OSError("lock unavailable")
        yield

    monkeypatch.setattr(compact, "artifact_lock", refused)
    with pytest.raises(compact.CompactRefused, match="writer lock"):
        compact.compact_journal(tmp_path)
    assert (tmp_path / JOURNAL_FILENAME).read_bytes() == original


@pytest.mark.parametrize("change", ["edit", "delete", "link"])
def test_journal_changed_during_census_is_not_published(tmp_path, monkeypatch, change):
    _reemission_run(tmp_path, n_functions=2, n_segments=3)
    journal = tmp_path / JOURNAL_FILENAME
    classify = compact._classify
    changed = False
    outside = tmp_path / "operator-journal"
    outside.write_bytes(b"operator data\n")

    def modify(*args):
        nonlocal changed
        result = classify(*args)
        if not changed:
            changed = True
            if change == "edit":
                journal.write_bytes(b"operator data\n")
            else:
                journal.unlink()
                if change == "link":
                    journal.symlink_to(outside)
        return result

    monkeypatch.setattr(compact, "_classify", modify)
    with pytest.raises(compact.CompactRefused, match="changed"):
        compact.compact_journal(tmp_path)
    if change == "delete":
        assert not journal.exists()
    else:
        assert journal.read_bytes() == b"operator data\n"
    assert outside.read_bytes() == b"operator data\n"
    assert not list(tmp_path.glob(compact._COMPACT_TMP_PREFIX + "*"))


def test_noop_census_still_observes_late_cancellation(tmp_path, monkeypatch):
    append_entry(tmp_path, _entry(1, body="small"))
    original = (tmp_path / JOURNAL_FILENAME).read_bytes()
    classify = compact._classify
    cancelled = False

    def cancel(*args):
        nonlocal cancelled
        result = classify(*args)
        cancelled = True
        return result

    monkeypatch.setattr(compact, "_classify", cancel)
    with pytest.raises(compact.CompactAborted, match="abort requested"):
        compact.compact_journal(tmp_path, should_abort=lambda: cancelled)
    assert (tmp_path / JOURNAL_FILENAME).read_bytes() == original
    assert not list(tmp_path.glob("*.pre-*"))
    assert not list(tmp_path.glob(compact._COMPACT_TMP_PREFIX + "*"))


def test_cli_reports_unchanged_without_empty_backup_label(tmp_path, capsys):
    from types import SimpleNamespace
    from core.coverage.tests.test_journal_supersede import TestCli

    append_entry(tmp_path, _entry(1, body="small"))
    cli = TestCli()._load_cli()
    assert (
        cli.cmd_journal(
            SimpleNamespace(
                journal_command="compact", out_dir=str(tmp_path), supersede=False
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "journal unchanged; no backup created" in output
    assert "backup: \n" not in output
