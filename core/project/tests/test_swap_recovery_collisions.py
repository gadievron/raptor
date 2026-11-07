"""Report replacement and recovery preserve late directory contenders."""

import os
from pathlib import Path

import pytest

from core.atomic_fs import rmtree_hardened
from core.project import report
from core.run import scratch


@pytest.fixture
def report_swap(tmp_path):
    final = tmp_path / "findings"
    final.mkdir()
    (final / "old").write_bytes(b"previous report")
    try:
        yield tmp_path, final
    finally:
        for root in tmp_path.glob(".findings-stage-*"):
            rmtree_hardened(root)


def contender(path, kind, victim):
    if kind in {"empty", "populated"}:
        path.mkdir()
        if kind == "populated":
            (path / "data").write_bytes(b"contender")
    elif kind == "file":
        path.write_bytes(b"contender")
    elif kind in {"symlink", "dangling"}:
        path.symlink_to(victim if kind == "symlink" else path.parent / "missing")
    else:
        os.mkfifo(path)


@pytest.mark.parametrize("phase", ["publish", "rollback"])
@pytest.mark.parametrize("kind", ["empty", "populated", "file", "symlink", "dangling", "fifo"])
def test_report_swap_refuses_late_contender(report_swap, monkeypatch, phase, kind):
    output, final = report_swap
    victim = output / "victim"
    victim.write_bytes(b"preserve")
    move = report.rename_without_replace
    primary = OSError("publication interrupted")
    backups, occupied = [], []

    def race(source, destination):
        source, destination = Path(source), Path(destination)
        if source.name == "next":
            backup = source.parent / "previous"
            backups.append(backup)
            contender(destination, kind, victim)
            occupied.append(destination.lstat().st_ino)
            if phase == "rollback":
                raise primary
        return move(source, destination)

    monkeypatch.setattr(report, "rename_without_replace", race)
    with pytest.raises(OSError) as caught:
        report.export_findings_directory([], output)
    if phase == "rollback":
        assert caught.value is primary
    assert final.lstat().st_ino == occupied[0]
    assert (backups[0] / "old").read_bytes() == b"previous report"
    assert not (backups[0].parent / "next").exists()
    assert victim.read_bytes() == b"preserve"
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("disappeared", [False, True])
def test_report_does_not_adopt_unrelated_backup(report_swap, monkeypatch, disappeared):
    output, final = report_swap
    move = report.rename_without_replace
    occupied = []

    def race(source, destination):
        source, destination = Path(source), Path(destination)
        if source == final:
            destination.mkdir()
            (destination / "foreign").write_bytes(b"unrelated backup")
            occupied.append(destination)
            if disappeared:
                move(source, output / "relocated-original")
        return move(source, destination)

    monkeypatch.setattr(report, "rename_without_replace", race)
    with pytest.raises(OSError):
        report.export_findings_directory([], output)
    assert (occupied[0] / "foreign").read_bytes() == b"unrelated backup"
    original = output / "relocated-original" if disappeared else final
    assert (original / "old").read_bytes() == b"previous report"
    assert os.path.lexists(final) is (not disappeared)


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_discarding_failed_new_report_preserves_primary_error(report_swap, monkeypatch, cleanup_type):
    output, final = report_swap
    move = report.rename_without_replace
    clear = report._clear_generated_findings_dir
    primary = KeyboardInterrupt("publication cancelled")
    backups, discarded = [], []

    def fail_publication_and_restore(source, destination):
        source, destination = Path(source), Path(destination)
        if source.name == "next":
            backups.append(source.parent / "previous")
            raise primary
        if source.name == "previous":
            raise OSError("rollback blocked")
        return move(source, destination)

    def cleanup(path):
        discarded.append(path)
        clear(path)
        raise cleanup_type("cleanup interrupted")

    monkeypatch.setattr(report, "rename_without_replace", fail_publication_and_restore)
    monkeypatch.setattr(report, "_clear_generated_findings_dir", cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:
        report.export_findings_directory([], output)
    assert caught.value is primary
    assert (backups[0] / "old").read_bytes() == b"previous report"
    assert discarded == [backups[0].parent / "next"]
    assert not discarded[0].exists()
    assert not scratch._keepalive_paths
