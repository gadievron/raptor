"""Coverage-store budget class: over-budget load degradation is loud
and save-refusing; compaction is the remedial path."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

import core.coverage.store as store_mod
from core.coverage.store import (
    CoverageStore,
    StoreWriteOverBudget,
    compact_store_file,
)


import core.coverage.store as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


def _store_doc(n_files: int = 3) -> dict:
    return {
        "version": 1,
        "target": "/t",
        "files": {
            f"src/f{i}.c": {
                "total_lines": 100,
                "sloc": 80,
                "tools": {"semgrep": [[1, 50]]},
                "findings": [],
                "provenance": {},
            }
            for i in range(n_files)
        },
    }


def test_over_budget_load_is_loud_and_refuses_save(tmp_path, monkeypatch,
                                                   caplog):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    monkeypatch.setattr(store_mod, "_MAX_STORE_BYTES", 64)
    original = path.read_bytes()
    with caplog.at_level(logging.ERROR, logger="core.coverage.store"):
        store = CoverageStore(path)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "read budget" in joined
    assert "raptor-audit coverage compact" in joined
    # Degraded to empty, and the durable union is protected: save
    # refuses instead of replacing it with the empty view.
    assert store.files() == []
    with pytest.raises(StoreWriteOverBudget) as exc:
        store.save()
    assert "compact" in str(exc.value)
    assert path.read_bytes() == original


def test_corrupt_store_keeps_recovery_semantics(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text("{broken json")
    store = CoverageStore(path)
    # Corrupt (not over-budget) stores keep the historical contract:
    # degrade to empty and remain saveable (backfill reconstructs).
    store.mark("src/a.c", 1, 5, "semgrep")
    store.save()
    assert json.loads(path.read_text())["files"]["src/a.c"]


def test_save_emits_compact_form(tmp_path):
    path = tmp_path / "coverage.json"
    store = CoverageStore(path, target="/t")
    store.mark("src/a.c", 1, 5, "semgrep")
    store.save()
    text = path.read_text()
    assert "\n  " not in text          # no indented lines
    assert json.loads(text)["files"]["src/a.c"]


def test_compact_store_file_shrinks_and_backs_up(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(8), indent=2))
    before, after = compact_store_file(path)
    assert after < before
    backup = tmp_path / "coverage.json.pre-compact"
    assert backup.is_file()
    # Compacted store loads healthy.
    store = CoverageStore(path)
    assert len(store.files()) == 8


def test_compact_refuses_when_still_over_budget(tmp_path, monkeypatch):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(8), indent=2))
    original = path.read_bytes()
    monkeypatch.setattr(store_mod, "_MAX_STORE_BYTES", 64)
    with pytest.raises(StoreWriteOverBudget):
        compact_store_file(path)
    assert path.read_bytes() == original
    assert not (tmp_path / "coverage.json.pre-compact").exists()


def test_compact_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        compact_store_file(tmp_path / "coverage.json")


def test_repeated_compaction_preserves_inode_and_backup_count(tmp_path, monkeypatch):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    monkeypatch.setattr(store_mod, "_now_iso", lambda: "first-compaction")
    compact_store_file(path)
    before = path.read_bytes()
    inode = path.stat().st_ino
    monkeypatch.setattr(store_mod, "_now_iso", lambda: "second-compaction")
    assert compact_store_file(path) == (len(before), len(before))
    assert path.read_bytes() == before
    assert path.stat().st_ino == inode
    assert len(list(tmp_path.glob("*.pre-compact*"))) == 1


def test_compaction_keeps_coverage_generation_time(tmp_path):
    path = tmp_path / "coverage.json"
    data = _store_doc()
    data["generated_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(data, indent=2))
    compact_store_file(path)
    assert json.loads(path.read_text())["generated_at"] == data["generated_at"]


def test_compaction_rejects_source_replaced_during_normalization(tmp_path, monkeypatch):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    normalize = store_mod.normalise_loaded_files
    replacement = json.dumps(_store_doc(4), indent=2).encode()

    def replace_source(files, subject):
        alternate = tmp_path / "new-store"
        alternate.write_bytes(replacement)
        alternate.replace(path)
        return normalize(files, subject)

    monkeypatch.setattr(store_mod, "normalise_loaded_files", replace_source)
    with pytest.raises(ValueError, match="changed"):
        compact_store_file(path)
    assert path.read_bytes() == replacement
    assert not list(tmp_path.glob("*.pre-compact*"))


def test_saved_canonical_store_is_unchanged(tmp_path):
    path = tmp_path / "coverage.json"
    store = CoverageStore(path, target="/t")
    store.mark("src/a.c", 1, 5, "semgrep")
    store.save()
    before = path.stat()
    stats = store_mod.compact_store_file_disclosed(path)
    assert stats.backup is None
    assert stats.bytes_before == stats.bytes_after == before.st_size
    after = path.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_ino, before.st_size, before.st_mtime_ns)
    assert not list(tmp_path.glob("*.pre-compact*"))


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_compaction_refuses_nonregular_source(tmp_path, kind):
    path = tmp_path / "coverage.json"
    if kind == "symlink":
        target = tmp_path / "real.json"
        target.write_text(json.dumps(_store_doc()))
        path.symlink_to(target)
    else:
        os.mkfifo(path)
    with pytest.raises((OSError, ValueError)):
        compact_store_file(path)
    assert not list(tmp_path.glob("*.pre-compact*"))


def test_dangling_backup_names_are_not_reused(tmp_path):
    path = tmp_path / "coverage.json"
    original = json.dumps(_store_doc(), indent=2).encode()
    path.write_bytes(original)
    for suffix in ("", ".2"):
        path.with_name(path.name + ".pre-compact" + suffix).symlink_to("missing")
    stats = store_mod.compact_store_file_disclosed(path)
    assert stats.backup.name == path.name + ".pre-compact.3"
    assert stats.backup.read_bytes() == original
    assert path.with_name(path.name + ".pre-compact").is_symlink()
    assert path.with_name(path.name + ".pre-compact.2").is_symlink()


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_compaction_removes_redundant_backup(tmp_path, monkeypatch, cancel):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    original = path.read_bytes()

    def fail_write(*args, **kwargs):
        if cancel:
            raise KeyboardInterrupt("cancelled publication")
        raise OSError("failed publication")

    monkeypatch.setattr(store_mod, "write_text_atomically", fail_write)
    with pytest.raises(KeyboardInterrupt if cancel else OSError):
        compact_store_file(path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.pre-compact*"))


def test_failed_backup_cleanup_preserves_primary_error(tmp_path, monkeypatch, caplog):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    original = path.read_bytes()
    unlink = Path.unlink

    def fail_write(*args, **kwargs):
        raise OSError("primary publication error")

    def fail_cleanup(candidate, *args, **kwargs):
        if candidate.name.endswith(".pre-compact"):
            raise PermissionError("secondary cleanup error")
        return unlink(candidate, *args, **kwargs)

    with monkeypatch.context() as faults:
        faults.setattr(store_mod, "write_text_atomically", fail_write)
        faults.setattr(Path, "unlink", fail_cleanup)
        with pytest.raises(OSError, match="primary publication error"):
            compact_store_file(path)
    backup = path.with_name(path.name + ".pre-compact")
    assert backup.read_bytes() == path.read_bytes() == original
    assert str(backup) in caplog.text
    backup.unlink()


def test_source_replaced_after_backup_keeps_recovery_copy(tmp_path, monkeypatch):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    original = path.read_bytes()
    replacement = json.dumps(_store_doc(4)).encode()
    link = os.link

    def replace_after_link(src, dst, **kwargs):
        link(src, dst, **kwargs)
        alternate = tmp_path / "new-store"
        alternate.write_bytes(replacement)
        alternate.replace(path)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "link", replace_after_link)
    with pytest.raises(ValueError, match="changed"):
        compact_store_file(path)
    assert path.read_bytes() == replacement
    assert path.with_name(path.name + ".pre-compact").read_bytes() == original


def test_compaction_uses_writer_lock_and_refuses_contention(tmp_path, monkeypatch):
    from core.atomic_fs import fs_lock

    if not fs_lock._HAS_FCNTL:
        pytest.skip("requires flock")
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    original = path.read_bytes()
    monkeypatch.setattr(fs_lock, "_ACQUIRE_DEADLINE_S", 0.01)
    monkeypatch.setattr(fs_lock, "_ACQUIRE_POLL_S", 0.001)
    with store_mod.coverage_store_lock(path):
        with pytest.raises(TimeoutError):
            compact_store_file(path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.pre-compact*"))


def test_compaction_refuses_unavailable_lock(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    original = path.read_bytes()
    path.with_suffix(".json.lock").symlink_to("missing")
    with pytest.raises(OSError):
        compact_store_file(path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.pre-compact*"))


@pytest.mark.parametrize("bom", [False, True])
def test_compaction_keeps_bounded_bom_tolerant_input(tmp_path, monkeypatch, bom):
    path = tmp_path / "coverage.json"
    original = json.dumps(_store_doc(), indent=2).encode()
    if bom:
        original = b"\xef\xbb\xbf" + original
    path.write_bytes(original)
    monkeypatch.setattr(store_mod, "_COMPACT_READ_MAX_BYTES", len(original) - 1)
    with pytest.raises(ValueError, match="max_bytes"):
        compact_store_file(path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.pre-compact*"))
    monkeypatch.setattr(store_mod, "_COMPACT_READ_MAX_BYTES", len(original))
    compact_store_file(path)
    assert len(CoverageStore(path).files()) == 3


@pytest.mark.parametrize("restore_mtime", [False, True])
def test_same_size_edits_during_normalization_are_refused(tmp_path, monkeypatch, restore_mtime):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    before = path.stat()
    replacement = path.read_bytes().replace(b"src/f0.c", b"src/g0.c")
    normalize = store_mod.normalise_loaded_files

    def edit_source(files, subject):
        path.write_bytes(replacement)
        if restore_mtime:
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return normalize(files, subject)

    monkeypatch.setattr(store_mod, "normalise_loaded_files", edit_source)
    with pytest.raises(ValueError, match="changed"):
        compact_store_file(path)
    assert path.read_bytes() == replacement
    assert not list(tmp_path.glob("*.pre-compact*"))


@pytest.mark.parametrize("existing_backup", [False, True])
def test_cli_reports_actual_backup_and_noop(tmp_path, capsys, existing_backup):
    import argparse
    import importlib.util
    import sys
    from importlib.machinery import SourceFileLoader
    from unittest.mock import patch

    script = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"
    loader = SourceFileLoader("raptor_audit_cli_store_compact", str(script))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(cli)
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    if existing_backup:
        path.with_name(path.name + ".pre-compact").write_text("old backup")
    args = argparse.Namespace(coverage_command="compact", store_path=str(path))
    assert cli.cmd_coverage(args) == 0
    output = capsys.readouterr().out
    suffix = ".pre-compact.2" if existing_backup else ".pre-compact"
    assert f"backup: {path.name}{suffix} (same directory)" in output
    assert cli.cmd_coverage(args) == 0
    output = capsys.readouterr().out
    assert "unchanged; no backup created" in output
    assert "  backup:" not in output
