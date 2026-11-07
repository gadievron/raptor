"""Checklist replacement never overwrites a contender during rollback."""

import os
from pathlib import Path

import pytest

import core.inventory as inventory
from core.atomic_fs import rmtree_hardened
from core.project.tests.test_swap_recovery_collisions import contender
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(params=[False, True], ids=["single", "sharded"])
def swap(request, tmp_path):
    final = tmp_path / "checklist"
    final.mkdir()
    (final / "old").write_bytes(b"previous checklist")
    staged = tmp_path / "staged"
    if request.param:
        staged.mkdir()
        (staged / "new").write_bytes(b"new checklist")
    else:
        staged.write_bytes(b"new checklist")

    def invoke():
        path = tmp_path / "checklist.json"
        with inventory._checklist_lock(path):
            inventory._publish_checklist_form(path, staged, sharded=request.param)

    try:
        yield tmp_path, final, staged, request.param, invoke
    finally:
        for root in tmp_path.glob(".checklist-stale-*"):
            rmtree_hardened(root)


@pytest.mark.parametrize("kind", ["empty", "populated", "file", "symlink", "dangling", "fifo"])
def test_checklist_rollback_refuses_late_contender(swap, monkeypatch, kind):
    output, final, staged, sharded, invoke = swap
    move = inventory.rename_without_replace
    victim = output / "victim"
    victim.write_bytes(b"preserve")
    primary = KeyboardInterrupt("publication interrupted")
    occupied = []

    def before_publication(source, destination):
        contender(final, kind, victim)
        occupied.append(final.lstat().st_ino)
        raise primary

    def rename(source, destination):
        if Path(source) == staged:
            return before_publication(source, destination)
        return move(source, destination)

    monkeypatch.setattr(inventory, "rename_without_replace", rename)
    patch_module_attribute(monkeypatch, inventory, "os", "replace", before_publication)
    with pytest.raises(KeyboardInterrupt) as caught:
        invoke()
    assert caught.value is primary
    assert final.lstat().st_ino == occupied[0]
    roots = list(output.glob(".checklist-stale-*"))
    assert len(roots) == 1
    assert (roots[0] / "old").read_bytes() == b"previous checklist"
    assert victim.read_bytes() == b"preserve"


@pytest.mark.parametrize("swap", [True], indirect=True, ids=["sharded"])
@pytest.mark.parametrize("kind", ["empty", "populated", "file", "symlink", "dangling", "fifo"])
def test_sharded_publication_refuses_late_contender(swap, monkeypatch, kind):
    output, final, staged, sharded, invoke = swap
    assert sharded
    move = inventory.rename_without_replace
    victim = output / "victim"
    victim.write_bytes(b"preserve")
    occupied = []

    def race(source, destination):
        if Path(source) == staged:
            contender(final, kind, victim)
            occupied.append(final.lstat().st_ino)
        return move(source, destination)

    monkeypatch.setattr(inventory, "rename_without_replace", race)
    with pytest.raises(OSError):
        invoke()
    assert final.lstat().st_ino == occupied[0]
    roots = list(output.glob(".checklist-stale-*"))
    assert (roots[0] / "old").read_bytes() == b"previous checklist"
    assert victim.read_bytes() == b"preserve"


@pytest.mark.parametrize("disappeared", [False, True])
def test_checklist_does_not_adopt_unrelated_retirement(swap, monkeypatch, disappeared):
    output, final, staged, sharded, invoke = swap
    move = inventory.rename_without_replace
    occupied = []

    def race(source, destination):
        if Path(source) == final:
            Path(destination).mkdir()
            (Path(destination) / "foreign").write_bytes(b"unrelated backup")
            occupied.append(Path(destination))
            if disappeared:
                move(source, output / "relocated-original")
        return move(source, destination)

    monkeypatch.setattr(inventory, "rename_without_replace", race)
    with pytest.raises(OSError):
        invoke()
    assert (occupied[0] / "foreign").read_bytes() == b"unrelated backup"
    original = output / "relocated-original" if disappeared else final
    assert (original / "old").read_bytes() == b"previous checklist"
    assert os.path.lexists(final) is (not disappeared)
