"""Checklist staging roots remain private through both publication forms."""

from contextlib import contextmanager

import pytest

import core.inventory as inventory
from core.inventory.tests.test_checklist_replacement import document
from core.run import scratch


@pytest.fixture(params=[False, True], ids=["single", "sharded"])
def staged_checklist(request, tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "_MAX_CHECKLIST_BYTES", 1024)
    monkeypatch.setattr(inventory, "_CHECKLIST_SHARD_TARGET_BYTES", 1024)
    inventory.save_checklist(tmp_path, document("old"))
    roots = []
    state = {"error": None}
    original_scope = scratch.scratch_dir
    publish = inventory._publish_checklist_form

    @contextmanager
    def workspace(*args, **kwargs):
        assert kwargs["keepalive"] is True
        with original_scope(*args, **kwargs) as root:
            roots.append(root)
            yield root

    def observe(checklist, staged, *, sharded):
        root = roots[-1]
        assert staged.parent == root
        assert staged != root
        assert str(root) in scratch._keepalive_paths
        nested = root / "restricted-debris"
        nested.mkdir()
        (nested / "partial").write_bytes(b"partial shard")
        nested.chmod(0)
        if state["error"] is not None:
            raise state["error"]
        publish(checklist, staged, sharded=sharded)
        assert root.is_dir()
        assert not staged.exists()

    monkeypatch.setattr(scratch, "scratch_dir", workspace)
    monkeypatch.setattr(inventory, "_publish_checklist_form", observe)
    invoke = lambda: inventory.save_checklist(tmp_path, document("new", request.param))
    return state, invoke, roots, tmp_path


def reclaimed(roots):
    assert len(roots) == 1 and not roots[0].exists()
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("error_type", [None, OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_checklist_staging_lifetimes(staged_checklist, error_type):
    state, invoke, roots, output = staged_checklist
    state["error"] = error_type("checklist failed") if error_type else None
    if error_type:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is state["error"]
    else:
        invoke()
    reclaimed(roots)
    assert inventory.read_checklist(output)["revision"] == ("old" if error_type else "new")


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_checklist_cleanup_preserves_original_error(staged_checklist, monkeypatch, error_type, cleanup_type):
    state, invoke, roots, output = staged_checklist
    state["error"] = error_type("publication failed")
    remove = scratch.rmtree_hardened
    calls = []

    def cleanup(root):
        calls.append(root)
        assert remove(root)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        invoke()
    assert caught.value is state["error"]
    assert calls == roots
    reclaimed(roots)
    assert inventory.read_checklist(output)["revision"] == "old"


def test_checklist_cleanup_oserror_keeps_committed_result(staged_checklist, monkeypatch):
    state, invoke, roots, output = staged_checklist
    remove = scratch.rmtree_hardened
    calls = []

    def cleanup(root):
        calls.append(root)
        assert remove(root)
        raise OSError("cleanup failed")

    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    invoke()
    assert calls == roots
    reclaimed(roots)
    assert inventory.read_checklist(output)["revision"] == "new"
