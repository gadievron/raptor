"""Directory seeding retires independent native descriptors after faults."""
import os
from types import SimpleNamespace

import pytest

from packages.openant import resume


@pytest.fixture
def tree_io(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "left").mkdir()
    (source / "right").mkdir()
    destination = tmp_path / "destination"
    destination.mkdir()
    state = {"source": source, "destination": destination, "live": set(),
             "opens": 0, "closes": 0, "primary": None, "cleanup": None,
             "faults": set()}
    native_seed = resume._seed_one_dir

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["opens"] += 1
        state["live"].add(fd)
        return fd

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["closes"] in state["faults"]:
            raise state["cleanup"]

    def seed(fd, dst, depth, top, stack):
        native_seed(fd, dst, depth, top, stack)
        if top and state["primary"] is not None:
            raise state["primary"]

    monkeypatch.setattr(resume, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(resume, "_seed_one_dir", seed)
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_pending_cleanup_interrupt_retires_remaining_directories(tree_io):
    primary = KeyboardInterrupt("after native root enumeration")
    tree_io["primary"] = primary
    tree_io["cleanup"] = MemoryError("after native pending close")
    tree_io["faults"] = {2}
    with pytest.raises(KeyboardInterrupt) as raised:
        resume._copy_regular_tree(tree_io["source"], tree_io["destination"])
    assert raised.value is primary
    assert tree_io["opens"] == tree_io["closes"] == 3
    assert not tree_io["live"]


@pytest.mark.parametrize("primary_type", [OSError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, MemoryError])
@pytest.mark.parametrize("fault_at", [1, 2])
def test_operation_primary_survives_independent_directory_cleanup(
        tree_io, primary_type, close_type, fault_at):
    primary = primary_type("after native root enumeration")
    tree_io["primary"] = primary
    tree_io["cleanup"] = close_type("after native directory close")
    tree_io["faults"] = {fault_at}
    with pytest.raises(primary_type) as raised:
        resume._copy_regular_tree(tree_io["source"], tree_io["destination"])
    assert raised.value is primary
    assert tree_io["opens"] == tree_io["closes"] == 3
    assert not tree_io["live"]


def test_every_cleanup_fault_still_retires_every_directory(tree_io):
    primary = KeyboardInterrupt("after native root enumeration")
    tree_io["primary"] = primary
    tree_io["cleanup"] = KeyboardInterrupt("after every native close")
    tree_io["faults"] = {1, 2, 3}
    with pytest.raises(KeyboardInterrupt) as raised:
        resume._copy_regular_tree(tree_io["source"], tree_io["destination"])
    assert raised.value is primary
    assert tree_io["opens"] == tree_io["closes"] == 3
    assert not tree_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("fault_at", [1, 2])
def test_fresh_directory_close_fault_stays_visible(tree_io, close_type, fault_at):
    cleanup = close_type("after native directory close")
    tree_io["cleanup"] = cleanup
    tree_io["faults"] = {fault_at}
    with pytest.raises(close_type) as raised:
        resume._copy_regular_tree(tree_io["source"], tree_io["destination"])
    assert raised.value is cleanup
    assert tree_io["opens"] == tree_io["closes"] == 3
    assert not tree_io["live"]


def test_native_plain_tree_copy_retires_all_handles(tree_io):
    (tree_io["source"] / "plain.txt").write_bytes(b"inert text")
    resume._copy_regular_tree(tree_io["source"], tree_io["destination"])
    assert (tree_io["destination"] / "plain.txt").read_bytes() == b"inert text"
    assert (tree_io["destination"] / "left").is_dir()
    assert (tree_io["destination"] / "right").is_dir()
    assert tree_io["opens"] == tree_io["closes"] == 5
    assert not tree_io["live"]
