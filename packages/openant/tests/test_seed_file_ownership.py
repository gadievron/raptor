"""Raw file-copy ownership under actual native creation refusal and faults."""
import errno
import os
from types import SimpleNamespace

import pytest

from packages.openant import resume


@pytest.fixture
def copy_io(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "plain.txt").write_bytes(b"inert plain text")
    parent = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    destination = tmp_path / "destination"
    state = {"source": source, "parent": parent, "destination": destination,
             "live": {}, "closes": [], "faults": {}, "primary": None,
             "parent_live": True}
    native_copy = resume.shutil.copyfileobj

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"][fd] = "out" if args[1] & os.O_WRONLY else "in"
        return fd

    def close(fd):
        os.close(fd)
        if fd == parent:
            state["parent_live"] = False
            pytest.fail("borrowed parent descriptor was closed")
        role = state["live"].pop(fd)
        state["closes"].append(role)
        if role in state["faults"]:
            raise state["faults"][role]

    def copied(inp, out):
        native_copy(inp, out)
        out.flush()
        if state["primary"] is not None:
            raise state["primary"]

    monkeypatch.setattr(resume, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "close": close}))
    monkeypatch.setattr(resume, "shutil", SimpleNamespace(
        **{**vars(resume.shutil), "copyfileobj": copied}))
    state["run"] = lambda: resume._copy_regular_file("plain.txt", destination, dir_fd=parent)
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)
        if state["parent_live"]:
            os.close(parent)


def test_existing_destination_refusal_keeps_native_error(copy_io):
    copy_io["destination"].write_bytes(b"keep existing")
    copy_io["faults"] = {"in": OSError("after native input close")}
    with pytest.raises(FileExistsError) as raised:
        copy_io["run"]()
    assert raised.value.errno == errno.EEXIST
    assert copy_io["destination"].read_bytes() == b"keep existing"
    assert copy_io["closes"] == ["in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


def test_native_creation_refusal_survives_close_cancellation(copy_io):
    copy_io["destination"].write_bytes(b"keep existing")
    copy_io["faults"] = {"in": KeyboardInterrupt("after native input close")}
    with pytest.raises(FileExistsError) as raised:
        copy_io["run"]()
    assert raised.value.errno == errno.EEXIST
    assert copy_io["destination"].read_bytes() == b"keep existing"
    assert copy_io["closes"] == ["in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("role", ["out", "in"])
def test_copy_primary_survives_descriptor_close(copy_io, primary_type, close_type, role):
    primary = primary_type("after native copy and flush")
    copy_io["primary"] = primary
    copy_io["faults"] = {role: close_type("after native descriptor close")}
    with pytest.raises(primary_type) as raised:
        copy_io["run"]()
    assert raised.value is primary
    assert copy_io["closes"] == ["out", "in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, MemoryError])
def test_both_close_failures_do_not_replace_copy_primary(copy_io, primary_type):
    primary = primary_type("after native copy and flush")
    copy_io["primary"] = primary
    copy_io["faults"] = {"out": KeyboardInterrupt("after native output close"),
                         "in": OSError("after native input close")}
    with pytest.raises(primary_type) as raised:
        copy_io["run"]()
    assert raised.value is primary
    assert copy_io["closes"] == ["out", "in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("role", ["out", "in"])
def test_fresh_close_error_remains_visible(copy_io, close_type, role):
    cleanup = close_type("after native descriptor close")
    copy_io["faults"] = {role: cleanup}
    with pytest.raises(close_type) as raised:
        copy_io["run"]()
    assert raised.value is cleanup
    assert copy_io["closes"] == ["out", "in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


def test_native_copy_keeps_content_mtime_and_borrowed_parent(copy_io):
    before = (copy_io["source"] / "plain.txt").stat()
    copy_io["run"]()
    assert copy_io["destination"].read_bytes() == b"inert plain text"
    assert copy_io["destination"].stat().st_mtime_ns == before.st_mtime_ns
    assert copy_io["closes"] == ["out", "in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])


def test_tree_composition_retires_directory_and_file_descriptors(copy_io):
    destination = copy_io["destination"]
    destination.mkdir()
    resume._copy_regular_tree(copy_io["source"], destination)
    assert (destination / "plain.txt").read_bytes() == b"inert plain text"
    assert copy_io["closes"] == ["out", "in", "in"]
    assert not copy_io["live"]
    os.fstat(copy_io["parent"])
