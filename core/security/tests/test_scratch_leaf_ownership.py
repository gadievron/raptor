"""Private owned ordinary leaves only; no scratch/session/control operations."""
from contextlib import ExitStack
import os
import sys
from types import SimpleNamespace

import pytest

from core.security import scratch_lifecycle as module


@pytest.fixture
def leaf_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.bin"
    path.write_bytes(b"owned payload")
    path.chmod(0o600)
    state = {"path": path, "live": {}, "closes": 0, "reads": [], "private_attempts": 0,
             "private_passes": 0, "metadata_error": None, "read_error": None,
             "close_error": None, "primary": None, "grow": False}
    with ExitStack() as resources:
        node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        resources.callback(os.close, node)
        state["node"] = node
        directory = os.fstat(node)
        state["node_identity"] = directory.st_dev, directory.st_ino
        # Own this cache binding before the real adjacent stdlib loader fills it.
        monkeypatch.setattr(module, "_scratch_module", None)
        helper = module.scratch()
        native_private = helper._private

        def private(info, is_directory):
            state["private_attempts"] += 1
            native_private(info, is_directory)
            state["private_passes"] += 1

        def opened(name, flags, **kwargs):
            assert name == path.name and kwargs == {"dir_fd": node}
            fd = os.open(name, flags, **kwargs)
            info = os.fstat(fd)
            state["live"][fd] = info.st_dev, info.st_ino
            state["flags"] = flags
            return fd

        def metadata(fd):
            info = os.fstat(fd)
            if state["metadata_error"] is not None:
                raise state["metadata_error"]
            if state["grow"]:
                state["grow"] = False
                with path.open("ab") as writer:
                    writer.write(b"x" * (module.MAX_RECORD + 1))
            return info

        def read(fd, limit):
            data = os.read(fd, limit)
            state["reads"].append((limit, len(data)))
            if state["read_error"] is not None:
                raise state["read_error"]
            return data

        def close(fd):
            assert fd in state["live"], "leaf owner must not close its borrowed directory"
            state["primary"] = sys.exc_info()[1]
            os.close(fd)
            del state["live"][fd]
            state["closes"] += 1
            if state["close_error"] is not None:
                raise state["close_error"]

        monkeypatch.setattr(helper, "_private", private)
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened,
                                                            "fstat": metadata, "read": read, "close": close}))
        try:
            yield state
        finally:
            for fd, identity in tuple(state["live"].items()):
                info = os.fstat(fd)
                assert (info.st_dev, info.st_ino) == identity
                os.close(fd)
                del state["live"][fd]


def _call(state):
    return module._read_file(state["node"], state["path"].name)


def _assert_retired(state):
    assert state["closes"] == 1 and not state["live"]
    info = os.fstat(state["node"])
    assert (info.st_dev, info.st_ino) == state["node_identity"]
    assert state["flags"] == os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def test_native_oversize_refusal_survives_secondary_close(leaf_io):
    leaf_io["path"].write_bytes(b"x" * (module.MAX_RECORD + 1))
    leaf_io["close_error"] = OSError("after native leaf close")
    with pytest.raises(ValueError, match="oversized scratch control record") as raised:
        _call(leaf_io)
    assert raised.value is leaf_io["primary"]
    assert leaf_io["private_passes"] == 1 and leaf_io["reads"] == []
    _assert_retired(leaf_io)


@pytest.mark.parametrize("stage", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, MemoryError])
def test_operation_error_keeps_identity(leaf_io, stage, primary_type, close_type):
    primary = primary_type("after native owned leaf IO")
    leaf_io[stage + "_error"] = primary
    leaf_io["close_error"] = close_type("after native leaf close")
    with pytest.raises(primary_type) as raised:
        _call(leaf_io)
    assert raised.value is primary
    assert leaf_io["private_passes"] == int(stage == "read")
    assert len(leaf_io["reads"]) == int(stage == "read")
    _assert_retired(leaf_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_private_leaf_bytes_and_fresh_close_policy(leaf_io, close_type):
    cleanup = close_type("after native leaf close") if close_type else None
    leaf_io["close_error"] = cleanup
    if cleanup is None:
        assert _call(leaf_io) == b"owned payload"
    else:
        with pytest.raises(close_type) as raised:
            _call(leaf_io)
        assert raised.value is cleanup
    assert leaf_io["primary"] is None
    assert leaf_io["private_passes"] == 1
    assert leaf_io["reads"] == [(module.MAX_RECORD + 1, len(b"owned payload"))]
    _assert_retired(leaf_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_native_private_mode_refusal_remains_primary(leaf_io, close_type):
    leaf_io["path"].chmod(0o640)
    leaf_io["close_error"] = close_type("after native leaf close") if close_type else None
    with pytest.raises(PermissionError, match="private and owned") as raised:
        _call(leaf_io)
    assert raised.value is leaf_io["primary"]
    assert leaf_io["private_attempts"] == 1 and leaf_io["private_passes"] == 0
    assert leaf_io["reads"] == []
    _assert_retired(leaf_io)


def test_growth_after_metadata_is_refused_after_one_bounded_read(leaf_io):
    leaf_io["grow"] = True
    leaf_io["close_error"] = OSError("after native leaf close")
    with pytest.raises(ValueError, match="oversized scratch control record") as raised:
        _call(leaf_io)
    assert raised.value is leaf_io["primary"]
    assert leaf_io["reads"] == [(module.MAX_RECORD + 1, module.MAX_RECORD + 1)]
    _assert_retired(leaf_io)
