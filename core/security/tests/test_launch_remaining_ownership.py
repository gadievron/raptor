"""The remaining standalone launcher owners settle each native descriptor."""
import errno
import json
import os
from pathlib import Path

import pytest

from core.security import launch_scratch as launch
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="requires directory descriptors")


def _identity(fd):
    info = os.fstat(fd)
    return fd, info.st_dev, info.st_ino


def _is_live(identity):
    try:
        return _identity(identity[0]) == identity
    except OSError as error:
        assert error.errno == errno.EBADF
        return False


def _exercise(tmp_path, monkeypatch, kind, close_type=None, *, body_type=None, close_role="child"):
    base = (tmp_path / "base").resolve()
    base.mkdir(mode=0o700)
    authority = (tmp_path / "authority").resolve()
    pid = os.getpid()
    metadata = raw = entry = original = None
    if kind != "allocate":
        metadata = launch.allocate(base, pid)
    if kind == "restore":
        raw = launch.issue(authority, metadata, pid)
        entry = Path(json.loads(raw)["entry"])
        original = entry.read_bytes()
    opened, retired = {}, []
    native_open, native_close, native_mkdir, native_read = os.open, os.close, os.mkdir, os.read
    primary = body_type("owned operation failed") if body_type is not None else None
    cleanup = close_type("owned close failed") if close_type is not None else None
    cleanup_started = False

    def opened_file(path, flags, *args, **kwargs):
        fd = native_open(path, flags, *args, **kwargs)
        match = ((kind == "allocate" and path == f"raptor-{os.geteuid()}")
                 or (kind == "issue" and str(path).startswith("auth-"))
                 or (kind == "restore" and path == str(pid)))
        if match and not opened:
            opened["child"] = _identity(fd)
            opened["parent"] = _identity(kwargs["dir_fd"])
        return fd

    def close(fd):
        nonlocal cleanup_started
        identity = _identity(fd)
        native_close(fd)
        role = next((name for name, own in opened.items() if own == identity and name not in retired), None)
        if role is not None:
            retired.append(role)
            if cleanup is not None and role == close_role:
                cleanup_started = True
                raise cleanup
            if cleanup_started:
                raise RuntimeError("secondary parent close failed")

    def mkdir(path, *args, **kwargs):
        if primary is not None and str(path).startswith("session-"):
            raise primary
        return native_mkdir(path, *args, **kwargs)

    def dump(*args, **kwargs):
        raise primary

    def read(fd, count):
        if primary is not None and opened.get("child") == _identity(fd):
            raise primary
        return native_read(fd, count)

    result = None
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, launch, "os", "open", opened_file)
        patch_module_attribute(fault, launch, "os", "close", close)
        if primary is not None:
            if kind == "allocate":
                patch_module_attribute(fault, launch, "os", "mkdir", mkdir)
            elif kind == "issue":
                patch_module_attribute(fault, launch, "json", "dump", dump)
            else:
                patch_module_attribute(fault, launch, "os", "read", read)
        def invoke():
            if kind == "allocate":
                return launch.allocate(base, pid)
            if kind == "issue":
                return launch.issue(authority, metadata, pid)
            return launch._restore_authorized(raw)
        try:
            if primary is not None or cleanup is not None:
                with pytest.raises(body_type if primary is not None else close_type) as caught:
                    invoke()
                assert caught.value is (primary if primary is not None else cleanup)
            else:
                result = invoke()
            assert set(opened) == {"child", "parent"}
            live = {role: _is_live(identity) for role, identity in opened.items()}
            assert not any(live.values()), live
            assert retired == ["child", "parent"]
        finally:
            for identity in opened.values():
                if _is_live(identity):
                    native_close(identity[0])
    if kind == "allocate":
        roots = list((base / f"raptor-{os.geteuid()}").glob("session-*"))
        assert len(roots) == (0 if primary is not None else 1)
        if roots:
            assert (roots[0] / "metadata/launch.json").exists() is (cleanup is None)
        if result is not None:
            assert launch.read(result) == str(result.parent.parent / "tmp")
    elif kind == "issue":
        entries = list(authority.rglob(str(pid)))
        assert len(entries) == 1 and entries[0].is_file()
        if primary is not None:
            assert entries[0].read_bytes() == b""
        else:
            record = json.loads(entries[0].read_bytes())
            assert set(record) == {"v", "identity", "metadata", "token"}
            assert record["identity"] == launch._birth(pid) and len(record["token"]) == 64
            assert record["metadata"] == str(metadata)
        if result is not None:
            assert Path(json.loads(result)["entry"]) == entries[0]
    else:
        assert entry.read_bytes() == original
        if result is not None:
            assert result == (metadata, str(metadata.parent.parent / "tmp"))


@pytest.mark.parametrize("kind", ["allocate", "issue", "restore"])
def test_failed_child_close_retires_native_parent(tmp_path, monkeypatch, kind):
    _exercise(tmp_path, monkeypatch, kind, OSError)


@pytest.mark.parametrize("kind", ["allocate", "issue", "restore"])
@pytest.mark.parametrize("body_type,close_type", [(OSError, KeyboardInterrupt), (KeyboardInterrupt, OSError), (SystemExit, SystemExit)])
def test_operation_error_survives_independent_cleanup(tmp_path, monkeypatch, kind, body_type, close_type):
    _exercise(tmp_path, monkeypatch, kind, close_type, body_type=body_type)


@pytest.mark.parametrize("kind", ["allocate", "issue", "restore"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_parent_close_failure_propagates(tmp_path, monkeypatch, kind, close_type):
    _exercise(tmp_path, monkeypatch, kind, close_type, close_role="parent")


@pytest.mark.parametrize("kind", ["allocate", "issue", "restore"])
@pytest.mark.parametrize("close_type", [KeyboardInterrupt, SystemExit])
def test_fresh_child_cancellation_propagates(tmp_path, monkeypatch, kind, close_type):
    _exercise(tmp_path, monkeypatch, kind, close_type)


@pytest.mark.parametrize("kind", ["allocate", "issue", "restore"])
def test_successful_native_owner_keeps_original_result(tmp_path, monkeypatch, kind):
    _exercise(tmp_path, monkeypatch, kind)
