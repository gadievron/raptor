"""Owned tiny valid ZIP member cleanup; injected faults follow native operations."""
import io
from types import SimpleNamespace
import zipfile

import pytest

from core.zip import extract as module


@pytest.fixture
def member_io(monkeypatch):
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("plain.txt", b"plain text\n")
    source.seek(0)
    state = {"source": source, "primary": None, "cleanup": None,
             "members": [], "member_closes": 0, "archive_closes": 0, "skips": []}

    class Member:
        def __init__(self, native):
            self.native = native

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

        def read(self):
            result = self.native.read()
            assert result == b"plain text\n"
            if state["primary"] is not None:
                raise state["primary"]
            return result

        def close(self):
            self.native.close()
            state["member_closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    class Archive(zipfile.ZipFile):
        def open(self, *args, **kwargs):
            native = super().open(*args, **kwargs)
            state["members"].append(native)
            return Member(native)

        def close(self):
            active = self.fp is not None
            super().close()
            if active:
                state["archive_closes"] += 1

    monkeypatch.setattr(module, "zipfile", SimpleNamespace(**{**vars(zipfile), "ZipFile": Archive}))
    try:
        yield state
    finally:
        for member in state["members"]:
            member.close()
        source.close()


def _extract(state):
    return module.extract_files_from_zip(
        state["source"], selector=lambda info: info.filename,
        on_skipped=lambda info, reason: state["skips"].append((info.filename, reason)))


def _assert_retired(state):
    assert state["member_closes"] == state["archive_closes"] == 1
    assert len(state["members"]) == 1
    assert state["members"][0].closed
    assert not state["source"].closed


def test_active_read_error_does_not_become_encrypted_skip(member_io):
    primary = KeyboardInterrupt("after native plaintext member read")
    member_io.update(primary=primary, cleanup=RuntimeError("after native member close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        _extract(member_io)
    assert raised.value is primary
    assert member_io["skips"] == []
    _assert_retired(member_io)


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit, ValueError])
@pytest.mark.parametrize("close_type", [RuntimeError, OSError, KeyboardInterrupt])
def test_active_member_error_keeps_identity(member_io, primary_type, close_type):
    primary = primary_type("after native plaintext member read")
    member_io.update(primary=primary, cleanup=close_type("after native member close"))
    with pytest.raises(primary_type) as raised:
        _extract(member_io)
    assert raised.value is primary
    assert member_io["skips"] == []
    _assert_retired(member_io)


@pytest.mark.parametrize("primary_type", [zipfile.BadZipFile, OSError])
@pytest.mark.parametrize("close_type", [RuntimeError, KeyboardInterrupt])
def test_read_error_classification_keeps_read_cause(member_io, primary_type, close_type):
    # The archive is valid; this read error is injected AFTER native CRC-checked read.
    primary = primary_type("injected after native plaintext member read")
    member_io.update(primary=primary, cleanup=close_type("after native member close"))
    with pytest.raises(module.ZipOpenError) as raised:
        _extract(member_io)
    assert raised.value.__cause__ is primary
    assert member_io["skips"] == []
    _assert_retired(member_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_primary_runtime_error_retains_existing_skip_policy(member_io, close_type):
    member_io.update(primary=RuntimeError("injected read runtime error"),
                     cleanup=close_type("after native close") if close_type else None)
    assert _extract(member_io) == {}
    assert member_io["skips"] == [("plain.txt", "encrypted")]
    _assert_retired(member_io)


@pytest.mark.parametrize("close_type", [RuntimeError, OSError, KeyboardInterrupt, SystemExit, MemoryError])
def test_fresh_member_close_retains_existing_policy(member_io, close_type):
    cleanup = close_type("after native member close")
    member_io["cleanup"] = cleanup
    if close_type is RuntimeError:
        assert _extract(member_io) == {}
        assert member_io["skips"] == [("plain.txt", "encrypted")]
    elif close_type is OSError:
        with pytest.raises(module.ZipOpenError) as raised:
            _extract(member_io)
        assert raised.value.__cause__ is cleanup
        assert member_io["skips"] == []
    else:
        with pytest.raises(close_type) as raised:
            _extract(member_io)
        assert raised.value is cleanup
        assert member_io["skips"] == []
    _assert_retired(member_io)


def test_native_member_success_returns_bytes_and_preserves_borrowed_source(member_io):
    assert _extract(member_io) == {"plain.txt": b"plain text\n"}
    assert member_io["skips"] == []
    _assert_retired(member_io)


def test_native_aggregate_refusal_after_member_close_is_retained(member_io):
    with pytest.raises(module.ZipTotalBytesExceeded):
        module.extract_files_from_zip(member_io["source"], selector=lambda info: info.filename,
                                      max_total_bytes=0)
    assert member_io["skips"] == []
    _assert_retired(member_io)
