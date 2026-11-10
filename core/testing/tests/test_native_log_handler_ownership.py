"""Unattached native audit-file handlers close on formatter interrupts."""

import importlib

import pytest

from core.testing.module_bindings import patch_module_attribute

CASES = [
    ("test_record_content_persisted", 0),
    ("test_reopen_appends_and_stays_owner_only", 0),
    ("test_reopen_appends_and_stays_owner_only", 1),
]


def _exercise(method, tmp_path, monkeypatch, *, position=None, error=None):
    native = importlib.import_module("core.logging.tests.test_file_handler_noise")
    borrowed = native.core_logging
    original = borrowed._OwnerOnlyFileHandler
    handlers, streams, reached = [], [], []
    failure = error("owned formatter interruption") if error else None

    class Handler(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            handlers.append(self)

        def _open(self):
            stream = super()._open()
            streams.append(stream)
            return stream

        def format(self, record):
            result = super().format(record)
            if error and len(handlers) > position and self is handlers[position]:
                reached.append(True)
                raise failure
            return result

    try:
        with monkeypatch.context() as patch:
            patch_module_attribute(patch, native, "core_logging", "_OwnerOnlyFileHandler", Handler)
            invoke = getattr(native.TestOwnerOnlyFileHandler(), method)
            if error:
                with pytest.raises(error) as caught:
                    invoke(tmp_path)
                assert caught.value is failure and reached == [True]
            else:
                invoke(tmp_path)
                assert not reached
            expected = position + 1 if error else 1 if method == "test_record_content_persisted" else 2
            assert len(handlers) == len(streams) == expected
            assert all(handler._closed for handler in handlers)
            # Stream objects retain consumed-descriptor state; do not close
            # raw historical fd numbers which the process may have reused.
            assert all(stream.closed for stream in streams)
        assert native.core_logging is borrowed
        assert borrowed._OwnerOnlyFileHandler is original
    finally:
        for handler in handlers:
            original.close(handler)


@pytest.mark.parametrize("method,position", CASES)
@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_formatter_interruption_closes_native_handler(method, position, error, tmp_path, monkeypatch):
    _exercise(method, tmp_path, monkeypatch, position=position, error=error)


@pytest.mark.parametrize("method", ["test_record_content_persisted", "test_reopen_appends_and_stays_owner_only"])
def test_native_content_append_and_permissions_remain_live(method, tmp_path, monkeypatch):
    _exercise(method, tmp_path, monkeypatch)
