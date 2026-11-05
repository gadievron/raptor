"""Owned capture handlers must detach and close after setup or body errors."""

import io
import logging
import unittest
from importlib import import_module
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.usefixtures("handler_removal_mode")

CLASS_SCOPES = [
    ("core.logging.tests.test_logger_format_args", "FormatArgsAcrossLevelsTest"),
    ("core.logging.tests.test_logger_format_args", "FormatStyleTest"),
    ("core.logging.tests.test_logger_format_args", "BackwardsCompatTest"),
    ("core.logging.tests.test_logger_reserved_kwargs", "ReservedKwargAcrossLevelsTest"),
    ("core.logging.tests.test_security_event", "_SecurityEventTestBase"),
    ("core.logging.tests.test_stdlib_method_parity", "StdlibMethodParityTest"),
]
INLINE_SCOPES = [
    ("core.llm.tests.test_pinned_model", "_RaptorLogCapture"),
    ("core.llm.tests.test_structured_response_cache", "_RecordingHandler"),
]


def private_logger():
    logger = logging.Logger("owned-log-capture", logging.DEBUG)
    borrowed = logging.NullHandler()
    logger.addHandler(borrowed)
    return logger, borrowed


@pytest.mark.parametrize("module_name,class_name", CLASS_SCOPES)
@pytest.mark.parametrize(
    "stage", ["normal", "body-error", "attach-error", "attach-interrupt"]
)
def test_class_capture_cleanup(module_name, class_name, stage, tmp_path, monkeypatch):
    module = import_module(module_name)
    logger, borrowed = private_logger()
    handler = logging.FileHandler(tmp_path / "owned.log")
    stream = handler.stream
    wrapper = SimpleNamespace(logger=logger)
    if module_name.endswith("test_security_event"):
        monkeypatch.setattr(
            module, "core_logging", SimpleNamespace(RaptorLogger=lambda: wrapper)
        )
    else:
        monkeypatch.setattr(module, "RaptorLogger", lambda: wrapper)
    monkeypatch.setattr(module, "_CapturingHandler", lambda: handler)
    add = logger.addHandler

    def attach(item):
        add(item)
        if stage == "attach-error":
            raise OSError("attachment interrupted")
        if stage == "attach-interrupt":
            raise KeyboardInterrupt("attachment interrupted")

    monkeypatch.setattr(logger, "addHandler", attach)

    class Controlled(getattr(module, class_name)):
        def runTest(self):
            logger.warning("owned message")
            if stage == "body-error":
                raise RuntimeError("body failed")

    case = Controlled()
    result = unittest.TestResult()
    try:
        if stage == "attach-interrupt":
            with pytest.raises(KeyboardInterrupt, match="attachment interrupted"):
                case.run(result)
        else:
            case.run(result)
            assert len(result.errors) == (stage != "normal")
        assert logger.handlers == [borrowed], "capture handler remained attached"
        assert stream.closed, "owned file capture remained open"
        assert handler._closed
        assert not borrowed._closed
        if stage in {"normal", "body-error"}:
            assert (tmp_path / "owned.log").read_text().strip() == "owned message"
    finally:
        case.doCleanups()
        logger.removeHandler(handler)
        handler.close()
        borrowed.close()


@pytest.mark.parametrize("module_name,class_name", INLINE_SCOPES)
@pytest.mark.parametrize(
    "stage", ["normal", "body-error", "attach-error", "attach-interrupt"]
)
def test_inline_capture_cleanup(module_name, class_name, stage):
    module = import_module(module_name)
    logger, borrowed = private_logger()
    owned = logging.Handler()
    capture = getattr(module, class_name)()
    get_logger = logging.getLogger
    add = logger.addHandler

    def attach(item):
        add(item)
        if stage == "attach-error":
            raise OSError("attachment interrupted")
        if stage == "attach-interrupt":
            raise KeyboardInterrupt("attachment interrupted")

    logger.addHandler = attach

    def invoke():
        with capture:
            logger.warning("owned message")
            if stage == "body-error":
                raise RuntimeError("body failed")

    try:
        with pytest.MonkeyPatch.context() as scope:
            scope.setattr(logging, "Handler", lambda: owned)
            scope.setattr(
                logging,
                "getLogger",
                lambda name=None: logger if name == "raptor" else get_logger(name),
            )
            error = {
                "body-error": RuntimeError,
                "attach-error": OSError,
                "attach-interrupt": KeyboardInterrupt,
            }.get(stage)
            if error is None:
                invoke()
            else:
                with pytest.raises(error):
                    invoke()
        assert logger.handlers == [borrowed], "inline capture remained attached"
        assert owned._closed, "inline capture handler was not closed"
        assert not borrowed._closed
        if stage in {"normal", "body-error"}:
            assert capture.messages() == ["owned message"]
    finally:
        logger.removeHandler(owned)
        owned.close()
        borrowed.close()


@pytest.mark.parametrize(
    "stage",
    ["normal", "close", "throw", "level-error", "attach-error", "attach-interrupt"],
)
def test_stream_fixture_cleanup(stage, monkeypatch):
    module = import_module("core.security.tests.test_prompt_telemetry")
    logger, borrowed = private_logger()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    add, set_level = logger.addHandler, handler.setLevel

    def attach(item):
        add(item)
        if stage == "attach-error":
            raise OSError("attachment interrupted")
        if stage == "attach-interrupt":
            raise KeyboardInterrupt("attachment interrupted")

    def level(value):
        set_level(value)
        if stage == "level-error":
            raise OSError("level setup interrupted")

    monkeypatch.setattr(logger, "addHandler", attach)
    monkeypatch.setattr(handler, "setLevel", level)
    monkeypatch.setattr(module, "io", SimpleNamespace(StringIO=lambda: stream))
    monkeypatch.setattr(
        module,
        "logging",
        SimpleNamespace(
            StreamHandler=lambda s: handler,
            getLogger=lambda name: logger,
            WARNING=logging.WARNING,
        ),
    )
    fixture = module.log_capture.__wrapped__()
    try:
        error = {
            "level-error": OSError,
            "attach-error": OSError,
            "attach-interrupt": KeyboardInterrupt,
        }.get(stage)
        if error is not None:
            with pytest.raises(error):
                next(fixture)
        else:
            assert next(fixture) is stream
            logger.warning("owned message")
            assert stream.getvalue().strip() == "owned message"
            if stage == "normal":
                with pytest.raises(StopIteration):
                    next(fixture)
            elif stage == "close":
                fixture.close()
            else:
                with pytest.raises(RuntimeError, match="cancelled"):
                    fixture.throw(RuntimeError("cancelled"))
        assert logger.handlers == [borrowed], "fixture capture remained attached"
        assert handler._closed, "fixture handler was not closed"
        assert stream.closed, "fixture stream was not closed"
        assert not borrowed._closed
    finally:
        fixture.close()
        logger.removeHandler(handler)
        handler.close()
        stream.close()
        borrowed.close()


@pytest.mark.parametrize("stage", ["remove", "close"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_handler_cleanup_attempts_both_operations(stage, error, tmp_path, monkeypatch):
    from core.testing.logging_state import owned_log_handler

    logger, borrowed = private_logger()
    handler = logging.FileHandler(tmp_path / "owned.log")
    stream = handler.stream
    remove, close = logger.removeHandler, handler.close
    attempts = []

    def remove_owned(item):
        attempts.append("remove")
        remove(item)
        if stage == "remove":
            raise error("cleanup interrupted")

    def close_owned():
        attempts.append("close")
        close()
        if stage == "close":
            raise error("cleanup interrupted")

    try:
        with pytest.MonkeyPatch.context() as scope:
            scope.setattr(logger, "removeHandler", remove_owned)
            scope.setattr(handler, "close", close_owned)
            with pytest.raises(error, match="cleanup interrupted"):
                with owned_log_handler(logger, handler):
                    logger.warning("owned message")
        assert attempts == ["remove", "close"]
        assert logger.handlers == [borrowed]
        assert stream.closed
        assert handler._closed
        assert not borrowed._closed
    finally:
        remove(handler)
        close()
        borrowed.close()
