"""Logging cleanup restores later state even after a restoration raises."""

import logging
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing import logging_state as support
from core.llm import log_quiet
from core.llm.tests import test_log_quiet as quiet_tests
from core.llm.dispatcher.tests import test_dispatcher as dispatcher_tests


@pytest.mark.parametrize(
    "stage",
    [
        "list",
        "contents",
        "handler0",
        "handler1",
        "root",
        "sdk0",
        "sdk1",
        "sdk2",
        "owned-close",
        "none",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, RuntimeError])
@pytest.mark.parametrize("body_fails", [False, True])
def test_restore_failure_does_not_strand_logging_state(
    stage, error, body_fails, tmp_path, monkeypatch
):
    failure = error("owned logging restoration failure")
    body_error = LookupError("owned CLI failed")
    armed = False
    closed_failure = []

    class Level:
        def __init__(self, name, level):
            self.name, self.level = name, level

        def setLevel(self, value):
            self.level = value
            if armed and stage == self.name:
                raise failure

    class HandlerList(list):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if armed and stage == "contents":
                raise failure

    handlers = [Level("handler0", 20), Level("handler1", 40)]
    original = HandlerList(handlers)

    class Root(Level):
        def __setattr__(self, name, value):
            super().__setattr__(name, value)
            if armed and name == "handlers" and value is original and stage == "list":
                raise failure

    root = Root("root", 30)
    root.handlers = original
    sdk = {
        name: Level(name, 10 + index * 10)
        for index, name in enumerate(("sdk0", "sdk1", "sdk2"))
    }
    sdk_levels = {name: logger.level for name, logger in sdk.items()}

    class OwnedHandler(logging.FileHandler):
        def close(self):
            super().close()
            if (
                armed
                and stage == "owned-close"
                and self is created[1]
                and not closed_failure
            ):
                closed_failure.append(True)
                raise failure

    created = [OwnedHandler(tmp_path / f"owned-{index}.log") for index in range(2)]
    streams = [item.stream for item in created]
    fake_logging = SimpleNamespace(
        **(
            vars(logging)
            | {"getLogger": lambda name=None: root if name is None else sdk[name]}
        )
    )

    def invoke():
        nonlocal armed
        with support.isolated_cli_logging():
            root.handlers = list(created)
            original.clear()
            for item in [root, *handlers, *sdk.values()]:
                item.level = 1
            armed = True
            if body_fails:
                raise body_error

    try:
        monkeypatch.setattr(support, "logging", fake_logging)
        monkeypatch.setattr(support, "NOISY_THIRD_PARTY_LOGGERS", tuple(sdk))
        expected = failure if stage != "none" else body_error if body_fails else None
        if expected is None:
            invoke()
        else:
            with pytest.raises(BaseException) as caught:
                invoke()
            assert caught.value is expected
        assert root.handlers is original
        assert tuple(original) == tuple(handlers), (
            "logging scope left its original handler list mutated"
        )
        assert [item.level for item in handlers] == [20, 40], (
            "logging scope skipped later handler restoration"
        )
        assert root.level == 30, "logging scope skipped root-level restoration"
        assert {name: logger.level for name, logger in sdk.items()} == sdk_levels, (
            "logging scope skipped later SDK restoration"
        )
        assert all(stream.closed for stream in streams), (
            "logging scope left an owned file open"
        )
    finally:
        armed = False
        for item in created:
            item.close()


_QUIET_CASES = [
    ("TestQuietNoisyLoggers", name)
    for name in (
        "test_default_level_is_warning",
        "test_explicit_level_honoured",
        "test_root_logger_unaffected",
        "test_idempotent",
    )
] + [
    ("TestSdkRetrySpamQuieting", name)
    for name in (
        "test_anthropic_and_openai_sdks_quiet_to_warning",
        "test_instructor_redundant_error_is_quieted",
    )
]


@pytest.mark.parametrize("owner,name", _QUIET_CASES)
def test_quieting_test_restores_all_touched_logger_families(owner, name):
    names = (*log_quiet._NOISY_LOGGERS, *log_quiet._REDUNDANT_ERROR_LOGGERS)
    loggers = {name: logging.getLogger(name) for name in names}
    saved = {name: logger.level for name, logger in loggers.items()}
    try:
        for logger in loggers.values():
            logger.setLevel(logging.ERROR)
        loggers["instructor"].setLevel(logging.DEBUG)
        expected = {name: logger.level for name, logger in loggers.items()}
        getattr(getattr(quiet_tests, owner)(), name)()
        assert {name: logger.level for name, logger in loggers.items()} == expected, (
            "quieting test leaked logger levels"
        )
    finally:
        for name, logger in loggers.items():
            logging.Logger.setLevel(logger, saved[name])


@pytest.mark.parametrize("stage", ["info", "construct", "shutdown", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_dispatcher_logging_wire_test_restores_state_on_setup_or_shutdown_failure(
    stage, error, tmp_path, monkeypatch
):
    names = (*log_quiet._NOISY_LOGGERS, *log_quiet._REDUNDANT_ERROR_LOGGERS)
    loggers = {name: logging.getLogger(name) for name in names}
    saved = {name: logger.level for name, logger in loggers.items()}
    failure = error("owned wiring test failure")
    owned = socket.socket()

    def shutdown():
        owned.close()
        if stage == "shutdown":
            raise failure

    dispatcher = SimpleNamespace(shutdown=Mock(side_effect=shutdown))

    def construct(**kwargs):
        log_quiet.quiet_noisy_loggers()
        if stage == "construct":
            raise failure
        return dispatcher

    first = loggers[log_quiet._NOISY_LOGGERS[0]]
    set_level = first.setLevel

    def set_info(level):
        set_level(level)
        if level == logging.INFO:
            raise failure

    try:
        for logger in loggers.values():
            logger.setLevel(logging.ERROR)
        loggers["instructor"].setLevel(logging.DEBUG)
        expected = {name: logger.level for name, logger in loggers.items()}
        with monkeypatch.context() as patcher:
            patcher.setattr(dispatcher_tests, "LLMDispatcher", construct)
            if stage == "info":
                patcher.setattr(first, "setLevel", set_info)
            invoke = dispatcher_tests.TestQuietNoisyLoggersWired().test_dispatcher_init_silences_noisy_third_party_loggers
            if stage == "none":
                invoke(None, tmp_path)
            else:
                with pytest.raises(error, match="owned wiring test failure"):
                    invoke(None, tmp_path)
        assert {name: logger.level for name, logger in loggers.items()} == expected, (
            "dispatcher wiring test leaked logger levels"
        )
        if stage in ("shutdown", "none"):
            assert owned.fileno() == -1
            dispatcher.shutdown.assert_called_once()
    finally:
        owned.close()
        for name, logger in loggers.items():
            logging.Logger.setLevel(logger, saved[name])
