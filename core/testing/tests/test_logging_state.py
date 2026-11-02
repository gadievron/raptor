"""CLI logging scopes preserve inherited handlers and close owned files."""

import logging

import pytest

from core.logging import configure_cli_logging, quiet_third_party_loggers
from core.testing.logging_state import isolated_cli_logging


@pytest.mark.parametrize("fail", [False, True])
def test_file_handler_and_levels_restored_on_every_exit(tmp_path, fail):
    with isolated_cli_logging():
        root = logging.getLogger()
        sdk = logging.getLogger("botocore")
        sdk.setLevel(logging.DEBUG)
        original_list = root.handlers
        original_handlers = tuple(root.handlers)
        original_levels = [handler.level for handler in original_handlers]
        original_root_level = root.level
        created = []

        def call():
            with isolated_cli_logging():
                handler = logging.FileHandler(tmp_path / "debug.log", encoding="utf-8")
                created.append((handler, handler.stream))
                root.addHandler(handler)
                root.setLevel(logging.DEBUG)
                for existing in original_handlers:
                    existing.setLevel(logging.ERROR)
                quiet_third_party_loggers()
                assert sdk.level == logging.WARNING
                handler.emit(logging.LogRecord("probe", logging.WARNING, __file__, 0,
                                               "written", (), None))
                if fail:
                    raise RuntimeError("CLI failed")

        if fail:
            with pytest.raises(RuntimeError, match="CLI failed"):
                call()
        else:
            call()

        assert root.handlers is original_list
        assert tuple(root.handlers) == original_handlers
        assert [handler.level for handler in original_handlers] == original_levels
        assert root.level == original_root_level
        assert sdk.level == logging.DEBUG
        assert created[0][1].closed
        assert (tmp_path / "debug.log").read_text().strip() == "written"


def test_fresh_console_setup_restores_original_handler_list():
    root = logging.getLogger()
    original_list = root.handlers
    original_handlers = tuple(root.handlers)
    original_level = root.level
    with isolated_cli_logging():
        root.handlers = []
        configure_cli_logging(logging.DEBUG)
        created = tuple(root.handlers)
        assert created
    assert root.handlers is original_list
    assert tuple(root.handlers) == original_handlers
    assert root.level == original_level
    assert all(handler._closed for handler in created)
