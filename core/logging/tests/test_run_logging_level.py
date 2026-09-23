"""configure_run_logging validates the level NAME before resolving it.

The pre-fix getattr(logging, name) crashed with AttributeError on an
unknown name and, worse, resolved a colliding module attribute
("basicConfig") to a callable that rode into setLevel.
"""

from __future__ import annotations

import logging

import pytest

import core.logging as clog


@pytest.fixture()
def level_spy(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    monkeypatch.setattr(
        clog, "set_console_log_level",
        lambda level, include_root=False: calls.append(level))
    return calls


def test_known_level_resolves_case_insensitively(level_spy: list) -> None:
    clog.configure_run_logging("warning", verbose=False)
    assert level_spy == [logging.WARNING]


def test_unknown_level_name_is_a_value_error(level_spy: list) -> None:
    with pytest.raises(ValueError, match="unknown log level"):
        clog.configure_run_logging("nosuch", verbose=False)
    assert level_spy == []


def test_colliding_module_attribute_is_refused(level_spy: list) -> None:
    # "basicConfig" is a logging-module attribute but not a level —
    # getattr-resolution passed the FUNCTION into setLevel.
    with pytest.raises(ValueError, match="unknown log level"):
        clog.configure_run_logging("basicConfig", verbose=False)
    assert level_spy == []


def test_verbose_flag_still_selects_debug(level_spy: list) -> None:
    clog.configure_run_logging(None, verbose=True)
    assert level_spy == [logging.DEBUG]
