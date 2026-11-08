"""Formatting-test fakes restore caller state on every exit path."""

from contextlib import ExitStack
import logging
import os
import sys
from types import ModuleType

import pytest

from core.llm.tests import test_llm_ask_json_lane_scrub as cases
from core.testing.logging_state import isolated_cli_logging, owned_log_handler


@pytest.mark.parametrize("presence", ["absent", "empty", "present"])
@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
def test_formatting_fixture_restores_borrowed_state(presence, finish, tmp_path):
    names = ("raptor", "httpx", "httpcore")
    keys = ("_RAPTOR_TRUSTED", "RAPTOR_DIR", "RAPTOR_LLM_QUIET", "RAPTOR_SCORECARD_PATH")
    missing = object()
    borrowed = {
        name: (sys.modules.get(name, missing), attribute)
        for name, attribute in (
            ("core.llm.client", "LLMClient"),
            ("core.llm.dispatcher.lifecycle", "ensure_route_for_model_configs"),
        )
    }
    attributes = {
        name: vars(module).get(attribute, missing)
        for name, (module, attribute) in borrowed.items() if module is not missing
    }
    with pytest.MonkeyPatch.context() as caller, ExitStack() as cleanup:
        cleanup.enter_context(isolated_cli_logging(logger_names=names))
        loggers = [logging.getLogger(name) for name in ("", *names)]
        for logger in loggers:
            logger.setLevel(logging.ERROR)
            cleanup.enter_context(owned_log_handler(logger, logging.NullHandler(logging.WARNING)))
        handlers = [(logger.handlers, tuple(logger.handlers)) for logger in loggers]
        levels = [(handler, handler.level) for logger in loggers for handler in logger.handlers]
        for key in keys:
            if presence == "absent":
                caller.delenv(key, raising=False)
            else:
                caller.setenv(key, "" if presence == "empty" else str(tmp_path / "borrowed"))
        environment = {key: os.environ.get(key, missing) for key in keys}
        owners = [cases._hermetic_process_state.__wrapped__(), cases._isolate_scorecard.__wrapped__(tmp_path)]
        for owner in owners:
            cleanup.callback(owner.close)
            next(owner)
        mod = ModuleType("owned_formatting_cli")
        mod.expected_client = cases._StubClient
        mod.failure = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[finish]
        exec('''def main():
    import logging, os
    from core.llm.client import LLMClient
    from core.llm.dispatcher.lifecycle import ensure_route_for_model_configs
    assert isinstance(LLMClient(), expected_client)
    ensure_route_for_model_configs([])
    for name in ("", "raptor", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL)
        for handler in logger.handlers:
            handler.setLevel(logging.CRITICAL)
    os.environ["RAPTOR_DIR"] = "cli-direct-write"
    os.environ["RAPTOR_LLM_QUIET"] = "1"
    if failure is not None:
        raise failure("injected")
    return 7
''', vars(mod))
        original_main = mod.main
        with pytest.MonkeyPatch.context() as body:
            if mod.failure is None:
                assert cases._run_main(mod, [], body, tmp_path) == 7
            else:
                with pytest.raises(mod.failure, match="injected"):
                    cases._run_main(mod, [], body, tmp_path)
            body.undo()
            assert os.environ["_RAPTOR_TRUSTED"] == "1"
            assert os.environ["RAPTOR_SCORECARD_PATH"] == str(tmp_path / "scorecard.json")
        assert mod.main is original_main
        assert all(logger.level == logging.ERROR for logger in loggers)
        assert all(logger.handlers is saved_list and tuple(logger.handlers) == saved
                   for logger, (saved_list, saved) in zip(loggers, handlers))
        assert all(handler.level == level for handler, level in levels)
        for name, (module, attribute) in borrowed.items():
            assert sys.modules.get(name, missing) is module
            if module is not missing:
                assert vars(module).get(attribute, missing) is attributes[name]
        for owner in reversed(owners):
            if mod.failure is None:
                with pytest.raises(StopIteration):
                    next(owner)
            else:
                with pytest.raises(mod.failure, match="fixture interrupted"):
                    owner.throw(mod.failure("fixture interrupted"))
        assert {key: os.environ.get(key, missing) for key in keys} == environment
