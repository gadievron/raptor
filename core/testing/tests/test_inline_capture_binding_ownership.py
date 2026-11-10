"""Inline capture factories remain private through normal and exceptional exits."""
from contextlib import contextmanager
from importlib import import_module
import logging
from types import SimpleNamespace

import pytest

from core.testing.module_views import module_function_view
from core.testing.tests import test_log_capture_cleanup as native
from core.testing.tests.conftest import handler_removal_mode as handler_removal_mode

pytestmark = pytest.mark.usefixtures("handler_removal_mode")


@pytest.mark.parametrize("module_name,class_name", native.INLINE_SCOPES)
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt])
def test_inline_capture_scope_restores_borrowed_logging(
    module_name, class_name, outcome
):
    module = import_module(module_name)
    original = getattr(module, class_name)
    methods = original.__enter__, original.__exit__
    had_logging = "logging" in vars(module)
    module_logging = vars(module).get("logging")
    borrowed = logging.Handler, logging.getLogger
    actual_context = pytest.MonkeyPatch.context
    loggers, handlers, seen = [], [], []

    def private_logger():
        result = native.private_logger()
        loggers.append(result)
        return result

    @contextmanager
    def context():
        with actual_context() as actual:
            class Scope:
                def __getattr__(self, name):
                    return getattr(actual, name)

                def setattr(self, target, name, value, *args, **kwargs):
                    assert (logging.Handler, logging.getLogger) == borrowed
                    if name in ("Handler", "getLogger"):
                        assert target is not logging
                        seen.append(name)
                        if name == "Handler":
                            cells = dict(zip(value.__code__.co_freevars,
                                             (c.cell_contents for c in value.__closure__)))
                            handlers.append(cells["owned"])
                    actual.setattr(target, name, value, *args, **kwargs)
            yield Scope()
            assert seen == ["Handler", "getLogger"]
            assert handlers[0]._closed
            logger, caller_handler = loggers[0]
            assert logger.handlers == [caller_handler]
            assert not caller_handler._closed
            assert (logging.Handler, logging.getLogger) == borrowed
            if outcome is not None:
                raise outcome("outer capture scope exit")

    pytest_view = SimpleNamespace(**(vars(pytest) | {
        "MonkeyPatch": SimpleNamespace(context=context),
    }))
    view = module_function_view(native, bindings={
        "pytest": pytest_view, "private_logger": private_logger,
    })

    def invoke():
        view.test_inline_capture_cleanup(module_name, class_name, "normal")

    if outcome is None:
        invoke()
    else:
        with pytest.raises(outcome, match="outer capture scope exit"):
            invoke()
    assert len(loggers) == len(handlers) == 1
    assert handlers[0]._closed and loggers[0][1]._closed
    assert (logging.Handler, logging.getLogger) == borrowed
    assert getattr(module, class_name) is original
    assert (original.__enter__, original.__exit__) == methods
    assert ("logging" in vars(module)) is had_logging
    assert vars(module).get("logging") is module_logging
