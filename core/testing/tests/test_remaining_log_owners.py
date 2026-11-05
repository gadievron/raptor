"""Native capture scopes release handlers, streams, proxies and borrowed flags."""

import io
import logging
from contextlib import contextmanager
from importlib import import_module
from types import SimpleNamespace

import pytest

from core.testing import logging_state

pytestmark = pytest.mark.usefixtures("handler_removal_mode")


@pytest.fixture
def private_logs(monkeypatch, tmp_path):
    names = [
        "raptor",
        "core.inventory",
        "core.sandbox",
        "core.sandbox.proxy",
        "core.sandbox.context",
        "core.sandbox.observe",
        "jailfix_hostile_closed_test",
        "jailfix_guard_walk_test",
        "jailfix_guard_walk_test.child",
        *logging_state.NOISY_THIRD_PARTY_LOGGERS,
    ]
    root = logging.Logger("owned-root", logging.ERROR)
    loggers = {name: logging.Logger(name, logging.ERROR) for name in names}
    loggers["core.sandbox.proxy"].parent = loggers["core.sandbox"]
    loggers["jailfix_guard_walk_test.child"].parent = loggers["jailfix_guard_walk_test"]
    loggers["jailfix_guard_walk_test.child"].propagate = False
    borrowed = {}
    for logger in [root, *loggers.values()]:
        handler = logging.NullHandler()
        logger.addHandler(handler)
        borrowed[logger] = (handler, logger.level, logger.propagate)
    created = []
    proxy = SimpleNamespace(
        **(
            vars(logging)
            | {"getLogger": lambda name=None: root if name is None else loggers[name]}
        )
    )
    monkeypatch.setattr(logging_state, "logging", proxy)

    def instrument(handler):
        stream = (tmp_path / f"owned-{len(created)}.log").open("w")
        close = handler.close

        def close_owned():
            try:
                close()
            finally:
                stream.close()

        handler.close = close_owned
        created.append((handler, stream))

    def verify(require_handler=True):
        if require_handler:
            assert created, "native capture was not reached"
        assert all(handler._closed and stream.closed for handler, stream in created), (
            "capture remained open"
        )
        for handler, _ in created:
            stream = getattr(handler, "stream", None)
            if isinstance(stream, io.StringIO):
                assert stream.closed, "capture buffer remained open"
        for logger, (handler, level, propagate) in borrowed.items():
            assert logger.handlers == [handler], "capture remained attached"
            assert logger.level == level, "logger level leaked"
            assert logger.propagate == propagate, "logger propagation leaked"
            assert not handler._closed, "borrowed handler was closed"

    yield SimpleNamespace(
        root=root,
        loggers=loggers,
        borrowed=borrowed,
        created=created,
        instrument=instrument,
        verify=verify,
    )
    for handler, stream in created:
        for logger in [root, *loggers.values()]:
            logging.Logger.removeHandler(logger, handler)
        handler.close()
        stream.close()
    for logger, (handler, _, _) in borrowed.items():
        logging.Logger.removeHandler(logger, handler)
        handler.close()


@contextmanager
def route_captures(state, scope, stage):
    get_logger, init = logging.getLogger, logging.Handler.__init__

    def construct(handler, *args, **kwargs):
        init(handler, *args, **kwargs)
        state.instrument(handler)

    scope.setattr(
        logging,
        "getLogger",
        lambda name=None: (
            state.loggers[name] if name in state.loggers else get_logger(name)
        ),
    )
    scope.setattr(logging.Handler, "__init__", construct)
    for logger in state.loggers.values():
        add, remove = logger.addHandler, logger.removeHandler

        def attach(handler, add=add):
            add(handler)
            if stage == "attach-error":
                raise OSError("owned attachment failed")
            if stage == "attach-interrupt":
                raise KeyboardInterrupt("owned attachment failed")

        def detach(handler, remove=remove):
            remove(handler)
            if stage == "remove-error":
                raise OSError("owned removal failed")

        scope.setattr(logger, "addHandler", attach)
        scope.setattr(logger, "removeHandler", detach)
    yield


INLINE = [
    "key",
    "metadata",
    "scorecard-drop",
    "scorecard-quiet",
    "thread-guard",
    "thread-spawn",
    "command-display",
    "asan-display",
]


@pytest.mark.parametrize("kind", INLINE)
@pytest.mark.parametrize("stage", ["attach-error", "attach-interrupt", "body-error"])
def test_inline_capture_failure_releases_ownership(
    kind, stage, private_logs, monkeypatch, tmp_path
):
    # Load every production/test module before redirecting logger resolution.
    module = import_module(
        {
            "key": "core.sage.tests.test_sage_client",
            "metadata": "core.run.tests.test_metadata",
            "scorecard-drop": "core.llm.scorecard.tests.test_scorecard",
            "scorecard-quiet": "core.llm.scorecard.tests.test_scorecard",
            "thread-guard": "core.run.tests.test_agentic_parent_death",
            "thread-spawn": "core.run.tests.test_agentic_parent_death",
            "command-display": "core.sandbox.tests.test_e2e_sandbox",
            "asan-display": "core.sandbox.tests.test_e2e_sandbox",
        }[kind]
    )
    metadata = import_module("core.run.metadata")
    sage = import_module("core.sage.client")
    observe = import_module("core.sandbox.observe")
    failure = RuntimeError("owned body failed")

    def fail(*args, **kwargs):
        raise failure

    case = None
    if kind == "key":
        case = module.TestHardenIdentityKeyPerms()
        case.setUp()
        monkeypatch.setattr(sage, "harden_identity_key_perms", fail)
        call = case.test_tight_key_untouched_no_warning
    elif kind == "metadata":
        monkeypatch.setattr(metadata, "_promote_checklist", fail)
        call = module.PromoteChecklistFrameGateTest().test_tampered_candidate_refused
    elif kind.startswith("scorecard"):
        record = module.ModelScorecard.record_event

        def record_after_attachment(*args, **kwargs):
            if private_logs.created:
                raise failure
            return record(*args, **kwargs)

        monkeypatch.setattr(
            module.ModelScorecard, "record_event", record_after_attachment
        )
        owner = module.TestAutoGc()
        call = (
            (lambda: owner.test_logs_summary_on_drop(tmp_path, None))
            if kind.endswith("drop")
            else (lambda: owner.test_no_log_when_nothing_dropped(tmp_path))
        )
    elif kind.startswith("thread"):
        monkeypatch.setattr(
            module,
            "_import_agentic",
            lambda: SimpleNamespace(
                _parent_death_preexec=fail, run_command_streaming=fail
            ),
        )
        owner = module.TestMainThreadGuard()
        call = (
            owner.test_worker_thread_refuses_with_loud_warning
            if kind.endswith("guard")
            else owner.test_worker_thread_spawn_falls_back_to_no_pdeathsig
        )
    elif kind == "command-display":
        monkeypatch.setattr(module, "sandbox_run", fail)
        call = (
            module.TestE2EEgressProxy().test_cmd_display_sanitises_control_chars_in_argv
        )
    else:
        monkeypatch.setattr(observe, "_interpret_result", fail)
        call = module.TestE2EEgressProxy().test_asan_bug_type_sanitises_control_chars

    try:
        with pytest.MonkeyPatch.context() as scope:
            if kind.startswith("thread"):
                import threading

                class UnstartedThread:
                    def __init__(self, *args, **kwargs):
                        pass

                    def start(self):
                        raise failure

                scope.setattr(threading, "Thread", UnstartedThread)
            with route_captures(private_logs, scope, stage):
                with pytest.raises(
                    KeyboardInterrupt
                    if stage == "attach-interrupt"
                    else OSError
                    if stage == "attach-error"
                    else RuntimeError
                ):
                    call()
        private_logs.verify()
    finally:
        if case is not None:
            case.tearDown()


PROXY_METHODS = [
    "test_emit_skipped_when_a_servicing_handler_stream_is_closed",
    "test_closed_handler_above_record_level_does_not_suppress",
    "test_hostile_closed_property_fails_toward_skip",
    "test_guard_walk_honours_propagate_false",
]


@pytest.mark.parametrize("method", PROXY_METHODS)
@pytest.mark.parametrize("stage", ["normal", "attach-error", "remove-error"])
def test_proxy_logging_scopes_release_all_owners(
    method, stage, private_logs, monkeypatch
):
    module = import_module("core.sandbox.tests.test_proxy_observability")
    proxy_type = module.proxy_mod.EgressProxy
    stopped = []

    def proxy(*args, **kwargs):
        instance = proxy_type(*args, **kwargs)
        stop = instance.stop

        def stop_owned():
            stopped.append(instance)
            stop()

        instance.stop = stop_owned
        return instance

    monkeypatch.setattr(module.proxy_mod, "EgressProxy", proxy)
    monkeypatch.setattr(
        module.proxy_mod, "logger", private_logs.loggers["core.sandbox.proxy"]
    )

    class Capture:
        @contextmanager
        def at_level(self, level, logger):
            target = private_logs.loggers[logger]
            saved = target.level
            target.setLevel(level)
            try:
                yield
            finally:
                target.setLevel(saved)

    def call():
        function = getattr(module.TestStatsLineClosedStreamGuard(), method)
        if method in PROXY_METHODS[:2]:
            function(None, Capture())
        else:
            function()

    with pytest.MonkeyPatch.context() as scope:
        with route_captures(private_logs, scope, stage):
            if stage == "normal":
                call()
            else:
                with pytest.raises(OSError):
                    call()
    private_logs.verify()
    if method in PROXY_METHODS[:2]:
        assert len(stopped) == 1, "proxy stop was skipped"


@pytest.mark.parametrize("method", PROXY_METHODS[:2])
def test_proxy_stops_when_capture_stream_setup_fails(method, private_logs, monkeypatch):
    module = import_module("core.sandbox.tests.test_proxy_observability")
    stopped = []
    proxy = SimpleNamespace(stop=lambda: stopped.append(True))
    monkeypatch.setattr(module.proxy_mod, "EgressProxy", lambda **kwargs: proxy)

    def stream():
        raise RuntimeError("owned stream setup failed")

    monkeypatch.setattr(module, "io", SimpleNamespace(StringIO=stream))
    with pytest.MonkeyPatch.context() as scope:
        with route_captures(private_logs, scope, "normal"):
            with pytest.raises(RuntimeError, match="owned stream setup failed"):
                getattr(module.TestStatsLineClosedStreamGuard(), method)(None, None)
    private_logs.verify(require_handler=False)
    assert stopped == [True], "proxy stop was skipped before capture setup"


@pytest.mark.parametrize("original", [False, True])
@pytest.mark.parametrize("exit_kind", ["normal", "close", "throw"])
def test_scorecard_propagation_fixture_restores_borrowed_flag(
    original, exit_kind, private_logs, monkeypatch
):
    module = import_module("core.llm.scorecard.tests.test_scorecard")
    logger = private_logs.loggers["raptor"]
    logger.propagate = original
    monkeypatch.setattr(
        module, "logging", SimpleNamespace(getLogger=lambda name: logger)
    )
    scope = module._raptor_logger_propagates.__wrapped__()
    next(scope)
    assert logger.propagate is True
    try:
        if exit_kind == "normal":
            with pytest.raises(StopIteration):
                next(scope)
        elif exit_kind == "close":
            scope.close()
        else:
            with pytest.raises(RuntimeError, match="cancelled"):
                scope.throw(RuntimeError("cancelled"))
        assert logger.propagate is original
    finally:
        scope.close()


def test_asan_formatting_capture_positive_control(private_logs, monkeypatch):
    module = import_module("core.sandbox.tests.test_e2e_sandbox")
    observe = import_module("core.sandbox.observe")
    monkeypatch.setattr(observe, "logger", private_logs.loggers["core.sandbox.observe"])
    with pytest.MonkeyPatch.context() as scope:
        with route_captures(private_logs, scope, "normal"):
            # This native method feeds a synthetic CompletedProcess directly
            # to the formatter. It never opens a sandbox or starts a child.
            module.TestE2EEgressProxy().test_asan_bug_type_sanitises_control_chars()
    private_logs.verify()
