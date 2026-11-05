"""Logging setup and cleanup failures preserve borrowed handlers and levels."""

import logging
from importlib import import_module
from types import SimpleNamespace

import pytest

from core.testing import logging_state


@pytest.fixture
def state(tmp_path, monkeypatch):
    root = logging.Logger("owned-root", logging.ERROR)
    borrowed = logging.NullHandler(logging.WARNING)
    root.addHandler(borrowed)
    sdk = {
        name: logging.Logger(name, logging.ERROR)
        for name in logging_state.NOISY_THIRD_PARTY_LOGGERS
    }
    named = {
        name: logging.Logger(name, logging.ERROR)
        for name in ["raptor", "packages.sca.discovery"]
    }
    originals = (root.handlers, tuple(root.handlers), root.level, borrowed.level)
    created = []

    def get_logger(name=None):
        if name is None:
            return root
        return sdk[name] if name in sdk else named[name]

    proxy = SimpleNamespace(**(vars(logging) | {"getLogger": get_logger}))
    monkeypatch.setattr(logging_state, "logging", proxy)

    def instrument(handler, stream=None):
        if stream is None:
            stream = (tmp_path / f"owned-{len(created)}.log").open("w")
        close = handler.close

        def close_owned():
            try:
                close()
            finally:
                stream.close()

        handler.close = close_owned
        created.append((handler, stream))
        return handler

    def assert_restored():
        assert created, "capture setup was not reached"
        assert all(handler._closed and stream.closed for handler, stream in created), (
            "owned logging resource remained open"
        )
        assert root.handlers is originals[0]
        assert tuple(root.handlers) == originals[1], "root handler list changed"
        assert root.level == originals[2], "root level leaked"
        assert borrowed.level == originals[3], "borrowed handler level leaked"
        assert not borrowed._closed
        assert all(
            logger.level == logging.ERROR for logger in [*sdk.values(), *named.values()]
        ), "named logger level leaked"

    yield SimpleNamespace(
        root=root,
        sdk=sdk,
        named=named,
        proxy=proxy,
        created=created,
        instrument=instrument,
        assert_restored=assert_restored,
    )
    for handler, stream in created:
        logging.Logger.removeHandler(root, handler)
        for logger in named.values():
            logging.Logger.removeHandler(logger, handler)
        handler.close()
        stream.close()
    borrowed.close()


@pytest.mark.parametrize("kind", ["dependencies", "target-shape"])
@pytest.mark.parametrize(
    "stage", ["normal", "attach-error", "level-error", "remove-error"]
)
def test_describe_capture_restores_level(kind, stage, state, tmp_path, monkeypatch):
    # Load all target modules before redirecting logger resolution. No module
    # should cache one of this probe's private loggers at import time.
    deps = import_module("packages.describe.tests.test_deps")
    shape = import_module("packages.describe.tests.test_target_shape")
    import_module("core.build.build_detector")
    name = "packages.sca.discovery" if kind == "dependencies" else "raptor"
    logger = state.named[name]
    borrowed = logging.NullHandler()
    logger.addHandler(borrowed)
    original_list = logger.handlers
    get_logger, init = logging.getLogger, logging.Handler.__init__
    add, remove, level = logger.addHandler, logger.removeHandler, logger.setLevel

    def attach(handler):
        add(handler)
        if stage == "attach-error":
            raise OSError("owned attach failed")

    def detach(handler):
        remove(handler)
        if stage == "remove-error":
            raise OSError("owned removal failed")

    def set_level(value):
        level(value)
        if stage == "level-error" and value == logging.INFO:
            raise OSError("owned level setup failed")

    def construct(handler, *args, **kwargs):
        init(handler, *args, **kwargs)
        state.instrument(handler)

    monkeypatch.setattr(logger, "addHandler", attach)
    monkeypatch.setattr(logger, "removeHandler", detach)
    monkeypatch.setattr(logger, "setLevel", set_level)
    try:
        with pytest.MonkeyPatch.context() as scope:
            scope.setattr(
                logging,
                "getLogger",
                lambda requested=None: (
                    logger if requested == name else get_logger(requested)
                ),
            )
            scope.setattr(logging.Handler, "__init__", construct)
            call = (
                (
                    lambda: (
                        deps.TestThreadScopedSuppression().test_concurrent_threads_records_survive_window(
                            tmp_path, monkeypatch
                        )
                    )
                )
                if kind == "dependencies"
                else (
                    lambda: (
                        shape.TestProbeNoiseFilterThreadScoped().test_concurrent_threads_probe_lines_survive(
                            monkeypatch, tmp_path
                        )
                    )
                )
            )
            if stage == "normal":
                call()
            else:
                with pytest.raises(OSError):
                    call()
        state.assert_restored()
        assert logger.handlers is original_list
        assert logger.handlers == [borrowed]
        assert not borrowed._closed
    finally:
        # A failed baseline must not leave its private handler attached.
        for handler in list(logger.handlers):
            remove(handler)
        borrowed.close()


@pytest.mark.parametrize("kind", ["negative-cache", "sweep", "trust-cli"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_cli_call_scopes_restore_all_logging(kind, error, state, tmp_path, monkeypatch):
    module = import_module(
        {
            "negative-cache": "packages.sca.registries.tests.test_negative_cache",
            "sweep": "packages.sca.calibration.tests.test_stress_logging",
            "trust-cli": "packages.sca.tests.test_trust_switchboard",
        }[kind]
    )
    cli = import_module("packages.sca.cli")
    stress = import_module("packages.sca.calibration.stress")
    failure = error("owned CLI setup failed")

    def configure(*args, **kwargs):
        # A non-FileHandler with an owned stream catches cleanups that close
        # only FileHandlers. Multiple additions catch mutation during iteration.
        stream = (tmp_path / "owned-console.log").open("w")
        handler = state.instrument(logging.StreamHandler(stream), stream)
        state.root.addHandler(handler)
        for index in range(2):
            handler = logging.FileHandler(tmp_path / f"owned-file-{index}.log")
            state.instrument(handler, handler.stream)
            state.root.addHandler(handler)
        state.root.setLevel(logging.DEBUG)
        for handler in state.root.handlers:
            handler.setLevel(logging.CRITICAL)
        for logger in state.sdk.values():
            logger.setLevel(logging.INFO)
        raise failure

    monkeypatch.setattr(module, "logging", state.proxy, raising=False)
    if kind == "negative-cache":
        monkeypatch.setattr(cli, "_configure_logging", configure)
        call = lambda: module.test_configure_logging_debug_file(tmp_path)
    elif kind == "sweep":
        monkeypatch.setattr(stress, "configure_sweep_logging", configure)
        call = lambda: module.test_sweep_logging_installs_one_console_handler(tmp_path)
    else:
        monkeypatch.setattr(cli, "_run_analyse", configure)
        call = lambda: module.TestScanCliEntrypoint()._run(monkeypatch, tmp_path, [])
    get_logger = logging.getLogger
    private_names = {*state.sdk, *state.named}
    with pytest.MonkeyPatch.context() as scope:
        scope.setattr(
            logging,
            "getLogger",
            lambda name=None: (
                state.proxy.getLogger(name)
                if name is None or name in private_names
                else get_logger(name)
            ),
        )
        with pytest.raises(error) as caught:
            call()
    assert caught.value is failure
    state.assert_restored()


@pytest.mark.parametrize(
    "stage", ["normal", "cancel", "attach-error", "attach-interrupt"]
)
def test_sdk_capture_fixture_does_not_change_levels(stage, state, monkeypatch):
    module = import_module("core.logging.tests.test_third_party_quiet")
    cls = module._CaptureHandler
    monkeypatch.setattr(module, "logging", state.proxy)
    monkeypatch.setattr(module, "_CaptureHandler", lambda: state.instrument(cls()))
    add = state.root.addHandler

    def attach(handler):
        add(handler)
        if stage == "attach-error":
            raise OSError("owned attach failed")
        if stage == "attach-interrupt":
            raise KeyboardInterrupt("owned attach failed")

    monkeypatch.setattr(state.root, "addHandler", attach)
    scope = module.root_capture.__wrapped__()
    try:
        if stage.startswith("attach"):
            with pytest.raises(
                KeyboardInterrupt if stage.endswith("interrupt") else OSError
            ):
                next(scope)
        else:
            handler = next(scope)
            assert state.root.level == logging.ERROR, (
                "fixture changed root level before the call phase"
            )
            assert all(logger.level == logging.ERROR for logger in state.sdk.values())
            if stage == "cancel":
                with pytest.raises(RuntimeError, match="cancelled"):
                    scope.throw(RuntimeError("cancelled"))
            else:
                with pytest.raises(StopIteration):
                    next(scope)
            assert handler._closed
        state.assert_restored()
    finally:
        scope.close()


@pytest.mark.parametrize(
    "stage", ["normal", "body-error", "root-setup-error", "sdk-setup-error"]
)
def test_sdk_call_window_restores_after_partial_setup(
    stage, state, monkeypatch, tmp_path
):
    module = import_module("core.logging.tests.test_third_party_quiet")
    monkeypatch.setattr(module, "logging", state.proxy)
    set_root = state.root.setLevel
    first_sdk = next(iter(state.sdk.values()))
    set_sdk = first_sdk.setLevel

    def root_level(value):
        set_root(value)
        if stage == "root-setup-error" and value == logging.INFO:
            raise OSError("owned root setup failed")

    def sdk_level(value):
        set_sdk(value)
        if stage == "sdk-setup-error" and value == logging.NOTSET:
            raise OSError("owned SDK setup failed")

    monkeypatch.setattr(state.root, "setLevel", root_level)
    monkeypatch.setattr(first_sdk, "setLevel", sdk_level)

    def call():
        with module._sdk_logging_baseline():
            assert state.root.level == logging.INFO
            assert all(logger.level == logging.NOTSET for logger in state.sdk.values())
            handler = logging.FileHandler(tmp_path / "owned-window.log")
            state.instrument(handler, handler.stream)
            state.root.addHandler(handler)
            if stage == "body-error":
                raise RuntimeError("owned body failed")

    if stage == "normal":
        call()
    else:
        with pytest.raises(RuntimeError if stage == "body-error" else OSError):
            call()
    if state.created:
        state.assert_restored()
    else:
        assert state.root.level == logging.ERROR
        assert all(logger.level == logging.ERROR for logger in state.sdk.values())
