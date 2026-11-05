"""Inline logging captures release owned resources without touching pytest logs."""

import logging
from importlib import import_module
from types import SimpleNamespace

import pytest

from core.testing import logging_state

pytestmark = pytest.mark.usefixtures("handler_removal_mode")


@pytest.fixture
def owners(tmp_path):
    created = []

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
        return handler

    def factory(cls):
        return lambda *args, **kwargs: instrument(cls(*args, **kwargs))

    yield SimpleNamespace(created=created, instrument=instrument, factory=factory)
    for handler, stream in created:
        handler.close()
        stream.close()


@pytest.fixture
def private_log(monkeypatch):
    logger = logging.Logger("owned-inline-capture", logging.DEBUG)
    borrowed = logging.NullHandler()
    logger.addHandler(borrowed)
    get_logger = logging.getLogger

    def route(prefix):
        monkeypatch.setattr(
            logging,
            "getLogger",
            lambda name=None: (
                logger if name and name.startswith(prefix) else get_logger(name)
            ),
        )

    yield SimpleNamespace(
        logger=logger, borrowed=borrowed, route=route
    )
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    borrowed.close()


def assert_released(owners, private_log):
    assert owners.created, "capture constructor was not reached"
    assert all(
        handler._closed and stream.closed for handler, stream in owners.created
    ), "owned capture stayed open"
    assert private_log.logger.handlers == [private_log.borrowed], (
        "capture stayed attached"
    )
    assert not private_log.borrowed._closed


def fail_attachment(private_log, stage, monkeypatch):
    add = private_log.logger.addHandler

    def attach(handler):
        add(handler)
        if stage == "attach-error":
            raise OSError("owned attachment failed")
        if stage == "attach-interrupt":
            raise KeyboardInterrupt("owned attachment failed")

    monkeypatch.setattr(private_log.logger, "addHandler", attach)


def invoke_expected(call, stage):
    error = {
        "body-error": RuntimeError,
        "attach-error": OSError,
        "attach-interrupt": KeyboardInterrupt,
    }.get(stage)
    if error is None:
        return call()
    with pytest.raises(error):
        call()


@pytest.mark.parametrize("kind", ["store", "promotion", "sage", "health"])
@pytest.mark.parametrize(
    "stage", ["normal", "body-error", "attach-error", "attach-interrupt"]
)
def test_capture_helpers_release_on_every_exit(
    kind, stage, owners, private_log, monkeypatch, tmp_path
):
    # Import before redirecting getLogger so imported modules never cache a
    # reference to the probe's private logger.
    module = import_module(
        {
            "store": "core.env.tests.test_spec_store",
            "promotion": "core.run.tests.test_checklist_promotion_shape",
            "sage": "packages.codeql.tests.test_sage_build_prior",
            "health": "packages.sca.tests.test_health",
        }[kind]
    )
    metadata = import_module("core.run.metadata")
    import_module("core.sage.hooks")
    prefix = {
        "store": "core.env.store",
        "promotion": "raptor.core.run.metadata",
        "sage": "raptor",
        "health": "packages.sca.registries",
    }[kind]
    private_log.route(prefix)
    fail_attachment(private_log, stage, monkeypatch)

    def body(*args, **kwargs):
        private_log.logger.warning("owned message")
        if stage == "body-error":
            raise RuntimeError("owned operation failed")
        return "owned result"

    if kind == "store":
        monkeypatch.setattr(
            module, "_RecordingHandler", owners.factory(module._RecordingHandler)
        )
        call = lambda: module._with_store_warnings(body)
    elif kind == "promotion":
        monkeypatch.setattr(
            module, "_CaptureHandler", owners.factory(module._CaptureHandler)
        )
        monkeypatch.setattr(metadata, "_promote_checklist", body)
        call = lambda: module.NonDictCandidateSkippedTest()._promote_capturing(tmp_path)
    elif kind == "sage":
        monkeypatch.setattr(module, "_Capture", owners.factory(module._Capture))
        call = lambda: module._run_with_row(
            SimpleNamespace(run_autonomous_analysis=body), {}, verify=False
        )
    else:
        monkeypatch.setattr(
            module.health_mod,
            "_ThreadLogCapture",
            owners.factory(module.health_mod._ThreadLogCapture),
        )
        monkeypatch.setattr(module.health_mod, "_run_probe", body)
        call = lambda: module.TestProbeErrorAttribution()._probe_with_capture(object())

    result = invoke_expected(call, stage)
    assert_released(owners, private_log)
    if stage == "normal":
        assert (
            result
            == {
                "store": ["owned message"],
                "promotion": "owned message",
                "sage": ["owned message"],
                "health": "owned result",
            }[kind]
        )


@pytest.mark.parametrize("stage", ["normal", "body-error", "attach-error"])
def test_parallel_health_capture_release(stage, owners, private_log, monkeypatch):
    module = import_module("packages.sca.tests.test_health")
    private_log.route("packages.sca.registries")
    fail_attachment(private_log, stage, monkeypatch)
    monkeypatch.setattr(
        module.health_mod,
        "_ThreadLogCapture",
        owners.factory(module.health_mod._ThreadLogCapture),
    )
    if stage == "body-error":

        def probe(*args):
            raise RuntimeError("owned operation failed")

        monkeypatch.setattr(module.health_mod, "_run_probe", probe)
    invoke_expected(
        module.TestProbeErrorAttribution().test_parallel_probes_attribute_to_own_thread,
        stage,
    )
    assert_released(owners, private_log)


@pytest.mark.parametrize(
    "stage",
    [
        "normal",
        "attach-error",
        "attach-interrupt",
        "tag-error",
        "filter-add-error",
        "filter-remove-error",
    ],
)
def test_filter_failure_does_not_strand_capture(
    stage, owners, private_log, monkeypatch
):
    module = import_module(
        "packages.static-analysis.tests.test_scanner_semgrep_parallel"
    )
    private_log.route("raptor")
    fail_attachment(private_log, stage, monkeypatch)
    original_init = logging.Handler.__init__

    def init(handler, *args, **kwargs):
        original_init(handler, *args, **kwargs)
        owners.instrument(handler)

    original_filters = private_log.logger.filters
    borrowed = logging.Filter()
    private_log.logger.addFilter(borrowed)
    add, remove = private_log.logger.addFilter, private_log.logger.removeFilter

    def add_filter(tag):
        add(tag)
        if stage == "filter-add-error":
            raise OSError("owned filter attachment failed")

    def remove_filter(tag):
        remove(tag)
        if stage == "filter-remove-error":
            raise OSError("owned filter removal failed")

    monkeypatch.setattr(private_log.logger, "addFilter", add_filter)
    monkeypatch.setattr(private_log.logger, "removeFilter", remove_filter)
    if stage == "tag-error":

        def tag():
            raise OSError("owned tag setup failed")

        monkeypatch.setattr(module._scanner_mod, "_CodeQLStageTag", tag)

    with pytest.MonkeyPatch.context() as scope:
        scope.setattr(logging.Handler, "__init__", init)
        call = lambda: module.TestCodeQLStageTag()._emit_from_codeql_thread(
            private_log.logger
        )
        if stage == "normal":
            assert call().startswith("[codeql] ")
        else:
            with pytest.raises(
                KeyboardInterrupt if stage == "attach-interrupt" else OSError
            ):
                call()
    assert_released(owners, private_log)
    assert private_log.logger.filters is original_filters
    assert private_log.logger.filters == [borrowed], "stage filter stayed attached"


@pytest.mark.parametrize(
    "stage", ["body-error", "body-interrupt", "attach-error", "attach-interrupt"]
)
def test_build_warning_capture_release(
    stage, owners, private_log, monkeypatch, tmp_path
):
    module = import_module("packages.codeql.tests.test_build_synthesis")
    private_log.route("raptor")
    fail_attachment(private_log, stage, monkeypatch)
    original_init = logging.Handler.__init__

    def init(handler, *args, **kwargs):
        original_init(handler, *args, **kwargs)
        owners.instrument(handler)

    def synthesis(*args, **kwargs):
        raise (KeyboardInterrupt if stage == "body-interrupt" else RuntimeError)(
            "owned operation failed"
        )

    monkeypatch.setattr(module.BuildDetector, "synthesise_build_command", synthesis)
    with pytest.MonkeyPatch.context() as scope:
        scope.setattr(logging.Handler, "__init__", init)
        with pytest.raises(
            KeyboardInterrupt
            if stage.endswith("interrupt")
            else OSError
            if stage == "attach-error"
            else RuntimeError
        ):
            module.TestMissingConfigHeaderDetection().test_synthesised_compile_logs_missing_config_warning(
                tmp_path, None
            )
    assert_released(owners, private_log)


@pytest.mark.parametrize("fail", [False, True])
def test_health_offline_cli_restores_logging(fail, tmp_path, monkeypatch):
    module = import_module("packages.sca.tests.test_health")
    root = logging.Logger("owned-cli-root", logging.DEBUG)
    borrowed = logging.NullHandler()
    root.addHandler(borrowed)
    original_list = root.handlers
    sdk = {
        name: logging.Logger(name, logging.ERROR)
        for name in logging_state.NOISY_THIRD_PARTY_LOGGERS
    }
    proxy = SimpleNamespace(
        getLogger=lambda name=None: root if name is None else sdk[name]
    )
    created = []

    def configure(verbose):
        handler = logging.FileHandler(tmp_path / "owned-cli.log")
        created.append((handler, handler.stream))
        root.addHandler(handler)
        root.setLevel(logging.CRITICAL)
        for logger in sdk.values():
            logger.setLevel(logging.INFO)
        if fail:
            raise RuntimeError("owned CLI setup failed")

    monkeypatch.setattr(logging_state, "logging", proxy)
    monkeypatch.setattr(module.health_mod, "_configure_logging", configure)
    try:
        if fail:
            with pytest.raises(RuntimeError, match="owned CLI setup failed"):
                module.test_offline_flag_is_refused()
        else:
            module.test_offline_flag_is_refused()
        assert created
        assert all(handler._closed and stream.closed for handler, stream in created), (
            "CLI capture remained open"
        )
        assert root.handlers is original_list
        assert root.handlers == [borrowed]
        assert root.level == logging.DEBUG
        assert all(logger.level == logging.ERROR for logger in sdk.values())
        assert not borrowed._closed
    finally:
        for handler, stream in created:
            root.removeHandler(handler)
            handler.close()
        borrowed.close()
