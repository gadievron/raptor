"""Reset fixtures own temporary state without clearing their caller's values."""

import builtins
import inspect
from contextlib import contextmanager
from importlib import import_module
from types import FunctionType, SimpleNamespace

import pytest

BANNERS = dict.fromkeys(
    (
        "_MODEL_BANNER_SHOWN",
        "_TRANSPORT_BANNER_SHOWN",
        "_UNCAPPED_BANNER_SHOWN",
        "_DEFAULT_CEILING_LOG_SHOWN",
    ),
    False,
)
CLI = {
    "_cli_sandbox_audit": False,
    "_cli_sandbox_audit_verbose": False,
    "_cli_sandbox_disabled": False,
    "_cli_sandbox_profile": None,
    "_cli_sandbox_readable_paths": None,
    "_cli_sandbox_tool_paths": None,
    "_cli_sandbox_audit_budget": None,
    "_cli_sandbox_disable_consent": None,
    "_cli_sandbox_floor": None,
}
SPECS = [
    ("core.llm.tests.test_pinned_model", "_reset_banner_flag", BANNERS),
    ("core.llm.tests.test_llm_callbacks", "_reset_banner_flag", BANNERS),
    (
        "core.llm.tests.test_bedrock_detection",
        "_clear_availability_cache",
        {"_cached_llm_availability": None},
    ),
    (
        "core.startup.tests.test_wsl",
        "reset_wsl_cache",
        {"_is_wsl_cache": None, "_is_wsl2_cache": None},
    ),
    (
        "core.startup.tests.test_wsl",
        "TestWarnTmpdirWindowsInterop.reset_tmpdir_latch",
        {"_tmpdir_warned": False},
    ),
    (
        "core.run.tests.test_workdir",
        "TestTempRootInteropAdvisory._reset_latch",
        {"_tmpdir_warned": False},
    ),
    (
        "core.run.tests.test_scratch",
        "TestTempRootInteropAdvisory._reset_latch",
        {"_tmpdir_warned": False},
    ),
    (
        "core.startup.tests.test_check_env_macos",
        "reset_seatbelt_cache",
        {"_seatbelt_available_cache": None},
    ),
    ("core.sandbox.tests.test_audit_cli_flags", "reset_state", CLI),
    (
        "core.sandbox.tests.test_context_backend_dispatch",
        "reset_caches",
        {
            "_seatbelt_available_cache": None,
            "_mount_available_cache": None,
            "_mount_ns_available_cache": None,
        },
    ),
    (
        "core.llm.tests.test_consumed_attempt_gate",
        "_clean_attempt_state",
        {"response_started": False},
    ),
    (
        "core.llm.tests.test_turn_consumed_gate",
        "_clean_attempt_state",
        {"response_started": False},
    ),
    (
        "core.llm.dispatcher.tests.test_child_ledger_vetoed_death",
        "_clean_attempt_state",
        {"response_started": False},
    ),
]
FAULTS = [
    (index, field)
    for index, (_, _, defaults) in enumerate(SPECS)
    for field in dict.fromkeys((next(iter(defaults)), next(reversed(defaults))))
]


def native_fixture(module_name, path, namespace):
    module = import_module(module_name)
    fixture = module
    for part in path.split("."):
        fixture = getattr(fixture, part)
    original = fixture.__wrapped__
    environment = dict(original.__globals__)
    environment.update(
        _client_mod=namespace,
        wsl=namespace,
        state=namespace,
        dispatcher_client=SimpleNamespace(_attempt_state=namespace),
    )

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Route only the fixture's explicit imports. No real package attributes,
        # capability flags, thread-local state or sys.modules entries change.
        if name == "core.sandbox" and "state" in fromlist:
            return SimpleNamespace(state=namespace)
        if name == "core.startup" and "wsl" in fromlist:
            return SimpleNamespace(wsl=namespace)
        if name == "core.llm.detection":
            return SimpleNamespace(llm=SimpleNamespace(detection=namespace))
        return builtins.__import__(name, globals, locals, fromlist, level)

    environment["__builtins__"] = dict(vars(builtins), __import__=private_import)
    clone = FunctionType(
        original.__code__,
        environment,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    clone.__kwdefaults__ = original.__kwdefaults__
    return original, clone


@contextmanager
def fixture_scope(spec, namespace):
    original, function = native_fixture(spec[0], spec[1], namespace)
    with pytest.MonkeyPatch.context() as patch:
        parameters = inspect.signature(original).parameters
        args = {}
        if "self" in parameters:
            args["self"] = object()
        if "monkeypatch" in parameters:
            args["monkeypatch"] = patch
        result = function(**args)
        if not inspect.isgenerator(result):
            yield
            return
        try:
            next(result)
            try:
                yield
            finally:
                # Pytest resumes yield fixtures normally even when the test
                # body raises. Throwing the body error into the generator
                # would test a different lifecycle and invent false failures.
                with pytest.raises(StopIteration):
                    next(result)
        finally:
            result.close()


def assert_same(namespace, originals):
    assert vars(namespace).keys() == originals.keys(), (
        "fixture changed attribute presence"
    )
    assert all(
        getattr(namespace, name) is value for name, value in originals.items()
    ), "fixture clobbered borrowed state"


@pytest.mark.parametrize("index", range(len(SPECS)))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("interrupt", [False, True])
def test_native_fixture_restores_borrowed_values(index, borrowed, interrupt):
    spec = SPECS[index]
    defaults = spec[2]
    originals = {
        name: object() if borrowed else value for name, value in defaults.items()
    }
    originals["untouched"] = object()
    namespace = SimpleNamespace(**originals)

    def run():
        with fixture_scope(spec, namespace):
            assert all(
                getattr(namespace, name) is value for name, value in defaults.items()
            ), "fixture did not provide its private baseline"
            for name in defaults:
                setattr(namespace, name, object())
            if interrupt:
                raise KeyboardInterrupt("owned test interrupted")

    if interrupt:
        with pytest.raises(KeyboardInterrupt, match="owned test interrupted"):
            run()
    else:
        run()
    assert_same(namespace, originals)


@pytest.mark.parametrize("index", range(10, 13))
@pytest.mark.parametrize("interrupt", [False, True])
def test_attempt_fixture_restores_missing_attribute(index, interrupt):
    namespace = SimpleNamespace(untouched=object())
    originals = dict(vars(namespace))

    def run():
        with fixture_scope(SPECS[index], namespace):
            assert namespace.response_started is False
            namespace.response_started = True
            if interrupt:
                raise RuntimeError("owned test failed")

    if interrupt:
        with pytest.raises(RuntimeError, match="owned test failed"):
            run()
    else:
        run()
    assert_same(namespace, originals)


@pytest.mark.parametrize("index,field", FAULTS)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_partial_fixture_setup_unwinds_every_pin(index, field, error):
    spec = SPECS[index]
    originals = {name: object() for name in spec[2]}
    originals["untouched"] = object()
    failure = error("owned fixture setup interrupted")
    armed = False
    raised = False

    class Namespace(SimpleNamespace):
        def __setattr__(self, name, value):
            nonlocal raised
            super().__setattr__(name, value)
            if armed and not raised and name == field and value is spec[2][name]:
                raised = True
                raise failure

    namespace = Namespace(**originals)
    armed = True
    with pytest.raises(error) as caught:
        with fixture_scope(spec, namespace):
            pytest.fail(
                "fixture skipped a baseline field instead of reaching the injected failure"
            )
    assert caught.value is failure
    assert_same(namespace, originals)


@pytest.mark.parametrize("original", [False, True])
@pytest.mark.parametrize("exit_kind", ["close", "throw"])
def test_turn_logging_fixture_restores_on_generator_cancellation(original, exit_kind):
    module_name = "core.llm.tests.test_turn_consumed_gate"
    namespace = SimpleNamespace(propagate=original)
    module = import_module(module_name)
    source = module._raptor_logger_propagates.__wrapped__
    environment = dict(
        source.__globals__, logging=SimpleNamespace(getLogger=lambda name: namespace)
    )
    function = FunctionType(
        source.__code__,
        environment,
        source.__name__,
        source.__defaults__,
        source.__closure__,
    )
    generator = function()
    next(generator)
    assert namespace.propagate is True
    try:
        if exit_kind == "close":
            generator.close()
        else:
            with pytest.raises(RuntimeError, match="cancelled"):
                generator.throw(RuntimeError("cancelled"))
        assert namespace.propagate is original
    finally:
        generator.close()
