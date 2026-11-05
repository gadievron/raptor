"""Reset fixtures must restore borrowed containers, config, and environment."""

from builtins import __import__ as real_import
from inspect import isgenerator, signature
from types import FunctionType, SimpleNamespace
import importlib

import pytest


CASES = [
    ("packages.sca.conftest", "_deterministic_typosquat_popular", "sca"),
    (
        "packages.sca.supply_chain.tests.test_typosquat_denylist",
        "real_loader",
        "denylist",
    ),
    ("core.dataflow.tests.test_sanitizer_cut_config", "_clean", "config"),
    (
        "core.analysis.tests.test_sanitizer_cut_precision",
        "TestAuditWiring._reset_config",
        "config",
    ),
    ("core.analysis.tests.test_binary_oracle_edges_pins", "pins", "pins"),
]
ENV_VARS = (
    "RAPTOR_SANITIZER_CUT",
    "RAPTOR_SANITIZER_CUT_NO_LEXICAL",
    "RAPTOR_SANITIZER_CUT_PARITY_LOG",
    "RAPTOR_SANITIZER_CUT_AUDIT_DIR",
)
POPULAR = ("_POPULAR_BY_ECO", "_POPULAR_SET", "_POPULAR_BY_LEN")
OTHER = ("_DENYLIST_BY_ECO", "_ALLOWLIST_BY_ECO")
RAW = ("_DENYLIST_RAW", "_ALLOWLIST_RAW")


def _prepare(case, tmp_path, initial="value", fail_at=None):
    module_name, fixture_name, kind = case
    module = importlib.import_module(module_name)
    fixture = module
    for part in fixture_name.split("."):
        fixture = getattr(fixture, part)
    original = fixture.__wrapped__
    namespace = dict(original.__globals__)
    typosquat = SimpleNamespace(
        **{name: {"borrowed": object()} for name in (*POPULAR, *OTHER)}
    )
    typosquat._DENYLIST_RAW = {"borrowed": object()}
    typosquat._ALLOWLIST_RAW = {"borrowed": object()}
    typosquat._load_popular = object()
    typosquat._DATA_DIR = tmp_path / "old-popular"
    typosquat._DENYLIST_PATH = tmp_path / "old-denylist"
    slopsquat = SimpleNamespace(
        _COLLAPSED_INDEX={"borrowed": object()}, _load_popular=object()
    )
    config = SimpleNamespace(_active=object())
    config.reset = lambda: setattr(config, "_active", None)
    pins = SimpleNamespace()
    if initial != "absent":
        pins.BINARY_ORACLE_IDENTITY_PINS = (
            None if initial == "none" else {"borrowed": object()}
        )
    env = (
        {}
        if initial == "absent"
        else {name: "" if initial == "none" else "caller-" + name for name in ENV_VARS}
    )
    private_os = SimpleNamespace(environ=env)
    count = []

    class Patch(pytest.MonkeyPatch):
        def _after(self):
            count.append(None)
            if len(count) == fail_at:
                raise RuntimeError("injected setup failure")

        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            self._after()

        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            self._after()

        def setenv(self, name, value, prepend=None):
            assert prepend is None
            self.setitem(env, name, value)

        def delenv(self, name, raising=True):
            super().delitem(env, name, raising=raising)
            self._after()

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "packages.sca.supply_chain":
            return SimpleNamespace(typosquat=typosquat, slopsquat=slopsquat)
        if name == "core.dataflow" and "sanitizer_cut_config" in fromlist:
            return SimpleNamespace(sanitizer_cut_config=config)
        if name == "os":
            return private_os
        return real_import(name, globals, locals, fromlist, level)

    namespace.update(typosquat=typosquat, cfg=config, RaptorConfig=pins, os=private_os)
    namespace["__builtins__"] = dict(
        vars(__import__("builtins")), __import__=fixture_import
    )
    if "_reset_caches" in namespace and kind == "denylist":
        reset = namespace["_reset_caches"]
        namespace["_reset_caches"] = FunctionType(reset.__code__, namespace)
    function = FunctionType(
        original.__code__,
        namespace,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    owners = (typosquat, slopsquat, config, pins)
    snapshots = [(owner, dict(vars(owner))) for owner in owners]
    containers = [
        (value, value.copy())
        for _, values in snapshots
        for value in values.values()
        if isinstance(value, dict)
    ]
    expected_env = env.copy()
    patch = Patch()
    return function, patch, owners, snapshots, containers, env, expected_env


def _start(function, patch, tmp_path):
    available = {"self": object(), "monkeypatch": patch, "tmp_path": tmp_path}
    result = function(
        **{name: available[name] for name in signature(function).parameters}
    )
    if isgenerator(result):
        return result, next(result)
    return None, result


def _finish(generator, mode):
    if generator is None:
        return
    try:
        if mode == "close":
            generator.close()
        elif mode == "throw":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            with pytest.raises(StopIteration):
                next(generator)
    finally:
        generator.close()


def _assert_restored(snapshots, containers, env, expected_env):
    for owner, fields in snapshots:
        assert vars(owner).keys() == fields.keys()
        for name, value in fields.items():
            assert getattr(owner, name) is value
    for borrowed, contents in containers:
        assert borrowed == contents
    assert env == expected_env


@pytest.mark.parametrize(
    "case,initial",
    [
        (case, initial)
        for case in CASES
        for initial in (
            ("absent", "none", "value") if case[2] in {"config", "pins"} else ("value",)
        )
    ],
)
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_reset_fixture_preserves_borrowed_state(case, initial, mode, tmp_path):
    function, patch, owners, snapshots, containers, env, expected_env = _prepare(
        case,
        tmp_path,
        initial,
    )
    generator = None
    try:
        generator, value = _start(function, patch, tmp_path)
        typosquat, slopsquat, config, pins = owners
        if case[2] in {"sca", "denylist"}:
            fields = (*POPULAR, *OTHER)
            for name in fields:
                cache = getattr(typosquat, name)
                assert cache == {}
                assert cache is not snapshots[0][1][name]
                cache["test"] = object()
            assert slopsquat._load_popular is typosquat._load_popular
            assert slopsquat._COLLAPSED_INDEX == {}
            slopsquat._COLLAPSED_INDEX["test"] = object()
            assert typosquat._DENYLIST_RAW is None
            assert typosquat._ALLOWLIST_RAW is None
            typosquat._DENYLIST_RAW = {"test": True}
            typosquat._ALLOWLIST_RAW = {"test": True}
            if case[2] == "denylist":
                assert value == tmp_path
        elif case[2] == "config":
            assert config._active is None
            assert not any(name in env for name in ENV_VARS)
            config._active = object()
            env.update({name: "exported-by-test" for name in ENV_VARS})
        else:
            assert value is pins.BINARY_ORACLE_IDENTITY_PINS
            assert value == {}
            value["test"] = object()
        for borrowed, contents in containers:
            assert borrowed == contents
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _assert_restored(snapshots, containers, env, expected_env)


@pytest.mark.parametrize(
    "case,fail_at",
    [
        *((case, 1) for case in CASES),
        (CASES[0], 10),
        (CASES[1], 12),
        (CASES[2], 9),
        (CASES[3], 9),
    ],
)
def test_reset_fixture_unwinds_partial_setup(case, fail_at, tmp_path):
    function, patch, _, snapshots, containers, env, expected_env = _prepare(
        case,
        tmp_path,
        fail_at=fail_at,
    )
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            _start(function, patch, tmp_path)
    finally:
        patch.undo()
    _assert_restored(snapshots, containers, env, expected_env)
