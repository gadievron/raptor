"""Fixture-owned parser settings and calibrated-profile state."""

import ast
from contextlib import contextmanager
from importlib import import_module
from inspect import isgenerator, signature
from pathlib import Path
import sys
import threading
from types import FunctionType, ModuleType
from unittest.mock import patch as object_patch

import pytest

from core.sandbox.calibrated_hosts import _CacheEntry


CASES = [
    (
        "packages/sca/parsers/tests/test_requirements_commented.py",
        "_reset_toggle",
        "requirements",
        "_INCLUDE_COMMENTED",
    ),
    (
        "packages/sca/parsers/tests/test_gradle_version_catalog.py",
        "_reset_cache",
        "gradle",
        "_PARSE_CACHE",
    ),
    (
        "packages/sca/parsers/tests/test_directory_packages_props.py",
        "_reset_cache",
        "msbuild",
        "_PARSE_CACHE",
    ),
    ("core/llm/tests/test_cc_proxy_hosts.py", "_reset_calibrate_memo", "cc", "_CACHE"),
    (
        "packages/codeql/tests/test_codeql_proxy_hosts.py",
        "_reset_calibrate_memo",
        "codeql",
        "_CACHE",
    ),
    (
        "packages/sca/resolvers/tests/test_proxy_hosts.py",
        "_reset_cache",
        "sca",
        "_CACHE",
    ),
    ("packages/semgrep/tests/test_proxy_hosts.py", "_reset_cache", "semgrep", "_CACHE"),
    (
        "core/sandbox/tests/test_proxy_hosts_ladder_closure.py",
        "_isolated",
        "ladder",
        "_CACHE",
    ),
]
ROOT = Path(__file__).resolve().parents[3]
MODULES = {
    "requirements": "packages.sca.parsers.requirements",
    "gradle": "packages.sca.parsers.gradle_version_catalog",
    "msbuild": "packages.sca.parsers.directory_packages_props",
    "cc": "core.llm.cc_proxy_hosts",
    "codeql": "packages.codeql.codeql_proxy_hosts",
    "sca": "packages.sca.resolvers._proxy_hosts",
    "semgrep": "packages.semgrep._proxy_hosts",
}


def _module_view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


def _prepare(case, initial=True, fail_at=None):
    path, fixture_name, kind, field = case
    if kind == "ladder":
        owner = _module_view(import_module("core.sandbox.calibrated_hosts"))
        site = None
    else:
        site = _module_view(import_module(MODULES[kind]))
        owner = (
            site
            if field != "_CACHE"
            else _module_view(import_module("core.sandbox.calibrated_hosts"))
        )
    if field == "_INCLUDE_COMMENTED":
        borrowed = initial
    elif field == "_PARSE_CACHE":
        borrowed = {Path("borrowed-missing-file"): None}
    else:
        entry = _CacheEntry(identity=("borrowed",))
        entry.ready.set()
        borrowed = {("/borrowed/tool", (), ("--version",)): entry}
        owner._CACHE_LOCK = threading.Lock()
    setattr(owner, field, borrowed)
    contents = borrowed.copy() if isinstance(borrowed, dict) else None
    overrides = []
    env = {"CLAUDE_CODE_USE_BEDROCK": "1"}
    env_before = env.copy()
    steps = []

    class Patch(pytest.MonkeyPatch):
        def _after(self):
            steps.append(None)
            if len(steps) == fail_at:
                raise RuntimeError("injected setup failure")

        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            self._after()

        def setenv(self, name, value, prepend=None):
            assert prepend is None
            self.setitem(env, name, value)
            self._after()

        def delenv(self, name, raising=True):
            self.delitem(env, name, raising=raising)
            self._after()

    def reset_cache():
        borrowed.clear()

    if field == "_CACHE":
        owner.reset_cache_for_tests = reset_cache

    namespace = {
        "Path": Path,
        "req_parser": site,
        "mod": site,
        "_proxy_hosts": site,
        "calibrated_hosts": owner,
        "_reset_cache_for_tests": reset_cache,
    }
    if kind == "requirements":
        site.set_include_commented = lambda value: setattr(site, field, value)
    elif field == "_CACHE" and site is not None:
        site._reset_calibrate_cache_for_tests = reset_cache
        overrides.append((site, site._OVERRIDE_CONFIG_PATH))
    tree = ast.parse((ROOT / path).read_text())
    if kind == "ladder":
        # Reuse the native site's full class and factory. Only provider module
        # bindings are copied; their files and processes are never consulted.
        importlib_view = _module_view(import_module("importlib"))
        providers = {}

        def provider(name):
            if name not in providers:
                providers[name] = _module_view(import_module(name))
                overrides.append(
                    (providers[name], providers[name]._OVERRIDE_CONFIG_PATH)
                )
            return providers[name]

        importlib_view.import_module = provider
        namespace["importlib"] = importlib_view
        nodes = [
            n for n in tree.body if getattr(n, "name", None) in ("_Site", "_sites")
        ]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), path, "exec"), namespace)
        sites = namespace["_sites"]()
        assert len(sites) == 4
        namespace["_sites"] = lambda: sites
    module_names = {MODULES.get(kind): site, "core.sandbox.calibrated_hosts": owner}

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "importlib":
            view = _module_view(import_module(name))
            view.import_module = lambda key: module_names[key]
            return view
        if name == "core.sandbox" and "calibrated_hosts" in fromlist:
            view = _module_view(import_module(name))
            view.calibrated_hosts = owner
            return view
        if name == "core.llm" and "cc_proxy_hosts" in fromlist and kind == "ladder":
            view = _module_view(import_module(name))
            view.cc_proxy_hosts = providers["core.llm.cc_proxy_hosts"]
            return view
        if name == "core.testing.module_state":
            original = import_module(name).isolated_module_state.__wrapped__
            pytest_view = _module_view(pytest)
            pytest_view.MonkeyPatch = Patch
            clone = FunctionType(
                original.__code__,
                dict(original.__globals__, pytest=pytest_view),
                original.__name__,
            )
            clone.__kwdefaults__ = original.__kwdefaults__
            view = ModuleType(name)
            view.isolated_module_state = contextmanager(clone)
            return view
        return __import__(name, globals, locals, fromlist, level)

    namespace["__builtins__"] = dict(
        vars(__import__("builtins")), __import__=fixture_import
    )
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == fixture_name
    )
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return (
        namespace[fixture_name],
        Patch,
        owner,
        field,
        borrowed,
        contents,
        overrides,
        env,
        env_before,
    )


def _start(function, patch, tmp_path):
    available = {"monkeypatch": patch, "tmp_path": tmp_path}
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


def _restored(owner, field, borrowed, contents, overrides, env, env_before):
    assert getattr(owner, field) is borrowed
    if contents is not None:
        assert borrowed == contents
        for key, value in contents.items():
            assert borrowed[key] is value
    for site, original in overrides:
        assert site._OVERRIDE_CONFIG_PATH is original
    assert env == env_before


@pytest.mark.parametrize(
    "case,initial",
    [
        (case, flag)
        for case in CASES
        for flag in ((False, True) if case[2] == "requirements" else (True,))
    ],
    ids=[
        case[2] + "-" + str(flag)
        for case in CASES
        for flag in ((False, True) if case[2] == "requirements" else (True,))
    ],
)
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_parser_proxy_fixture_preserves_caller_state(case, initial, mode, tmp_path):
    (
        function,
        patch_type,
        owner,
        field,
        borrowed,
        contents,
        overrides,
        env,
        env_before,
    ) = _prepare(case, initial)
    patch = patch_type()
    generator = None
    try:
        generator, _ = _start(function, patch, tmp_path)
        active = getattr(owner, field)
        if field == "_INCLUDE_COMMENTED":
            assert active is False
            setattr(owner, field, True)
        else:
            assert active is not borrowed
            assert active == {}
        for site, _ in overrides:
            assert site._OVERRIDE_CONFIG_PATH.is_relative_to(tmp_path)
        if field == "_CACHE":
            assert owner._CACHE_LOCK.acquire(blocking=False)
            owner._CACHE_LOCK.release()
            owner._CACHE[("/owned/tool", (), ())] = _CacheEntry(identity=("owned",))
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _restored(owner, field, borrowed, contents, overrides, env, env_before)


@pytest.mark.parametrize("case", CASES, ids=[c[2] for c in CASES])
def test_parser_proxy_fixture_restores_partial_setup(case, tmp_path):
    (
        function,
        patch_type,
        owner,
        field,
        borrowed,
        contents,
        overrides,
        env,
        env_before,
    ) = _prepare(case, fail_at=1)
    patch = patch_type()
    generator = None
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            generator, _ = _start(function, patch, tmp_path)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    _restored(owner, field, borrowed, contents, overrides, env, env_before)


def test_ladder_import_preserves_the_callers_path_list():
    import importlib.util

    original = sys.path.copy()
    original_before = original.copy()
    # Loading under a private name exercises module-level behavior even if
    # pytest already imported its canonical module during collection.
    name = "private_proxy_ladder_module"
    spec = importlib.util.spec_from_file_location(name, ROOT / CASES[-1][0])
    module = importlib.util.module_from_spec(spec)
    with object_patch.object(sys, "path", original):
        spec.loader.exec_module(module)
        assert sys.path is original
        assert sys.path == original_before
