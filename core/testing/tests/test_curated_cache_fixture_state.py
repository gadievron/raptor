"""Native metadata fixtures must retain warmed LRU objects and statistics."""

import ast
import functools
from pathlib import Path
import textwrap
from types import ModuleType
from unittest.mock import patch

import pytest

from core.config import RaptorConfig
from packages.describe import package_manager, tool_readiness
from packages.describe.target_shape import TargetShape
from packages.llm_analysis import dataflow_query_builder
from packages.sca.llm import exemplars


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/describe/tests/test_package_manager.py", "_isolated_package_manager_cache", package_manager, ("detect_package_manager",)),
    ("packages/describe/tests/test_tool_readiness.py", "_isolated_package_manager_cache", package_manager, ("detect_package_manager",)),
    ("packages/sca/llm/tests/test_exemplars.py", "_isolated_exemplar_caches", exemplars, ("popular_names_block", "exfil_destinations_block")),
    ("packages/llm_analysis/tests/test_dataflow_query_builder.py", "_isolated_query_discovery_cache", dataflow_query_builder, ("discover_prebuilt_queries",)),
]


def _module_view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


def _load(path, namespace):
    # Definitions only: avoid executing the baseline's import-time sys.path edit.
    for node in ast.parse((ROOT / path).read_text()).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)


def _call(cache, name):
    return cache("npm") if name == "popular_names_block" else cache()


def _baseline_consumer(path, namespace, tmp_path, monkeypatch):
    # Run the actual original cache-clearing setup and consuming test, rather
    # than fail because the new fixture does not exist on the baseline.
    if path.endswith("test_package_manager.py"):
        test = namespace["TestDetectPackageManager"]()
        test.setup_method()
        test.test_apt_detected()
    elif path.endswith("test_tool_readiness.py"):
        namespace["TestCheckCodeql"]().test_present_binary_missing_autoreconf_warns()
    elif path.endswith("test_exemplars.py"):
        namespace["test_popular_names_block_tolerates_non_string_elements"](tmp_path, monkeypatch)
    else:
        test = namespace["TestDiscovery"]()
        test.setup_method()
        test.test_finds_path_problem_query(tmp_path, monkeypatch)
        test.teardown_method()


@pytest.mark.parametrize("path,fixture_name,owner,names", CASES)
@pytest.mark.parametrize("finish", ["normal", "body_error", "body_interrupt", "setup_error"])
def test_metadata_fixture_preserves_warm_cache(monkeypatch, tmp_path, path, fixture_name, owner, names, finish):
    # The warm wrappers still execute the original production functions. Only
    # incidental PATH/pack-root discovery uses owned metadata.
    if owner is package_manager:
        tools = _module_view(package_manager.shutil)
        tools.which = lambda name: "/usr/bin/apt" if name == "apt" else None
        monkeypatch.setattr(package_manager, "shutil", tools)
    elif owner is dataflow_query_builder:
        root = tmp_path / "warm" / "python-queries" / "1.0" / "Security" / "CWE-078"
        root.mkdir(parents=True)
        (root / "Warm.ql").write_text("/** @kind path-problem\n * @tags external/cwe/cwe-78\n */\n")
        monkeypatch.setattr(owner, "_DEFAULT_PACK_ROOT", tmp_path / "warm")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        tools = _module_view(owner.shutil)
        tools.which = lambda *args, **kwargs: None
        monkeypatch.setattr(owner, "shutil", tools)
    borrowed = {}
    for name in names:
        original = getattr(owner, name)
        cache = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
        monkeypatch.setattr(owner, name, cache)
        value = _call(cache, name)
        # Distinct warm counters cannot accidentally match a test that clears
        # and happens to repopulate the same interned scalar result.
        for _ in range(7):
            assert _call(cache, name) is value
        borrowed[name] = (cache, value, cache.cache_info())
    namespace = {
        "__name__": "native_cache_fixture", "__file__": str(ROOT / path),
        "functools": functools, "pytest": pytest, "patch": patch,
        "Path": Path, "textwrap": textwrap, "_dqb": dataflow_query_builder,
        "TargetShape": TargetShape,
    }
    for module in (package_manager, tool_readiness, exemplars, dataflow_query_builder):
        for name, value in vars(module).items():
            if callable(value):
                namespace.setdefault(name, value)
    _load(path, namespace)
    if path.endswith("test_tool_readiness.py"):
        namespace.pop("detect_package_manager")  # imported locally by the native test
    original_aliases = {name: namespace[name] for name in names if name in namespace}
    published = []

    class PublicationFailure(RuntimeError):
        pass

    class FixturePatch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            published.append(args)
            if finish == "setup_error":
                raise PublicationFailure

    fixture_patch = FixturePatch()
    try:
        if fixture_name not in namespace:
            native_path = tmp_path / "native"
            native_path.mkdir()
            _baseline_consumer(path, namespace, native_path, fixture_patch)
        else:
            fixture = namespace[fixture_name]
            kwargs = {"monkeypatch": fixture_patch}
            if "tmp_path" in fixture.__code__.co_varnames[:fixture.__code__.co_argcount]:
                kwargs["tmp_path"] = tmp_path / "private"
            try:
                if finish == "setup_error":
                    with pytest.raises(PublicationFailure):
                        fixture(**kwargs)
                else:
                    fixture(**kwargs)
                    for name, (cache, _value, _stats) in borrowed.items():
                        private = getattr(owner, name)
                        assert private is not cache
                        assert private.cache_parameters() == cache.cache_parameters()
                        assert private.cache_info().currsize == 0
                        if name in original_aliases:
                            assert namespace[name] is private
                        _call(private, name)
                        private.cache_clear()
                    if finish == "body_error":
                        raise PublicationFailure
                    if finish == "body_interrupt":
                        raise KeyboardInterrupt
            except (PublicationFailure, KeyboardInterrupt):
                assert finish in {"body_error", "body_interrupt"}
    finally:
        fixture_patch.undo()
    for name, (cache, value, stats) in borrowed.items():
        assert getattr(owner, name) is cache
        assert cache.cache_info() == stats, name
        assert _call(cache, name) is value
    for name, value in original_aliases.items():
        assert namespace[name] is value
    if fixture_name in namespace:
        assert published
