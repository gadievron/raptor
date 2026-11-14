"""Owned version directories and scalar sort keys; no CodeQL execution."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def resolver(tmp_path):
    source = Path(__file__).parents[1] / "codeql_query_resolver.py"
    nodes = [n for n in ast.parse(source.read_text()).body if isinstance(n, ast.FunctionDef)
             and n.name in {"_version_key", "_package_cache_roots"}]

    class OwnedPath(type(Path())):
        @classmethod
        def home(cls):
            return cls(tmp_path)

    namespace = {"Path": OwnedPath}
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    return SimpleNamespace(key=namespace["_version_key"], roots=namespace["_package_cache_roots"], home=tmp_path)


@pytest.mark.parametrize("component", ["\u00b2", "1\u00b2", "\u2460"])
def test_non_decimal_digit_components_keep_string_fallback(resolver, component):
    assert resolver.key(component + ".0") == ((0, 0, component), (1, 0, ""))


def test_numeric_component_order_and_decimal_unicode_are_preserved(resolver):
    assert resolver.key("1.10.0") > resolver.key("1.9.0")
    assert resolver.key("\u0661.\u0662") == resolver.key("1.2")
    assert resolver.key("1.01") == resolver.key("1.1")


def test_non_decimal_version_directory_does_not_discard_valid_pack_root(resolver):
    pack = resolver.home / ".codeql" / "packages" / "codeql" / "cpp-queries"
    pack.mkdir(parents=True)
    for version in ("1.9.0", "1.10.0", "\u00b2.0"):
        (pack / version).mkdir()
    roots = resolver.roots("codeql/cpp-queries")
    assert roots == [pack / "1.10.0"]
