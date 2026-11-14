"""Owned filesystem selectors; no CLI or query execution."""
import ast
import os
from pathlib import Path

import pytest


@pytest.mark.parametrize("route", ["package", "distribution"])
@pytest.mark.parametrize("versions", [[], ["1.9", "1.10"], ["1.01", "1.1"]])
def test_single_pass_selection_preserves_roots(tmp_path, monkeypatch, route, versions):
    source = Path(__file__).parents[1] / "codeql_query_resolver.py"
    names = {"_version_key", "_package_cache_roots", "_distribution_roots"}
    nodes = [n for n in ast.parse(source.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name in names]

    class OwnedPath(type(Path())):
        @classmethod
        def home(cls):
            return cls(tmp_path)

    def forbidden_sort(*args, **kwargs):
        raise AssertionError("selector must not retain a sorted version list")

    namespace = {"Path": OwnedPath, "os": os, "sorted": forbidden_sort}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    monkeypatch.setenv("CODEQL_CLI", str(tmp_path / "codeql"))
    base = tmp_path / (".codeql/packages" if route == "package" else "qlpacks")
    pack = base / "codeql/cpp-queries"
    pack.mkdir(parents=True)
    for version in versions:
        (pack / version).mkdir()
    (pack / "non-directory").write_text("owned")
    ordered = [d for d in pack.iterdir() if d.is_dir()]
    expected = sorted(ordered, key=lambda d: namespace["_version_key"](d.name), reverse=True)[:1]
    if not expected and route == "distribution":
        expected = [pack]
    function = namespace["_package_cache_roots" if route == "package" else "_distribution_roots"]
    assert function("codeql/cpp-queries") == expected
    assert function("codeql/missing") == []
