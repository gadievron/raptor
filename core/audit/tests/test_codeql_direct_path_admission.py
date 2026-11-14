"""Owned dispatch-path admission with the resolver import seam replaced."""
import ast
import builtins
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def dispatch_lookup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path(__file__).parents[1] / "orchestrator.py"
    node = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == "_codeql_query_file")
    calls = []
    lookup_result = [None]

    def resolve(query):
        calls.append(query)
        return lookup_result[0]

    def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
        assert name == "codeql_query_resolver" and level == 1
        assert fromlist == ("resolve_query_id",)
        return SimpleNamespace(resolve_query_id=resolve)

    namespace = {"Path": Path, "logger": logging.getLogger(__name__),
                 "__builtins__": {**vars(builtins), "__import__": owned_import}}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    return namespace, calls, lookup_result


def test_owned_regular_file_retains_direct_admission(dispatch_lookup, tmp_path):
    namespace, calls, _ = dispatch_lookup
    owned = tmp_path / "owned-file"
    owned.write_text("owned")
    assert namespace["_codeql_query_file"](str(owned)) == str(owned)
    assert calls == []


def test_owned_directory_is_not_a_dispatchable_query_file(dispatch_lookup, tmp_path):
    namespace, calls, _ = dispatch_lookup
    assert namespace["_codeql_query_file"](str(tmp_path)) is None
    assert calls == [str(tmp_path)]


def test_absent_path_retains_query_id_fallback(dispatch_lookup):
    namespace, calls, result = dispatch_lookup
    result[0] = "/owned/resolved.ql"
    assert namespace["_codeql_query_file"]("cpp/owned") == result[0]
    assert calls == ["cpp/owned"]


def test_metadata_refusal_retains_query_id_fallback(dispatch_lookup):
    namespace, calls, result = dispatch_lookup

    class RefusedPath(type(Path())):
        def is_file(self):
            raise PermissionError("owned metadata refusal")

    namespace["Path"] = RefusedPath
    result[0] = "/owned/resolved.ql"
    assert namespace["_codeql_query_file"]("cpp/owned") == result[0]
    assert calls == ["cpp/owned"]


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_unexpected_path_failures_propagate(dispatch_lookup, error):
    namespace, calls, _ = dispatch_lookup

    class FailedPath(type(Path())):
        def is_file(self):
            raise error("owned unexpected failure")

    namespace["Path"] = FailedPath
    with pytest.raises(error, match="owned unexpected failure"):
        namespace["_codeql_query_file"]("cpp/owned")
    assert calls == []


def test_empty_query_remains_a_miss_without_import(dispatch_lookup):
    namespace, calls, _ = dispatch_lookup
    assert namespace["_codeql_query_file"]("") is None
    assert calls == []
