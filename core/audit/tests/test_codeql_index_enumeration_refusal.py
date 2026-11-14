"""Owned iterator refusals and header callbacks; no CodeQL grammar or CLI."""
import ast
import io
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.source import open_regular_gated
from core.source.streams import preserving_stream_error


@pytest.fixture
def indexer():
    source = Path(__file__).parents[1] / "codeql_query_resolver.py"
    nodes = [n for n in ast.parse(source.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name in {"_index_pack", "_iter_pack_query_paths"}]
    visited = []

    def header(text):
        visited.append(text)
        return SimpleNamespace(group=lambda _: text.strip(), end=lambda _: len(text.strip()))

    namespace = {"Path": Path, "_pack_roots": lambda _: [], "_MAX_PACK_FILES": 20,
                 "_HEADER_READ_BYTES": 4096, "io": io,
                 "logger": logging.getLogger(__name__),
                 "open_regular_gated": open_regular_gated,
                 "preserving_stream_error": preserving_stream_error,
                 "_ID_HEADER_RE": SimpleNamespace(search=header)}
    exec(compile(ast.Module(body=ast.parse("from __future__ import annotations").body + nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace, visited


@pytest.mark.parametrize("phase", ["creation", "advancement"])
def test_refused_root_retains_prefix_and_later_root(indexer, tmp_path, phase):
    namespace, visited = indexer
    first, later = tmp_path / "first.ql", tmp_path / "later.ql"
    first.write_text("cpp/first")
    later.write_text("cpp/later")

    class RefusedPath(type(Path())):
        def rglob(self, pattern):
            assert pattern == "*.ql"
            if phase == "creation":
                raise PermissionError("owned creation refusal")

            def entries():
                yield first
                raise PermissionError("owned advancement refusal")

            return entries()

    class LaterPath(type(Path())):
        def rglob(self, pattern):
            return iter([later])

    namespace["_pack_roots"] = lambda _: [RefusedPath(tmp_path), LaterPath(tmp_path)]
    expected = {"cpp/later": str(later)}
    if phase == "advancement":
        expected["cpp/first"] = str(first)
    assert namespace["_index_pack"]("owned/pack") == expected
    assert visited == (["cpp/first"] if phase == "advancement" else []) + ["cpp/later"]


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_unexpected_enumeration_failure_propagates(indexer, tmp_path, error):
    namespace, visited = indexer

    class FailedPath(type(Path())):
        def rglob(self, pattern):
            raise error("owned unexpected failure")

    namespace["_pack_roots"] = lambda _: [FailedPath(tmp_path)]
    with pytest.raises(error, match="owned unexpected failure"):
        namespace["_index_pack"]("owned/pack")
    assert visited == []


def test_index_file_cap_and_first_id_remain_unchanged(indexer, tmp_path):
    namespace, visited = indexer
    first, duplicate, extra = [tmp_path / name for name in ("first.ql", "duplicate.ql", "extra.ql")]
    first.write_text("cpp/same")
    duplicate.write_text("cpp/same")
    extra.write_text("cpp/extra")

    class OrderedPath(type(Path())):
        def rglob(self, pattern):
            return iter([first, duplicate, extra])

    namespace["_pack_roots"] = lambda _: [OrderedPath(tmp_path)]
    namespace["_MAX_PACK_FILES"] = 2
    assert namespace["_index_pack"]("owned/pack") == {"cpp/same": str(first)}
    assert visited == ["cpp/same", "cpp/same"]


def test_absent_roots_remain_none(indexer):
    namespace, visited = indexer
    assert namespace["_index_pack"]("owned/pack") is None
    assert visited == []
