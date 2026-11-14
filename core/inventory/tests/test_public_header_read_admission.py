"""Public-header read admission with inert pattern boundaries."""

import ast
import io
import logging
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.source import read_bytes_capped
from core.source.streams import preserving_stream_error


@pytest.fixture
def scanner():
    tree = ast.parse((Path(__file__).parents[1] / "header_api.py").read_text())
    ns = {"Path": Path, "os": os, "io": io, "read_bytes_capped": read_bytes_capped,
          "logger": logging.getLogger("owned-public-header-reader"),
          "preserving_stream_error": preserving_stream_error}
    for name in ("_HEADER_EXTENSIONS", "_EXCLUDE_DIRS", "_SKIP_NAMES"):
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
        ns[name] = frozenset(ast.literal_eval(node.value.args[0]))
    seen = []

    class Boundary:
        def finditer(self, text):
            seen.append(text)
            return iter(())

    for name in ("_DECL_RE", "_OF_DECL_RE", "_EXPORT_MACRO_RE"):
        ns[name] = Boundary()
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "scan_public_api")
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + [node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "<owned-public-header-reader>", "exec"), ns)
    return ns, seen


def test_stale_metadata_does_not_admit_oversize_header(tmp_path, scanner):
    ns, seen = scanner
    path = tmp_path / "owned.h"
    path.write_bytes(b"x" * (1_048_576 + 1))

    class StalePath(type(Path())):
        def stat(self, *, follow_symlinks=True):
            if self.name == "owned.h" and follow_symlinks:
                return SimpleNamespace(st_size=0)
            return super().stat(follow_symlinks=follow_symlinks)

    ns["Path"] = StalePath
    assert ns["scan_public_api"](str(tmp_path)) == frozenset()
    assert seen == []


def test_exact_byte_cap_is_admitted(tmp_path, scanner):
    ns, seen = scanner
    (tmp_path / "owned.h").write_bytes(b"x" * 1_048_576)
    assert ns["scan_public_api"](str(tmp_path)) == frozenset()
    assert len(seen) == 3 and all(len(text) == 1_048_576 for text in seen)


def test_utf8_replacement_and_newlines_are_preserved(tmp_path, scanner):
    ns, seen = scanner
    path = tmp_path / "owned.h"
    path.write_bytes(b"owned\r\nutf8 \xe2\x98\x83\rmalformed \xff")
    assert ns["scan_public_api"](str(tmp_path)) == frozenset()
    assert seen == [path.read_text(encoding="utf-8", errors="replace")] * 3


def test_include_and_exclusion_filters_remain(tmp_path, scanner):
    ns, seen = scanner
    for folder in ("include", "other", "tests"):
        root = tmp_path / folder
        root.mkdir()
        (root / "owned.h").write_text(folder)
    assert ns["scan_public_api"](str(tmp_path), include_dirs=["include"]) == frozenset()
    assert seen == ["include"] * 3


def test_refused_read_never_reaches_patterns(tmp_path, scanner):
    ns, seen = scanner
    (tmp_path / "owned.h").write_text("owned scalar")
    ns["read_bytes_capped"] = lambda path, cap: None
    assert ns["scan_public_api"](str(tmp_path)) == frozenset()
    assert seen == []
