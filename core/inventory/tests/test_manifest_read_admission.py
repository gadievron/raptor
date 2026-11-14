"""Manifest byte admission without parsing manifests or classifying projects."""

import ast
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.source import read_bytes_capped


@pytest.fixture
def reader():
    source = Path(__file__).parents[1] / "library_detection.py"
    tree = ast.parse(source.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_read_text")
    namespace = {"io": io, "read_bytes_capped": read_bytes_capped, "_MAX_MANIFEST_BYTES": 16}
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + [node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    return namespace["_read_text"]


def test_stale_manifest_size_does_not_admit_oversize_read(tmp_path, reader):
    class StaleSizePath(type(Path())):
        def stat(self, **kwargs):
            return SimpleNamespace(st_size=0)

    path = StaleSizePath(tmp_path / "owned-manifest")
    path.write_bytes(b"x" * 17)
    assert reader(path) is None


@pytest.mark.parametrize("data", [b"", b"x" * 16, b"owned\r\ntext\r", b"bad\xfftext"])
def test_admitted_manifest_decoding_matches_utf8_read(tmp_path, reader, data):
    path = tmp_path / "owned-manifest"
    path.write_bytes(data)
    assert reader(path) == path.read_text(encoding="utf-8", errors="replace")


def test_manifest_budget_counts_bytes_not_characters(tmp_path, reader):
    path = tmp_path / "owned-manifest"
    path.write_bytes("\u2603".encode("utf-8") * 6)
    assert reader(path) is None


def test_missing_directory_and_final_link_are_refused(tmp_path, reader):
    assert reader(tmp_path / "missing") is None
    assert reader(tmp_path) is None
    target = tmp_path / "target"
    target.write_text("owned scalar")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert reader(link) is None
