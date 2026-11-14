"""Header read admission before the source-pattern boundary."""

from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory import header_functions as hf


@pytest.fixture
def boundary(monkeypatch):
    seen = []

    class PatternBoundary:
        def finditer(self, text):
            seen.append(text)
            return iter(())

    monkeypatch.setattr(hf, "_cache", OrderedDict())
    monkeypatch.setattr(hf, "_FUNC_DEF_RE", PatternBoundary())
    return seen


def test_stale_header_size_does_not_admit_oversize_content(tmp_path, monkeypatch, boundary):
    class StaleSizePath(type(Path())):
        def stat(self, **kwargs):
            return SimpleNamespace(st_size=0)

    path = StaleSizePath(tmp_path / "owned.h")
    path.write_bytes(b"x" * (1_048_576 + 1))
    monkeypatch.setattr(hf, "iter_regular_files", lambda root, extensions: iter([path]))
    assert hf.build_header_function_index(tmp_path) == {}
    assert boundary == []


@pytest.mark.parametrize("data", [b"", b"owned\r\ntext\r", b"bad\xfftext"])
def test_admitted_headers_keep_default_text_decoding(tmp_path, monkeypatch, boundary, data):
    path = tmp_path / "owned.h"
    path.write_bytes(data)
    monkeypatch.setattr(hf, "iter_regular_files", lambda root, extensions: iter([path]))
    assert hf.build_header_function_index(tmp_path) == {}
    assert boundary == [path.read_text(errors="replace")]


def test_final_header_link_is_refused_before_pattern(tmp_path, monkeypatch, boundary):
    target = tmp_path / "target.h"
    target.write_text("owned scalar")
    path = tmp_path / "link.h"
    path.symlink_to(target)
    monkeypatch.setattr(hf, "iter_regular_files", lambda root, extensions: iter([path]))
    assert hf.build_header_function_index(tmp_path) == {}
    assert boundary == []


def test_exact_byte_cap_header_reaches_pattern(tmp_path, monkeypatch, boundary):
    path = tmp_path / "owned.h"
    path.write_bytes(b"x" * 1_048_576)
    monkeypatch.setattr(hf, "iter_regular_files", lambda root, extensions: iter([path]))
    assert hf.build_header_function_index(tmp_path) == {}
    assert len(boundary) == 1
    assert len(boundary[0]) == 1_048_576
