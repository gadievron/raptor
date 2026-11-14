"""Byte admission with owned files and replaced source-parser seams."""

from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory import macro_resolve as mr
from core.testing.module_state import isolated_module_state


@pytest.fixture(params=["c", "rust"])
def builder(request, monkeypatch):
    captures = []

    def capture(text):
        captures.append((len(text), text[:32]))
        return iter(())

    monkeypatch.setattr(mr, "_iter_macro_definitions", capture)
    monkeypatch.setattr(mr, "_iter_enum_bodies", lambda text: iter(()))
    monkeypatch.setattr(mr, "_RUST_MACRO_RULES_RE", SimpleNamespace(finditer=capture))
    with isolated_module_state(mr, {"_table_cache": OrderedDict(), "_rust_table_cache": OrderedDict()}):
        yield SimpleNamespace(build=mr.build_macro_table if request.param == "c" else mr.build_rust_macro_table,
                              filename="owned.h" if request.param == "c" else "owned.rs", captures=captures)


def test_stale_small_metadata_cannot_admit_oversized_read(tmp_path, monkeypatch, builder):
    path = tmp_path / builder.filename
    path.write_bytes(b"X" * (1_048_576 + 1))
    monkeypatch.setattr(mr, "iter_regular_files", lambda *args: iter([path]))
    original = Path.stat
    monkeypatch.setattr(Path, "stat", lambda self, *args, **kwargs:
                        SimpleNamespace(st_size=0) if self == path else original(self, *args, **kwargs))
    assert builder.build(tmp_path) == {}
    assert builder.captures == []


def test_known_oversized_metadata_keeps_fast_rejection(tmp_path, monkeypatch, builder):
    path = tmp_path / builder.filename
    path.write_bytes(b"X" * (1_048_576 + 1))
    monkeypatch.setattr(mr, "iter_regular_files", lambda *args: iter([path]))
    monkeypatch.setattr(mr, "read_bytes_capped", lambda *args: pytest.fail("oversize prefix read"))
    assert builder.build(tmp_path) == {}
    assert builder.captures == []


def test_valid_input_preserves_existing_text_translation(tmp_path, monkeypatch, builder):
    path = tmp_path / builder.filename
    path.write_bytes(b"owned\r\ntext\r")
    expected = path.read_text(errors="replace")
    monkeypatch.setattr(mr, "iter_regular_files", lambda *args: iter([path]))
    assert builder.build(tmp_path) == {}
    assert builder.captures == [(len(expected), expected[:32])]


def test_byte_budget_and_text_decode_contract(tmp_path, monkeypatch):
    path = tmp_path / "owned.h"
    data = b"first\r\nsecond\rthird\n" + bytes([255]) + "雪".encode()
    path.write_bytes(data)
    monkeypatch.setattr(mr, "_MAX_MACRO_SOURCE_BYTES", len(data))
    assert mr._read_macro_text(path) == path.read_text(errors="replace")
    monkeypatch.setattr(mr, "_MAX_MACRO_SOURCE_BYTES", len(data) - 1)
    assert mr._read_macro_text(path) is None


def test_multibyte_budget_is_bytes_and_final_link_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "owned.h"
    path.write_bytes("雪".encode())
    monkeypatch.setattr(mr, "_MAX_MACRO_SOURCE_BYTES", 2)
    assert mr._read_macro_text(path) is None
    monkeypatch.setattr(mr, "_MAX_MACRO_SOURCE_BYTES", 3)
    assert mr._read_macro_text(path) == path.read_text(errors="replace")
    link = tmp_path / "alias.h"
    link.symlink_to(path)
    assert mr._read_macro_text(link) is None
