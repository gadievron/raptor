"""Macro header admission using owned files and inert parser seams."""

from collections import OrderedDict

from core.inventory import macro_resolve as mr
from core.testing.module_state import isolated_module_state


def test_cpp_header_extensions_reach_macro_reader(tmp_path, monkeypatch):
    expected = {"owned.h", "owned.hh", "owned.hpp", "owned.hxx"}
    for name in expected | {"unrelated.txt"}:
        (tmp_path / name).write_text("owned scalar marker\n")
    seen = []

    def read(path):
        seen.append(path.name)
        return path.read_text()

    monkeypatch.setattr(mr, "_read_macro_text", read)
    monkeypatch.setattr(mr, "_iter_macro_definitions", lambda text: iter(()))
    monkeypatch.setattr(mr, "_iter_enum_bodies", lambda text: iter(()))
    with isolated_module_state(mr, {"_table_cache": OrderedDict()}):
        assert mr.build_macro_table(tmp_path) == {}
    assert set(seen) == expected
    assert len(seen) == len(expected)
