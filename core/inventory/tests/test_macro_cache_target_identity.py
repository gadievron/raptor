"""Macro table cache identity with owned files and parser seams."""

from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory import macro_resolve as mr
from core.testing.module_state import isolated_module_state


@pytest.fixture(params=["c", "rust"])
def builder(request, monkeypatch):
    language = request.param
    filename = "owned.h" if language == "c" else "owned.rs"
    monkeypatch.setattr(mr, "_iter_enum_bodies", lambda text: iter(()))
    bodies = {"macro_rules! OWNED { FIRST }": "FIRST", "macro_rules! OWNED { SECOND }": "SECOND"}
    monkeypatch.setattr(mr, "_extract_braced_body", lambda text, pos: bodies[text])
    monkeypatch.setattr(mr, "iter_regular_files", lambda target, extensions: iter([Path(target) / filename]))

    def write(root, body):
        root.mkdir(parents=True)
        text = "#define OWNED " + body + "\n" if language == "c" else "macro_rules! OWNED { " + body + " }"
        (root / filename).write_text(text)

    with isolated_module_state(mr, {"_table_cache": OrderedDict(), "_rust_table_cache": OrderedDict()}):
        yield SimpleNamespace(
            build=mr.build_macro_table if language == "c" else mr.build_rust_macro_table,
            cache=mr._table_cache if language == "c" else mr._rust_table_cache,
            filename=filename, write=write, table=lambda body: {"OWNED": ("", body) if language == "c" else body})


def test_relative_target_cache_is_bound_to_current_directory(tmp_path, monkeypatch, builder):
    first = tmp_path / "first"
    second = tmp_path / "second"
    builder.write(first / "src", "FIRST")
    builder.write(second / "src", "SECOND")
    monkeypatch.chdir(first)
    first_table = builder.build(Path("src"))
    monkeypatch.chdir(second)
    second_table = builder.build(Path("src"))
    assert first_table == builder.table("FIRST")
    assert second_table == builder.table("SECOND")
    assert first_table is not second_table


def test_absolute_and_relative_spellings_reuse_one_target_table(tmp_path, monkeypatch, builder):
    builder.write(tmp_path / "src", "FIRST")
    monkeypatch.chdir(tmp_path)
    first = builder.build(Path("src"))
    monkeypatch.setattr(mr, "iter_regular_files", lambda *args: pytest.fail("unexpected second walk"))
    assert builder.build(tmp_path / "src") is first
    assert len(builder.cache) == 1


def test_unknown_relative_location_does_not_reuse_old_cache_key(monkeypatch, builder):
    old = builder.table("FIRST")
    builder.cache["src"] = old

    def unavailable(path):
        raise OSError("owned unavailable location")

    monkeypatch.setattr(mr, "Path", unavailable)
    monkeypatch.setattr(mr, "iter_regular_files", lambda *args: pytest.fail("unavailable location walked"))
    assert builder.build(Path("src")) == {}
    assert builder.cache == {"src": old}


def test_string_target_path_remains_accepted(tmp_path, builder):
    target = tmp_path / "src"
    builder.write(target, "FIRST")
    assert builder.build(str(target)) == builder.table("FIRST")


def test_walk_uses_identified_target_when_cwd_changes(tmp_path, monkeypatch, builder):
    first = tmp_path / "first"
    second = tmp_path / "second"
    builder.write(first / "src", "FIRST")
    builder.write(second / "src", "SECOND")
    monkeypatch.chdir(first)

    def files(target, extensions):
        monkeypatch.chdir(second)
        return iter([Path(target) / builder.filename])

    monkeypatch.setattr(mr, "iter_regular_files", files)
    assert builder.build(Path("src")) == builder.table("FIRST")
