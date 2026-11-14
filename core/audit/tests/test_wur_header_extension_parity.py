"""Header admission controls with owned metadata and reader callbacks."""

import ast
import __future__
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.paths import confine


@pytest.fixture
def target_harvest():
    path = Path(__file__).resolve().parents[1] / "return_contracts.py"
    tree = ast.parse(path.read_text())
    names = {"_WUR_SCAN_SUFFIXES", "_MAX_WUR_SCAN_FILES", "_MAX_WUR_FILE_CHARS"}
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "harvest_wur_from_target":
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            selected.append(node)
    namespace = {"Path": Path, "confine": confine,
                 "logger": SimpleNamespace(warning=lambda *args: None)}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec",
                 flags=__future__.annotations.compiler_flag), namespace)
    return namespace["harvest_wur_from_target"], namespace


@pytest.mark.parametrize("suffix", [".h", ".hpp", ".hh", ".hxx", ".H", ".HPP", ".HH", ".HXX"],
                         ids=["h", "hpp", "hh", "hxx", "upper-h", "upper-hpp", "upper-hh", "upper-hxx"])
def test_header_spellings_reach_existing_harvester(tmp_path, target_harvest, suffix):
    helper, namespace = target_harvest
    header = tmp_path / ("owned" + suffix)
    header.touch()
    reads = []

    def read(path, cap):
        assert path == header and cap == namespace["_MAX_WUR_FILE_CHARS"]
        reads.append(path)
        return "owned header text", False

    namespace["read_text_capped"] = read
    namespace["harvest_wur_declarations"] = lambda texts: frozenset(texts)
    assert helper(tmp_path) == frozenset({str(header)})
    assert reads == [header]


@pytest.mark.parametrize("state", ["read-refused", "truncated", "confine-refused"])
def test_existing_header_refusals_remain_empty(tmp_path, target_harvest, state):
    helper, namespace = target_harvest
    (tmp_path / "owned.H").touch()
    if state == "confine-refused":
        namespace["confine"] = lambda *args: None
    reads = []

    def read(*args):
        assert state != "confine-refused"
        reads.append(args)
        return None if state == "read-refused" else ("owned", True)

    namespace["read_text_capped"] = read
    namespace["harvest_wur_declarations"] = lambda texts: frozenset(texts)
    assert helper(tmp_path) == frozenset()
    assert len(reads) == (0 if state == "confine-refused" else 1)


def test_header_like_suffix_does_not_reach_reader(tmp_path, target_harvest):
    helper, namespace = target_harvest
    (tmp_path / "owned.H.bak").touch()
    namespace["read_text_capped"] = lambda *args: pytest.fail("unexpected read")
    namespace["harvest_wur_declarations"] = lambda texts: frozenset(texts)
    assert helper(tmp_path) == frozenset()


def test_uppercase_and_lowercase_headers_share_existing_budget(tmp_path, target_harvest):
    helper, namespace = target_harvest
    (tmp_path / "one.H").touch()
    (tmp_path / "two.h").touch()
    namespace["_MAX_WUR_SCAN_FILES"] = 1
    reads = []
    namespace["read_text_capped"] = lambda path, cap: (reads.append(path) or "owned", False)
    namespace["harvest_wur_declarations"] = lambda texts: frozenset(texts)
    assert len(helper(tmp_path)) == 1
    assert len(reads) == 1


def test_headers_are_harvested_between_reads_and_names_are_unioned(tmp_path, target_harvest):
    helper, namespace = target_harvest
    for name in ["a.h", "b.H"]:
        (tmp_path / name).touch()
    events = []

    def read(path, cap):
        events.append("read:" + path.name)
        return "owned text", False

    def harvest(texts):
        assert len(texts) == 1
        name = Path(next(iter(texts))).name
        events.append("harvest:" + name)
        return frozenset({"shared", Path(name).stem})

    namespace["read_text_capped"] = read
    namespace["harvest_wur_declarations"] = harvest
    assert helper(tmp_path) == frozenset({"shared", "a", "b"})
    assert events == ["read:a.h", "harvest:a.h", "read:b.H", "harvest:b.H"]


def test_all_read_refusals_skip_declaration_harvesting(tmp_path, target_harvest):
    helper, namespace = target_harvest
    (tmp_path / "owned.h").touch()
    namespace["read_text_capped"] = lambda *args: None
    namespace["harvest_wur_declarations"] = lambda texts: pytest.fail("no admitted text")
    assert helper(tmp_path) == frozenset()


@pytest.mark.parametrize("refused", [False, True], ids=["readable", "read-refused"])
def test_equivalent_selected_header_aliases_are_read_once(tmp_path, target_harvest, refused):
    helper, namespace = target_harvest
    base = tmp_path / "base.h"
    base.touch()
    (tmp_path / "alias.H").symlink_to(base)
    (tmp_path / "alias.h").symlink_to(base)
    reads = []

    def read(path, cap):
        reads.append(path)
        return None if refused else ("owned", False)

    namespace["read_text_capped"] = read
    namespace["harvest_wur_declarations"] = lambda texts: frozenset({"owned"})
    assert helper(tmp_path) == (frozenset() if refused else frozenset({"owned"}))
    assert reads == [base]


def test_different_header_suffix_retains_its_own_view_input(tmp_path, target_harvest):
    helper, namespace = target_harvest
    base = tmp_path / "base.h"
    base.touch()
    (tmp_path / "alias.hpp").symlink_to(base)
    reads = []
    inputs = []
    namespace["read_text_capped"] = lambda path, cap: (reads.append(path) or "owned", False)

    def harvest(texts):
        inputs.extend(texts)
        return frozenset({"owned"})

    namespace["harvest_wur_declarations"] = harvest
    assert helper(tmp_path) == frozenset({"owned"})
    assert reads == [base, base]
    assert {Path(path).suffix for path in inputs} == {".h", ".hpp"}


def test_skipped_selected_aliases_do_not_backfill_sample(tmp_path, target_harvest):
    helper, namespace = target_harvest
    base = tmp_path / "z.h"
    base.touch()
    (tmp_path / "a.H").symlink_to(base)
    (tmp_path / "b.h").touch()
    namespace["_MAX_WUR_SCAN_FILES"] = 2
    reads = []
    namespace["read_text_capped"] = lambda path, cap: (reads.append(path) or "owned", False)
    namespace["harvest_wur_declarations"] = lambda texts: frozenset({"owned"})
    assert helper(tmp_path) == frozenset({"owned"})
    # Existing even selection chooses indices0,2: a.H and z.h. b.h is not selected.
    assert reads == [base]
