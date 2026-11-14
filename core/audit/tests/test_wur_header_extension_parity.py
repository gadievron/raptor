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
    names = {"_WUR_SCAN_SUFFIXES", "_MAX_WUR_SCAN_FILES", "_MAX_WUR_FILE_BYTES"}
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
        assert path == header and cap == namespace["_MAX_WUR_FILE_BYTES"]
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
