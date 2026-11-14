"""Call-graph input admission with owned files and a recording extractor."""

import ast
import io
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory.call_graph import FileCallGraph, estimate_call_graph_bytes
from core.source import read_bytes_capped


@pytest.fixture
def loader():
    source = Path(__file__).parents[1] / "call_graph.py"
    node = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == "load_call_graphs")
    seen = []
    graph = FileCallGraph()

    def extract(text):
        seen.append(text)
        return graph

    namespace = {
        "io": io, "read_bytes_capped": read_bytes_capped,
        "CALL_GRAPH_MAX_FILE_BYTES": 16, "CALL_GRAPH_MAX_TOTAL_BYTES": 1_000_000,
        "logger": logging.getLogger("owned-call-graph-reader"),
        "_extractor_for_language": lambda language: extract,
        "estimate_call_graph_bytes": estimate_call_graph_bytes,
    }
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + [node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)

    def run(paths, **kwargs):
        namespace["iter_call_graph_candidates"] = lambda target, checklist: iter(
            (path.name, path, "c") for path in paths)
        return namespace["load_call_graphs"](None, max_files=10, max_bytes=16, **kwargs)

    return SimpleNamespace(run=run, seen=seen, graph=graph)


def test_poststat_oversize_is_refused_and_disclosed(tmp_path, loader, caplog):
    class StaleSizePath(type(Path())):
        def stat(self, **kwargs):
            return SimpleNamespace(st_size=0)

    path = StaleSizePath(tmp_path / "owned.c")
    path.write_bytes(b"x" * 17)
    with caplog.at_level(logging.WARNING, logger="owned-call-graph-reader"):
        assert loader.run([path]) == {}
    assert loader.seen == []
    warnings = [r.getMessage() for r in caplog.records if "per-file size gate" in r.getMessage()]
    assert len(warnings) == 1
    assert "1 file(s)" in warnings[0] and "owned.c" in warnings[0]


@pytest.mark.parametrize("data", [b"x" * 16, b"owned\r\ntext\r", b"bad\xfftext"])
def test_admitted_call_graph_text_preserves_decoding(tmp_path, loader, data):
    path = tmp_path / "owned.c"
    path.write_bytes(data)
    assert loader.run([path]) == {"owned.c": loader.graph}
    assert loader.seen == [path.read_text(encoding="utf-8", errors="replace")]


def test_refused_link_never_reaches_extractor(tmp_path, loader):
    target = tmp_path / "target.c"
    target.write_text("owned scalar")
    link = tmp_path / "link.c"
    link.symlink_to(target)
    assert loader.run([link]) == {}
    assert loader.seen == []


def test_retained_output_budget_still_stops_later_extraction(tmp_path, loader, caplog):
    paths = [tmp_path / name for name in ("first.c", "second.c", "third.c")]
    for path in paths:
        path.write_text(path.stem)
    with caplog.at_level(logging.WARNING, logger="owned-call-graph-reader"):
        result = loader.run(paths, max_total_bytes=estimate_call_graph_bytes(loader.graph))
    assert result == {"first.c": loader.graph}
    assert loader.seen == ["first", "second"]
    assert "retained-byte budget" in caplog.text
