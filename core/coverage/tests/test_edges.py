"""Touched-edge capture from flow-traces (core.coverage.edges)."""

from __future__ import annotations

import json

from core.coverage.edges import (
    EDGES_TOUCHED_FILENAME,
    collect_touched_edges,
    load_touched,
    write_touched,
)

_CHECKLIST = {
    "files": [
        {"path": "src/a.c", "items": [
            {"name": "handle_input", "line_start": 1, "line_end": 20}]},
        {"path": "src/b.c", "items": [
            {"name": "process", "line_start": 10, "line_end": 40}]},
        {"path": "src/c.c", "items": [
            {"name": "page_op", "line_start": 1, "line_end": 9}]},
    ],
}


def _trace(steps):
    return {"meta": {}, "steps": steps}


def _write_trace(run_dir, name, steps):
    (run_dir / name).write_text(json.dumps(_trace(steps)), encoding="utf-8")


def test_call_step_yields_edge(tmp_path):
    _write_trace(tmp_path, "flow-trace-1.json", [
        {"step": 1, "type": "entry", "call_site": None,
         "definition": "src/a.c:1"},
        {"step": 2, "type": "call", "call_site": "src/a.c:5",
         "definition": "src/b.c:12"},
    ])
    edges = collect_touched_edges(tmp_path, _CHECKLIST)
    assert edges == [{
        "caller_file": "src/a.c", "caller": "handle_input",
        "callee_file": "src/b.c", "callee": "process",
        "call_line": 5, "source": "flow-trace-1.json",
    }]


def test_absolute_trace_paths_normalise(tmp_path):
    # Trace files are LLM output and often carry absolute paths.
    _write_trace(tmp_path, "flow-trace-1.json", [
        {"step": 2, "type": "call", "call_site": "/tgt/src/a.c:5",
         "definition": "/tgt/src/b.c:12"},
    ])
    edges = collect_touched_edges(tmp_path, _CHECKLIST)
    assert len(edges) == 1
    assert edges[0]["caller_file"] == "src/a.c"
    assert edges[0]["callee_file"] == "src/b.c"


def test_ast_view_calls_made_yields_edges(tmp_path):
    # Body-level evidence: the stepped-into function's calls, resolved
    # only when the name has exactly one inventory definition.
    _write_trace(tmp_path, "flow-trace-1.json", [
        {"step": 2, "type": "call", "call_site": "src/a.c:5",
         "definition": "src/b.c:12",
         "ast_view": {"function": "process", "calls_made": [
             {"line": 20, "chain": ["page_op"]},
             {"line": 21, "chain": ["memcpy"]},      # not in inventory
         ]}},
    ])
    edges = collect_touched_edges(tmp_path, _CHECKLIST)
    keys = {(e["caller"], e["callee"]) for e in edges}
    assert ("process", "page_op") in keys
    assert not any(e["callee"] == "memcpy" for e in edges)


def test_dedup_and_library_sink_skipped(tmp_path):
    # A sink whose definition is a library function (not file:line in
    # the inventory) contributes no edge; duplicates collapse.
    steps = [
        {"step": 2, "type": "call", "call_site": "src/a.c:5",
         "definition": "src/b.c:12"},
        {"step": 3, "type": "sink", "call_site": "src/b.c:31",
         "definition": "psycopg2.cursor.execute()"},
    ]
    _write_trace(tmp_path, "flow-trace-1.json", steps)
    _write_trace(tmp_path, "flow-trace-2.json", steps)
    edges = collect_touched_edges(tmp_path, _CHECKLIST)
    assert len(edges) == 1


def test_malformed_trace_tolerated(tmp_path):
    (tmp_path / "flow-trace-1.json").write_text("{corrupt", encoding="utf-8")
    assert collect_touched_edges(tmp_path, _CHECKLIST) == []


def test_write_load_roundtrip(tmp_path):
    edges = [{"caller_file": "src/a.c", "caller": "handle_input",
              "callee_file": "src/b.c", "callee": "process",
              "call_line": 5, "source": "flow-trace-1.json"}]
    write_touched(tmp_path, edges)
    assert (tmp_path / EDGES_TOUCHED_FILENAME).is_file()
    assert load_touched(tmp_path) == edges
    assert load_touched(tmp_path / "missing") == []


def test_import_understand_writes_touched(tmp_path):
    # The importer records edge structure alongside its line marks.
    from core.coverage.importer import import_understand
    from core.coverage.store import CoverageStore
    _write_trace(tmp_path, "flow-trace-1.json", [
        {"step": 2, "type": "call", "call_site": "src/a.c:5",
         "definition": "src/b.c:12", "file": "src/a.c", "line": 5},
    ])
    store = CoverageStore(tmp_path / "coverage.json")
    marks = import_understand(store, tmp_path, _CHECKLIST)
    assert marks >= 1
    assert load_touched(tmp_path), "edges-touched.json should be written"
