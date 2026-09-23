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


class TestNormaliseTracePath:

    def test_out_of_tree_dotdot_path_returns_none(self):
        from core.coverage.edges import normalise_trace_path

        # lstrip("./") used to charset-strip "../shared/util.c" into
        # the inventory key; and the suffix arm used to accept the
        # ".." prefix as separator-aligned.
        assert normalise_trace_path(
            "../shared/util.c", {"shared/util.c"}) is None

    def test_dot_slash_prefix_stripped_once(self):
        from core.coverage.edges import normalise_trace_path

        assert normalise_trace_path(
            "./shared/util.c", {"shared/util.c"}) == "shared/util.c"

    def test_hidden_file_name_not_mangled(self):
        from core.coverage.edges import normalise_trace_path

        # lstrip would have stripped the leading dot off ".hidden.c".
        assert normalise_trace_path(
            ".hidden.c", {".hidden.c"}) == ".hidden.c"

    def test_absolute_in_tree_suffix_still_matches(self):
        from core.coverage.edges import normalise_trace_path

        assert normalise_trace_path(
            "/repo/shared/util.c", {"shared/util.c"}) == "shared/util.c"


class TestNormaliseTracePathIndex:
    """The basename index keeps the suffix strategy O(candidates):
    per-step O(inventory) scans admitted hours of CPU from one
    budget-max hostile trace on the render path."""

    def test_index_and_scan_agree(self):
        from core.coverage.edges import normalise_trace_path
        from core.coverage.summary import _inventory_name_index

        inv = {"shared/util.c", "a/util.c", "src/main.c", ".hidden.c"}
        idx = _inventory_name_index(inv)
        for raw in ("/repo/src/main.c", "src/main.c", "./src/main.c",
                    "/x/util.c", "/repo/shared/util.c",
                    "../shared/util.c", "/nowhere/else.c", ".hidden.c"):
            assert (normalise_trace_path(raw, inv, idx)
                    == normalise_trace_path(raw, inv)), raw

    def test_suffix_lookup_never_scans_inventory(self):
        from core.coverage.edges import normalise_trace_path
        from core.coverage.summary import _inventory_name_index

        class CountingSet(set):
            iters = 0

            def __iter__(self):
                CountingSet.iters += 1
                return super().__iter__()

        inv = CountingSet({"shared/util.c", "src/main.c"})
        idx = _inventory_name_index(set(inv))
        CountingSet.iters = 0
        # Unresolvable absolute step — the hostile-trace shape that
        # previously scanned the whole inventory per step.
        assert normalise_trace_path("/abs/no/such.c", inv, idx) is None
        assert normalise_trace_path("/repo/src/main.c", inv, idx) \
            == "src/main.c"
        assert CountingSet.iters == 0, (
            "suffix strategy iterated the inventory despite the index"
        )

    def test_collect_touched_edges_passes_the_index(self, tmp_path,
                                                    monkeypatch):
        import core.coverage.edges as edges_mod

        seen: list[bool] = []
        real = edges_mod.normalise_trace_path

        def _spy(raw, inv_paths, name_index=None):
            seen.append(name_index is not None)
            return real(raw, inv_paths, name_index)

        monkeypatch.setattr(edges_mod, "normalise_trace_path", _spy)
        _write_trace(tmp_path, "flow-trace-x.json", [{
            "type": "call",
            "call_site": "src/a.c:3",
            "definition": "src/b.c:11",
        }])
        edges_mod.collect_touched_edges(tmp_path, _CHECKLIST)
        assert seen and all(seen), (
            "collect_touched_edges called normalise_trace_path "
            "without the basename index"
        )
