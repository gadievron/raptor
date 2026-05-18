"""Tests for the transitive closure primitives in
:mod:`core.inventory.reachability`:
``reverse_closure``, ``forward_closure``, ``shortest_path``.

The fixture helpers here intentionally mirror those in
``test_reachability_adjacency.py`` so the closure tests can share
the same mental model. Each test pins one design decision:

  * Closure walks DEFINITIVE edges only — uncertain 1-hop edges
    are visible via ``callers_of`` / ``callees_of`` and are NOT
    surfaced by closure semantics.
  * External nodes are TERMINAL in forward closure (recorded but
    not expanded).
  * Cycles are handled via the visited set; no infinite loop.
  * ``max_depth`` bounds the BFS; results may be ``truncated``.
  * Same External-to-Internal aliasing as the 1-hop primitives.
  * Stable result ordering across heterogeneous Internal+External
    node types (Internal first by path+name+line, External after
    by qualified_name).
"""

from __future__ import annotations

from typing import Any, Dict, List


from core.inventory.call_graph import extract_call_graph_python
from core.inventory.reachability import (
    ClosureResult,
    ExternalFunction,
    InternalFunction,
    all_paths,
    forward_closure,
    reverse_closure,
    shortest_path,
)


# ---------------------------------------------------------------------------
# Fixture helpers (duplicated from adjacency tests intentionally — keeps
# the closure suite readable in isolation)
# ---------------------------------------------------------------------------


def _file(path: str, source: str, *,
          items: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    cg = extract_call_graph_python(source).to_dict()
    if items is None:
        items = _derive_items(source)
    return {
        "path": path, "language": "python",
        "items": items, "call_graph": cg,
    }


def _derive_items(source: str) -> List[Dict[str, Any]]:
    import ast
    out: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append({
                "name": node.name, "kind": "function",
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", None),
            })
    return out


def _inv(*files: Dict[str, Any]) -> Dict[str, Any]:
    return {"files": list(files)}


# ---------------------------------------------------------------------------
# reverse_closure
# ---------------------------------------------------------------------------


def test_reverse_closure_chain():
    """A → B → target. reverse_closure(target) returns {A, B}."""
    inv = _inv(_file("src/a.py",
        "def target():\n"        # line 1
        "    pass\n"
        "def b():\n"              # line 3
        "    target()\n"
        "def a():\n"              # line 5
        "    b()\n"
    ))
    target = InternalFunction("src/a.py", "target", 1)
    r = reverse_closure(inv, target)
    a = InternalFunction("src/a.py", "a", 5)
    b = InternalFunction("src/a.py", "b", 3)
    assert set(r.nodes) == {a, b}
    # Path for `a` should be a → b → target (3 hops).
    assert r.paths[a] == (a, b, target)
    assert r.paths[b] == (b, target)
    assert r.truncated is False


def test_reverse_closure_target_excluded_from_result():
    """The seed target itself is never in the result, even though
    it's the root of the BFS."""
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def caller():\n"
        "    target()\n"
    ))
    target = InternalFunction("src/a.py", "target", 1)
    r = reverse_closure(inv, target)
    assert target not in r.nodes


def test_reverse_closure_empty_when_unreachable():
    """A function with no callers anywhere has an empty reverse
    closure."""
    inv = _inv(_file("src/a.py",
        "def lonely():\n"
        "    pass\n"
    ))
    target = InternalFunction("src/a.py", "lonely", 1)
    r = reverse_closure(inv, target)
    assert r.nodes == ()
    assert r.paths == {}
    assert r.truncated is False


def test_reverse_closure_external_target_aliases_to_internal():
    """``ExternalFunction("pkg.mod.fn")`` aliasing to a project
    InternalFunction yields the same closure as the Internal form."""
    inv = _inv(
        _file("pkg/helpers.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg.helpers import fn\n"
            "def b():\n"
            "    fn()\n"
            "def a():\n"
            "    b()\n"
        ),
    )
    via_int = reverse_closure(
        inv, InternalFunction("pkg/helpers.py", "fn", 1))
    via_ext = reverse_closure(
        inv, ExternalFunction("pkg.helpers.fn"))
    assert set(via_int.nodes) == set(via_ext.nodes)


def test_reverse_closure_external_target_unaliased_returns_callers():
    """``requests.get`` doesn't alias to anything internal — the
    closure is just every direct caller (since External nodes have
    no further reverse-edges to follow)."""
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def fetch():\n"
        "    requests.get('/')\n"
        "def main():\n"
        "    fetch()\n"
    ))
    r = reverse_closure(inv, ExternalFunction("requests.get"))
    fetch = InternalFunction("src/a.py", "fetch", 2)
    main = InternalFunction("src/a.py", "main", 4)
    assert set(r.nodes) == {fetch, main}


def test_reverse_closure_handles_cycles():
    """A → B → A → target (recursion in the call chain). BFS must
    terminate — the visited set prevents revisiting."""
    inv = _inv(_file("src/a.py",
        "def target():\n"          # 1
        "    pass\n"
        "def a():\n"                # 3
        "    b()\n"
        "def b():\n"                # 5
        "    a()\n"
        "    target()\n"
    ))
    target = InternalFunction("src/a.py", "target", 1)
    r = reverse_closure(inv, target)
    assert {fn.name for fn in r.nodes} == {"a", "b"}


def test_reverse_closure_max_depth_bound():
    """``max_depth`` bounds the BFS. Truncated flag is set."""
    # Chain: f0 → f1 → f2 → ... → f10 → target
    src_lines = ["def target():", "    pass"]
    for i in range(10):
        src_lines.append(f"def f{i}():")
        if i == 0:
            src_lines.append("    target()")
        else:
            src_lines.append(f"    f{i - 1}()")
    inv = _inv(_file("src/a.py", "\n".join(src_lines) + "\n"))

    target = InternalFunction("src/a.py", "target", 1)
    r3 = reverse_closure(inv, target, max_depth=3)
    # f0 → target = 1 hop; f1 → f0 → target = 2; f2 = 3; f3 = 4 (out)
    assert {fn.name for fn in r3.nodes} == {"f0", "f1", "f2"}
    assert r3.truncated is True
    # Higher depth picks up the rest.
    r_full = reverse_closure(inv, target, max_depth=50)
    assert {fn.name for fn in r_full.nodes} == {f"f{i}" for i in range(10)}
    assert r_full.truncated is False


def test_reverse_closure_excludes_test_file_callers_by_default():
    """Test-file callers are filtered from the result, but the BFS
    still walks them (so a chain test → app → target still surfaces
    `app` but drops `test`)."""
    inv = _inv(
        _file("src/a.py",
            "def target():\n"
            "    pass\n"
            "def app():\n"
            "    target()\n"
        ),
        _file("tests/test_a.py",
            "from src.a import app\n"
            "def test_app():\n"
            "    app()\n",
            items=[{"name": "test_app", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
    )
    r = reverse_closure(inv, InternalFunction("src/a.py", "target", 1))
    assert all(not n.file_path.startswith("tests/") for n in r.nodes
               if isinstance(n, InternalFunction))


# ---------------------------------------------------------------------------
# forward_closure
# ---------------------------------------------------------------------------


def test_forward_closure_chain():
    """entry → A → B → ext_call. forward_closure({entry}) returns
    {A, B, ExternalFunction(ext)}."""
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def b():\n"               # line 2
        "    json.dumps({})\n"
        "def a():\n"                # line 4
        "    b()\n"
        "def entry():\n"            # line 6
        "    a()\n"
    ))
    entry = InternalFunction("src/a.py", "entry", 6)
    r = forward_closure(inv, [entry])
    a = InternalFunction("src/a.py", "a", 4)
    b = InternalFunction("src/a.py", "b", 2)
    json_dumps = ExternalFunction("json.dumps")
    assert set(r.nodes) == {a, b, json_dumps}


def test_forward_closure_external_terminal():
    """External nodes are recorded but not expanded — even if the
    External name happens to coincide with a project-internal name,
    the substrate doesn't expand foreign code."""
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def main():\n"
        "    requests.get('/')\n"
    ))
    main = InternalFunction("src/a.py", "main", 2)
    r = forward_closure(inv, [main])
    assert ExternalFunction("requests.get") in r.nodes
    # No phantom expansion — we don't have requests' internals.
    assert len(r.nodes) == 1


def test_forward_closure_multi_entry():
    """Closure unions across all entries."""
    inv = _inv(_file("src/a.py",
        "def a():\n"        # 1
        "    pass\n"
        "def b():\n"         # 3
        "    pass\n"
        "def entry1():\n"    # 5
        "    a()\n"
        "def entry2():\n"    # 7
        "    b()\n"
    ))
    e1 = InternalFunction("src/a.py", "entry1", 5)
    e2 = InternalFunction("src/a.py", "entry2", 7)
    r = forward_closure(inv, [e1, e2])
    a = InternalFunction("src/a.py", "a", 1)
    b = InternalFunction("src/a.py", "b", 3)
    assert set(r.nodes) == {a, b}


def test_forward_closure_entries_excluded_from_result():
    inv = _inv(_file("src/a.py",
        "def helper():\n"
        "    pass\n"
        "def entry():\n"
        "    helper()\n"
    ))
    entry = InternalFunction("src/a.py", "entry", 3)
    r = forward_closure(inv, [entry])
    assert entry not in r.nodes


def test_forward_closure_max_depth():
    # Chain entry → f0 → f1 → ... → f5
    src_lines = ["def entry():", "    f0()"]
    for i in range(5):
        src_lines.append(f"def f{i}():")
        if i == 4:
            src_lines.append("    pass")
        else:
            src_lines.append(f"    f{i + 1}()")
    inv = _inv(_file("src/a.py", "\n".join(src_lines) + "\n"))
    entry = InternalFunction("src/a.py", "entry", 1)
    r = forward_closure(inv, [entry], max_depth=2)
    # entry has depth 0; f0 depth 1; f1 depth 2; f2 NOT visited (would
    # be depth 3 — past max_depth).
    assert {fn.name for fn in r.nodes if isinstance(fn, InternalFunction)} \
        == {"f0", "f1"}
    assert r.truncated is True


def test_forward_closure_handles_cycles():
    inv = _inv(_file("src/a.py",
        "def a():\n"
        "    b()\n"
        "def b():\n"
        "    a()\n"
        "def entry():\n"
        "    a()\n"
    ))
    entry = InternalFunction("src/a.py", "entry", 5)
    r = forward_closure(inv, [entry])
    # Should terminate. Both a + b in result.
    names = {fn.name for fn in r.nodes if isinstance(fn, InternalFunction)}
    assert names == {"a", "b"}


def test_forward_closure_empty_entries():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    r = forward_closure(inv, [])
    assert r == ClosureResult()


# ---------------------------------------------------------------------------
# shortest_path
# ---------------------------------------------------------------------------


def test_shortest_path_simple():
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def a():\n"
        "    target()\n"
    ))
    a = InternalFunction("src/a.py", "a", 3)
    target = InternalFunction("src/a.py", "target", 1)
    p = shortest_path(inv, a, target)
    assert p == (a, target)


def test_shortest_path_picks_shorter_chain():
    """When two chains exist, the shorter one wins."""
    inv = _inv(_file("src/a.py",
        "def target():\n"          # 1
        "    pass\n"
        "def short():\n"           # 3 — direct
        "    target()\n"
        "def long():\n"            # 5 — indirect
        "    short()\n"
        "def entry():\n"           # 7
        "    target()\n"           # direct, 1 hop
        "    long()\n"             # also reaches via 3 hops
    ))
    entry = InternalFunction("src/a.py", "entry", 7)
    target = InternalFunction("src/a.py", "target", 1)
    p = shortest_path(inv, entry, target)
    assert p == (entry, target)


def test_shortest_path_returns_none_when_unreachable():
    inv = _inv(_file("src/a.py",
        "def isolated():\n"
        "    pass\n"
        "def standalone():\n"
        "    pass\n"
    ))
    src = InternalFunction("src/a.py", "standalone", 3)
    dst = InternalFunction("src/a.py", "isolated", 1)
    assert shortest_path(inv, src, dst) is None


def test_shortest_path_source_equals_target():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    f = InternalFunction("src/a.py", "f", 1)
    assert shortest_path(inv, f, f) == (f,)


def test_shortest_path_max_depth_bound():
    """Long chain truncated by max_depth → returns None."""
    src_lines = ["def f0():", "    f1()"]
    for i in range(1, 5):
        src_lines.append(f"def f{i}():")
        if i == 4:
            src_lines.append("    pass")
        else:
            src_lines.append(f"    f{i + 1}()")
    inv = _inv(_file("src/a.py", "\n".join(src_lines) + "\n"))
    src = InternalFunction("src/a.py", "f0", 1)
    dst = InternalFunction("src/a.py", "f4", 9)
    assert shortest_path(inv, src, dst, max_depth=2) is None
    p = shortest_path(inv, src, dst, max_depth=10)
    assert p is not None and len(p) == 5


def test_shortest_path_to_external_target():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def fetch():\n"
        "    requests.get('/')\n"
    ))
    fetch = InternalFunction("src/a.py", "fetch", 2)
    p = shortest_path(inv, fetch, ExternalFunction("requests.get"))
    assert p == (fetch, ExternalFunction("requests.get"))


def test_shortest_path_external_target_aliases_to_internal():
    """When an external qualified name aliases to a project-internal
    function, shortest_path follows the alias — same semantics as
    callers_of."""
    inv = _inv(
        _file("pkg/helpers.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg.helpers import fn\n"
            "def main():\n"
            "    fn()\n"
        ),
    )
    main = InternalFunction("app.py", "main", 2)
    p = shortest_path(inv, main, ExternalFunction("pkg.helpers.fn"))
    expected = InternalFunction("pkg/helpers.py", "fn", 1)
    assert p == (main, expected)


def test_shortest_path_exclude_test_files_filters_intermediates():
    """When ``exclude_test_files=True``, paths whose intermediate
    hops cross test-file functions are rejected; the BFS continues
    looking for a non-test path."""
    inv = _inv(
        _file("src/a.py",
            "def target():\n"          # 1
            "    pass\n"
            "def app():\n"              # 3
            "    target()\n"
        ),
        _file("tests/helpers.py",
            "from src.a import target\n"
            "def via_test():\n"
            "    target()\n",
            items=[{"name": "via_test", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
        _file("src/entry.py",
            "from tests.helpers import via_test\n"
            "from src.a import app\n"
            "def entry():\n"
            "    via_test()\n"          # path 1: entry → via_test → target
            "    app()\n"                # path 2: entry → app → target
        ),
    )
    entry = InternalFunction("src/entry.py", "entry", 3)
    target = InternalFunction("src/a.py", "target", 1)
    # Without filter: BFS picks up the test-helper path (3 hops same
    # length as app path; insertion order may vary, but BOTH are
    # acceptable answers).
    p_default = shortest_path(inv, entry, target)
    assert p_default is not None
    # With filter: must pick the non-test chain.
    p_filtered = shortest_path(inv, entry, target, exclude_test_files=True)
    assert p_filtered is not None
    assert all(
        not (isinstance(s, InternalFunction)
             and s.file_path.startswith("tests/"))
        for s in p_filtered[1:-1]
    )


# ---------------------------------------------------------------------------
# Path validity invariant
# ---------------------------------------------------------------------------


def test_closure_paths_are_valid_edges():
    """Every adjacent pair in a closure path must correspond to an
    actual call edge in the index."""
    from core.inventory.reachability import (
        callees_of,
    )
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def leaf():\n"
        "    json.dumps({})\n"
        "def mid():\n"
        "    leaf()\n"
        "def entry():\n"
        "    mid()\n"
    ))

    entry = InternalFunction("src/a.py", "entry", 5)
    fc = forward_closure(inv, [entry])
    for node, path in fc.paths.items():
        assert path[0] == entry
        assert path[-1] == node
        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            assert isinstance(src, InternalFunction), \
                f"source step in path is External: {src}"
            cees = callees_of(inv, src).definitive
            assert dst in cees, \
                f"step {src} → {dst} not in source's callees: {cees}"


# ---------------------------------------------------------------------------
# ClosureResult shape
# ---------------------------------------------------------------------------


def test_closure_result_default_is_empty():
    r = ClosureResult()
    assert r.nodes == ()
    assert r.paths == {}
    assert r.truncated is False


# ---------------------------------------------------------------------------
# Test-file traversal semantics: closures must NOT walk through test
# functions when exclude_test_files=True. Otherwise a non-test function
# reachable only via a test-file caller ends up in the closure with a
# path that crosses test code — surprising and inconsistent with
# shortest_path.
# ---------------------------------------------------------------------------


def test_reverse_closure_does_not_walk_through_test_files():
    """target is called by a test helper, which is itself called by
    a non-test function. With exclude_test_files=True, the non-test
    function should NOT appear in the closure — its only path
    crosses a test file, and we don't treat that as reachability."""
    inv = _inv(
        _file("src/a.py",
            "def target():\n"
            "    pass\n"
        ),
        _file("tests/helpers.py",
            "from src.a import target\n"
            "def via_test():\n"
            "    target()\n",
            items=[{"name": "via_test", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
        _file("src/upstream.py",
            "from tests.helpers import via_test\n"
            "def upstream():\n"
            "    via_test()\n"
        ),
    )
    target = InternalFunction("src/a.py", "target", 1)
    r = reverse_closure(inv, target)
    upstream = InternalFunction("src/upstream.py", "upstream", 2)
    # via_test is a test function — filtered.
    # upstream's only path to target crosses via_test — also filtered.
    assert upstream not in r.nodes


def test_forward_closure_does_not_walk_through_test_files():
    """Symmetric: entry → test_helper → real_target should NOT put
    real_target in the closure when exclude_test_files=True."""
    inv = _inv(
        _file("src/real.py",
            "def real_target():\n"
            "    pass\n"
        ),
        _file("tests/helpers.py",
            "from src.real import real_target\n"
            "def test_helper():\n"
            "    real_target()\n",
            items=[{"name": "test_helper", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
        _file("src/entry.py",
            "from tests.helpers import test_helper\n"
            "def entry():\n"
            "    test_helper()\n"
        ),
    )
    entry = InternalFunction("src/entry.py", "entry", 2)
    r = forward_closure(inv, [entry])
    # test_helper filtered as test file.
    # real_target's only path crosses test_helper — also filtered.
    assert all(
        not (isinstance(n, InternalFunction) and n.name == "real_target")
        for n in r.nodes
    )


# ---------------------------------------------------------------------------
# all_paths — k-shortest simple paths (no node repeats per chain).
# Companion to shortest_path when consumers want evidence diversity.
# ---------------------------------------------------------------------------


def test_all_paths_single_chain():
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def b():\n"
        "    target()\n"
        "def a():\n"
        "    b()\n"
    ))
    a = InternalFunction("src/a.py", "a", 5)
    target = InternalFunction("src/a.py", "target", 1)
    paths = all_paths(inv, a, target)
    assert len(paths) == 1
    assert paths[0] == (a, InternalFunction("src/a.py", "b", 3), target)


def test_all_paths_finds_multiple():
    """entry has two paths to target: direct and via mid."""
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def mid():\n"
        "    target()\n"
        "def entry():\n"
        "    target()\n"
        "    mid()\n"
    ))
    entry = InternalFunction("src/a.py", "entry", 5)
    target = InternalFunction("src/a.py", "target", 1)
    paths = all_paths(inv, entry, target)
    assert len(paths) == 2
    # Sorted by length: direct first.
    assert paths[0] == (entry, target)
    assert paths[1] == (entry, InternalFunction("src/a.py", "mid", 3),
                        target)


def test_all_paths_handles_cycles_no_repeated_node():
    """A cycle shouldn't cause infinite recursion or duplicate paths.
    Simple-path constraint: no node repeats in a single chain."""
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def a():\n"
        "    b()\n"
        "    target()\n"
        "def b():\n"
        "    a()\n"
    ))
    a = InternalFunction("src/a.py", "a", 3)
    target = InternalFunction("src/a.py", "target", 1)
    paths = all_paths(inv, a, target)
    assert any(p == (a, target) for p in paths)
    for p in paths:
        assert len(set(p)) == len(p), p


def test_all_paths_max_paths_bound():
    """Many distinct paths exist; max_paths caps the result."""
    src_lines = ["def target():", "    pass"]
    for n in "abcde":
        src_lines.append(f"def {n}():")
        src_lines.append("    target()")
    src_lines.append("def entry():")
    for n in "abcde":
        src_lines.append(f"    {n}()")
    src_lines.append("    target()")
    inv = _inv(_file("src/a.py", "\n".join(src_lines) + "\n"))
    entry = next(InternalFunction("src/a.py", "entry", item["line_start"])
                 for f in inv["files"]
                 for item in f.get("items", [])
                 if item.get("name") == "entry")
    target = InternalFunction("src/a.py", "target", 1)
    all_p = all_paths(inv, entry, target, max_paths=10)
    assert len(all_p) == 6     # direct + 5 via single intermediate
    capped = all_paths(inv, entry, target, max_paths=2)
    assert len(capped) == 2


def test_all_paths_max_depth_bound():
    src_lines = ["def f0():", "    f1()"]
    for i in range(1, 5):
        src_lines.append(f"def f{i}():")
        if i == 4:
            src_lines.append("    pass")
        else:
            src_lines.append(f"    f{i + 1}()")
    inv = _inv(_file("src/a.py", "\n".join(src_lines) + "\n"))
    src = InternalFunction("src/a.py", "f0", 1)
    dst = InternalFunction("src/a.py", "f4", 9)
    deep = all_paths(inv, src, dst, max_depth=10)
    assert len(deep) == 1
    shallow = all_paths(inv, src, dst, max_depth=2)
    assert shallow == ()


def test_all_paths_unreachable_returns_empty():
    inv = _inv(_file("src/a.py",
        "def isolated():\n"
        "    pass\n"
        "def standalone():\n"
        "    pass\n"
    ))
    src = InternalFunction("src/a.py", "standalone", 3)
    dst = InternalFunction("src/a.py", "isolated", 1)
    assert all_paths(inv, src, dst) == ()


def test_all_paths_source_equals_target():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    f = InternalFunction("src/a.py", "f", 1)
    assert all_paths(inv, f, f) == ((f,),)


def test_all_paths_external_target_alias():
    """External target aliasing to a project InternalFunction yields
    paths to the InternalFunction (matches shortest_path / closure
    semantics)."""
    inv = _inv(
        _file("pkg/helpers.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg.helpers import fn\n"
            "def main():\n"
            "    fn()\n"
        ),
    )
    main = InternalFunction("app.py", "main", 2)
    paths = all_paths(inv, main, ExternalFunction("pkg.helpers.fn"))
    expected = InternalFunction("pkg/helpers.py", "fn", 1)
    assert paths == ((main, expected),)


def test_all_paths_excludes_test_files_when_requested():
    inv = _inv(
        _file("src/a.py",
            "def target():\n"
            "    pass\n"
            "def app():\n"
            "    target()\n"
        ),
        _file("tests/helpers.py",
            "from src.a import target\n"
            "def via_test():\n"
            "    target()\n",
            items=[{"name": "via_test", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
        _file("src/entry.py",
            "from tests.helpers import via_test\n"
            "from src.a import app\n"
            "def entry():\n"
            "    via_test()\n"
            "    app()\n"
        ),
    )
    entry = InternalFunction("src/entry.py", "entry", 3)
    target = InternalFunction("src/a.py", "target", 1)
    p_default = all_paths(inv, entry, target)
    assert len(p_default) == 2
    p_filtered = all_paths(inv, entry, target, exclude_test_files=True)
    assert len(p_filtered) == 1
    assert all(
        not (isinstance(s, InternalFunction)
             and s.file_path.startswith("tests/"))
        for s in p_filtered[0]
    )


def test_all_paths_sorted_by_length():
    inv = _inv(_file("src/a.py",
        "def target():\n"
        "    pass\n"
        "def m():\n"
        "    target()\n"
        "def n():\n"
        "    target()\n"
        "def via_m():\n"
        "    m()\n"
        "def entry():\n"
        "    m()\n"
        "    n()\n"
        "    via_m()\n"
    ))
    entry = InternalFunction("src/a.py", "entry", 9)
    target = InternalFunction("src/a.py", "target", 1)
    paths = all_paths(inv, entry, target)
    lengths = [len(p) for p in paths]
    assert lengths == sorted(lengths)
