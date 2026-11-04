"""Lazy identifier facts must equal the original eager row computation."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from core.audit import callsite_consistency as census


@pytest.mark.parametrize("path,source", [
    ("a.c", "int f(void) { int r=load(); int x=2; if(r<0) return r; r=again(); return x; }"),
    ("a.cpp", "int f() { int r=load(); auto g=[&](){return r;}; return r==0; }"),
    ("a.py", "def f():\n r = load()\n if r:\n  return r\n return other\n"),
    ("a.js", "function f() { let r=load(); if (r) return r; return other; }"),
    ("a.go", "package p\nfunc f() int { r := load(); if r < 0 { return r }; return 0 }"),
])
def test_rows_match_eager_predicates_in_document_order(path, source):
    tree, _ = census._parse_file(source, path)
    if tree is None:
        pytest.skip("tree-sitter grammar unavailable")
    src = source.encode()
    expected = {}
    for node in census._walk_descendants(tree.root_node):
        if node.type not in census._ID_NODE_TYPES:
            continue
        write = census._is_write_target(node)
        expected.setdefault(census._node_text(node, src), []).append(
            (node.start_byte, write, not write and census._read_is_tested(node)))
    index = census._ScopeReadIndex(tree.root_node, src)
    for name, rows in reversed(list(expected.items())):
        assert index.occurrences(name) == rows
        assert index.occurrences(name) == rows
    assert index.occurrences("not_in_this_file") == []


def test_unrequested_names_do_not_run_usage_predicates(monkeypatch):
    source = "int f(void) { int result=load(); int unused=1; if(result<0) return result; return unused; }"
    tree, _ = census._parse_file(source, "a.c")
    if tree is None:
        pytest.skip("C grammar unavailable")
    src = source.encode()
    real = census._read_is_tested
    seen = []

    def tested(node):
        seen.append(census._node_text(node, src))
        return real(node)

    monkeypatch.setattr(census, "_read_is_tested", tested)
    index = census._ScopeReadIndex(tree.root_node, src)
    first = index.occurrences("result")
    assert seen and set(seen) == {"result"}
    count = len(seen)
    assert index.occurrences("result") is first
    assert len(seen) == count


def test_overlapping_queries_never_observe_false_empty_rows(monkeypatch):
    source = "int f(void) { int result=load(); if(result<0) return result; return 0; }"
    tree, _ = census._parse_file(source, "a.c")
    if tree is None:
        pytest.skip("C grammar unavailable")
    src = source.encode()
    index = census._ScopeReadIndex(tree.root_node, src)
    index.occurrences("f")  # Warm name indexing, leaving result unclassified.
    real = census._read_is_tested
    barrier = threading.Barrier(2)
    local = threading.local()

    def tested(node):
        if not getattr(local, "joined", False):
            local.joined = True
            barrier.wait(timeout=5)
        return real(node)

    monkeypatch.setattr(census, "_read_is_tested", tested)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(index.occurrences, "result") for _ in range(2)]
        rows = [f.result(timeout=10) for f in futures]
    assert rows[0] and rows[0] == rows[1] == index.occurrences("result")
