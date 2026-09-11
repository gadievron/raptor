"""Entry-reachability caller-uncertainty, test-file entry seeding,
same-file bare-name language gating, and cache LRU behaviour tests
for :mod:`core.analysis.reachability`."""
from __future__ import annotations

from typing import Any, Dict, List

from core.analysis.reachability import (
    InternalFunction,
    Verdict,
    entry_reachability,
    function_called,
)


def _fn(name, line, vis=None, line_end=None):
    item = {"name": name, "kind": "function", "line_start": line,
            "metadata": {"visibility": vis}}
    if line_end is not None:
        item["line_end"] = line_end
    return item


def _file(path, language, items, calls, imports=None):
    return {
        "path": path, "language": language, "items": items,
        "call_graph": {"imports": imports or {}, "calls": calls},
    }


def _inv(*files: Dict[str, Any]) -> Dict[str, Any]:
    out: List[Dict[str, Any]] = list(files)
    return {"files": out}


def _er(inv, path, name, line):
    return entry_reachability(inv, InternalFunction(
        file_path=path, name=name, line=line))


# ---------------------------------------------------------------------------
# Transitive-caller uncertainty degrades a dead-island claim
# ---------------------------------------------------------------------------


def test_private_helper_with_uncertain_public_caller_reads_uncertain():
    # ``_helper`` is private (no ``__all__``), but its ONLY caller is
    # a public function that itself reads uncertain (public-named, no
    # ``__all__`` — could be library API). The dead claim on the
    # helper rests on the caller being dead, which is unproven —
    # verdict must degrade to uncertain, not confident no_path.
    inv = _inv(_file(
        "m.py", "python",
        [_fn("api", 1), _fn("_helper", 5)],
        [{"caller": "api", "chain": ["_helper"], "line": 2}],
    ))
    assert _er(inv, "m.py", "api", 1) == "uncertain"
    assert _er(inv, "m.py", "_helper", 5) == "uncertain"


def test_private_helper_with_certain_private_caller_still_no_path():
    # Two-direction: when every transitive caller is itself
    # confidently internal (underscore convention, no ``__all__``),
    # the dead-island claim stands.
    inv = _inv(_file(
        "m.py", "python",
        [_fn("_caller", 1), _fn("_helper", 5)],
        [{"caller": "_caller", "chain": ["_helper"], "line": 2}],
    ))
    assert _er(inv, "m.py", "_helper", 5) == "no_path_from_entry"


def test_private_helper_with_dunder_all_exported_caller_reads_uncertain():
    # The caller is exported via ``__all__`` — externally reachable
    # even with no in-project caller, so the helper it calls cannot
    # be confidently dead.
    file_record = _file(
        "m.py", "python",
        [_fn("api", 1), _fn("_helper", 5)],
        [{"caller": "api", "chain": ["_helper"], "line": 2}],
    )
    file_record["exports"] = ["api"]
    inv = _inv(file_record)
    assert _er(inv, "m.py", "_helper", 5) == "uncertain"


# ---------------------------------------------------------------------------
# Test-file items must not seed entry points
# ---------------------------------------------------------------------------


def test_function_called_from_prod_entry_is_reachable():
    # Control: the exact shape below in a PRODUCTION file — the
    # non-static caller is an entry and the static helper it calls is
    # reachable through it.
    inv = _inv(
        _file("app.c", "c",
              [_fn("run_app", 1), _fn("helper", 5, "static")],
              [{"caller": "run_app", "chain": ["helper"], "line": 2}]),
    )
    assert _er(inv, "app.c", "helper", 5) == "reachable"


def test_function_called_only_from_test_file_entry_is_not_reachable():
    # Identical shape, but the file is a test file. A test-file item
    # must not seed the entry set (the framework entry sets already
    # exclude test files), so neither the would-be entry nor the
    # helper it calls reads entry-reachable.
    inv = _inv(
        _file("tests/test_app.c", "c",
              [_fn("run_app", 1), _fn("helper", 5, "static")],
              [{"caller": "run_app", "chain": ["helper"], "line": 2}]),
    )
    assert _er(inv, "tests/test_app.c", "helper", 5) == "no_path_from_entry"
    assert _er(inv, "tests/test_app.c", "run_app", 1) != "reachable"


# ---------------------------------------------------------------------------
# Same-file bare-name fast-path: header includes are not name bindings
# ---------------------------------------------------------------------------


def test_c_static_function_named_after_included_header_reads_called():
    # foo.c includes foo.h (extractor records imports["foo"]="foo.h")
    # and defines static foo(); bar() calls it. A header include is
    # preprocessor text, not a name binding — the same-file fast-path
    # must still fire.
    inv = _inv(_file(
        "foo.c", "c",
        [_fn("foo", 1, "static"), _fn("bar", 5)],
        [{"caller": "bar", "chain": ["foo"], "line": 6}],
        imports={"foo": "foo.h"},
    ))
    r = function_called(inv, "foo.foo")
    assert r.verdict == Verdict.CALLED


def test_python_shadowing_import_still_skips_same_file_fast_path():
    # Two-direction: in Python an import DOES bind the bare name. A
    # file that imports ``helper`` from elsewhere and calls it bare
    # must not count as evidence for a same-named local definition.
    inv = _inv(_file(
        "src/x.py", "python",
        [_fn("helper", 1)],
        [{"chain": ["helper"], "line": 3}],
        imports={"helper": "src.other.helper"},
    ))
    r = function_called(inv, "src.x.helper")
    assert r.verdict == Verdict.NOT_CALLED


# ---------------------------------------------------------------------------
# Cache eviction is LRU, not FIFO
# ---------------------------------------------------------------------------


def test_files_by_path_cache_evicts_least_recently_used():
    import core.analysis.reachability as reach_mod

    with reach_mod._FILES_BY_PATH_CACHE_LOCK:
        reach_mod._FILES_BY_PATH_CACHE.clear()

    invs = [
        {"files": [{"path": f"f{i}.py", "language": "python",
                    "items": [], "call_graph": {}}]}
        for i in range(reach_mod._FILES_BY_PATH_CACHE_MAX + 1)
    ]
    # Fill to capacity.
    for inv in invs[:-1]:
        reach_mod._files_by_path(inv)
    # Touch the FIRST-inserted entry — under LRU it becomes the most
    # recently used and must survive the next eviction.
    reach_mod._files_by_path(invs[0])
    # Insert one more to trigger eviction.
    reach_mod._files_by_path(invs[-1])

    with reach_mod._FILES_BY_PATH_CACHE_LOCK:
        cached_ids = set(reach_mod._FILES_BY_PATH_CACHE.keys())
    assert id(invs[0]) in cached_ids, (
        "recently-used entry was evicted (FIFO behaviour)"
    )
    assert id(invs[1]) not in cached_ids, (
        "least-recently-used entry survived eviction"
    )
    with reach_mod._FILES_BY_PATH_CACHE_LOCK:
        reach_mod._FILES_BY_PATH_CACHE.clear()
