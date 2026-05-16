"""Tests for the 1-hop adjacency primitives in
:mod:`core.inventory.reachability` — ``callers_of`` and
``callees_of``.

These exercise the resolver against synthetic inventory dicts that
mirror the shape :func:`core.inventory.builder.build_inventory`
produces: each file has ``items`` (function definitions with name +
line_start) AND ``call_graph`` (imports, calls with caller name,
indirection flags).

Built-in policy points pinned by the tests below:

  * Project-internal call edges (``foo()`` → local def of ``foo``)
    appear in ``definitive``.
  * Cross-package call edges (``mod.fn()`` → ``ExternalFunction``)
    appear in ``definitive``.
  * Method-dispatch chains (``self.foo()``, ``obj.foo()``) appear
    in ``method_match_overinclusive`` for any project-internal
    target named ``foo``, and in the source's
    ``CalleesResult.uncertain`` + ``has_method_dispatch=True``.
  * File-level masking flags (``getattr`` / ``importlib`` /
    wildcard import) flag every internal function in that file
    as an uncertain caller of any tail-name the file mentions.
  * Test files (``tests/``, ``test_*.py``, ``*_test.py``,
    ``conftest.py``) are filtered out by default.
  * The adjacency index is memoised per-inventory so back-to-back
    queries don't rebuild.
"""

from __future__ import annotations

from typing import Any, Dict, List


from core.inventory.call_graph import (
    extract_call_graph_python,
)
from core.inventory.reachability import (
    CalleesResult,
    CallersResult,
    ExternalFunction,
    InternalFunction,
    call_lines_of,
    callees_of,
    callers_of,
    is_framework_callable,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _file(path: str, source: str, *, items: List[Dict[str, Any]] = None,
          ) -> Dict[str, Any]:
    """Build one file record. Auto-derives items from the AST if not
    supplied — convenient for most tests where the function defs in
    the source are exactly what we want indexed."""
    cg = extract_call_graph_python(source).to_dict()
    if items is None:
        items = _derive_items(source)
    return {
        "path": path,
        "language": "python",
        "items": items,
        "call_graph": cg,
    }


def _derive_items(source: str) -> List[Dict[str, Any]]:
    """Walk the source with stdlib ast and pull out top-level + nested
    function defs. Mirrors what extract_items would do for the test's
    purposes."""
    import ast
    out: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append({
                "name": node.name,
                "kind": "function",
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", None),
            })
    return out


def _inv(*files: Dict[str, Any]) -> Dict[str, Any]:
    return {"files": list(files)}


# ---------------------------------------------------------------------------
# callers_of — external target (the SCA / codeql case)
# ---------------------------------------------------------------------------


def test_external_callers_definitive_via_attribute_chain():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def fetch():\n"
        "    requests.get('/')\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    assert r.definitive == (InternalFunction("src/a.py", "fetch", 2),)
    assert r.uncertain == ()
    assert r.method_match_overinclusive == ()


def test_external_callers_definitive_via_aliased_import():
    inv = _inv(_file("src/a.py",
        "from requests.utils import extract_zipped_paths as ezp\n"
        "def unzip():\n"
        "    ezp('/')\n"
    ))
    r = callers_of(inv, ExternalFunction(
        "requests.utils.extract_zipped_paths"))
    assert r.definitive == (InternalFunction("src/a.py", "unzip", 2),)


def test_external_callers_multiple_callers_sorted():
    inv = _inv(
        _file("src/b.py", "import requests\ndef b1():\n    requests.get('/')\n"),
        _file("src/a.py", "import requests\ndef a1():\n    requests.get('/')\n"),
    )
    r = callers_of(inv, ExternalFunction("requests.get"))
    # Stable sort by (file_path, name, line).
    assert r.definitive == (
        InternalFunction("src/a.py", "a1", 2),
        InternalFunction("src/b.py", "b1", 2),
    )


def test_external_callers_no_callers():
    inv = _inv(_file("src/a.py",
        "import json\n"
        "def f():\n"
        "    json.dumps({})\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    assert r.definitive == ()
    assert r.uncertain == ()


# ---------------------------------------------------------------------------
# callers_of — internal target
# ---------------------------------------------------------------------------


def test_internal_callers_via_local_bare_call():
    """`foo()` referring to a peer function defined in the same file."""
    inv = _inv(_file("src/a.py",
        "def helper():\n"
        "    pass\n"
        "def main():\n"
        "    helper()\n"
    ))
    target = InternalFunction("src/a.py", "helper", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("src/a.py", "main", 3),)


def test_internal_callers_method_match_class_aware_narrowing():
    """``self.foo()`` inside ``class A`` cannot resolve to
    ``class B.foo`` when A and B are unrelated. The class-aware
    narrowing in ``callers_of`` drops the cross-class entry; same-
    class entries survive."""
    inv = _inv(
        _file("src/a.py",
            "class A:\n"
            "    def foo(self):\n"
            "        pass\n"
            "    def main(self):\n"
            "        self.foo()\n"
        ),
        _file("src/b.py",
            "class B:\n"
            "    def foo(self):\n"
            "        pass\n"
        ),
    )
    target_a = InternalFunction("src/a.py", "foo", 2)
    target_b = InternalFunction("src/b.py", "foo", 2)
    r_a = callers_of(inv, target_a)
    r_b = callers_of(inv, target_b)
    main_fn = InternalFunction("src/a.py", "main", 4)
    # ``main`` survives narrowing for A.foo — same class.
    assert main_fn in r_a.method_match_overinclusive
    # And is correctly dropped from B.foo — different hierarchy.
    assert main_fn not in r_b.method_match_overinclusive
    # Definitive is empty for both: the substrate doesn't statically
    # resolve self.foo() to a definitive callee; it only narrows
    # the over-inclusive candidate pool.
    assert main_fn not in r_a.definitive
    assert main_fn not in r_b.definitive


def test_internal_callers_method_match_inheritance_keeps_parent():
    """When ``class B(A)`` and ``A.foo`` exists, ``self.foo()``
    inside ``class B`` may resolve to the inherited ``A.foo`` —
    narrowing must keep the entry on ``A.foo``'s caller list."""
    inv = _inv(
        _file("src/a.py",
            "class A:\n"
            "    def foo(self):\n"
            "        pass\n"
            "class B(A):\n"
            "    def main(self):\n"
            "        self.foo()\n"
        ),
    )
    a_foo = InternalFunction("src/a.py", "foo", 2)
    main_fn = InternalFunction("src/a.py", "main", 5)
    r = callers_of(inv, a_foo)
    assert main_fn in r.method_match_overinclusive


def test_internal_callers_method_match_cross_file_inheritance_stays_inclusive():
    """When ``class B(SomeImported)`` and the base is imported from
    another file, the resolver can't compute the full ancestor
    chain. Stays over-inclusive (prefers reporting an extra caller
    over dropping a real one)."""
    inv = _inv(
        _file("src/base.py",
            "class Base:\n"
            "    def foo(self):\n"
            "        pass\n"
        ),
        _file("src/sub.py",
            "from .base import Base\n"
            "class Sub(Base):\n"
            "    def main(self):\n"
            "        self.foo()\n"
        ),
        # An unrelated class with its own ``foo`` — under strict
        # narrowing this would be dropped, but because Sub's base
        # is unresolvable (imported), we stay over-inclusive.
        _file("src/other.py",
            "class Other:\n"
            "    def foo(self):\n"
            "        pass\n"
        ),
    )
    other_foo = InternalFunction("src/other.py", "foo", 2)
    main_fn = InternalFunction("src/sub.py", "main", 3)
    r = callers_of(inv, other_foo)
    # Cross-file inheritance means we can't safely narrow.
    # main_fn IS kept (over-inclusive), even though in reality the
    # call resolves to Base.foo.
    assert main_fn in r.method_match_overinclusive


def test_internal_callers_method_match_object_base_narrows():
    """``class A(object)`` should narrow the same as ``class A`` —
    ``object`` is a safe builtin base that adds nothing to the
    dispatch set."""
    inv = _inv(
        _file("src/a.py",
            "class A(object):\n"
            "    def foo(self):\n"
            "        pass\n"
            "    def main(self):\n"
            "        self.foo()\n"
        ),
        _file("src/b.py",
            "class B:\n"
            "    def foo(self):\n"
            "        pass\n"
        ),
    )
    b_foo = InternalFunction("src/b.py", "foo", 2)
    main_fn = InternalFunction("src/a.py", "main", 4)
    r = callers_of(inv, b_foo)
    # Same as bare ``class A`` — main_fn correctly excluded from
    # B.foo's callers.
    assert main_fn not in r.method_match_overinclusive


def test_internal_callers_method_match_skipped_for_external_target():
    """Method-match over-inclusive is only meaningful for internal
    targets (``the project's foo``). For ``requests.get`` we don't
    want every ``self.get()`` showing up."""
    inv = _inv(_file("src/a.py",
        "class A:\n"
        "    def main(self):\n"
        "        self.get('/')\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    assert r.method_match_overinclusive == ()


# ---------------------------------------------------------------------------
# callers_of — uncertain via masking flags
# ---------------------------------------------------------------------------


def test_uncertain_when_file_uses_getattr_and_mentions_target_tail():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def hidden():\n"
        "    f = getattr(requests, 'get')\n"
        "    f('/')\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    # No definitive call (getattr indirection); uncertain because
    # the file uses getattr AND mentions the tail 'get'.
    assert r.definitive == ()
    assert InternalFunction("src/a.py", "hidden", 2) in r.uncertain


def test_uncertain_does_not_overlap_definitive():
    """If a function has a definitive call AND its file uses getattr
    on the same target, only the definitive entry should appear."""
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def fetch():\n"
        "    requests.get('/')\n"
        "    f = getattr(requests, 'get')\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    fetch_fn = InternalFunction("src/a.py", "fetch", 2)
    assert fetch_fn in r.definitive
    assert fetch_fn not in r.uncertain


# ---------------------------------------------------------------------------
# callees_of
# ---------------------------------------------------------------------------


def test_callees_internal_and_external_mixed():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def helper():\n"
        "    pass\n"
        "def main():\n"
        "    helper()\n"
        "    requests.get('/')\n"
    ))
    src = InternalFunction("src/a.py", "main", 4)
    r = callees_of(inv, src)
    assert InternalFunction("src/a.py", "helper", 2) in r.definitive
    assert ExternalFunction("requests.get") in r.definitive
    assert r.uncertain == ()
    assert r.has_method_dispatch is False


def test_callees_method_dispatch_marks_uncertain_and_flag():
    inv = _inv(_file("src/a.py",
        "class A:\n"
        "    def main(self):\n"
        "        self.foo()\n"
        "        self.bar.baz()\n"
    ))
    src = InternalFunction("src/a.py", "main", 2)
    r = callees_of(inv, src)
    assert r.has_method_dispatch is True
    # Both unresolved chains landed in uncertain (string form).
    assert "self.foo" in r.uncertain
    assert "self.bar.baz" in r.uncertain
    # Definitive may be empty — neither call resolved via imports.
    assert r.definitive == ()


def test_callees_returns_empty_for_unknown_source():
    inv = _inv(_file("src/a.py", "def f():\n    pass\n"))
    bogus = InternalFunction("nope.py", "missing", 1)
    r = callees_of(inv, bogus)
    assert r == CalleesResult()


# ---------------------------------------------------------------------------
# Test-file exclusion
# ---------------------------------------------------------------------------


def test_test_file_caller_excluded_by_default():
    inv = _inv(
        _file("src/a.py",
            "def helper():\n"
            "    pass\n"
        ),
        _file("tests/test_a.py",
            "from src.a import helper\n"
            "def test_h():\n"
            "    helper()\n",
            items=[{"name": "test_h", "kind": "function",
                    "line_start": 2, "line_end": 3}],
        ),
    )
    target = InternalFunction("src/a.py", "helper", 1)
    r = callers_of(inv, target)
    # The test file's `test_h` would be a caller via wildcard, but
    # the file isn't a true cross-import we can resolve from the
    # local def. Either way, exclude_test_files=True means the test
    # file shouldn't contribute.
    for c in r.definitive + r.uncertain + r.method_match_overinclusive:
        assert not c.file_path.startswith("tests/"), c


def test_test_file_caller_included_when_opt_out():
    """``exclude_test_files=False`` lets test-file callers through."""
    inv = _inv(_file("tests/test_x.py",
        "import requests\n"
        "def test_get():\n"
        "    requests.get('/')\n"
    ))
    r_excl = callers_of(inv, ExternalFunction("requests.get"))
    r_incl = callers_of(inv, ExternalFunction("requests.get"),
                        exclude_test_files=False)
    assert r_excl.definitive == ()
    assert r_incl.definitive == (
        InternalFunction("tests/test_x.py", "test_get", 2),
    )


# ---------------------------------------------------------------------------
# Caller-resolution edge cases
# ---------------------------------------------------------------------------


def test_module_level_calls_dropped():
    """Calls outside any function don't have a useful caller node."""
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "requests.get('/')\n"      # module-level call, caller=None
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    assert r.definitive == ()


def test_same_name_nested_def_picks_innermost_by_line():
    """When two functions share name in one file (outer + nested
    redefining), the call's caller-name resolves to the lexically
    innermost one — the def with greatest line_start ≤ call_line."""
    src = (
        "def helper():\n"          # line 1
        "    def helper():\n"      # line 2 — nested redefinition
        "        import requests\n"
        "        requests.get('/')\n"  # line 4 — caller is inner
        "    return helper\n"
    )
    inv = _inv(_file("src/a.py", src))
    r = callers_of(inv, ExternalFunction("requests.get"))
    # The inner helper (line 2) should be the caller.
    callers = r.definitive
    assert any(c.line == 2 for c in callers)


# ---------------------------------------------------------------------------
# Memoisation
# ---------------------------------------------------------------------------


def test_index_memoised_across_queries():
    """Two queries against the same inventory dict should not rebuild
    the index. We verify by mocking the build pass and checking
    invocation count."""
    from core.inventory import reachability as r

    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def f():\n"
        "    requests.get('/')\n"
    ))

    # Drop any cached entry for this exact inventory id.
    r._INDEX_CACHE.pop(id(inv), None)

    build_calls = {"n": 0}
    real_build = r._get_or_build_index

    def _spy(inv_arg, *, exclude_test_files):
        # Detect a "miss" by checking the cache before delegating.
        if id(inv_arg) not in r._INDEX_CACHE:
            build_calls["n"] += 1
        return real_build(inv_arg, exclude_test_files=exclude_test_files)

    r._get_or_build_index = _spy        # type: ignore[assignment]
    try:
        callers_of(inv, ExternalFunction("requests.get"))
        callers_of(inv, ExternalFunction("requests.get"))
        callers_of(inv, ExternalFunction("requests.get"))
    finally:
        r._get_or_build_index = real_build  # type: ignore[assignment]

    assert build_calls["n"] == 1


# ---------------------------------------------------------------------------
# CallersResult.all_callers convenience
# ---------------------------------------------------------------------------


def test_all_callers_dedups_and_orders():
    """Each caller should appear at most once across all groups in the
    union view, in (definitive, uncertain, method_match) priority."""
    a = InternalFunction("src/a.py", "fn", 1)
    b = InternalFunction("src/b.py", "fn", 1)
    c = InternalFunction("src/c.py", "fn", 1)
    res = CallersResult(
        definitive=(a,),
        uncertain=(a, b),
        method_match_overinclusive=(c,),
    )
    assert res.all_callers == (a, b, c)


# ---------------------------------------------------------------------------
# FunctionId rendering
# ---------------------------------------------------------------------------


def test_internal_function_str_renders_path_name_line():
    fn = InternalFunction("src/auth.py", "verify_token", 42)
    assert str(fn) == "src/auth.py:verify_token@42"


def test_external_function_str_is_qualified_name():
    fn = ExternalFunction("requests.utils.extract_zipped_paths")
    assert str(fn) == "requests.utils.extract_zipped_paths"


def test_internal_functions_with_same_identity_are_equal():
    """Frozen dataclass equality + hashable for set/dict use."""
    a = InternalFunction("src/x.py", "f", 1)
    b = InternalFunction("src/x.py", "f", 1)
    assert a == b
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_internal_function_line_disambiguates():
    a = InternalFunction("src/x.py", "f", 1)
    b = InternalFunction("src/x.py", "f", 5)
    assert a != b
    assert {a, b} != {a}


# ---------------------------------------------------------------------------
# Cross-package import canonicalisation
# ---------------------------------------------------------------------------


def test_cross_package_import_call_resolves_to_internal():
    """``from pkg.mod import fn; fn()`` should land in
    ``callers_of(InternalFunction(pkg/mod.py, fn, ...))`` —
    not just under ``ExternalFunction("pkg.mod.fn")``.

    Pre-fix the substrate kept those as separate graph nodes, so a
    consumer holding the InternalFunction def saw 0 callers despite
    the function being demonstrably called from another file."""
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
    target = InternalFunction("pkg/helpers.py", "fn", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_external_form_returns_same_callers_when_aliased():
    """Querying by the External qualified name should produce the
    same answer as querying by the InternalFunction def — they're
    the same physical function."""
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
    via_internal = callers_of(inv, InternalFunction("pkg/helpers.py", "fn", 1))
    via_external = callers_of(inv, ExternalFunction("pkg.helpers.fn"))
    assert via_internal == via_external


def test_attribute_call_to_project_internal_canonicalises():
    """``import pkg.helpers; pkg.helpers.fn()`` (attribute chain
    rather than ``from`` import) should also canonicalise."""
    inv = _inv(
        _file("pkg/helpers.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "import pkg.helpers\n"
            "def main():\n"
            "    pkg.helpers.fn()\n"
        ),
    )
    target = InternalFunction("pkg/helpers.py", "fn", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_init_py_module_resolves_to_package_dotted_name():
    """``pkg/__init__.py`` corresponds to module ``pkg``, not
    ``pkg.__init__``. The candidate-name heuristic must strip
    ``__init__``."""
    inv = _inv(
        _file("pkg/__init__.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg import fn\n"
            "def main():\n"
            "    fn()\n"
        ),
    )
    target = InternalFunction("pkg/__init__.py", "fn", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_src_layout_alias():
    """``src/mypkg/foo.py`` is imported as ``mypkg.foo``, not
    ``src.mypkg.foo`` — the candidate-name helper handles the
    standard src-layout."""
    inv = _inv(
        _file("src/mypkg/foo.py",
            "def fn():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from mypkg.foo import fn\n"
            "def main():\n"
            "    fn()\n"
        ),
    )
    target = InternalFunction("src/mypkg/foo.py", "fn", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_external_qualified_name_not_a_project_alias_unchanged():
    """``requests.get`` doesn't resolve to anything project-internal;
    callers_of should behave exactly like before for that case."""
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def fetch():\n"
        "    requests.get('/')\n"
    ))
    r = callers_of(inv, ExternalFunction("requests.get"))
    assert r.definitive == (InternalFunction("src/a.py", "fetch", 2),)


# ---------------------------------------------------------------------------
# Cache safety: id() reuse guard + LRU eviction
# ---------------------------------------------------------------------------


def test_cache_identity_check_rejects_collision():
    """Even if id(new_inv) collides with a stale cached id, the
    identity check rejects the stale entry and rebuilds. We force
    the collision deterministically by hand-poking the cache."""
    from core.inventory import reachability as r

    inv_a = _inv(_file("src/a.py",
        "import requests\n"
        "def f():\n"
        "    requests.get('/')\n"
    ))
    callers_of(inv_a, ExternalFunction("requests.get"))
    a_id = id(inv_a)
    cached_a = r._INDEX_CACHE[a_id]
    # Hand-poke a stale entry under a different id() — same shape
    # the bug would produce when GC reuses an address.
    inv_b = _inv(_file("src/b.py",
        "import flask\n"
        "def g():\n"
        "    flask.run('/')\n"
    ))
    b_id = id(inv_b)
    # Replace cache[b_id] with the OTHER inventory's entry — this
    # simulates the post-eviction id-reuse race.
    r._INDEX_CACHE[b_id] = cached_a
    # Query inv_b. The identity check should detect the stale
    # entry, drop it, and rebuild from inv_b's own data.
    result = callers_of(inv_b, ExternalFunction("flask.run"))
    assert result.definitive == (
        InternalFunction("src/b.py", "g", 2),
    )


def test_cache_lru_eviction():
    """Once the cache exceeds _CACHE_MAX_ENTRIES, the oldest entry
    drops out. Bound by insertion order."""
    from core.inventory import reachability as r

    saved_max = r._CACHE_MAX_ENTRIES
    r._CACHE_MAX_ENTRIES = 4
    saved_cache = dict(r._INDEX_CACHE)
    r._INDEX_CACHE.clear()
    try:
        invs = [
            _inv(_file(f"src/m{i}.py",
                "import requests\n"
                f"def f{i}():\n"
                "    requests.get('/')\n"
            ))
            for i in range(6)
        ]
        for inv in invs:
            callers_of(inv, ExternalFunction("requests.get"))
        # First two inventories should have been evicted; last 4 cached.
        cached_ids = set(r._INDEX_CACHE.keys())
        assert id(invs[0]) not in cached_ids
        assert id(invs[1]) not in cached_ids
        for inv in invs[2:]:
            assert id(inv) in cached_ids
    finally:
        r._CACHE_MAX_ENTRIES = saved_max
        r._INDEX_CACHE.clear()
        r._INDEX_CACHE.update(saved_cache)


# ---------------------------------------------------------------------------
# __init__.py re-export aliasing — extends the cross-package canonicalisation
# above to handle ``pkg/__init__.py`` that re-exports from submodules,
# both via relative (``from .helpers import foo``) and absolute (``from
# pkg.helpers import foo``) import forms.
# ---------------------------------------------------------------------------


def test_reexport_basic():
    """``pkg/__init__.py`` does ``from .helpers import foo`` and
    ``app.py`` does ``from pkg import foo; foo()``. The caller must
    resolve to the def in ``pkg/helpers.py``."""
    inv = _inv(
        _file("pkg/__init__.py",
            "from .helpers import foo\n",
            items=[],
        ),
        _file("pkg/helpers.py",
            "def foo():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg import foo\n"
            "def main():\n"
            "    foo()\n"
        ),
    )
    target = InternalFunction("pkg/helpers.py", "foo", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_reexport_with_alias():
    """``from .helpers import foo as bar`` — alias name must be the
    one consumers can call by."""
    inv = _inv(
        _file("pkg/__init__.py",
            "from .helpers import foo as bar\n",
            items=[],
        ),
        _file("pkg/helpers.py",
            "def foo():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg import bar\n"
            "def main():\n"
            "    bar()\n"
        ),
    )
    target = InternalFunction("pkg/helpers.py", "foo", 1)
    r = callers_of(inv, target)
    assert r.definitive == (InternalFunction("app.py", "main", 2),)


def test_reexport_transitive():
    """``pkg/__init__.py`` re-exports from ``pkg/sub/__init__.py``
    which re-exports from ``pkg/sub/impl.py``. Three-level chain;
    fixed-point iteration must collapse them all to the same def."""
    inv = _inv(
        _file("pkg/__init__.py",
            "from .sub import foo\n",
            items=[],
        ),
        _file("pkg/sub/__init__.py",
            "from .impl import foo\n",
            items=[],
        ),
        _file("pkg/sub/impl.py",
            "def foo():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg import foo\n"
            "def main():\n"
            "    foo()\n"
        ),
    )
    target = InternalFunction("pkg/sub/impl.py", "foo", 1)
    r = callers_of(inv, target)
    assert InternalFunction("app.py", "main", 2) in r.definitive


def test_reexport_via_double_dot():
    """``pkg/sub/__init__.py`` does ``from ..other import x``,
    making ``pkg.sub.x`` an alias for ``pkg.other.x``."""
    inv = _inv(
        _file("pkg/__init__.py", "", items=[]),
        _file("pkg/sub/__init__.py",
            "from ..other import x\n",
            items=[],
        ),
        _file("pkg/other.py",
            "def x():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg.sub import x\n"
            "def main():\n"
            "    x()\n"
        ),
    )
    target = InternalFunction("pkg/other.py", "x", 1)
    r = callers_of(inv, target)
    assert InternalFunction("app.py", "main", 2) in r.definitive


def test_reexport_doesnt_steal_unrelated():
    """``pkg/__init__.py`` re-exporting ``foo`` shouldn't make
    ``pkg.bar`` resolve to anything — there's no ``bar`` re-export."""
    inv = _inv(
        _file("pkg/__init__.py",
            "from .helpers import foo\n",
            items=[],
        ),
        _file("pkg/helpers.py",
            "def foo():\n"
            "    pass\n"
            "def bar():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg import bar\n"
            "def main():\n"
            "    bar()\n"
        ),
    )
    target = InternalFunction("pkg/helpers.py", "bar", 3)
    r = callers_of(inv, target)
    assert r.definitive == ()


def test_reexport_src_layout():
    """``src/mypkg/__init__.py`` re-exports from
    ``src/mypkg/helpers.py``. Caller does ``from mypkg import foo``."""
    inv = _inv(
        _file("src/mypkg/__init__.py",
            "from .helpers import foo\n",
            items=[],
        ),
        _file("src/mypkg/helpers.py",
            "def foo():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from mypkg import foo\n"
            "def main():\n"
            "    foo()\n"
        ),
    )
    target = InternalFunction("src/mypkg/helpers.py", "foo", 1)
    r = callers_of(inv, target)
    assert InternalFunction("app.py", "main", 2) in r.definitive


def test_reexport_absolute_import():
    """``core/__init__.py`` does ``from core.config import RaptorConfig``
    (absolute import, not ``.config``). RAPTOR's actual
    ``core/__init__.py`` uses this style."""
    inv = _inv(
        _file("core/__init__.py",
            "from core.config import RaptorConfig\n",
            items=[],
        ),
        _file("core/config.py",
            "def RaptorConfig():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from core import RaptorConfig\n"
            "def main():\n"
            "    RaptorConfig()\n"
        ),
    )
    target = InternalFunction("core/config.py", "RaptorConfig", 1)
    r = callers_of(inv, target)
    assert InternalFunction("app.py", "main", 2) in r.definitive


def test_reexport_target_not_in_project_unchanged():
    """``from .nonexistent import foo`` where the source isn't a
    project module — no alias should be created."""
    inv = _inv(
        _file("pkg/__init__.py",
            "from .nonexistent import foo\n",
            items=[],
        ),
        _file("app.py",
            "from pkg import foo\n"
            "def main():\n"
            "    foo()\n"
        ),
    )
    from core.inventory.reachability import _get_or_build_index
    idx = _get_or_build_index(inv, exclude_test_files=False)
    assert "pkg.foo" not in idx.qualified_to_internal


# ---------------------------------------------------------------------------
# call_lines_of — preserves multiplicity past the dedup'd forward / reverse
# adjacency. Useful for evidence rendering ("X calls Y at lines …").
# ---------------------------------------------------------------------------


def test_call_lines_of_records_every_call_site():
    inv = _inv(_file("src/a.py",
        "def helper():\n"
        "    pass\n"
        "def main():\n"
        "    helper()\n"
        "    x = 1\n"
        "    helper()\n"
        "    y = 2\n"
        "    helper()\n"
    ))
    main = InternalFunction("src/a.py", "main", 3)
    helper = InternalFunction("src/a.py", "helper", 1)
    assert call_lines_of(inv, main, helper) == (4, 6, 8)


def test_call_lines_of_external_callee():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def f():\n"
        "    requests.get('/')\n"
        "    requests.get('/x')\n"
    ))
    f = InternalFunction("src/a.py", "f", 2)
    assert call_lines_of(inv, f, ExternalFunction("requests.get")) == (3, 4)


def test_call_lines_of_returns_empty_when_no_edge():
    inv = _inv(_file("src/a.py",
        "def a():\n"
        "    pass\n"
        "def b():\n"
        "    pass\n"
    ))
    a = InternalFunction("src/a.py", "a", 1)
    b = InternalFunction("src/a.py", "b", 3)
    assert call_lines_of(inv, a, b) == ()


def test_call_lines_of_internal_alias_target():
    """A consumer holding ``ExternalFunction("pkg.helpers.foo")``
    should get the same line numbers as one holding the
    ``InternalFunction`` form — same alias semantics as
    ``callers_of``."""
    inv = _inv(
        _file("pkg/helpers.py",
            "def foo():\n"
            "    pass\n"
        ),
        _file("app.py",
            "from pkg.helpers import foo\n"
            "def main():\n"
            "    foo()\n"
            "    foo()\n"
        ),
    )
    main = InternalFunction("app.py", "main", 2)
    foo = InternalFunction("pkg/helpers.py", "foo", 1)
    via_internal = call_lines_of(inv, main, foo)
    via_external = call_lines_of(
        inv, main, ExternalFunction("pkg.helpers.foo"))
    assert via_internal == via_external == (3, 4)


def test_call_lines_dedups_same_line():
    """The recorder is idempotent: repeated calls with the same
    (line, edge) don't introduce duplicates."""
    from core.inventory.reachability import (
        _AdjacencyIndex, _record_call_line,
    )
    idx = _AdjacencyIndex()
    fn = InternalFunction("a.py", "x", 1)
    callee = ExternalFunction("os.path.join")
    _record_call_line(idx, fn, callee, 5)
    _record_call_line(idx, fn, callee, 5)
    _record_call_line(idx, fn, callee, 7)
    _record_call_line(idx, fn, callee, 3)
    assert idx.call_lines[(fn, callee)] == (3, 5, 7)


# ---------------------------------------------------------------------------
# Framework-callable detection (decorator-dispatched entry points)
# ---------------------------------------------------------------------------


def test_inventory_with_none_entries_does_not_crash():
    """Malformed inventory with ``None`` in the files list shouldn't
    crash — every loop must guard with ``isinstance(file_record, dict)``."""
    inv = {"files": [None, {"path": "a.py", "items": []}]}
    # Any query against any target should return cleanly.
    target = InternalFunction("a.py", "f", 1)
    r = callers_of(inv, target)
    assert r.definitive == ()
    assert is_framework_callable(inv, target) is False


def test_framework_callable_flask_route():
    inv = _inv(_file("src/api.py",
        "@app.route('/users')\n"
        "def list_users():\n"
        "    return []\n"
    ))
    target = InternalFunction("src/api.py", "list_users", 2)
    assert is_framework_callable(inv, target) is True


def test_framework_callable_click_command():
    inv = _inv(_file("src/cli.py",
        "@cli.command()\n"
        "def deploy():\n"
        "    pass\n"
    ))
    target = InternalFunction("src/cli.py", "deploy", 2)
    assert is_framework_callable(inv, target) is True


def test_framework_callable_pytest_fixture():
    inv = _inv(_file("src/conftest.py",
        "@pytest.fixture\n"
        "def db():\n"
        "    yield None\n"
    ))
    target = InternalFunction("src/conftest.py", "db", 2)
    # ``conftest.py`` is a test path — exclude_test_files defaults
    # to True but is_framework_callable preserves the flag through
    # to _get_or_build_index. The framework_callable set is built
    # regardless of test classification (it doesn't filter); the
    # consumer is asking "did this carry a registration decorator?"
    # and the answer is yes.
    assert is_framework_callable(inv, target, exclude_test_files=False) is True


def test_framework_callable_fastapi_router_get():
    inv = _inv(_file("src/routes.py",
        "@router.get('/items')\n"
        "def list_items():\n"
        "    return []\n"
    ))
    target = InternalFunction("src/routes.py", "list_items", 2)
    assert is_framework_callable(inv, target) is True


def test_framework_callable_celery_task():
    inv = _inv(_file("src/tasks.py",
        "@app.task\n"
        "def send_email(addr):\n"
        "    pass\n"
    ))
    target = InternalFunction("src/tasks.py", "send_email", 2)
    assert is_framework_callable(inv, target) is True


def test_passthrough_decorator_not_framework_callable():
    """``@functools.cache`` is a pass-through — wraps the function
    but doesn't register it with a dispatcher. Should NOT be flagged."""
    inv = _inv(_file("src/a.py",
        "@functools.cache\n"
        "def fib(n):\n"
        "    return n\n"
    ))
    target = InternalFunction("src/a.py", "fib", 2)
    assert is_framework_callable(inv, target) is False


def test_bare_decorator_not_framework_callable():
    """``@property``, ``@staticmethod``, ``@classmethod`` are bare
    decorators with chain length 1. Never flagged."""
    inv = _inv(_file("src/a.py",
        "class A:\n"
        "    @property\n"
        "    def name(self):\n"
        "        return 'x'\n"
    ))
    target = InternalFunction("src/a.py", "name", 3)
    assert is_framework_callable(inv, target) is False


def test_undecorated_function_not_framework_callable():
    inv = _inv(_file("src/a.py",
        "def helper():\n"
        "    return 1\n"
    ))
    target = InternalFunction("src/a.py", "helper", 1)
    assert is_framework_callable(inv, target) is False


def test_framework_callable_class_method():
    """``@router.get`` on a class method also fires."""
    inv = _inv(_file("src/api.py",
        "class API:\n"
        "    @router.get('/items')\n"
        "    def list_items(self):\n"
        "        return []\n"
    ))
    target = InternalFunction("src/api.py", "list_items", 3)
    assert is_framework_callable(inv, target) is True


def test_decorator_call_not_attributed_to_decorated_fn():
    """The pre-#7 extractor mis-attributed the call inside
    ``@app.route('/x')`` to the decorated function. After the fix
    the call site is attributed to the enclosing scope (module-
    level) — caller=None. Regression check."""
    from core.inventory.call_graph import extract_call_graph_python
    src = (
        "@app.route('/users')\n"
        "def list_users():\n"
        "    pass\n"
    )
    g = extract_call_graph_python(src)
    # The decorator expression IS a call: ``app.route('/users')``.
    deco_call = next(
        (c for c in g.calls if c.chain == ["app", "route"]), None,
    )
    assert deco_call is not None
    # Must NOT be attributed to ``list_users`` (which would falsely
    # imply ``list_users`` calls ``app.route``).
    assert deco_call.caller is None
