"""Tests for :mod:`core.inventory.reachability`.

These exercise the resolver against synthetic inventory dicts. The
goal is to pin all the import / call-site shapes that arise in
real Python code so a SCA "this CVE function isn't reachable"
verdict means what it claims.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.inventory.call_graph import (
    extract_call_graph_python,
)
from core.inventory.reachability import (
    InternalFunction,
    Verdict,
    entry_reachability,
    function_called,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inv(*files: tuple) -> Dict[str, Any]:
    """Build a synthetic inventory from ``(path, source)`` pairs."""
    out: List[Dict[str, Any]] = []
    for path, source in files:
        cg = extract_call_graph_python(source).to_dict()
        out.append({
            "path": path,
            "language": "python",
            "call_graph": cg,
        })
    return {"files": out}


# ---------------------------------------------------------------------------
# CALLED — direct-import shapes
# ---------------------------------------------------------------------------


def test_attribute_chain_call_resolves():
    inv = _inv(("src/a.py", "import requests\nrequests.get('/')\n"))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.CALLED
    assert r.evidence == (("src/a.py", 2),)


def test_aliased_module_resolves():
    inv = _inv((
        "src/a.py",
        "import requests.utils as ru\nru.extract_zipped_paths('/')\n",
    ))
    r = function_called(inv, "requests.utils.extract_zipped_paths")
    assert r.verdict == Verdict.CALLED


def test_from_import_aliased_resolves():
    inv = _inv((
        "src/a.py",
        "from requests.utils import extract_zipped_paths as ezp\n"
        "ezp('/')\n",
    ))
    r = function_called(inv, "requests.utils.extract_zipped_paths")
    assert r.verdict == Verdict.CALLED


def test_from_import_no_alias_resolves():
    inv = _inv((
        "src/a.py",
        "from requests import get\nget('/')\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.CALLED


def test_dotted_module_attribute_chain_resolves():
    """``from os import path; path.join(...)`` — aliased to a
    sub-module."""
    inv = _inv((
        "src/a.py",
        "from os import path\npath.join('a', 'b')\n",
    ))
    r = function_called(inv, "os.path.join")
    assert r.verdict == Verdict.CALLED


# ---------------------------------------------------------------------------
# NOT_CALLED
# ---------------------------------------------------------------------------


def test_imported_but_never_called():
    inv = _inv((
        "src/a.py",
        "import requests\nx = 1\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_calls_different_function_in_same_module():
    inv = _inv((
        "src/a.py",
        "import requests\nrequests.post('/')\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_calls_same_tail_in_different_module():
    """Local function ``get`` shadows the queried ``requests.get``;
    chain doesn't resolve to the target."""
    inv = _inv((
        "src/a.py",
        "def get():\n    return 1\nget()\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_empty_inventory():
    r = function_called({"files": []}, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


# ---------------------------------------------------------------------------
# UNCERTAIN — indirection masking
# ---------------------------------------------------------------------------


def test_getattr_with_tail_match_is_uncertain():
    """A file that uses ``getattr`` AND has a call whose tail
    matches the target function name → UNCERTAIN, because the
    getattr could be the call."""
    inv = _inv((
        "src/a.py",
        "import requests\n"
        "def f():\n"
        "    g = getattr(requests, 'get')\n"
        "    g()\n"
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.UNCERTAIN
    assert any(reason == "getattr" for _, reason in r.uncertain_reasons)


def test_getattr_in_unrelated_file_doesnt_taint():
    """File-A has no mention of the target tail name AND uses
    getattr — NOT a confounder. File-B doesn't call the target →
    NOT_CALLED."""
    inv = _inv(
        ("src/a.py", "x = getattr(object(), 'something_else')\n"),
        ("src/b.py", "import requests\nrequests.post('/')\n"),
    )
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_importlib_with_tail_match_is_uncertain():
    inv = _inv((
        "src/a.py",
        "import importlib\n"
        "def f():\n"
        "    m = importlib.import_module('requests')\n"
        "    m.get()\n"
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.UNCERTAIN


def test_dunder_import_with_tail_match_is_uncertain():
    inv = _inv((
        "src/a.py",
        "def f():\n"
        "    m = __import__('requests')\n"
        "    m.get()\n"
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.UNCERTAIN


def test_wildcard_from_unrelated_module_doesnt_taint():
    """``from json import *`` in a file with a `.get(...)` call
    must not taint a query about ``requests.get``."""
    inv = _inv((
        "src/a.py",
        "from json import *\n"
        "x = 1\n"
        "x.get('foo')\n"
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_wildcard_from_same_root_module_is_uncertain():
    """``from requests import *`` then bare ``get(...)`` — wildcard
    plausibly bound ``get``. Conservative: UNCERTAIN."""
    inv = _inv((
        "src/a.py",
        "import requests\n"
        "from requests.utils import *\n"
        "get('/')\n"
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.UNCERTAIN


# ---------------------------------------------------------------------------
# Test-file exclusion
# ---------------------------------------------------------------------------


def test_test_file_excluded_by_default():
    """Mock-style references in tests aren't real calls."""
    inv = _inv((
        "tests/test_thing.py",
        "import requests\nrequests.get('/')\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_test_file_included_when_opted_in():
    inv = _inv((
        "tests/test_thing.py",
        "import requests\nrequests.get('/')\n",
    ))
    r = function_called(inv, "requests.get", exclude_test_files=False)
    assert r.verdict == Verdict.CALLED


def test_conftest_excluded_by_default():
    inv = _inv((
        "conftest.py",
        "import requests\nrequests.get('/')\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


def test_test_suffix_filename_excluded_by_default():
    inv = _inv((
        "src/widget_test.py",
        "import requests\nrequests.get('/')\n",
    ))
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.NOT_CALLED


# ---------------------------------------------------------------------------
# Multiple files
# ---------------------------------------------------------------------------


def test_evidence_lists_all_call_sites_across_files():
    inv = _inv(
        ("src/a.py", "import requests\nrequests.get('/')\n"),
        ("src/b.py", "import requests\n\nrequests.get('/x')\n"),
    )
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.CALLED
    assert set(r.evidence) == {("src/a.py", 2), ("src/b.py", 3)}


def test_one_called_one_uncertain_returns_called():
    """Hard evidence beats indirection. CALLED + UNCERTAIN → CALLED.
    The uncertain reasons are still attached for transparency."""
    inv = _inv(
        ("src/a.py", "import requests\nrequests.get('/')\n"),
        ("src/b.py",
         "import requests\ndef f():\n    g = getattr(requests, 'get')\n    g()\n"),
    )
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.CALLED


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------


def test_bare_function_name_rejected():
    """Querying ``"open"`` is meaningless without a module — the
    resolver can't tell ``builtins.open`` from a local ``open``."""
    import pytest
    with pytest.raises(ValueError):
        function_called({"files": []}, "open")


def test_non_python_files_silently_skipped():
    """Files without a ``call_graph`` field (e.g. JS, Go, C) are
    no-evidence — they don't contribute either way."""
    inv = {
        "files": [
            {"path": "src/a.js", "language": "javascript"},  # no call_graph
            {"path": "src/b.py", "language": "python",
             "call_graph": extract_call_graph_python(
                 "import requests\nrequests.get('/')\n"
             ).to_dict()},
        ]
    }
    r = function_called(inv, "requests.get")
    assert r.verdict == Verdict.CALLED


def test_result_is_immutable():
    """``ReachabilityResult`` is frozen — consumers can stash it
    without defensive-copying."""
    r = function_called({"files": []}, "requests.get")
    import dataclasses
    assert dataclasses.is_dataclass(r)
    import pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.verdict = Verdict.CALLED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Same-file bare-name resolution. Pre-fix the resolver only matched bare
# calls via the import map; same-file calls (where the function isn't
# "imported" because it's defined in the same file) returned NOT_CALLED
# even when callers_of correctly showed the link. Particularly load-
# bearing for C / C++ where there are no symbol-level imports for in-
# file functions — every bare-name same-file C call was a false-negative
# in the high-level API.
# ---------------------------------------------------------------------------


class TestSameFileBareNameResolution:
    def _c_inv(self, path: str, source: str) -> dict:
        # tree-sitter-c isn't declared in requirements.txt (only in a
        # comment) so CI venvs may not have it. Skip the C-flavoured
        # tests when the grammar isn't importable rather than failing
        # — the same mechanism the inventory builder uses to degrade
        # gracefully when the dep is absent.
        import pytest
        pytest.importorskip("tree_sitter_c")
        from core.inventory.call_graph import extract_call_graph_c
        from core.inventory.extractors import extract_items
        items = extract_items(path, "c", source)
        cg = extract_call_graph_c(source).to_dict()
        return {"files": [{
            "path": path, "language": "c",
            "items": [it.to_dict() for it in items],
            "call_graph": cg,
        }]}

    def test_c_bare_name_same_file_resolves(self):
        # Helper function called by another function in the same C
        # file — the dominant shape for static helpers in driver /
        # kernel / library code. Pre-fix this returned NOT_CALLED
        # because C has no symbol-level imports so the import-map
        # path couldn't see the call.
        inv = self._c_inv("c/heartbeat.c",
            "uint16_t read_u16_be(const uint8_t *p) {\n"
            "    return (p[0] << 8) | p[1];\n"
            "}\n"
            "int parse_heartbeat(const uint8_t *buf) {\n"
            "    uint16_t len = read_u16_be(buf);\n"
            "    return len;\n"
            "}\n"
        )
        r = function_called(inv, "c.heartbeat.read_u16_be")
        assert r.verdict == Verdict.CALLED, (
            f"C bare-name same-file call must resolve as CALLED; "
            f"got {r.verdict.value}"
        )
        # Evidence should point at the call site in heartbeat.c.
        assert any("heartbeat.c" in p for p, _ in r.evidence), (
            f"evidence missing the calling file; got {r.evidence}"
        )

    def test_c_bare_name_no_caller_still_not_called(self):
        # Sanity: a same-file def with no caller is still NOT_CALLED.
        # The fast-path doesn't over-fire.
        inv = self._c_inv("c/dead.c",
            "uint16_t orphan(const uint8_t *p) { return p[0]; }\n"
            "int main() { return 0; }\n"  # main doesn't call orphan
        )
        r = function_called(inv, "c.dead.orphan")
        assert r.verdict == Verdict.NOT_CALLED

    def test_python_bare_name_same_file_resolves(self):
        # Python had the same gap. ``helper()`` from another function
        # in the same file pre-fix returned NOT_CALLED via
        # function_called (callers_of was correct via the direct
        # InternalFunction probe, but the high-level API didn't link).
        from core.inventory.call_graph import extract_call_graph_python
        cg = extract_call_graph_python(
            "def helper(): pass\n"
            "def main():\n"
            "    helper()\n"
        ).to_dict()
        inv = {"files": [{
            "path": "src/x.py", "language": "python",
            "items": [
                {"name": "helper", "kind": "function", "line_start": 1},
                {"name": "main", "kind": "function", "line_start": 2},
            ],
            "call_graph": cg,
        }]}
        r = function_called(inv, "src.x.helper")
        assert r.verdict == Verdict.CALLED

    def test_shadowing_import_takes_precedence(self):
        # When the bare name is shadowed by an import, the import-map
        # path is authoritative — the same-file fast-path must NOT
        # fire, otherwise we'd over-report. The fast-path explicitly
        # skips when chain[0] is in imports[].
        from core.inventory.call_graph import extract_call_graph_python
        # x.py imports helper from src.other, defines NO local helper,
        # calls helper() bare. The call resolves to src.other.helper
        # (via the import map), not to anything in x.py.
        cg = extract_call_graph_python(
            "from src.other import helper\n"
            "def main():\n"
            "    helper()\n"
        ).to_dict()
        inv = {"files": [
            {"path": "src/other.py", "language": "python",
             "items": [{"name": "helper", "kind": "function",
                        "line_start": 1}],
             "call_graph": extract_call_graph_python(
                 "def helper(): pass\n"
             ).to_dict()},
            {"path": "src/x.py", "language": "python",
             "items": [{"name": "main", "kind": "function",
                        "line_start": 2}],
             "call_graph": cg},
        ]}
        r = function_called(inv, "src.other.helper")
        # src.other.helper IS called via the bare-name path in x.py
        # (the import map resolves "helper" → "src.other.helper").
        assert r.verdict == Verdict.CALLED, (
            "import-map path must catch the shadowed bare-name call"
        )

    def test_no_module_for_extensionless_path_is_no_op(self):
        # Defensive: a file with no extension can't have a path-
        # derived module, so the fast-path silently doesn't apply.
        # The bare-name call still has no evidence → NOT_CALLED.
        from core.inventory.call_graph import extract_call_graph_c
        inv = {"files": [{
            "path": "scripts/build_helper",  # no extension
            "language": "c",
            "items": [{"name": "helper", "kind": "function",
                       "line_start": 1}],
            "call_graph": extract_call_graph_c(
                "int helper() { return 0; }\n"
                "int main() { helper(); return 0; }\n"
            ).to_dict(),
        }]}
        # Can't form a qualified name for extensionless path —
        # function_called will refuse the query OR return NOT_CALLED.
        # Either is acceptable; just verify no crash.
        try:
            r = function_called(inv, "scripts.build_helper.helper")
            # If query is accepted, the fast-path is a no-op because
            # _file_path_to_module returns None for extensionless.
            assert r.verdict in (Verdict.CALLED, Verdict.NOT_CALLED, Verdict.UNCERTAIN)
        except ValueError:
            pass  # extensionless query rejected — also acceptable


# ---------------------------------------------------------------------------
# U4 — function-like-macro masking (C/C++)
# ---------------------------------------------------------------------------
# Synthetic inventories (no tree-sitter dependency): a C function whose only
# invocation is inside a macro body reads NOT_CALLED in the static graph;
# the macro_call_targets index maps it to UNCERTAIN (FN-safe), never to a
# suppressible NOT_CALLED.


def _c_inv(path: str, calls=None, macro_targets=None) -> Dict[str, Any]:
    return {"files": [{
        "path": path, "language": "c",
        "call_graph": {
            "imports": {}, "calls": calls or [],
            "macro_call_targets": macro_targets or [],
        },
    }]}


def test_macro_masked_function_is_uncertain_not_not_called():
    inv = _c_inv("src/m.c", macro_targets=["f"])
    r = function_called(inv, "src.m.f")
    assert r.verdict == Verdict.UNCERTAIN
    assert any(reason == "func_like_macro" for _, reason in r.uncertain_reasons)


def test_unrelated_macro_leaves_not_called():
    # Macro references `g`, not `f` — targeted, so `f` stays NOT_CALLED.
    inv = _c_inv("src/m.c", macro_targets=["g"])
    assert function_called(inv, "src.m.f").verdict == Verdict.NOT_CALLED


def test_directly_called_beats_macro_masking():
    # Direct call edge to `f` → CALLED wins even if a macro also references it.
    inv = _c_inv(
        "src/m.c",
        calls=[{"chain": ["f"], "line": 9}],
        macro_targets=["f"],
    )
    # Same-file bare-name resolution requires the call's module to match;
    # the macro check must not downgrade a genuine CALLED to UNCERTAIN.
    assert function_called(inv, "src.m.f").verdict == Verdict.CALLED


# ---------------------------------------------------------------------------
# U7 — entry-point forward reachability
# ---------------------------------------------------------------------------
# Synthetic inventories (no tree-sitter): inject visibility + call edges
# directly so the dead-island / entry logic is exercised on any CI.


def _entry_inv(path, language, items, calls, indirection=None):
    cg = {"imports": {}, "calls": calls}
    if indirection:
        cg["indirection"] = indirection
    return {"files": [{
        "path": path, "language": language,
        "items": items, "call_graph": cg,
    }]}


def _fn(name, line, vis=None):
    return {"name": name, "kind": "function", "line_start": line,
            "metadata": {"visibility": vis}}


def _er(inv, path, name, line):
    return entry_reachability(inv, InternalFunction(
        file_path=path, name=name, line=line))


def test_entry_reachable_via_main():
    inv = _entry_inv("app.c", "c",
                     [_fn("main", 1), _fn("helper", 5, "static")],
                     [{"caller": "main", "chain": ["helper"], "line": 2}])
    assert _er(inv, "app.c", "helper", 5) == "reachable"


def test_entry_non_static_is_entry():
    inv = _entry_inv("app.c", "c", [_fn("api", 1)], [])
    assert _er(inv, "app.c", "api", 1) == "reachable"


def test_dead_island_no_path_from_entry():
    # island_a <-> island_b mutually call; both static; no entry reaches.
    inv = _entry_inv(
        "app.c", "c",
        [_fn("island_a", 1, "static"), _fn("island_b", 5, "static")],
        [{"caller": "island_a", "chain": ["island_b"], "line": 2},
         {"caller": "island_b", "chain": ["island_a"], "line": 6}],
    )
    assert _er(inv, "app.c", "island_a", 1) == "no_path_from_entry"
    assert _er(inv, "app.c", "island_b", 5) == "no_path_from_entry"


def test_go_exported_is_entry_unexported_orphan_dead():
    inv = _entry_inv(
        "svc.go", "go",
        [_fn("Handler", 1, "exported"), _fn("helper", 5),
         _fn("orphan", 9)],
        [{"caller": "Handler", "chain": ["helper"], "line": 2}],
    )
    assert _er(inv, "svc.go", "Handler", 1) == "reachable"
    assert _er(inv, "svc.go", "helper", 5) == "reachable"
    assert _er(inv, "svc.go", "orphan", 9) == "no_path_from_entry"


def test_masking_indirection_forces_uncertain():
    # A file with call-masking indirection could hide an entry edge →
    # never claim no_path_from_entry.
    inv = _entry_inv(
        "app.c", "c", [_fn("maybe", 1, "static")], [],
        indirection=["reflect"],
    )
    assert _er(inv, "app.c", "maybe", 1) == "uncertain"


def test_non_closeable_language_is_uncertain():
    # Python's entry model isn't a closed signal (a public fn may be dead
    # app code, not a library API) → uncertain (caller falls back to its
    # 1-hop NOT_CALLED logic), never a confident no_path verdict.
    inv = _entry_inv("m.py", "python", [_fn("_helper", 1)], [])
    assert _er(inv, "m.py", "_helper", 1) == "uncertain"


def _jfn(name, line, attrs=None, vis="public"):
    return {"name": name, "kind": "function", "line_start": line,
            "metadata": {"visibility": vis, "attributes": attrs or []}}


def test_java_servlet_method_is_entry():
    # A servlet handler is framework-dispatched (no in-project caller); it
    # and its callees must read reachable, not surface-demoted as not_called.
    inv = _entry_inv(
        "S.java", "java",
        [_jfn("doPost", 1), _jfn("helper", 5, vis="private")],
        [{"caller": "doPost", "chain": ["helper"], "line": 2}],
    )
    assert _er(inv, "S.java", "doPost", 1) == "reachable"
    assert _er(inv, "S.java", "helper", 5) == "reachable"


def test_java_jaxrs_and_spring_annotations_are_entries():
    inv = _entry_inv(
        "R.java", "java",
        [_jfn("jaxrs", 1, attrs=["GET"]),
         _jfn("spring", 5, attrs=['GetMapping("/y")'])],
        [],
    )
    assert _er(inv, "R.java", "jaxrs", 1) == "reachable"
    assert _er(inv, "R.java", "spring", 5) == "reachable"


def test_java_plain_method_stays_uncertain():
    # A non-servlet, non-annotated Java method isn't a confident entry
    # (Java non-closeable) → uncertain → caller's 1-hop logic, unchanged.
    inv = _entry_inv("P.java", "java", [_jfn("compute", 1)], [])
    assert _er(inv, "P.java", "compute", 1) == "uncertain"


def test_go_init_is_entry():
    # Adversarial FN: Go runs every `func init()` at package load, so init
    # and its callees are reachable even with no explicit caller.
    inv = _entry_inv(
        "p.go", "go", [_fn("init", 1), _fn("setup", 5)],
        [{"caller": "init", "chain": ["setup"], "line": 2}],
    )
    assert _er(inv, "p.go", "init", 1) == "reachable"
    assert _er(inv, "p.go", "setup", 5) == "reachable"


def test_deep_chain_not_truncated_to_no_path():
    # Adversarial FN: a function reachable from an entry via a chain deeper
    # than forward_closure's default depth must NOT read no_path. The entry
    # closure uses a high depth cap; on the off chance it still truncates,
    # the verdict degrades to uncertain (never a false no_path).
    items = [_fn("entry", 1)]
    calls = []
    for k in range(60):
        items.append(_fn(f"f{k}", 10 + k, "static"))
        calls.append({"caller": "entry" if k == 0 else f"f{k - 1}",
                      "chain": [f"f{k}"], "line": 10 + k})
    inv = _entry_inv("d.c", "c", items, calls)
    assert _er(inv, "d.c", "f55", 65) == "reachable"


def test_closeable_langs_derived_from_profiles():
    # _CLOSEABLE_ENTRY_LANGS is derived from PROFILES (entry_model=="sound"),
    # not hand-maintained — pin the membership + the per-language entry rules.
    from core.inventory.reachability import _CLOSEABLE_ENTRY_LANGS, PROFILES
    assert _CLOSEABLE_ENTRY_LANGS == frozenset({"c", "cpp", "go", "rust"})
    for lang in ("c", "cpp", "go", "rust"):
        assert PROFILES[lang].entry_model == "sound", lang
    assert PROFILES["c"].visibility_entry == "non_static"
    assert PROFILES["go"].has_go_init and PROFILES["go"].visibility_entry == "go_exported"
    assert PROFILES["rust"].visibility_entry == "rust_pub"
    assert PROFILES["java"].entry_model == "none" and PROFILES["java"].has_java_web
    assert PROFILES["python"].entry_model == "none"


def test_unknown_language_profile_has_no_entry_signal():
    # A language with no profile (e.g. kotlin) falls back to the default:
    # no visibility entry, entry_model "none" → UNCERTAIN, FN-safe.
    from core.inventory.reachability import _profile
    p = _profile("kotlin")
    assert p.entry_model == "none"
    assert p.visibility_entry == ""
    assert not p.has_go_init and not p.has_java_web


# ---------------------------------------------------------------------------
# Java framework-dispatch entries (_java_framework_entry / _annotation_tail).
# Path-independent: operate on synthetic item dicts, so they run on CI without
# tree-sitter-java. Adding an entry only grows the reachable set, so the key
# guarantees pinned here are the *negatives* — annotations that do NOT denote a
# no-caller entry (@Async / @Transactional) and non-public stereotype methods
# must not be promoted, or live code would never be demoted.
# ---------------------------------------------------------------------------


def _java_item(name, *, attrs=(), class_attrs=(), visibility="public"):
    return {
        "name": name,
        "kind": "function",
        "metadata": {
            "attributes": list(attrs),
            "class_attributes": list(class_attrs),
            "visibility": visibility,
        },
    }


def test_annotation_tail_strips_fqn_args_and_at():
    from core.inventory.reachability import _annotation_tail
    assert _annotation_tail(
        "org.springframework.web.bind.annotation.GetMapping(\"/x\")"
    ) == "GetMapping"
    assert _annotation_tail("@Service") == "Service"
    assert _annotation_tail("EventListener") == "EventListener"


def test_java_servlet_and_method_dispatch_are_entries():
    from core.inventory.reachability import _java_framework_entry
    assert _java_framework_entry("doPost", _java_item("doPost", attrs=()))
    assert _java_framework_entry("on", _java_item("on", attrs=["EventListener"]))
    assert _java_framework_entry("tick", _java_item("tick", attrs=["Scheduled"]))
    assert _java_framework_entry(
        "consume", _java_item("consume", attrs=["KafkaListener"]))
    # fully-qualified annotation form resolves via the tail.
    assert _java_framework_entry(
        "make",
        _java_item("make", attrs=["org.springframework.context.annotation.Bean"]),
    )


def test_java_class_stereotype_promotes_public_methods_only():
    from core.inventory.reachability import _java_framework_entry
    # public method of a @Service bean → container-dispatched entry.
    assert _java_framework_entry(
        "process", _java_item("process", class_attrs=["Service"], visibility="public"))
    assert _java_framework_entry(
        "p2", _java_item("p2", class_attrs=["RestController"], visibility="public static"))
    # private / protected / package-private bean methods are reachable only
    # through the static closure from the public entries → NOT promoted.
    assert not _java_framework_entry(
        "helper", _java_item("helper", class_attrs=["Service"], visibility="private"))
    assert not _java_framework_entry(
        "pp", _java_item("pp", class_attrs=["Component"], visibility=None))


def test_java_jpa_entity_stereotype_promotes_public_methods():
    from core.inventory.reachability import _java_framework_entry
    # @Entity / @Embeddable / @MappedSuperclass public accessors are reached
    # reflectively by the JPA provider / serializer, not via static calls.
    assert _java_framework_entry(
        "getName", _java_item("getName", class_attrs=["Entity"], visibility="public"))
    assert _java_framework_entry(
        "getId", _java_item("getId", class_attrs=["MappedSuperclass"], visibility="public"))
    assert _java_framework_entry(
        "getStreet",
        _java_item("getStreet",
                   class_attrs=["jakarta.persistence.Embeddable"], visibility="public"))
    # a private entity method is not reflectively dispatched → not promoted.
    assert not _java_framework_entry(
        "calcChecksum",
        _java_item("calcChecksum", class_attrs=["Entity"], visibility="private"))


def test_java_jaxb_reflective_serialization_entries():
    from core.inventory.reachability import _java_framework_entry
    # @XmlRootElement / @XmlType class → public accessors marshalled reflectively.
    assert _java_framework_entry(
        "getVetList",
        _java_item("getVetList", class_attrs=["XmlRootElement"], visibility="public"))
    # @XmlElement / @XmlAttribute on a getter → reflectively accessed property,
    # even in a class that isn't itself a root element.
    assert _java_framework_entry(
        "getName", _java_item("getName", attrs=["XmlElement"], visibility="public"))
    assert _java_framework_entry(
        "getId", _java_item("getId", attrs=["XmlAttribute"], visibility="public"))


def test_java_async_transactional_and_plain_are_not_entries():
    from core.inventory.reachability import _java_framework_entry
    # @Async / @Transactional only WRAP a normally-called method (it still has
    # an in-project caller), so they must not be treated as no-caller entries.
    assert not _java_framework_entry("bg", _java_item("bg", attrs=["Async"]))
    assert not _java_framework_entry("wr", _java_item("wr", attrs=["Transactional"]))
    # a plain public method in a non-stereotype class is not an entry.
    assert not _java_framework_entry("dead", _java_item("dead"))


def test_java_framework_entry_degrades_gracefully_on_stale_metadata():
    # A pre-feature checklist.json (reused for an unchanged file) has no
    # ``class_attributes`` key — and a malformed record may have no metadata at
    # all. The entry check must not crash and must not promote (degrades to the
    # existing 1-hop verdict; FN-safe surface-demote, self-heals on rebuild).
    from core.inventory.reachability import _java_framework_entry
    stale = {"name": "process", "kind": "function",
             "metadata": {"attributes": [], "visibility": "public"}}  # no class_attributes
    assert _java_framework_entry("process", stale) is False
    assert _java_framework_entry("x", {"name": "x", "kind": "function"}) is False
    # a recognised method-level annotation still fires on a stale record (the
    # ``attributes`` field predates this feature), so Tier-1 dispatch is robust.
    assert _java_framework_entry(
        "on", {"name": "on", "metadata": {"attributes": ["EventListener"]}})
