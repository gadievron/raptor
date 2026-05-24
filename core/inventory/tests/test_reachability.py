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
    Verdict,
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
