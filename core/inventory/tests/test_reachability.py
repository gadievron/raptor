"""Tests for :mod:`core.inventory.reachability`.

These exercise the resolver against synthetic inventory dicts. The
goal is to pin all the import / call-site shapes that arise in
real Python code so a SCA "this CVE function isn't reachable"
verdict means what it claims.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.inventory.call_graph import (
    INDIRECTION_DUNDER_IMPORT,
    INDIRECTION_GETATTR,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_WILDCARD_IMPORT,
    extract_call_graph_python,
)
from core.inventory.reachability import (
    ReachabilityResult,
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
