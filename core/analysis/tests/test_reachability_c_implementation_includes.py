"""Included C implementations share static helpers with their wrappers."""

from copy import deepcopy

import pytest

from core.analysis.reachability import InternalFunction, callers_of, callees_of
from core.audit.context import _find_callers


def inventory():
    return {"files": [
        {
            "path": "locking/impl.c", "language": "c",
            "items": [{"name": "helper", "kind": "function", "line_start": 10}],
            "call_graph": {"imports": {}, "calls": []},
        },
        {
            "path": "locking/api.c", "language": "c",
            "items": [{"name": "proxy", "kind": "function", "line_start": 20}],
            "call_graph": {"imports": {"impl": "impl.c"}, "calls": [
                {"caller": "proxy", "chain": ["helper"], "line": 21},
            ]},
        },
    ]}


def test_wrapper_is_a_caller_in_audit_context_and_both_graph_directions():
    data = inventory()
    helper = InternalFunction("locking/impl.c", "helper", 10)
    proxy = InternalFunction("locking/api.c", "proxy", 20)
    assert callers_of(data, helper).definitive == (proxy,)
    assert helper in callees_of(data, proxy).definitive
    assert _find_callers(data, helper.file_path, helper.name, helper.line) == [{
        "file": "locking/api.c", "name": "proxy", "line_start": 20,
    }]


@pytest.mark.parametrize("variation", ["no_include", "header", "non_c", "other_directory"])
def test_bare_name_without_matching_implementation_include_does_not_link(variation):
    data = inventory()
    wrapper = data["files"][1]
    if variation == "no_include":
        wrapper["call_graph"]["imports"] = {}
    elif variation == "header":
        wrapper["call_graph"]["imports"] = {"impl": "impl.h"}
    elif variation == "non_c":
        wrapper["language"] = "python"
    else:
        wrapper["path"] = "other/api.c"
    assert not callers_of(data, InternalFunction("locking/impl.c", "helper", 10)).definitive


def test_local_definition_takes_precedence_over_included_name():
    data = inventory()
    data["files"][1]["items"].append({
        "name": "helper", "kind": "function", "line_start": 1,
    })
    assert not callers_of(data, InternalFunction("locking/impl.c", "helper", 10)).definitive
    assert callers_of(data, InternalFunction("locking/api.c", "helper", 1)).definitive


def test_test_wrapper_exclusion_still_applies():
    data = inventory()
    data["files"][1]["path"] = "locking/test_api.c"
    helper = InternalFunction("locking/impl.c", "helper", 10)
    before = deepcopy(data)
    assert not callers_of(data, helper).definitive
    assert callers_of(data, helper, exclude_test_files=False).definitive
    assert data == before
