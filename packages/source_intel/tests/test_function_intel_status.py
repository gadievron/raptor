"""Tests for the function_intel_status() invariant.

Per design strict invariant: never fabricate; explicitly report
``name_not_in_tree`` when PR-4 prereqs ran but didn't see the
function name.
"""

from __future__ import annotations

import shutil

import pytest

from packages.source_intel.analyze import SourceIntelResult, analyze


def test_status_unknown_when_no_target():
    r = SourceIntelResult()  # no target set
    assert r.function_intel_status("anything") == "unknown"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_status_in_tree_for_defined_function(tmp_path):
    src = tmp_path / "x.c"
    src.write_text(
        "int defined_fn(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.function_intel_status("defined_fn") == "in_tree"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_status_name_not_in_tree_for_undefined(tmp_path):
    src = tmp_path / "x.c"
    src.write_text(
        "int real_fn(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.function_intel_status("not_in_this_file") == "name_not_in_tree"
