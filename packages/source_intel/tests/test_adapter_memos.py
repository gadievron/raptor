"""Per-target memoisation in the adapter's verdict helpers.

``gather_prereqs`` is a full spatch run and the pointer-reference
scan reads every C/C++ file under the target; both are invoked per
finding, and finding sets routinely share one sink directory. The
memos are keyed on a stat-only tree signature so an edit recomputes
while repeat lookups on an unchanged tree are free.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import packages.source_intel.adapter as adapter_mod
from packages.source_intel.adapter import (
    _function_referenced_as_pointer,
    _gather_prereqs_cached,
    clear_adapter_memos,
)


class _Facts:
    is_skipped = False
    skipped_reason = None


def test_gather_prereqs_memoised_until_tree_changes(tmp_path):
    (tmp_path / "a.c").write_text("int f(void){return 0;}\n")
    clear_adapter_memos()

    calls = {"n": 0}

    def _stub(target):
        calls["n"] += 1
        return _Facts()

    with patch(
        "packages.coccinelle.prereqs.gather_prereqs", side_effect=_stub,
    ):
        _gather_prereqs_cached(tmp_path)
        _gather_prereqs_cached(tmp_path)
        _gather_prereqs_cached(tmp_path)
        assert calls["n"] == 1

        (tmp_path / "a.c").write_text("int f(void){return 1;}\n")
        os.utime(tmp_path / "a.c", ns=(1, 1))
        _gather_prereqs_cached(tmp_path)
        assert calls["n"] == 2


def test_gather_prereqs_missing_target_never_memoised(tmp_path):
    clear_adapter_memos()
    missing = tmp_path / "nope"

    calls = {"n": 0}

    def _stub(target):
        calls["n"] += 1
        return _Facts()

    with patch(
        "packages.coccinelle.prereqs.gather_prereqs", side_effect=_stub,
    ):
        _gather_prereqs_cached(missing)
        _gather_prereqs_cached(missing)
        assert calls["n"] == 2


def test_pointer_reference_scan_memoised_per_target_and_function(tmp_path):
    (tmp_path / "ops.c").write_text(
        "static int handler(int a) { return a; }\n"
        "struct ops_t my_ops = { .handler = handler, };\n"
    )
    clear_adapter_memos()

    calls = {"n": 0}
    real = adapter_mod._function_referenced_as_pointer_scan

    def _counting(target, fn):
        calls["n"] += 1
        return real(target, fn)

    with patch.object(
        adapter_mod, "_function_referenced_as_pointer_scan", _counting,
    ):
        assert _function_referenced_as_pointer(tmp_path, "handler") is True
        assert _function_referenced_as_pointer(tmp_path, "handler") is True
        assert calls["n"] == 1

        # A different function name is a different memo entry.
        assert _function_referenced_as_pointer(tmp_path, "other") is False
        assert calls["n"] == 2

        # A tree edit invalidates.
        (tmp_path / "ops.c").write_text(
            "static int handler(int a) { return a; }\n"
        )
        os.utime(tmp_path / "ops.c", ns=(1, 1))
        assert _function_referenced_as_pointer(tmp_path, "handler") is False
        assert calls["n"] == 3
