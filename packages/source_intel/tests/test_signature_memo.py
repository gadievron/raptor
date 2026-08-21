"""Per-run signature memo for inventory-freshness checks.

``_lookup_cached_inventory`` recomputes the target signature on every
call (auto-invalidation). Inside a single analyze() run the evidence
parsers issue thousands of ``_enclosing_function`` lookups, each of
which paid a full stat-walk. The memo makes the signature O(1) for the
dynamic extent of one analyze() run and stays completely inactive
outside it, so cross-run staleness detection is untouched.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from packages.source_intel import cache as cache_mod
from packages.source_intel.analyze import (
    _lookup_cached_inventory,
    _register_inventory,
    _with_signature_memo,
    clear_inventory_cache,
)


@pytest.fixture(autouse=True)
def _reset():
    clear_inventory_cache()
    yield
    clear_inventory_cache()


def _counting_patch(calls):
    real = cache_mod.compute_target_signature

    def counting(target):
        calls.append(str(target))
        return real(target)

    return mock.patch.object(
        cache_mod, "compute_target_signature", side_effect=counting,
    )


def test_signature_computed_once_inside_memo_scope(tmp_path):
    (tmp_path / "a.c").write_text("int x;")
    calls: list[str] = []

    @_with_signature_memo
    def run():
        _register_inventory(tmp_path, SimpleNamespace(label="inv"))
        for _ in range(5):
            inv, _target = _lookup_cached_inventory(str(tmp_path / "a.c"))
            assert inv is not None

    with _counting_patch(calls):
        run()

    # One compute at registration; every lookup reused the memo.
    assert len(calls) == 1


def test_lookups_outside_scope_recompute_every_time(tmp_path):
    (tmp_path / "a.c").write_text("int x;")
    calls: list[str] = []

    with _counting_patch(calls):
        _register_inventory(tmp_path, SimpleNamespace(label="inv"))
        for _ in range(3):
            inv, _target = _lookup_cached_inventory(str(tmp_path / "a.c"))
            assert inv is not None

    # 1 at registration + 1 per lookup — no memoisation outside the
    # analyze() scope, so staleness detection between runs still works.
    assert len(calls) == 4


def test_memo_clears_when_outermost_scope_exits(tmp_path):
    (tmp_path / "a.c").write_text("int x;")
    calls: list[str] = []

    @_with_signature_memo
    def run():
        _register_inventory(tmp_path, SimpleNamespace(label="inv"))
        _lookup_cached_inventory(str(tmp_path / "a.c"))

    with _counting_patch(calls):
        run()
        # After the scope exits, a fresh lookup must recompute.
        _lookup_cached_inventory(str(tmp_path / "a.c"))

    assert len(calls) == 2
