"""Derived Joern tunables: the central-tuning auto sentinel must
reach JoernTunables as a usable number plus the auto flag, never as
the raw sentinel (a 0 s CPG timeout kills every build instantly)."""

from __future__ import annotations

import core.tuning
from core.tuning import JOERN_CPG_TIMEOUT_DERIVED, Tuning
from packages.joern.tunables import JoernTunables


def _fake_tuning(
    cpg_timeout_s: int, *, heap_derived: bool = False,
) -> Tuning:
    return Tuning(
        codeql_enabled=True,
        codeql_ram_mb=8192, codeql_threads=0,
        codeql_max_disk_cache_mb=0,
        joern_enabled=True,
        joern_heap_mb=2048,
        joern_heap_ceiling_mb=65536,
        joern_cpg_timeout_s=cpg_timeout_s,
        joern_query_timeout_s=300,
        max_semgrep_workers=4, max_codeql_workers=2,
        max_fuzz_parallel=4,
        max_inventory_workers=4, max_json_memo_mb=128,
        joern_heap_mb_derived=heap_derived,
    )


def test_sentinel_becomes_fallback_number_and_auto_flag(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning",
        lambda: _fake_tuning(JOERN_CPG_TIMEOUT_DERIVED),
    )
    t = JoernTunables.from_tuning()
    assert t.cpg_timeout_auto is True
    assert t.cpg_timeout_s == core.tuning.derive_joern_cpg_timeout_s(None)
    assert t.cpg_timeout_s > 0


def test_static_timeout_keeps_value_no_auto_flag(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning", lambda: _fake_tuning(7200),
    )
    t = JoernTunables.from_tuning()
    assert t.cpg_timeout_auto is False
    assert t.cpg_timeout_s == 7200


def test_operator_override_beats_auto(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning",
        lambda: _fake_tuning(JOERN_CPG_TIMEOUT_DERIVED),
    )
    t = JoernTunables.from_tuning(overrides={"cpg_timeout_s": 42})
    assert t.cpg_timeout_auto is False
    assert t.cpg_timeout_s == 42


def test_heap_derivation_flag_propagates(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning",
        lambda: _fake_tuning(300, heap_derived=True),
    )
    assert JoernTunables.from_tuning().heap_is_derived is True


def test_explicit_heap_not_flagged_derived(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning",
        lambda: _fake_tuning(300, heap_derived=False),
    )
    assert JoernTunables.from_tuning().heap_is_derived is False


def test_override_heap_never_flagged_derived(monkeypatch):
    monkeypatch.setattr(
        core.tuning, "get_tuning",
        lambda: _fake_tuning(300, heap_derived=True),
    )
    t = JoernTunables.from_tuning(overrides={"heap_mb": 4096})
    assert t.heap_mb == 4096
    assert t.heap_is_derived is False
