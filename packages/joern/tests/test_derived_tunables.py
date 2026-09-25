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


# ── Build-site resolution ───────────────────────────────────────────

class TestEstimateInScopeSloc:
    def test_sums_source_bytes_over_density(self, tmp_path):
        from packages.joern.runner import (
            _EST_SOURCE_BYTES_PER_LINE,
            estimate_in_scope_sloc,
        )
        (tmp_path / "a.c").write_bytes(b"x" * 640)
        (tmp_path / "b.py").write_bytes(b"y" * 320)
        (tmp_path / "notes.txt").write_bytes(b"z" * 9999)  # not source
        assert estimate_in_scope_sloc(tmp_path) == (
            960 // _EST_SOURCE_BYTES_PER_LINE
        )

    def test_prunes_shared_rule_and_declared_excludes(self, tmp_path):
        from packages.joern.runner import estimate_in_scope_sloc
        (tmp_path / "a.c").write_bytes(b"x" * 3200)
        dot = tmp_path / ".git"
        dot.mkdir()
        (dot / "b.c").write_bytes(b"x" * 32000)
        out = tmp_path / "out"
        out.mkdir()
        (out / "c.c").write_bytes(b"x" * 32000)
        assert estimate_in_scope_sloc(
            tmp_path, exclude_dirs=(str(out),),
        ) == 100

    def test_empty_tree_is_zero(self, tmp_path):
        from packages.joern.runner import estimate_in_scope_sloc
        assert estimate_in_scope_sloc(tmp_path) == 0


class TestResolveCpgTimeout:
    def test_non_auto_passthrough(self, tmp_path):
        from packages.joern.tunables import resolve_cpg_timeout_s
        t = JoernTunables(cpg_timeout_s=7200)
        assert resolve_cpg_timeout_s(t, tmp_path) == 7200

    def test_none_tunables_default(self, tmp_path):
        from packages.joern.tunables import resolve_cpg_timeout_s
        assert resolve_cpg_timeout_s(None, tmp_path) == (
            JoernTunables.cpg_timeout_s
        )

    def test_auto_derives_from_scope_estimate(self, tmp_path, monkeypatch):
        import packages.joern.runner as runner
        from packages.joern.tunables import resolve_cpg_timeout_s
        monkeypatch.setattr(
            runner, "estimate_in_scope_sloc",
            lambda target, exclude_dirs=(): 3_000_000,
        )
        t = JoernTunables(cpg_timeout_s=1800, cpg_timeout_auto=True)
        derived = resolve_cpg_timeout_s(t, tmp_path)
        assert derived >= 2 * 2849  # calibration wall clears with slack

    def test_auto_small_scope_floors(self, tmp_path):
        from packages.joern.tunables import resolve_cpg_timeout_s
        (tmp_path / "a.c").write_bytes(b"x" * 64)
        t = JoernTunables(cpg_timeout_s=1800, cpg_timeout_auto=True)
        assert resolve_cpg_timeout_s(t, tmp_path) == 300

    def test_estimation_failure_degrades_to_base(self, tmp_path, monkeypatch):
        import packages.joern.runner as runner
        from packages.joern.tunables import resolve_cpg_timeout_s

        def boom(target, exclude_dirs=()):
            raise OSError("walk failed")

        monkeypatch.setattr(runner, "estimate_in_scope_sloc", boom)
        t = JoernTunables(cpg_timeout_s=1800, cpg_timeout_auto=True)
        assert resolve_cpg_timeout_s(t, tmp_path) == 1800


class TestSessionUsesResolvedTimeout:
    def test_build_receives_derived_timeout(self, tmp_path):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        import packages.joern as joern_pkg

        (tmp_path / "a.c").write_bytes(b"x" * 64)  # tiny scope → floor
        captured: dict = {}

        def fake_build(*args, **kwargs):
            captured.update(kwargs)
            cpg = MagicMock()
            cpg.exists.return_value = False
            return cpg

        server = MagicMock()
        tunables = JoernTunables(cpg_timeout_s=1800, cpg_timeout_auto=True)
        with patch.object(joern_pkg, "is_available", return_value=True), \
                patch.object(joern_pkg.JoernServer, "from_tunables",
                             return_value=server), \
                patch.object(joern_pkg, "build_cpg_cached",
                             side_effect=fake_build), \
                patch.object(joern_pkg, "build_cpg", side_effect=fake_build):
            with joern_pkg.joern_session(
                Path(tmp_path),
                cache_dir=None,
                tunables=tunables,
                register_reach_audit=False,
            ) as srv:
                assert srv is server
        assert captured.get("timeout") == 300
