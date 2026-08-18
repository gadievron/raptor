"""Wiring tests: the prep phase feeds the peer-group resolver's L1
(binary co-callee) and L4 (type cohort) layers.

resolve_peer_groups has accepted ``binary_edge_index`` and
``type_ref_index`` since the layered resolver landed, but the
prep-phase call site never produced them — both layers were dead in
production. These exercise the real ``_compute_audit_prep`` with

* a warmed per-build-id r2 edge cache + an enriched-inventory
  ``binary_oracle`` block (L1), and
* a Python target whose AST extractor records parameter type
  annotations (L4).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")


def _build_checklist(target: Path, out: Path) -> None:
    env = dict(
        os.environ,
        CLAUDECODE="1",
        _RAPTOR_TRUSTED="1",
        PYTHONPATH=str(_RAPTOR_DIR),
    )
    r = subprocess.run(
        [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"


def _run_prep(target: Path, out: Path):
    from core.audit.orchestrator import (
        OrchestratorConfig,
        _compute_audit_prep,
    )

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )
    prep = _compute_audit_prep(config)
    assert prep is not None
    return prep


# ── L4: type cohort from inventory type annotations ──────────────────

# Two functions with unrelated names — no verb prefix (L5), no paired
# operation (L6), no dispatch table (L2), no domain model (L3) — that
# share one distinctive annotation type. Only the L4 producer can
# group them.
_TYPED_SRC = textwrap.dedent('''\
    class AuthContext:
        """Shared distinctive type."""


    def frobnicate(ctx: AuthContext):
        """One."""
        return ctx


    def quuxify(ctx: AuthContext):
        """Two."""
        return ctx
''')


@pytest.fixture()
def prep_with_typed_inventory(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "authy.py").write_text(_TYPED_SRC)
    out = tmp_path / "out"
    out.mkdir()
    _build_checklist(target, out)
    return _run_prep(target, out)


class TestTypeCohortPeerGroupWiring:
    def test_l4_type_cohort_group_formed(self, prep_with_typed_inventory):
        groups = prep_with_typed_inventory["peer_groups"]
        cohorts = [g for g in groups if g.sibling_type == "type_cohort"]
        assert cohorts, (
            "expected an L4 type-cohort group from the inventory's "
            f"parameter annotations; got {[g.group_id for g in groups]}"
        )
        by_id = {g.group_id: g for g in cohorts}
        assert "type_cohort:AuthContext" in by_id
        members = {
            s.function for s in by_id["type_cohort:AuthContext"].siblings
        }
        assert members == {"frobnicate", "quuxify"}


# ── L1: binary co-callee from the warmed r2 edge cache ───────────────

_C_SRC = textwrap.dedent('''\
    void frob_impl(int x) { (void)x; }
    void quux_impl(int x) { (void)x; }

    int main(void) {
        frob_impl(1);
        quux_impl(2);
        return 0;
    }
''')


@pytest.fixture()
def prep_with_binary_edges(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "prog.c").write_text(_C_SRC)
    out = tmp_path / "out"
    out.mkdir()
    _build_checklist(target, out)

    # Declared binary (as the provenance-filtered enrichment records
    # it) + a warmed per-build-id edge cache — the artifact an
    # /agentic --binary-edges run leaves behind.
    binary = tmp_path / "build" / "prog"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF fake test binary" * 4)

    from core.analysis.binary_oracle_edges import (
        BinaryCallEdge,
        BinaryEdgeIndex,
        _cache_path_for,
        _content_hash,
        _save_cached_index,
    )
    from core.config import RaptorConfig

    monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path / "cache")
    idx = BinaryEdgeIndex(binary_path=str(binary))
    idx.edges = [
        BinaryCallEdge("main", "frob_impl", str(binary)),
        BinaryCallEdge("main", "quux_impl", str(binary)),
    ]
    idx.callees = {"frob_impl", "quux_impl"}
    cache_file = _cache_path_for(_content_hash(binary))
    assert cache_file is not None
    _save_cached_index(cache_file, idx)

    # Inject the binary_oracle block the enrichment pass would have
    # written (full-DWARF tier — the gate the producer insists on).
    checklist_path = out / "checklist.json"
    checklist = json.loads(checklist_path.read_text())
    checklist["binary_oracle"] = {
        "binaries": [
            {"path": str(binary), "build_id": None, "tier": "full"},
        ],
        "counts": {},
        "earns_suppression": True,
        "any_symbol_only": False,
    }
    checklist_path.write_text(json.dumps(checklist))

    return _run_prep(target, out)


class TestBinaryEdgePeerGroupWiring:
    def test_l1_binary_co_callee_group_formed(self, prep_with_binary_edges):
        groups = prep_with_binary_edges["peer_groups"]
        l1 = [
            g for g in groups
            if g.group_id.startswith("binary_co_callee:")
        ]
        assert l1, (
            "expected an L1 binary co-callee group from the warmed "
            f"edge cache; got {[g.group_id for g in groups]}"
        )
        assert l1[0].sibling_type == "co_callee"
        members = {s.function for s in l1[0].siblings}
        assert members == {"frob_impl", "quux_impl"}
