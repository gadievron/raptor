"""The sites-enrichment save/changed gate must count EVERY section.

enrich_context_map_with_sites injects four sections (ownership_model,
privilege_model, shared_state, crypto_inventory) and returns four
counts. Both libexec shims gated saving on a hand-summed TWO of them
— a shared_state/crypto-only target ran the full pass, had the
enrichment injected in memory, then never saved and reported nothing
found. The gate is single-homed in total_enriched_sites now; these
tests pin the gate and the end-to-end save on each previously
discarded section.

Scripts run in-process via runpy so collaborators can be
monkeypatched (mirrors test_libexec_enrich_context_map.py).
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SITES_SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map-sites"
COMBINED_SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map"


class TestTotalEnrichedSites:
    def test_counts_every_section(self):
        from packages.code_understanding.context_map_sites import (
            enrich_context_map_with_sites,
            total_enriched_sites,
        )
        # The gate's domain is exactly the producer's count keys —
        # derive them from a real (empty) producer call so a fifth
        # section can never be silently outside the gate.
        counts = enrich_context_map_with_sites({}, object())
        assert set(counts) == {
            "ownership_model", "privilege_model",
            "shared_state", "crypto_inventory",
        }
        for key in counts:
            assert total_enriched_sites({**counts, key: 2}) == 2, key
        assert total_enriched_sites(counts) == 0


@pytest.fixture
def run_dir(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.c").write_text("int main(void) { return 0; }\n",
                                  encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "context-map.json").write_text(
        json.dumps({"sinks": []}), encoding="utf-8")
    (run_dir / "checklist.json").write_text(
        json.dumps({"target_path": str(target),
                    "files": [{"path": "app.c", "items": []}]}),
        encoding="utf-8")
    return run_dir


def _crypto_only_enrich(cmap, si, *, repo_root=None):
    cmap["crypto_inventory"] = [{"file": "app.c", "line": 3}]
    return {"ownership_model": 0, "privilege_model": 0,
            "shared_state": 0, "crypto_inventory": 1}


def _patch_sites_stage(monkeypatch, enrich_fn):
    import packages.code_understanding.context_map_sites as cms
    import packages.source_intel as si_mod

    monkeypatch.setattr(si_mod, "analyze",
                        lambda *a, **kw: object())
    monkeypatch.setattr(cms, "enrich_context_map_with_sites", enrich_fn)


def _run(script, run_dir, monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", [str(script), str(run_dir)])
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0)
    return 0


class TestSitesShimGate:
    def test_crypto_only_enrichment_is_saved(self, run_dir, monkeypatch):
        _patch_sites_stage(monkeypatch, _crypto_only_enrich)
        assert _run(SITES_SCRIPT, run_dir, monkeypatch) == 0
        saved = json.loads(
            (run_dir / "context-map.json").read_text(encoding="utf-8"))
        assert saved.get("crypto_inventory"), (
            "crypto-only enrichment was discarded by the save gate"
        )

    def test_zero_sections_still_skips_save(self, run_dir, monkeypatch):
        def _none(cmap, si, *, repo_root=None):
            return {"ownership_model": 0, "privilege_model": 0,
                    "shared_state": 0, "crypto_inventory": 0}
        _patch_sites_stage(monkeypatch, _none)
        before = (run_dir / "context-map.json").read_text(encoding="utf-8")
        assert _run(SITES_SCRIPT, run_dir, monkeypatch) == 0
        after = (run_dir / "context-map.json").read_text(encoding="utf-8")
        assert before == after


class TestCombinedShimGate:
    def test_shared_state_only_marks_changed_and_saves(
        self, run_dir, monkeypatch,
    ):
        import core.orchestration.context_map_callgraph as cg
        from core.inventory import builder

        def _zero(*a, **kw):
            return 0

        def _shared_only(cmap, si, *, repo_root=None):
            cmap["shared_state"] = [{"file": "app.c", "line": 1}]
            return {"ownership_model": 0, "privilege_model": 0,
                    "shared_state": 1, "crypto_inventory": 0}

        monkeypatch.setattr(cg, "enrich_with_call_edges", _zero)
        monkeypatch.setattr(cg, "enrich_with_forward_reachable", _zero)
        monkeypatch.setattr(
            builder, "build_inventory",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("stub")),
        )
        _patch_sites_stage(monkeypatch, _shared_only)
        assert _run(COMBINED_SCRIPT, run_dir, monkeypatch) == 0
        saved = json.loads(
            (run_dir / "context-map.json").read_text(encoding="utf-8"))
        assert saved.get("shared_state"), (
            "shared_state-only enrichment lost by the changed gate"
        )
