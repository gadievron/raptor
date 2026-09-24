"""Builder persistence of the include layer: fresh-parse
anchoring, SHA-reuse survival, and the pre-edge backfill."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.inventory.include_graph import (
    ARTIFACT_NAME,
    load_include_graph,
)

# ---------------------------------------------------------------------------
# Builder persistence: fresh anchor, SHA-reuse, pre-edge backfill
# ---------------------------------------------------------------------------


class TestBuilderPersistence:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_php")

    def _make_tree(self, tmp_path: Path) -> Path:
        target = tmp_path / "tree"
        (target / "sub").mkdir(parents=True)
        (target / "entry.php").write_text(
            "<?php\ndefine('APP_PATH', './');\n"
            "require_once(APP_PATH . 'sub/lib.php');\n"
            "include 'sub/other.php';\n$x = 1;\n")
        (target / "sub" / "lib.php").write_text(
            "<?php\nfunction lib_fn() { return 1; }\n")
        (target / "sub" / "other.php").write_text("<?php\n$y = 2;\n")
        return target

    def _entry_record(self, out: Path) -> dict:
        inv = json.loads((out / "checklist.json").read_text())
        return next(f for f in inv["files"] if f["path"] == "entry.php")

    def test_fresh_build_persists_edges_and_anchors_literals(
            self, tmp_path):
        from core.inventory.builder import build_inventory
        target = self._make_tree(tmp_path)
        out = tmp_path / "out"
        build_inventory(str(target), str(out), parallel=False)
        cg = self._entry_record(out)["call_graph"]
        assert "includes" in cg and "defines" in cg
        by_shape = {e["shape"]: e for e in cg["includes"]}
        # Anchoring is literal-only: const_prefix resolution is a
        # derivation/walk concern, never a Layer-0 target.
        assert by_shape["const_prefix"].get("target") is None
        assert by_shape["literal"]["target"] == "sub/other.php"

    def test_sha_reuse_keeps_edges(self, tmp_path):
        from core.inventory.builder import build_inventory
        target = self._make_tree(tmp_path)
        out = tmp_path / "out"
        build_inventory(str(target), str(out), parallel=False)
        build_inventory(str(target), str(out), parallel=False)
        cg = self._entry_record(out)["call_graph"]
        assert "includes" in cg
        assert len(cg["includes"]) == 2

    def test_pre_edge_checklist_backfills_on_reuse(self, tmp_path):
        from core.inventory.builder import build_inventory
        target = self._make_tree(tmp_path)
        out = tmp_path / "out"
        build_inventory(str(target), str(out), parallel=False)
        cl_path = out / "checklist.json"
        inv = json.loads(cl_path.read_text())
        fresh_edges = None
        for f in inv["files"]:
            cg = f.get("call_graph")
            if isinstance(cg, dict):
                if f["path"] == "entry.php":
                    fresh_edges = cg.get("includes")
                cg.pop("includes", None)
                cg.pop("defines", None)
                cg.pop("direct_access_guard", None)
        cl_path.write_text(json.dumps(inv))
        build_inventory(str(target), str(out), parallel=False)
        cg = self._entry_record(out)["call_graph"]
        assert cg.get("includes") == fresh_edges
        assert "defines" in cg


class TestBuilderIntegration:
    def test_build_inventory_writes_graph(self, tmp_path):
        pytest.importorskip("tree_sitter_php")
        from core.inventory.builder import build_inventory
        target = tmp_path / "tree"
        (target / "lib").mkdir(parents=True)
        (target / "entry.php").write_text(
            "<?php\ndefine('APP_PATH', './');\n"
            "require_once(APP_PATH . 'lib/shared.php');\n$a = 1;\n")
        (target / "lib" / "shared.php").write_text(
            "<?php\nif (!defined('APP_PATH')) { die(); }\n"
            "function s() { return 1; }\n")
        (target / "modules").mkdir()
        (target / "modules" / "page.mod").write_text("not php\n")
        (target / "dispatch.php").write_text(
            "<?php\ninclude(APP_PATH . \"modules/$page.mod\");\n")
        out = tmp_path / "out"
        build_inventory(str(target), str(out), parallel=False)
        g = load_include_graph(out)
        assert g is not None
        assert g["tier"] == "hint"
        assert g["files"]["lib/shared.php"]["role"] == "library"
        assert g["files"]["lib/shared.php"]["direct_access_guard"] is True
        assert [t["path"] for t in g["unwalked_targets"]] == [
            "modules/page.mod"]

    def test_no_php_no_graph(self, tmp_path):
        from core.inventory.builder import build_inventory
        target = tmp_path / "tree"
        target.mkdir()
        (target / "a.py").write_text("def f():\n    return 1\n")
        out = tmp_path / "out"
        build_inventory(str(target), str(out), parallel=False)
        assert not (out / ARTIFACT_NAME).exists()
