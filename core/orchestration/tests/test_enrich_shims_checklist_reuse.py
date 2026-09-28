"""The context-map enricher shims must reuse ``<workdir>/checklist.json``
as the inventory instead of re-parsing the target tree.

checklist.json is the serialized inventory (``build_checklist`` wraps
``build_inventory`` + ``save_checklist``), so when it carries a
populated ``files`` list the enrichers have everything they need — a
tree re-parse is pure waste (minutes on large targets) and can even
diverge from the run's recorded scope.

Scripts are executed in-process via runpy so collaborating modules can
be monkeypatched, mirroring ``test_libexec_enrich_context_map.py``.
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from core.inventory import build_inventory

REPO_ROOT = Path(__file__).resolve().parents[3]
CALLGRAPH_SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map-callgraph"
AST_VIEW_SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map-ast-view"
COMBINED_SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map"


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A run dir with checklist.json built from a real mini-project,
    whose source files are then DELETED — any tree re-parse yields an
    empty inventory, so enrichment succeeding proves checklist reuse."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.py").write_text(
        "from src.db import run_query\n"
        "def handle_query():\n"
        "    return run_query('SELECT 1')\n",
        encoding="utf-8",
    )
    (target / "src" / "db.py").write_text(
        "def run_query(sql):\n    pass\n", encoding="utf-8",
    )

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    build_inventory(str(target), str(run_dir))

    (run_dir / "context-map.json").write_text(
        json.dumps({
            "entry_points": [
                {"id": "EP-001", "file": "src/app.py", "line": 2},
            ],
        }),
        encoding="utf-8",
    )

    (target / "src" / "app.py").unlink()
    (target / "src" / "db.py").unlink()
    return run_dir


def _forbid_inventory_build(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.inventory import builder

    def _fail(*a: object, **kw: object) -> dict:
        raise AssertionError(
            "build_inventory called: target tree re-parsed despite a "
            "populated checklist.json in the workdir"
        )

    monkeypatch.setattr(builder, "build_inventory", _fail)


def _run_script(
    script: Path, workdir: Path, monkeypatch: pytest.MonkeyPatch,
) -> int:
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", [str(script), str(workdir)])
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0)
    return 0


class TestCallgraphShim:
    def test_enriches_from_checklist_without_tree_reparse(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _forbid_inventory_build(monkeypatch)
        code = _run_script(CALLGRAPH_SCRIPT, workdir, monkeypatch)
        assert code == 0
        cmap = json.loads(
            (workdir / "context-map.json").read_text(encoding="utf-8"))
        fr = cmap["entry_points"][0].get("forward_reachable")
        assert fr is not None, (
            "forward_reachable missing — enrichment did not use the "
            "checklist inventory"
        )
        assert fr["host"] == "src/app.py:handle_query@2"
        assert any("run_query" in n for n in fr["internal_names"])

    def test_passes_checklist_as_inventory_kwarg(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.orchestration.context_map_callgraph as cg

        seen: dict = {}

        def fake_forward(context_map, target_path, *, inventory=None,
                         max_depth=10):
            seen["inventory"] = inventory
            return 0

        monkeypatch.setattr(cg, "enrich_with_forward_reachable",
                            fake_forward)
        monkeypatch.setattr(cg, "enrich_with_call_edges",
                            lambda *a, **kw: 0)
        code = _run_script(CALLGRAPH_SCRIPT, workdir, monkeypatch)
        assert code == 0
        inv = seen["inventory"]
        assert isinstance(inv, dict)
        assert [f["path"] for f in inv["files"]] == [
            "src/app.py", "src/db.py",
        ]


class TestAstViewShim:
    def test_passes_checklist_as_inventory_kwarg(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.orchestration.context_map_ast_view as av

        seen: dict = {}

        def fake_ast(context_map, target_path, *, inventory=None):
            seen["inventory"] = inventory
            return 0

        monkeypatch.setattr(av, "enrich_with_ast_view", fake_ast)
        _forbid_inventory_build(monkeypatch)
        code = _run_script(AST_VIEW_SCRIPT, workdir, monkeypatch)
        assert code == 0
        inv = seen["inventory"]
        assert isinstance(inv, dict)
        assert [f["path"] for f in inv["files"]] == [
            "src/app.py", "src/db.py",
        ]

    def test_empty_files_checklist_falls_back_to_none(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A checklist without a populated ``files`` list must NOT be
        passed as the inventory — the enricher keeps its own fallback."""
        import core.orchestration.context_map_ast_view as av

        # Round-trip through the gated accessors: the frame is
        # MAC-stamped at the write chokepoint, so an in-place json
        # edit reads tampered and the shim refuses the checklist.
        from core.inventory import read_checklist, save_checklist

        checklist = read_checklist(workdir)
        checklist["files"] = []
        save_checklist(workdir, checklist)

        seen: dict = {}

        def fake_ast(context_map, target_path, *, inventory=None):
            seen["inventory"] = inventory
            return 0

        monkeypatch.setattr(av, "enrich_with_ast_view", fake_ast)
        code = _run_script(AST_VIEW_SCRIPT, workdir, monkeypatch)
        assert code == 0
        assert seen["inventory"] is None


class TestInventoryFromChecklist:
    """The shared promotion helper all four enricher shims delegate to."""

    def test_promotes_populated_files(self) -> None:
        from core.orchestration.checklist_inventory import (
            inventory_from_checklist,
        )
        checklist = {"target_path": "/t", "files": [{"path": "a.py"}]}
        assert inventory_from_checklist(checklist) is checklist

    def test_rejects_non_dict_and_missing_or_empty_files(self) -> None:
        from core.orchestration.checklist_inventory import (
            inventory_from_checklist,
        )
        assert inventory_from_checklist(None) is None
        assert inventory_from_checklist([{"path": "a.py"}]) is None
        assert inventory_from_checklist({"target_path": "/t"}) is None
        assert inventory_from_checklist({"files": []}) is None
        assert inventory_from_checklist({"files": "nope"}) is None

    def test_binary_checklist_promoted_and_source_enrichers_noop(
        self, tmp_path: Path,
    ) -> None:
        """Binary checklists DO carry a populated ``files`` list
        (build_binary_checklist), so they get promoted; their items
        carry addresses, not source line ranges, so host resolution
        finds nothing and the source enrichers no-op."""
        from core.orchestration.checklist_inventory import (
            inventory_from_checklist,
        )
        from core.orchestration.context_map_ast_view import (
            enrich_with_ast_view,
        )
        from core.orchestration.context_map_callgraph import (
            enrich_with_forward_reachable,
        )

        binary_checklist = {
            "target_path": str(tmp_path),
            "target_kind": "binary",
            "files": [{
                "path": "firmware.bin",
                "language": "binary",
                "items": [{
                    "name": "parse_hdr",
                    "kind": "function",
                    "address": 4096,
                    "size": 128,
                }],
            }],
        }
        inv = inventory_from_checklist(binary_checklist)
        assert inv is binary_checklist

        cmap = {
            "entry_points": [
                {"id": "EP-1", "file": "firmware.bin", "line": 10},
            ],
            "sinks": [
                {"id": "SINK-1", "file": "firmware.bin", "line": 20},
            ],
        }
        assert enrich_with_forward_reachable(
            cmap, tmp_path, inventory=inv,
        ) == 0
        assert enrich_with_ast_view(cmap, tmp_path, inventory=inv) == 0
        assert "forward_reachable" not in cmap["entry_points"][0]
        assert "ast_view" not in cmap["entry_points"][0]
        assert "ast_view" not in cmap["sinks"][0]


class TestCombinedScript:
    def test_shares_checklist_across_stages(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.iris.api as iris_api
        import core.orchestration.context_map_ast_view as av
        import core.orchestration.context_map_callgraph as cg
        import core.orchestration.context_map_sinks as sinks_mod
        import packages.code_understanding.context_map_sites as sites_mod
        import packages.source_intel as si

        seen: dict = {}

        def fake_forward(context_map, target_path, *, inventory=None,
                         max_depth=10):
            seen["forward_inventory"] = inventory
            return 0

        def fake_ast(context_map, target_path, *, inventory=None):
            seen["ast_inventory"] = inventory
            return 0

        def fake_analyze(target, checklist=None, **kw):
            seen["analyze_checklist"] = checklist
            return object()

        monkeypatch.setattr(cg, "enrich_with_call_edges",
                            lambda *a, **kw: 0)
        monkeypatch.setattr(cg, "enrich_with_forward_reachable",
                            fake_forward)
        monkeypatch.setattr(av, "enrich_with_ast_view", fake_ast)
        monkeypatch.setattr(si, "analyze", fake_analyze)
        monkeypatch.setattr(
            sites_mod, "enrich_context_map_with_sites",
            lambda *a, **kw: {"ownership_model": 0, "privilege_model": 0},
        )
        monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery",
                            lambda *a, **kw: 0)
        monkeypatch.setattr(iris_api, "get_project_sinks",
                            lambda out_dir=None: [])
        _forbid_inventory_build(monkeypatch)

        code = _run_script(COMBINED_SCRIPT, workdir, monkeypatch)
        assert code == 0
        for key in ("forward_inventory", "ast_inventory",
                    "analyze_checklist"):
            inv = seen[key]
            assert isinstance(inv, dict), key
            assert [f["path"] for f in inv["files"]] == [
                "src/app.py", "src/db.py",
            ], key
