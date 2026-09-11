"""Contract tests for the context-map / flow-trace enricher shims.

Every enricher in the family shares the same contracts: writes go
through ``enforce_context_map_budget``, checklist-recovered target
paths are corroborated against the run's sealed metadata, the
checklist is reused as the inventory when it qualifies, sink stages
plumb ``run_dir`` / IRIS ``extra_sinks`` into the substrate, and
best-effort shims never fail the calling pipeline on malformed data.

Scripts are executed in-process via runpy so collaborating modules can
be monkeypatched, mirroring ``test_libexec_enrich_context_map.py``.
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBEXEC = REPO_ROOT / "libexec"
AGGREGATOR = LIBEXEC / "raptor-enrich-context-map"
FRIDA_SHIM = LIBEXEC / "raptor-enrich-context-map-frida"
IMPORTS_SHIM = LIBEXEC / "raptor-enrich-context-map-imports"
SINKS_SHIM = LIBEXEC / "raptor-enrich-context-map-sinks"
MITIGATION_SHIM = LIBEXEC / "raptor-enrich-context-map-mitigation"
FLOW_TRACE_SHIM = LIBEXEC / "raptor-enrich-flow-trace-ast-view"
NORMALIZE_SHIM = LIBEXEC / "raptor-normalize-context-map"


def _run_script(
    script: Path,
    monkeypatch: pytest.MonkeyPatch,
    *args: str,
) -> int:
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", [str(script), *args])
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0)
    return 0


@pytest.fixture
def understand_dir(tmp_path: Path) -> Path:
    """A minimal run dir: context-map + checklist naming a real target."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def main():\n    pass\n",
                                   encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "context-map.json").write_text(
        json.dumps({"entry_points": [], "sinks": [], "sink_details": []}),
        encoding="utf-8")
    (run_dir / "checklist.json").write_text(
        json.dumps({"target_path": str(target), "files": []}),
        encoding="utf-8")
    return run_dir


def _record_budget(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the budget chokepoint with a call recorder.

    Patched on the source module BEFORE runpy executes the shim, so
    the shim's module-level ``from ... import`` binds the recorder.
    """
    import core.artifacts.context_map_budget as cmb

    calls: list = []

    def recorder(context_map: dict, **kw: object) -> list[str]:
        calls.append(context_map)
        return []

    monkeypatch.setattr(cmb, "enforce_context_map_budget", recorder)
    return calls


# ---------------------------------------------------------------------------
# Aggregator: sites stage progress reporting
# ---------------------------------------------------------------------------

def _stub_aggregator_stages(monkeypatch: pytest.MonkeyPatch) -> None:
    import core.iris.api as iris_api
    import core.orchestration.context_map_callgraph as cg
    import core.orchestration.context_map_sinks as sinks_mod
    from core.inventory import builder

    monkeypatch.setattr(cg, "enrich_with_call_edges", lambda *a, **kw: 0)
    monkeypatch.setattr(cg, "enrich_with_forward_reachable",
                        lambda *a, **kw: 0)
    monkeypatch.setattr(
        builder, "build_inventory",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("stubbed")))
    monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery",
                        lambda *a, **kw: 0)
    monkeypatch.setattr(iris_api, "get_project_sinks",
                        lambda out_dir=None: frozenset())


class TestAggregatorSitesProgress:
    def test_sites_stage_reports_progress(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """The combined sites pass must emit a start banner and hand
        analyze() a progress callback — a large C target otherwise
        sits for minutes with zero output."""
        import packages.code_understanding.context_map_sites as cms
        import packages.source_intel as si

        _stub_aggregator_stages(monkeypatch)
        seen: dict = {}

        def fake_analyze(target, checklist=None, progress=None):
            seen["progress"] = progress
            return object()

        monkeypatch.setattr(si, "analyze", fake_analyze)
        monkeypatch.setattr(
            cms, "enrich_context_map_with_sites",
            lambda *a, **kw: {"ownership_model": 0, "privilege_model": 0})

        code = _run_script(AGGREGATOR, monkeypatch, str(understand_dir))
        assert code == 0
        assert callable(seen.get("progress")), (
            "analyze() ran without a progress callback — the sites "
            "stage is silent again on slow targets"
        )
        err = capsys.readouterr().err
        assert "running source_intel" in err


class TestAggregatorSinkRunDir:
    def test_sink_stage_passes_run_dir(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Audit-discovered sinks only merge when the substrate gets
        the run dir — the combined pass must plumb it through."""
        import core.orchestration.context_map_sinks as sinks_mod
        import packages.code_understanding.context_map_sites as cms
        import packages.source_intel as si

        _stub_aggregator_stages(monkeypatch)
        monkeypatch.setattr(
            si, "analyze",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("stub")))
        monkeypatch.setattr(
            cms, "enrich_context_map_with_sites",
            lambda *a, **kw: {"ownership_model": 0, "privilege_model": 0})

        seen: dict = {}

        def fake_sinks(context_map, target_path, *, max_depth=6,
                       run_dir=None, extra_sinks=None):
            seen["run_dir"] = run_dir
            return 0

        monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery",
                            fake_sinks)
        code = _run_script(AGGREGATOR, monkeypatch, str(understand_dir))
        assert code == 0
        assert seen["run_dir"] == understand_dir.resolve()

    def test_sink_stage_tolerates_substrate_without_run_dir(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A substrate revision without ``run_dir`` must still get
        called (no TypeError eaten by the stage handler)."""
        import core.orchestration.context_map_sinks as sinks_mod
        import packages.code_understanding.context_map_sites as cms
        import packages.source_intel as si

        _stub_aggregator_stages(monkeypatch)
        monkeypatch.setattr(
            si, "analyze",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("stub")))
        monkeypatch.setattr(
            cms, "enrich_context_map_with_sites",
            lambda *a, **kw: {"ownership_model": 0, "privilege_model": 0})

        calls: list = []

        def legacy(context_map, target_path, *, max_depth=6,
                   extra_sinks=None):
            calls.append(True)
            return 0

        monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery",
                            legacy)
        code = _run_script(AGGREGATOR, monkeypatch, str(understand_dir))
        assert code == 0
        assert calls, "sink stage never ran against the legacy substrate"


# ---------------------------------------------------------------------------
# Frida shim: budget chokepoint + best-effort robustness
# ---------------------------------------------------------------------------

def _patch_frida_bridge(monkeypatch: pytest.MonkeyPatch, result) -> None:
    bridge = pytest.importorskip("packages.frida.context_bridge")

    if isinstance(result, Exception):
        def fake(ctx, search_dirs, target_path=None):
            raise result
    else:
        def fake(ctx, search_dirs, target_path=None):
            return result

    monkeypatch.setattr(bridge, "enrich_context_map_with_frida", fake)


class TestFridaShim:
    def test_write_goes_through_budget_chokepoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx_path = tmp_path / "context-map.json"
        ctx_path.write_text(json.dumps({"entry_points": []}),
                            encoding="utf-8")
        merged = {"entry_points": [
            {"id": "EP-1", "runtime_confirmed": True},
        ]}
        _patch_frida_bridge(monkeypatch, merged)
        calls = _record_budget(monkeypatch)

        code = _run_script(FRIDA_SHIM, monkeypatch, str(tmp_path))
        assert code == 0
        assert calls == [merged], (
            "context-map written without the budget chokepoint"
        )
        assert json.loads(ctx_path.read_text(encoding="utf-8")) == merged

    def test_non_dict_list_members_do_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """The map is LLM-authored — stray non-dict members in
        entry_points/sink_details must not break the count."""
        ctx_path = tmp_path / "context-map.json"
        ctx_path.write_text(json.dumps({"entry_points": []}),
                            encoding="utf-8")
        merged = {
            "entry_points": [
                "stray-string",
                {"id": "EP-1", "runtime_confirmed": True},
            ],
            "sink_details": [42],
        }
        _patch_frida_bridge(monkeypatch, merged)
        _record_budget(monkeypatch)

        code = _run_script(FRIDA_SHIM, monkeypatch, str(tmp_path))
        assert code == 0
        out = capsys.readouterr().out
        assert "1 entry points/sinks runtime-confirmed" in out

    def test_merge_failure_skips_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Best-effort contract: a substrate crash must not fail the
        calling pipeline, and the map stays untouched."""
        ctx_path = tmp_path / "context-map.json"
        original = json.dumps({"entry_points": []})
        ctx_path.write_text(original, encoding="utf-8")
        _patch_frida_bridge(monkeypatch, RuntimeError("boom"))

        code = _run_script(FRIDA_SHIM, monkeypatch, str(tmp_path))
        assert code == 0
        assert ctx_path.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# Imports shim: budget chokepoint
# ---------------------------------------------------------------------------

class TestImportsShim:
    def test_write_goes_through_budget_chokepoint(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.orchestration.context_map_imports as cmi

        def fake_enrich(context_map: dict, checklist: dict) -> int:
            context_map["imports"] = ["os", "sys"]
            return 2

        monkeypatch.setattr(cmi, "enrich_context_map_imports", fake_enrich)
        calls = _record_budget(monkeypatch)

        code = _run_script(IMPORTS_SHIM, monkeypatch, str(understand_dir))
        assert code == 0
        assert len(calls) == 1, (
            "context-map written without the budget chokepoint"
        )
        data = json.loads(
            (understand_dir / "context-map.json").read_text(
                encoding="utf-8"))
        assert data["imports"] == ["os", "sys"]

    def test_no_imports_means_no_write_and_no_budget_pass(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.orchestration.context_map_imports as cmi

        monkeypatch.setattr(cmi, "enrich_context_map_imports",
                            lambda *a, **kw: 0)
        calls = _record_budget(monkeypatch)

        code = _run_script(IMPORTS_SHIM, monkeypatch, str(understand_dir))
        assert code == 0
        assert calls == []


# ---------------------------------------------------------------------------
# Standalone sinks shim: IRIS extra_sinks parity with the combined pass
# ---------------------------------------------------------------------------

class TestSinksShimIris:
    def _run(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
        iris_result,
    ) -> dict:
        import core.iris.api as iris_api
        import core.orchestration.context_map_sinks as sinks_mod

        seen: dict = {}

        def fake_sinks(context_map, target_path, *, max_depth=6,
                       run_dir=None, extra_sinks=None):
            seen["run_dir"] = run_dir
            seen["extra_sinks"] = extra_sinks
            return 1

        monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery",
                            fake_sinks)
        if isinstance(iris_result, Exception):
            def fake_iris(out_dir=None, target_path=None):
                raise iris_result
        else:
            def fake_iris(out_dir=None, target_path=None):
                return iris_result
        monkeypatch.setattr(iris_api, "get_project_sinks", fake_iris)

        seen["code"] = _run_script(
            SINKS_SHIM, monkeypatch, str(understand_dir))
        return seen

    def test_iris_sinks_reach_the_substrate(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen = self._run(understand_dir, monkeypatch,
                         frozenset({"proj_sink"}))
        assert seen["code"] == 0
        assert seen["extra_sinks"] == frozenset({"proj_sink"})
        assert seen["run_dir"] == understand_dir.resolve()

    def test_iris_failure_does_not_block_sink_discovery(
        self, understand_dir: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen = self._run(understand_dir, monkeypatch,
                         RuntimeError("iris store unavailable"))
        assert seen["code"] == 0
        assert seen["extra_sinks"] is None


# ---------------------------------------------------------------------------
# Flow-trace shim: checklist reused as the inventory
# ---------------------------------------------------------------------------

class TestFlowTraceInventoryReuse:
    def _write_trace(self, run_dir: Path) -> Path:
        trace = run_dir / "flow-trace-001.json"
        trace.write_text(
            json.dumps({"steps": [{"step": 1, "definition": "app.py:1"}]}),
            encoding="utf-8")
        return trace

    def test_populated_checklist_skips_tree_reparse(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import core.orchestration.flow_trace_ast_view as ftav
        from core.inventory import builder

        target = tmp_path / "target"
        target.mkdir()
        (target / "app.py").write_text("def main():\n    pass\n",
                                       encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        checklist = {
            "target_path": str(target),
            "files": [{"path": "app.py", "items": []}],
        }
        (run_dir / "checklist.json").write_text(json.dumps(checklist),
                                                encoding="utf-8")
        self._write_trace(run_dir)

        def forbid_build(*a: object, **kw: object) -> dict:
            raise AssertionError(
                "build_inventory called: target tree re-parsed despite "
                "a populated checklist.json in the workdir"
            )

        monkeypatch.setattr(builder, "build_inventory", forbid_build)

        seen: dict = {}

        def fake_enrich(trace, target_path, *, inventory=None):
            seen["inventory"] = inventory
            return 1

        monkeypatch.setattr(ftav, "enrich_with_ast_view", fake_enrich)
        code = _run_script(FLOW_TRACE_SHIM, monkeypatch, str(run_dir))
        assert code == 0
        inv = seen["inventory"]
        assert isinstance(inv, dict)
        assert [f["path"] for f in inv["files"]] == ["app.py"]

    def test_unqualified_checklist_falls_back_to_tree_build(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A checklist without a populated ``files`` list cannot serve
        as the inventory — the shim must still build one."""
        import core.orchestration.flow_trace_ast_view as ftav
        from core.inventory import builder

        target = tmp_path / "target"
        target.mkdir()
        (target / "app.py").write_text("def main():\n    pass\n",
                                       encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "checklist.json").write_text(
            json.dumps({"target_path": str(target)}), encoding="utf-8")
        self._write_trace(run_dir)

        sentinel = {"files": [{"path": "app.py"}], "built": True}
        monkeypatch.setattr(builder, "build_inventory",
                            lambda *a, **kw: sentinel)

        seen: dict = {}

        def fake_enrich(trace, target_path, *, inventory=None):
            seen["inventory"] = inventory
            return 1

        monkeypatch.setattr(ftav, "enrich_with_ast_view", fake_enrich)
        code = _run_script(FLOW_TRACE_SHIM, monkeypatch, str(run_dir))
        assert code == 0
        assert seen["inventory"] is sentinel


# ---------------------------------------------------------------------------
# Normalize shim: corroborate the checklist-recovered target path
# ---------------------------------------------------------------------------

class TestNormalizeCorroboration:
    def _make_run(self, tmp_path: Path) -> tuple[Path, Path]:
        target = tmp_path / "target"
        target.mkdir()
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "context-map.json").write_text(
            json.dumps({"entry_points": []}), encoding="utf-8")
        (run_dir / "checklist.json").write_text(
            json.dumps({"target_path": str(target)}), encoding="utf-8")
        return run_dir, target

    def test_mismatched_sealed_target_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """A checklist steering normalisation at a different tree than
        the run was sealed against must be refused before any write."""
        run_dir, _target = self._make_run(tmp_path)
        other = tmp_path / "other"
        other.mkdir()
        (run_dir / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(other)}), encoding="utf-8")
        original = (run_dir / "context-map.json").read_text(
            encoding="utf-8")

        code = _run_script(NORMALIZE_SHIM, monkeypatch, str(run_dir))
        assert code == 1
        assert "refusing recovered target" in capsys.readouterr().err
        # No provenance stamp, no rewrite — the file is untouched.
        assert (run_dir / "context-map.json").read_text(
            encoding="utf-8") == original

    def test_matching_sealed_target_normalises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run_dir, target = self._make_run(tmp_path)
        (run_dir / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(target)}), encoding="utf-8")

        code = _run_script(NORMALIZE_SHIM, monkeypatch, str(run_dir))
        assert code == 0
        data = json.loads((run_dir / "context-map.json").read_text(
            encoding="utf-8"))
        assert data.get("provenance"), "map was not stamped/normalised"


# ---------------------------------------------------------------------------
# Mitigation shim: non-object map is bad input (exit 1), not exit 2
# ---------------------------------------------------------------------------

class TestMitigationInputValidation:
    def test_non_object_context_map_is_bad_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        (tmp_path / "context-map.json").write_text("[]", encoding="utf-8")
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF")

        code = _run_script(
            MITIGATION_SHIM, monkeypatch, str(tmp_path),
            "--binary", str(binary),
        )
        assert code == 1
        assert "not a JSON object" in capsys.readouterr().err

    def test_object_context_map_still_enriches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        enricher = pytest.importorskip(
            "packages.code_understanding.mitigation_enricher")
        monkeypatch.setattr(enricher, "enrich_context_map",
                            lambda cm, **kw: cm)
        (tmp_path / "context-map.json").write_text(
            json.dumps({"sinks": []}), encoding="utf-8")
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF")

        code = _run_script(
            MITIGATION_SHIM, monkeypatch, str(tmp_path),
            "--binary", str(binary), "--dry-run",
        )
        assert code == 0
        assert "sinks" in capsys.readouterr().out
