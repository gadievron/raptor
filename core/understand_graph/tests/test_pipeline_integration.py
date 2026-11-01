"""Exercise graph integrations at real producer and consumer boundaries."""

import hashlib
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.json import save_json
from core.understand_graph import (
    agentic_graph_groups, fuzz_targets, graph_summary, ingest_agentic_findings,
    ingest_fuzz_evidence, ingest_run, ingest_sca_evidence, ingest_threat_model,
    ingest_web_evidence, open_graph, rebuild_graph, sca_reachability,
)


def _seed(run, target, graph=None):
    target.mkdir(parents=True, exist_ok=True)
    source = target / "server.py"
    source.write_text("def parse(data: bytes):\n    return eval(data)\n")
    (target / "pyproject.toml").write_text('[project]\nname = "fixture"\nversion = "1"\n')
    run.mkdir(parents=True, exist_ok=True)
    save_json(run / "checklist.json", {
        "target_path": str(target), "files": [{
            "path": "server.py", "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "items": [{"kind": "function", "name": "parse", "line_start": 1, "line_end": 2}],
        }],
    })
    save_json(run / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "EP", "name": "parse", "file": "server.py", "line": 1}],
        "sink_details": [{"id": "SK", "name": "eval", "file": "server.py", "line": 2}],
        "unchecked_flows": [{"entry_point": "EP", "sink": "SK", "confidence": "high"}],
        "imports": [{"module": "example-dep", "file": "server.py"}],
    })
    return ingest_run(run, str(target), graph_path=graph)


@pytest.fixture
def project(tmp_path, monkeypatch):
    root, target = tmp_path / "project", tmp_path / "target"
    root.mkdir()
    (root / ".raptor-project-root").touch()
    owner = SimpleNamespace(output_dir=str(root), target=str(target))
    monkeypatch.setattr("core.project.project.ProjectManager.list_projects", lambda self: [owner])
    monkeypatch.setattr("core.project.project.ProjectManager.find_project_for_target",
                        lambda self, path, **kw: owner if str(path) == str(target) else None)
    graph = _seed(root / "understand", target)
    return root, target, graph


def _findings():
    return [{"finding_id": f"F{i}", "rule_id": f"r{i}", "file_path": "server.py",
             "function": "parse", "severity": "high", "message": f"issue {i}"}
            for i in range(2)]


def test_agentic_envelope_and_production_grouping(project):
    root, target, graph = project
    findings = _findings()
    groups = agentic_graph_groups(root / "agentic", str(target), findings)
    assert len(groups) == 1
    assert groups[0]["finding_ids"] == ["F0", "F1"]
    assert groups[0]["criterion"] == "graph_path_hint"
    assert len(findings) == 2 and all("suppressed" not in f for f in findings)
    with open_graph(graph) as conn:
        assert conn.execute("SELECT count(*) FROM edges WHERE kind='AFFECTS'").fetchone()[0] == 2


def test_agentic_groups_inventory_and_sarif_location_shapes(project):
    root, target, _ = project
    findings = _findings()
    findings[0].pop("function")
    findings[0]["metadata"] = {"name": "parse"}
    findings[1].pop("function")
    findings[1]["startLine"] = 2
    findings[1]["file_path"] = str(target / "server.py")
    groups = agentic_graph_groups(root / "agentic", str(target), findings)
    assert groups[0]["finding_ids"] == ["F0", "F1"]


def test_agentic_validation_phase_really_ingests_without_llm(project, monkeypatch):
    from packages.exploitability_validation.agentic import run_validation_phase
    root, target, graph = project
    monkeypatch.setattr("packages.exploitability_validation.agentic.convert_sarif_to_findings",
                        lambda *args: {"findings": _findings()})
    (root / "agentic").mkdir()
    result, count = run_validation_phase(str(target), root / "agentic", [], 2)
    assert count == 2 and result["completed"]
    assert graph_summary(graph)["nodes"]["scan_finding"] == 2
    # The disk-envelope adapter used by raptor.py also reads this format.
    assert ingest_agentic_findings(root / "agentic", str(target)) == graph


def test_sca_query_scopes_target_and_discards_stale_files(project, tmp_path):
    root, target, graph = project
    assert sca_reachability(graph, "example-dep", str(target))
    other = tmp_path / "other"
    _seed(root / "understand-other", other, graph)
    assert sca_reachability(graph, "example-dep", str(target))[0]["entry_point"] == "parse"
    assert sca_reachability(graph, "example-dep", str(tmp_path / "missing")) == []
    (target / "server.py").write_text("# changed since analysis\n")
    assert sca_reachability(graph, "example-dep", str(target)) == []
    assert fuzz_targets(graph, str(target)) == []
    assert agentic_graph_groups(root / "agentic", str(target), _findings()) == []
    assert sca_reachability(graph, "example-dep", str(other))


def test_sca_consumer_retains_mechanical_verdict(project):
    from packages.sca.models import Confidence, Reachability
    from packages.sca.understand_bridge import annotate_graph_reachability
    root, target, _ = project
    dep = SimpleNamespace(name="example-dep", key=lambda: "dep-key")
    reach = Reachability("not_reachable", Confidence("high", "static evidence"), ["static:1"])
    result = annotate_graph_reachability({"dep-key": reach}, [dep], target, root / "sca")
    assert result["dep-key"].verdict == "not_reachable"
    assert result["dep-key"].confidence == reach.confidence
    assert any("graph hint" in e for e in result["dep-key"].evidence)
    assert reach.evidence == ["static:1"]


def test_sca_pipeline_reads_graph_without_sibling_context_json(project, monkeypatch, tmp_path):
    from core.json import load_json, JsonCache
    from packages.sca.pipeline import run_sca, RunOptions
    from packages.sca.tests.test_pipeline import StubHttp

    root, target, graph = project
    cm = load_json(root / "understand" / "context-map.json")
    cm["imports"][0]["module"] = "org.apache.logging.log4j:log4j-core"
    save_json(root / "understand" / "context-map.json", cm)
    ingest_run(root / "understand", str(target))
    (target / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency>'
        '<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>'
        '<version>2.14.1</version></dependency></dependencies></project>')
    # Remove the sibling JSON after ingest: this must use SQLite memory.
    (root / "understand" / "context-map.json").unlink()
    result = run_sca(target=target, output_dir=root / "sca",
                     options=RunOptions(enable_llm_review=False, enable_triage=False),
                     http=StubHttp(), cache=JsonCache(root=tmp_path / "cache"))
    rows = load_json(result.findings_path)
    reach = next(r["sca"]["reachability"] for r in rows
                 if r["vuln_type"] == "sca:vulnerable_dependency")
    assert any("graph hint" in e for e in reach["evidence"])
    assert graph_summary(graph)["nodes"]["dependency"] >= 2


def test_fuzz_plan_selects_source_checked_entry_and_preserves_override(project, monkeypatch):
    from packages.fuzzing.orchestrator import FuzzingOrchestrator
    from packages.fuzzing.tests.test_orchestrator import _full_caps_linux
    root, target, _ = project
    monkeypatch.setitem(sys.modules, "atheris", SimpleNamespace())
    with patch("packages.fuzzing.orchestrator.probe_capabilities", return_value=_full_caps_linux()):
        orch = FuzzingOrchestrator()
    plan = orch.plan(target, run_dir=root / "fuzz")
    assert plan.graph_targets
    assert plan.atheris_entry == "server:parse"
    assert plan.atheris_payload == "bytes"
    explicit = orch.plan(target, run_dir=root / "fuzz", py_entry="server:operator_choice")
    assert explicit.atheris_entry == "server:operator_choice"


def test_fuzz_execution_writes_persistent_evidence(project, monkeypatch):
    from packages.fuzzing.orchestrator import FuzzingOrchestrator
    from packages.fuzzing.tests.test_orchestrator import _full_caps_linux
    root, target, graph = project
    monkeypatch.setitem(sys.modules, "atheris", SimpleNamespace())
    with patch("packages.fuzzing.orchestrator.probe_capabilities", return_value=_full_caps_linux()):
        orch = FuzzingOrchestrator()
    plan = orch.plan(target, run_dir=root / "fuzz")
    plan.can_run = True
    monkeypatch.setattr(orch, "_run_atheris", lambda *args: {"fuzzer": "atheris", "crashes": 1})
    corpus = root / "corpus"
    corpus.mkdir()
    orch.execute(plan, out_dir=root / "fuzz", corpus_dir=corpus, binary_understand=False)
    assert (root / "fuzz" / "fuzzing-result.json").is_file()
    with open_graph(graph) as conn:
        assert conn.execute("SELECT count(*) FROM snapshots WHERE producer='fuzz'").fetchone()[0] == 1


def test_producers_idempotent_imported_and_rebuildable(project):
    root, target, graph = project
    web, fuzz, sca = (root / name for name in ("web", "fuzz", "sca"))
    for run in (web, fuzz, sca):
        run.mkdir()
        save_json(run / ".raptor-run.json", {"target_path": str(target)})
    save_json(web / "web_findings.json", {"findings": [{"id": "W1", "url": "https://example.test/"}]})
    save_json(web / "verified-outcomes.json", {"outcomes": [{"finding_id": "W1", "status": "confirmed"}]})
    save_json(fuzz / "fuzzing-result.json", {"fuzzer": "atheris", "crashes": 1})
    save_json(sca / "findings.json", [{"id": "S1", "sca": {
        "name": "example-dep", "version": "1", "ecosystem": "PyPI",
        "reachability": {"verdict": "imported", "evidence": ["server.py:1"]},
    }}])
    save_json(root / "threat-model.json", {
        "target": str(target), "assets": ["service"], "trust_boundaries": ["HTTP"],
        "threats": [{"id": "T1", "title": "Untrusted input"}],
    })
    for _ in range(2):
        assert ingest_web_evidence(web, str(target)) == graph
        assert ingest_fuzz_evidence(fuzz, str(target)) == graph
        assert ingest_sca_evidence(sca, str(target)) == graph
        assert ingest_threat_model(root, str(target)) == graph
    with open_graph(graph) as conn:
        for lane in ("web", "fuzz", "sca", "threat-model"):
            assert conn.execute("SELECT count(*) FROM snapshots WHERE producer=?", (lane,)).fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM edges WHERE provenance='imported'").fetchone()[0] >= 4
    before = graph_summary(graph)["nodes"]
    assert rebuild_graph(root) == graph
    after = graph_summary(graph)["nodes"]
    for kind in ("asset", "threat", "dependency", "verified_outcome", "tool_verdict"):
        assert after[kind] >= before[kind]


def test_threat_save_is_actual_graph_producer(project):
    from core.threat_model import ThreatModel, save_model
    root, target, graph = project
    model = ThreatModel("test", str(target), threats=[{"id": "T1", "title": "test"}])
    save_model(model, root / "threat-model.json", root / "THREAT_MODEL.md")
    assert graph_summary(graph)["nodes"]["threat"] == 1


def test_missing_or_corrupt_graph_degrades_without_losing_findings(tmp_path, monkeypatch):
    from packages.sca.understand_bridge import annotate_graph_reachability
    from packages.sca.models import Confidence, Reachability
    from core.understand_graph import integration
    graph = tmp_path / "missing.sqlite"
    monkeypatch.setattr("core.understand_graph.graph_path_for_run", lambda *args: graph)
    reach = {"d": Reachability("not_evaluated", Confidence("low", "unknown"))}
    assert annotate_graph_reachability(reach, [], tmp_path, tmp_path) is reach
    graph.write_bytes(b"not sqlite")
    assert fuzz_targets(graph, str(tmp_path)) == []
    findings = _findings()
    monkeypatch.setattr(integration, "ingest_agentic_findings", lambda *args, **kwargs: None)
    assert integration.agentic_graph_groups(tmp_path, str(tmp_path), findings) == []
    assert findings == _findings()


def test_bad_artifacts_are_skipped_without_creating_store(tmp_path):
    save_json(tmp_path / "web_findings.json", {"findings": [None, 3]})
    save_json(tmp_path / "findings.json", [None, {"sca": []}])
    save_json(tmp_path / "fuzzing-result.json", [])
    assert ingest_web_evidence(tmp_path, str(tmp_path)) is None
    assert ingest_sca_evidence(tmp_path, str(tmp_path)) is None
    assert ingest_fuzz_evidence(tmp_path, str(tmp_path)) is None
    assert not (tmp_path / "graph").exists()
