"""Adversarial checks for the final #810 deployment-preparation changes."""

import hashlib
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from core.json import load_json, save_json
from core.understand_graph import ingest_agentic_findings, ingest_run, open_graph, rebuild_graph
from core.understand_graph.tests.test_pipeline_integration import project as project


def _sarif(uri, *, line=2, logical=False):
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if line is not None:
        location["physicalLocation"]["region"] = {"startLine": line}
    if logical:
        location["logicalLocations"] = [{"kind": "function", "name": "parse"}]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
            "results": [{"ruleId": "test", "message": {"text": "candidate"},
                         "locations": [location]}]}]}


def _run(root, target):
    run = root / "agentic"
    run.mkdir()
    save_json(run / ".raptor-run.json", {"command": "agentic", "target_path": str(target)})
    return run


def _affects(graph):
    with open_graph(graph) as conn:
        return conn.execute("SELECT count(*) FROM edges WHERE kind='AFFECTS'").fetchone()[0]


@pytest.mark.parametrize("uri_kind", ["relative", "absolute"])
@pytest.mark.parametrize("filename", ["server space.py", "server%20.py", "servér.py"])
def test_encoded_sarif_locations_join_inventory_and_rebuild(project, uri_kind, filename):
    root, target, graph = project
    source = target / "server.py"
    dest = target / filename
    source.rename(dest)
    u = root / "understand"
    checklist = load_json(u / "checklist.json")
    checklist["files"][0]["path"] = filename
    checklist["files"][0]["sha256"] = hashlib.sha256(dest.read_bytes()).hexdigest()
    save_json(u / "checklist.json", checklist)
    context = load_json(u / "context-map.json")
    for lane in ("entry_points", "sink_details", "imports"):
        for row in context[lane]:
            row["file"] = filename
    save_json(u / "context-map.json", context)
    ingest_run(u, str(target))
    run = _run(root, target)
    uri = dest.as_uri() if uri_kind == "absolute" else quote(filename)
    save_json(run / "scanner.sarif", _sarif(uri))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1
    assert rebuild_graph(root) == graph
    assert _affects(graph) == 1


@pytest.mark.parametrize("bad", [{"runs": 7}, {"runs": True}])
def test_malformed_sarif_does_not_discard_valid_sibling(project, bad):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "a-bad.sarif", bad)
    save_json(run / "z-good.sarif", _sarif("server.py"))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1


def test_sarif_logical_function_survives_without_optional_region(project):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "scanner.sarif", _sarif("server.py", line=None, logical=True))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1


def test_graph_plan_terminal_text_is_escaped_and_bounded():
    from packages.fuzzing.orchestrator import CampaignPlan
    from packages.fuzzing.tests.test_orchestrator import _full_caps_linux
    plan = CampaignPlan(target=SimpleNamespace(path="target", kind="python-pkg", arch=""),
                        capabilities=_full_caps_linux())
    plan.graph_targets = [{"file": "file\x1b[2J\x07\r\n", "function": "fn\u202e",
                           "dangerous_sink": "sink" + "x" * 10000}]
    summary = plan.summary()
    assert all(c not in summary for c in ("\x1b", "\x07", "\r", "\u202e"))
    assert "...[+" in summary
    assert len(summary) < 1500


@pytest.mark.parametrize("uri", ["./server.py", "sub/../server.py"])
def test_sarif_dot_paths_match_inventory(project, uri):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "scanner.sarif", _sarif(uri))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1


@pytest.mark.parametrize("uri", ["../outside.py", "%2e%2e/outside.py", "file:///etc/passwd",
                                  "file://remote/server.py", "https://remote/server.py"])
def test_sarif_outside_or_nonlocal_paths_never_get_function_links(project, uri):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "scanner.sarif", _sarif(uri, logical=True))
    ingest_agentic_findings(run, str(target))
    assert _affects(graph) == 0


def test_localhost_sarif_uri_matches_local_inventory(project):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "scanner.sarif", _sarif('file://localhost' + str(target / 'server.py')))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1


def test_json_literal_percent_path_is_not_uri_decoded(project):
    root, target, graph = project
    run = _run(root, target)
    save_json(run / "findings.json", [{"id": "literal", "file": "server%2epy", "function": "parse"}])
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 0


def test_bad_uri_does_not_discard_valid_sibling_result(project):
    root, target, graph = project
    run = _run(root, target)
    data = _sarif('file://[invalid/server.py')
    data['runs'][0]['results'].extend(_sarif('server.py')['runs'][0]['results'])
    save_json(run / 'scanner.sarif', data)
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1


def test_sarif_file_budget_is_checked_before_loading(project, monkeypatch, caplog):
    from core.understand_graph import integration
    root, target, graph = project
    run = _run(root, target)
    monkeypatch.setattr(integration, '_SARIF_MAX_FILES', 1)
    save_json(run / 'a.sarif', _sarif('server.py'))
    save_json(run / 'b.sarif', _sarif('server.py'))
    def unexpected_parse(*args, **kwargs):
        pytest.fail('file budget must be checked before loading')
    monkeypatch.setattr('core.sarif.parser.parse_sarif_findings', unexpected_parse)
    assert ingest_agentic_findings(run, str(target)) is None
    assert _affects(graph) == 0
    assert 'file budget exceeded' in caplog.text


def test_sarif_aggregate_record_budget_preserves_prior_evidence(project, monkeypatch, caplog):
    from core.understand_graph import integration
    root, target, graph = project
    run = _run(root, target)
    monkeypatch.setattr(integration, '_SARIF_MAX_FINDINGS', 1)
    save_json(run / 'a.sarif', _sarif('server.py'))
    assert ingest_agentic_findings(run, str(target)) == graph
    assert _affects(graph) == 1
    save_json(run / 'b.sarif', _sarif('server.py'))
    assert ingest_agentic_findings(run, str(target)) is None
    assert _affects(graph) == 1
    assert 'finding budget exceeded' in caplog.text


def test_localhost_uri_does_not_bypass_symlink_containment(project):
    root, target, graph = project
    run = _run(root, target)
    outside = root / 'outside.py'
    outside.write_text('def parse(data):\n    pass\n')
    (target / 'escape.py').symlink_to(outside)
    save_json(run / 'scanner.sarif', _sarif('file://localhost' + str(target / 'escape.py')))
    ingest_agentic_findings(run, str(target))
    with open_graph(graph) as conn:
        assert conn.execute("SELECT count(*) FROM nodes WHERE kind='scan_finding'").fetchone()[0] == 0
