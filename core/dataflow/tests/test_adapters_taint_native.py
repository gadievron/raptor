"""Battery for the cross-file taint → :class:`Finding` adapter.

The adapter consumes the taint emission's SARIF results — the rail-
bounded records — so the ground truth here runs the REAL chain
(builder plumbing → engine → emission) and pins the converted
:class:`Finding` fields by hand, plus the JSON round trip and the
degrade paths the taint step contract makes reachable (empty
location fields, flow-less records)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    PackageCallGraph,
    build_package_callgraph,
)
from core.analysis.route_models import RouteModels, build_route_models
from core.dataflow.adapters.taint_native import (
    PRODUCER,
    from_emission_report,
    from_sarif_result,
    make_finding_id,
)
from core.dataflow.finding import Finding
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor
from core.taint.emission import EmissionLimits, emit
from core.taint.engine import propagate
from core.taint.packs import PackSet, default_pack_names, load_packs

# ── fixture plumbing (real builders end to end) ──────────────────────


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(default_pack_names())


def _record(rel: str, content: str) -> dict:
    items = [i.to_dict() for i in PythonExtractor().extract(rel, content)]
    return {
        "path": rel,
        "language": "python",
        "items": items,
        "call_graph": extract_call_graph_python(content).to_dict(),
    }


def _build(root: Path, files: dict[str, str]) -> tuple[
        PackageCallGraph, RouteModels]:
    records = []
    for rel, content in sorted(files.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        records.append(_record(rel, content))
    inventory = {"files": records}
    graph = build_package_callgraph(inventory)
    return graph, build_route_models(inventory, graph)


_CHAIN = {
    "app/__init__.py": "",
    "app/exec_layer.py": (
        "import subprocess\n"
        "\n"
        "def launch(payload):\n"
        "    subprocess.run(payload, shell=True)\n"
        "    return None\n"
    ),
    "app/views.py": (
        "from flask import Flask\n"
        "from .helpers import prepare\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/run/<cmd>')\n"
        "def run_cmd(cmd):\n"
        "    return prepare(cmd)\n"
    ),
    "app/helpers.py": (
        "from .exec_layer import launch\n"
        "\n"
        "def prepare(text):\n"
        "    staged = 'prefix-' + text\n"
        "    return launch(staged)\n"
    ),
}


@pytest.fixture(scope="module")
def chain_report(tmp_path_factory, packs):
    tmp = tmp_path_factory.mktemp("taint-adapter")
    graph, routes = _build(tmp, _CHAIN)
    res = propagate(graph, routes, packs, target_root=tmp)
    return emit(res, packs)


def _result_of(report) -> dict:
    return report.sarif["runs"][0]["results"][0]


# ── ground truth ─────────────────────────────────────────────────────


class TestGroundTruth:
    def test_three_file_chain_finding_hand_computed(
            self, chain_report) -> None:
        finding = from_sarif_result(_result_of(chain_report))
        assert finding is not None
        assert finding.producer == PRODUCER
        assert finding.rule_id == (
            "raptor.taint.crossfile.command-injection.python")
        assert finding.source.file_path == "app/views.py"
        assert finding.source.line == 7
        assert finding.source.snippet == "def run_cmd(cmd):"
        assert finding.source.label == "source"
        assert finding.sink.file_path == "app/exec_layer.py"
        assert finding.sink.line == 4
        assert finding.sink.snippet == (
            "subprocess.run(payload, shell=True)")
        assert finding.sink.label == "sink"
        assert [(s.file_path, s.line, s.label)
                for s in finding.intermediate_steps] == [
            ("app/views.py", 8, "step"),
            ("app/helpers.py", 5, "step"),
        ]

    def test_finding_id_stable_and_producer_prefixed(
            self, chain_report) -> None:
        a = from_sarif_result(_result_of(chain_report))
        b = from_sarif_result(_result_of(chain_report))
        assert a.finding_id == b.finding_id
        assert a.finding_id.startswith(f"{PRODUCER}_")
        assert a.finding_id == make_finding_id(
            a.rule_id, a.source, a.sink)

    def test_raw_preserves_the_emitted_record(self, chain_report) -> None:
        """Round-trip fidelity: the producer record rides whole in
        ``raw`` — per-step tier/tag properties included."""
        result = _result_of(chain_report)
        finding = from_sarif_result(result)
        assert finding.raw == dict(result)
        step_props = (finding.raw["codeFlows"][0]["threadFlows"][0]
                      ["locations"][0]["properties"])
        assert step_props["tier"] == "resolved_static"
        assert step_props["kind"] == "seed"

    def test_from_emission_report_walks_all_results(
            self, chain_report) -> None:
        findings = from_emission_report(chain_report)
        assert len(findings) == 1
        assert all(isinstance(f, Finding) for f in findings)


class TestRoundTrip:
    def test_finding_json_round_trip(self, chain_report) -> None:
        finding = from_sarif_result(_result_of(chain_report))
        clone = Finding.from_json(finding.to_json())
        assert clone.to_dict() == finding.to_dict()
        assert clone.source == finding.source
        assert clone.sink == finding.sink
        assert clone.intermediate_steps == finding.intermediate_steps

    def test_reparsed_raw_reconverts_identically(
            self, chain_report) -> None:
        """Corpus replay: converting the preserved ``raw`` again
        yields the same finding — the adapter is a pure function of
        the emitted record."""
        finding = from_sarif_result(_result_of(chain_report))
        again = from_sarif_result(finding.raw)
        assert again.to_dict() == finding.to_dict()


# ── degrade paths (the taint step contract's honest-empty forms) ─────


def _flow_result(locations: list[dict]) -> dict:
    return {
        "ruleId": "raptor.taint.crossfile.command-injection.python",
        "message": {"text": "m"},
        "codeFlows": [{"threadFlows": [{"locations": locations}]}],
    }


def _loc(uri: str, line: int) -> dict:
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": uri},
        "region": {"startLine": line},
    }}}


class TestDegrades:
    def test_flowless_result_is_none(self) -> None:
        assert from_sarif_result({"ruleId": "r",
                                  "message": {"text": "m"}}) is None

    def test_record_capped_result_is_none_not_error(
            self, tmp_path, packs) -> None:
        """A record whose codeFlows were shed by the emission rail is
        a location-only record — skipped, never raised."""
        graph, routes = _build(tmp_path, _CHAIN)
        res = propagate(graph, routes, packs, target_root=tmp_path)
        rep = emit(res, packs,
                   limits=EmissionLimits(max_record_bytes=1200))
        assert "codeFlows" not in _result_of(rep)
        assert from_sarif_result(_result_of(rep)) is None
        assert from_emission_report(rep) == []

    def test_unlocated_source_or_sink_is_none(self) -> None:
        assert from_sarif_result(
            _flow_result([_loc("", 0), _loc("b.py", 2)])) is None
        assert from_sarif_result(
            _flow_result([_loc("a.py", 1), _loc("", 0)])) is None

    def test_unlocated_intermediate_dropped_counted(self) -> None:
        finding = from_sarif_result(_flow_result(
            [_loc("a.py", 1), _loc("", 0), _loc("b.py", 2)]))
        assert finding is not None
        assert finding.intermediate_steps == ()
        assert finding.raw["adapter_steps_dropped_unlocated"] == 1

    def test_single_location_flow_is_none(self) -> None:
        assert from_sarif_result(_flow_result([_loc("a.py", 1)])) is None


class TestHonestySurface:
    def test_no_refutation_vocabulary_on_the_finding(
            self, chain_report) -> None:
        finding = from_sarif_result(_result_of(chain_report))
        forbidden = ("refut", "disproven", "suppress", "clean",
                     "no_flow", "not_vulnerable", "is_dead",
                     "ruled_out")

        def walk_keys(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield k
                    yield from walk_keys(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from walk_keys(v)

        for key in walk_keys(finding.to_dict()):
            for bad in forbidden:
                assert bad not in key.lower(), key
