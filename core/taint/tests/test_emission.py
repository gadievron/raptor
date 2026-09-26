"""Ground-truth battery for finding emission.

Every expectation is hand-computed. The SARIF shape comes from a
small real source tree through the REAL builder chain (inventory
extractors → package callgraph → route models → seed packs → engine →
emission) — the ``test_paths.py`` plumbing; the artifact-rail
boundaries are pinned at ±1 with synthetic candidates whose byte
sizes are measured, not guessed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_STATIC,
    PackageCallGraph,
    build_package_callgraph,
)
from core.analysis.route_models import RouteModels, build_route_models
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor
from core.sarif.parser import (
    deduplicate_findings,
    parse_sarif_findings,
    validate_sarif,
)
from core.taint.emission import (
    GENERIC_FALLBACK_CWE,
    PRODUCER,
    EmissionLimits,
    EmissionReport,
    emit,
    sarif_bytes,
)
from core.taint.engine import (
    Candidate,
    EngineLimits,
    FrontierRecord,
    Hop,
    PropagationResult,
    propagate,
)
from core.taint.packs import PackSet, default_pack_names, load_packs
from core.taint.paths import AlternativePath, KilledOrigin, Step

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


def _run(
    tmp_path: Path,
    files: dict[str, str],
    packs: PackSet,
    *,
    limits: EngineLimits | None = None,
) -> PropagationResult:
    graph, routes = _build(tmp_path, files)
    return propagate(graph, routes, packs, target_root=tmp_path,
                     limits=limits)


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

#: Same chain with a SECOND command sink in the helper — two
#: candidates, same rule, different sink files/lines (the
#: cross-producer dedup shape).
_TWO_SINKS = dict(_CHAIN)
_TWO_SINKS["app/helpers.py"] = (
    "from .exec_layer import launch\n"
    "import os\n"
    "\n"
    "def prepare(text):\n"
    "    os.system(text)\n"
    "    return launch(text)\n"
)


# ── synthetic-candidate helpers (rail boundaries) ────────────────────


def _step(function: str, file: str, line: int, *, kind: str = "call",
          tier: str = TIER_RESOLVED_STATIC, call_file: str = "",
          call_line: int = 0, excerpt: str = "",
          tags: tuple = (), sanitizers: tuple = (),
          killed: tuple = ()) -> Step:
    return Step(
        function=function, file=file, function_line=line, tier=tier,
        kind=kind, call_file=call_file or file,
        call_line=call_line or line, tags=tags, sanitizers=sanitizers,
        killed_classes=killed, excerpt=excerpt,
    )


def _candidate(*, sink_class: str = "command-injection",
               sink_cwe: str = "CWE-78", spec_tier: str = "pack",
               path_tier: str = TIER_RESOLVED_STATIC,
               function: str = "a.py::f@1", file: str = "a.py",
               sink_line: int = 9, steps: tuple = None,
               alternatives: tuple = (),
               killed_origins: tuple = ()) -> Candidate:
    if steps is None:
        steps = (
            _step(function, file, 1, kind="seed"),
            _step(function, file, 1, kind="sink", call_line=sink_line),
        )
    return Candidate(
        taint_class="user-input",
        source=(("kind", "route_param"), ("handler", function)),
        sink_function=function,
        sink_line=sink_line,
        sink_class=sink_class,
        sink_cwe=sink_cwe,
        sink_match="subprocess.run",
        sink_confidence="exact",
        spec_tier=spec_tier,
        pack="web-injection-core" if spec_tier == "pack" else "",
        hops=(Hop(function=function, tier=path_tier, kind="seed",
                  line=1),),
        path_tier=path_tier,
        steps=steps,
        alternatives=alternatives,
        killed_origins=killed_origins,
    )


def _result(*candidates: Candidate, stats: dict | None = None,
            caps_hit: tuple = (),
            frontier: tuple = ()) -> PropagationResult:
    return PropagationResult(candidates=tuple(candidates),
                             frontier=frontier,
                             caps_hit=caps_hit, stats=stats or {})


def _frontier(callee: str = "unresolved_helper", *,
              function: str = "a.py::f@1", line: int = 5) -> FrontierRecord:
    return FrontierRecord(function=function, line=line, callee=callee,
                          resolution="unresolved",
                          taint_class="user-input")


def _record_size(candidate: Candidate, packs: PackSet) -> int:
    """Measured compact byte size of one candidate's emitted record."""
    rep = emit(_result(candidate), packs)
    assert rep.emitted == 1 and rep.refused == 0
    return rep.artifact_bytes


# ── the 3-file chain: hand-computed SARIF ────────────────────────────


def _flow_location(uri: str, line: int, snippet: str, name: str,
                   message: str, *, kind: str,
                   tainted_param: str = "") -> dict:
    """The expected threadFlow location for one clean chain step."""
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line,
                           "snippet": {"text": snippet}},
            },
            "logicalLocations": [{"kind": "function", "name": name}],
            "message": {"text": message},
        },
        "properties": {
            "tier": TIER_RESOLVED_STATIC,
            "kind": kind,
            "tags": [],
            "sanitizers": [],
            "killed_classes": [],
            "tainted_param": tainted_param,
            "excerpt_truncated": False,
        },
    }


class TestSarifGroundTruth:
    def test_three_file_chain_codeflow_hand_computed(
            self, tmp_path, packs) -> None:
        """route param (views.py) → helper (helpers.py) → sink
        (exec_layer.py): one result, one codeFlow, four threadFlow
        locations — every uri/line/snippet/message/property written
        out by hand."""
        res = _run(tmp_path, _CHAIN, packs)
        assert len(res.candidates) == 1
        rep = emit(res, packs)
        assert rep.emitted == 1 and rep.refused == 0

        result = rep.sarif["runs"][0]["results"][0]
        assert result["codeFlows"] == [{
            "threadFlows": [{
                "locations": [
                    _flow_location(
                        "app/views.py", 7, "def run_cmd(cmd):",
                        "app/views.py::run_cmd@7",
                        "seed: app/views.py::run_cmd@7 taints cmd",
                        kind="seed", tainted_param="cmd"),
                    _flow_location(
                        "app/views.py", 8, "return prepare(cmd)",
                        "app/helpers.py::prepare@3",
                        "call: app/helpers.py::prepare@3 taints text",
                        kind="call", tainted_param="text"),
                    _flow_location(
                        "app/helpers.py", 5, "return launch(staged)",
                        "app/exec_layer.py::launch@3",
                        "call: app/exec_layer.py::launch@3 "
                        "taints payload",
                        kind="call", tainted_param="payload"),
                    _flow_location(
                        "app/exec_layer.py", 4,
                        "subprocess.run(payload, shell=True)",
                        "app/exec_layer.py::launch@3",
                        "sink: app/exec_layer.py::launch@3",
                        kind="sink"),
                ],
            }],
        }]

    def test_result_envelope_hand_computed(self, tmp_path,
                                           packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        result = rep.sarif["runs"][0]["results"][0]
        assert result["ruleId"] == (
            "raptor.taint.crossfile.command-injection.python")
        assert result["level"] == "warning"
        assert result["message"]["text"] == (
            "Cross-file taint candidate: user-input reaches "
            "command-injection sink subprocess.run "
            "(3 hops, path tier resolved_static)")
        assert result["locations"] == [{
            "physicalLocation": {
                "artifactLocation": {"uri": "app/exec_layer.py"},
                "region": {
                    "startLine": 4,
                    "snippet": {
                        "text": "subprocess.run(payload, shell=True)",
                    },
                },
            },
            "logicalLocations": [{
                "kind": "function",
                "name": "app/exec_layer.py::launch@3",
            }],
        }]
        props = result["properties"]
        assert props["detection_tier"] == "candidate"
        assert props["path_tier"] == TIER_RESOLVED_STATIC
        assert props["spec_tier"] == "pack"
        assert props["pack"] == "web-injection-core"
        assert props["cwe"] == "CWE-78"
        assert props["source"]["kind"] == "route_param"

    def test_rule_carries_cwe_and_producer_identity(
            self, tmp_path, packs) -> None:
        """The rule table maps the sink class to its CWE (both the
        properties.cwe form and the external/cwe tag the parser
        reads) and the tool driver is the producer name."""
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        run = rep.sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == PRODUCER
        assert run["tool"]["driver"]["rules"] == [{
            "id": "raptor.taint.crossfile.command-injection.python",
            "shortDescription": {
                "text": "Cross-file taint flow to a "
                        "command-injection sink",
            },
            "properties": {
                "cwe": ["CWE-78"],
                "tags": ["security", "external/cwe/cwe-78"],
            },
        }]

    def test_fingerprint_stable_across_emissions(self, tmp_path,
                                                 packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        fp = lambda rep: (rep.sarif["runs"][0]["results"][0]  # noqa: E731
                          ["partialFingerprints"]["raptorTaintPathId/v1"])
        assert fp(emit(res, packs)) == fp(emit(res, packs))

    def test_emit_never_mutates_the_result(self, tmp_path,
                                           packs) -> None:
        """The rail bounds the ARTIFACT: candidates stay byte-identical
        in memory (pinned against a tiny record cap that sheds flows)."""
        res = _run(tmp_path, _CHAIN, packs)
        before = copy.deepcopy(res.to_dict())
        emit(res, packs, limits=EmissionLimits(max_record_bytes=64))
        assert res.to_dict() == before


# ── round trip through the repo's own SARIF consumers ────────────────


class TestRoundTrip:
    def test_parse_sarif_findings_round_trip(self, tmp_path,
                                             packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        out = tmp_path / "crossfile-taint.sarif"
        out.write_bytes(sarif_bytes(rep))
        assert validate_sarif(out) is not False
        parsed = parse_sarif_findings(out)
        assert len(parsed) == 1
        f = parsed[0]
        assert f["tool"] == PRODUCER
        assert f["rule_id"] == (
            "raptor.taint.crossfile.command-injection.python")
        assert f["cwe_id"] == "CWE-78"
        assert f["file"] == "app/exec_layer.py"
        assert f["startLine"] == 4
        assert f["level"] == "warning"
        assert f["has_dataflow"] is True

    def test_scan_shape_agrees_with_reparse(self, tmp_path,
                                            packs) -> None:
        """The scan-shaped twin's ``dataflow_path`` matches what
        ``extract_dataflow_path`` rebuilds from the SARIF bytes — the
        merge channel and a disk re-parse see the same path, including
        the per-step ``properties`` the parser carries through its
        sanitiser (benign values round-trip unchanged)."""
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        out = tmp_path / "crossfile-taint.sarif"
        out.write_bytes(sarif_bytes(rep))
        parsed = parse_sarif_findings(out)[0]["dataflow_path"]
        twin = rep.findings[0]["dataflow_path"]

        assert twin["source"] == parsed["source"]
        assert twin["sink"] == parsed["sink"]
        assert twin["steps"] == parsed["steps"]
        assert twin["total_steps"] == parsed["total_steps"]
        assert rep.findings[0]["finding_id"].startswith(PRODUCER)

    def test_two_sinks_survive_parse_and_dedup(self, tmp_path,
                                               packs) -> None:
        """Two candidates on the same rule at different sinks emit two
        results that survive the parsed-dedup layer (distinct
        location + fingerprint identity)."""
        res = _run(tmp_path, _TWO_SINKS, packs)
        assert len(res.candidates) == 2
        rep = emit(res, packs)
        out = tmp_path / "crossfile-taint.sarif"
        out.write_bytes(sarif_bytes(rep))
        parsed = parse_sarif_findings(out)
        assert len(deduplicate_findings(parsed)) == 2
        spans = {(f["file"], f["startLine"]) for f in parsed}
        assert spans == {("app/helpers.py", 5), ("app/exec_layer.py", 4)}


# ── CWE coherence ────────────────────────────────────────────────────


class TestCweCoherence:
    def test_learned_sink_maps_through_pack_table(self, packs) -> None:
        """A learned sink carries no CWE — the pack coherence table
        supplies its class's CWE, counted."""
        c = _candidate(sink_cwe="", spec_tier="learned",
                       sink_class="command-injection")
        rep = emit(_result(c), packs)
        assert rep.findings[0]["cwe_id"] == "CWE-78"
        assert rep.stats["cwe_from_coherence_table"] == 1
        assert "cwe_fallback_generic" not in rep.stats

    def test_unmapped_class_gets_counted_generic_fallback(
            self, packs) -> None:
        """CWE is ALWAYS set — a class no pack sink declares falls to
        the generic parent, counted (a CWE-less finding would be
        invisible to the recall matcher). ``user-input`` is real
        vocabulary — declared by pack SOURCES, paired by no pack
        sink — exactly the learned-sink shape that reaches here."""
        c = _candidate(sink_cwe="", spec_tier="learned",
                       sink_class="user-input")
        rep = emit(_result(c), packs)
        assert rep.findings[0]["cwe_id"] == GENERIC_FALLBACK_CWE
        assert rep.stats["cwe_fallback_generic"] == 1
        rule = rep.sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == [GENERIC_FALLBACK_CWE]

    def test_every_emitted_result_carries_a_cwe(self, tmp_path,
                                                packs) -> None:
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs)
        for f in rep.findings:
            assert f["cwe_id"].startswith("CWE-")
        for r in rep.sarif["runs"][0]["results"]:
            assert r["properties"]["cwe"].startswith("CWE-")


class TestTierHonesty:
    def test_sub_static_path_tier_is_note_level(self, packs) -> None:
        c = _candidate(path_tier=TIER_HEURISTIC_DYNAMIC)
        rep = emit(_result(c), packs)
        result = rep.sarif["runs"][0]["results"][0]
        assert result["level"] == "note"
        assert result["properties"]["path_tier"] == (
            TIER_HEURISTIC_DYNAMIC)

    def test_step_tier_and_tags_ride_the_flow_properties(
            self, packs) -> None:
        """M3: consumers see WHICH hop is weak — per-step tier and
        honesty tags serialize into the threadFlow location
        properties, not just the path minimum."""
        steps = (
            _step("a.py::f@1", "a.py", 1, kind="seed"),
            _step("b.py::g@1", "b.py", 3, tier=TIER_HEURISTIC_DYNAMIC,
                  tags=("assumed_propagation", "binding_approx"),
                  sanitizers=("re.match",)),
            _step("b.py::g@1", "b.py", 4, kind="sink"),
        )
        c = _candidate(path_tier=TIER_HEURISTIC_DYNAMIC, steps=steps)
        rep = emit(_result(c), packs)
        locations = (rep.sarif["runs"][0]["results"][0]["codeFlows"][0]
                     ["threadFlows"][0]["locations"])
        weak = locations[1]["properties"]
        assert weak["tier"] == TIER_HEURISTIC_DYNAMIC
        assert weak["tags"] == ["assumed_propagation", "binding_approx"]
        assert weak["sanitizers"] == ["re.match"]

    def test_alternatives_become_extra_codeflows(self, packs) -> None:
        alt_steps = (
            _step("c.py::h@1", "c.py", 1, kind="seed"),
            _step("a.py::f@1", "a.py", 9, kind="sink"),
        )
        alt = AlternativePath(
            source=(("kind", "route_param"),), steps=alt_steps,
            path_tier=TIER_RESOLVED_STATIC)
        c = _candidate(alternatives=(alt,))
        rep = emit(_result(c), packs)
        flows = rep.sarif["runs"][0]["results"][0]["codeFlows"]
        assert len(flows) == 2
        assert flows[1]["threadFlows"][0]["properties"] == {
            "alternative": True,
            "path_tier": TIER_RESOLVED_STATIC,
        }
        dp = rep.findings[0]["dataflow_path"]
        assert len(dp["alternative_paths"]) == 1


# ── the artifact rail, ±1 ────────────────────────────────────────────


class TestNameFieldRail:
    def test_name_at_cap_unchanged(self, packs) -> None:
        limits = EmissionLimits(max_name_field_chars=24)
        name = ("x" * 19) + "::f@1"  # exactly 24 chars
        assert len(name) == 24
        c = _candidate(function=name, file="x" * 19)
        rep = emit(_result(c), packs, limits=limits)
        assert "name_fields_capped" not in rep.stats
        meta = rep.findings[0]["metadata"]
        assert meta["sink_function"] == name

    def test_name_one_over_cap_capped_with_marker(self, packs) -> None:
        """Capped WITH the explicit elision marker, never dropped —
        the marker reports the elided length in raw characters."""
        limits = EmissionLimits(max_name_field_chars=24)
        name = ("x" * 20) + "::f@1"  # 25 chars — one over
        c = _candidate(function=name, file="x" * 20)
        rep = emit(_result(c), packs, limits=limits)
        assert rep.stats["name_fields_capped"] >= 1
        meta = rep.findings[0]["metadata"]
        assert meta["sink_function"] == name[:24] + "...[+1 chars]"

    def test_list_field_one_over_cap_gets_marker_entry(
            self, packs) -> None:
        limits = EmissionLimits(max_list_items=2)
        steps = (
            _step("a.py::f@1", "a.py", 1, kind="seed",
                  sanitizers=("s1", "s2", "s3")),
            _step("a.py::f@1", "a.py", 9, kind="sink"),
        )
        c = _candidate(steps=steps)
        rep = emit(_result(c), packs, limits=limits)
        assert rep.stats["list_fields_capped"] >= 1
        seed_props = (rep.sarif["runs"][0]["results"][0]["codeFlows"][0]
                      ["threadFlows"][0]["locations"][0]["properties"])
        assert seed_props["sanitizers"] == ["s1", "s2", "...[+1 more]"]

    def test_list_field_at_cap_unchanged(self, packs) -> None:
        limits = EmissionLimits(max_list_items=2)
        steps = (
            _step("a.py::f@1", "a.py", 1, kind="seed",
                  sanitizers=("s1", "s2")),
            _step("a.py::f@1", "a.py", 9, kind="sink"),
        )
        rep = emit(_result(_candidate(steps=steps)), packs,
                   limits=limits)
        assert "list_fields_capped" not in rep.stats


class TestRecordRail:
    def _with_alternative(self) -> Candidate:
        alt = AlternativePath(
            source=(("kind", "route_param"),),
            steps=(_step("c.py::h@1", "c.py", 1, kind="seed"),
                   _step("a.py::f@1", "a.py", 9, kind="sink")),
            path_tier=TIER_RESOLVED_STATIC)
        return _candidate(alternatives=(alt,))

    def test_record_within_cap_keeps_all_flows(self, packs) -> None:
        c = self._with_alternative()
        size = _record_size(c, packs)
        rep = emit(_result(c), packs,
                   limits=EmissionLimits(max_record_bytes=size))
        result = rep.sarif["runs"][0]["results"][0]
        assert len(result["codeFlows"]) == 2
        assert "record_capped" not in result["properties"]

    def test_record_one_over_cap_sheds_alternatives_first(
            self, packs) -> None:
        c = self._with_alternative()
        size = _record_size(c, packs)
        rep = emit(_result(c), packs,
                   limits=EmissionLimits(max_record_bytes=size - 1))
        result = rep.sarif["runs"][0]["results"][0]
        assert len(result["codeFlows"]) == 1
        assert result["properties"]["record_capped"] == "alternatives"
        assert rep.stats["record_alternatives_shed"] == 1
        # The scan twin sheds the SAME alternatives — one rail, two
        # shapes.
        assert rep.findings[0]["dataflow_path"]["alternative_paths"] == []
        assert rep.findings[0]["has_dataflow"] is True

    def test_record_far_over_cap_sheds_codeflows_marked(
            self, packs) -> None:
        """Second rung of the ladder: the witness flow goes too, the
        record ships marked — never dropped."""
        c = self._with_alternative()
        rep = emit(_result(c), packs,
                   limits=EmissionLimits(max_record_bytes=1200))
        result = rep.sarif["runs"][0]["results"][0]
        assert "codeFlows" not in result
        assert result["properties"]["record_capped"] == "codeflows"
        assert rep.stats["record_codeflows_shed"] == 1
        assert rep.emitted == 1
        assert rep.findings[0]["has_dataflow"] is False
        assert rep.findings[0]["dataflow_path"] is None

    def test_record_at_the_floor_ships_marked_counted(
            self, packs) -> None:
        """Bottom of the ladder: a cap below the record's bounded
        floor (all fields already capped, nothing left to shed) still
        SHIPS the record — marked ``floor``, counted, real size
        charged to the run budget. Never dropped, never silent."""
        c = self._with_alternative()
        rep = emit(_result(c), packs,
                   limits=EmissionLimits(max_record_bytes=64))
        result = rep.sarif["runs"][0]["results"][0]
        assert result["properties"]["record_capped"] == "floor"
        assert rep.stats["record_over_cap_after_shed"] == 1
        assert rep.emitted == 1 and rep.refused == 0
        assert rep.artifact_bytes > 64  # the REAL size is accounted


class TestRunBudgetRail:
    def _two(self, packs) -> tuple[Candidate, Candidate, int, int]:
        c1 = _candidate(sink_line=9)
        c2 = _candidate(sink_line=11)
        return c1, c2, _record_size(c1, packs), _record_size(c2, packs)

    def test_budget_exactly_fits_both(self, packs) -> None:
        c1, c2, s1, s2 = self._two(packs)
        rep = emit(_result(c1, c2), packs,
                   limits=EmissionLimits(max_artifact_bytes=s1 + s2))
        assert rep.emitted == 2 and rep.refused == 0
        assert "artifact_budget" not in rep.caps_hit
        assert rep.artifact_bytes == s1 + s2

    def test_budget_one_byte_short_refuses_the_tail(
            self, packs) -> None:
        """Refuse-further-records: counted, marked, deterministic —
        and the tail refused is the result's (priority-sorted) tail."""
        c1, c2, s1, s2 = self._two(packs)
        rep = emit(
            _result(c1, c2), packs,
            limits=EmissionLimits(max_artifact_bytes=s1 + s2 - 1))
        assert rep.emitted == 1 and rep.refused == 1
        assert "artifact_budget" in rep.caps_hit
        assert rep.stats["records_refused_budget"] == 1
        assert rep.findings[0]["startLine"] == 9  # head survives
        assert "artifact_budget" in (
            rep.sarif["runs"][0]["properties"]["caps_hit"])

    def test_refusal_is_a_prefix_no_smaller_record_rescue(
            self, packs) -> None:
        """Once the budget binds, EVERY later record is refused even
        if it would fit — deterministic prefix, no knapsack. The
        budget here admits the SMALL record alone, so a knapsack
        would emit it; the prefix rule must not."""
        big_steps = tuple(
            [_step("a.py::f@1", "a.py", 1, kind="seed",
                   excerpt="e" * 150)]
            + [_step(f"m{i}.py::g@1", f"m{i}.py", i + 2,
                     excerpt="e" * 150) for i in range(8)]
            + [_step("z.py::s@1", "z.py", 40, kind="sink")])
        big = _candidate(sink_line=40, steps=big_steps)
        small = _candidate(sink_line=9)
        s_big = _record_size(big, packs)
        s_small = _record_size(small, packs)
        assert s_small < s_big
        rep = emit(_result(big, small), packs,
                   limits=EmissionLimits(max_artifact_bytes=s_big - 1))
        assert rep.emitted == 0 and rep.refused == 2
        assert rep.findings == []
        assert rep.stats["records_refused_budget"] == 2

    def test_candidates_intact_in_memory_after_refusal(
            self, packs) -> None:
        c1, c2, s1, s2 = self._two(packs)
        res = _result(c1, c2)
        before = copy.deepcopy(res.to_dict())
        rep = emit(res, packs,
                   limits=EmissionLimits(max_artifact_bytes=s1))
        assert rep.refused == 1
        assert res.to_dict() == before

    def test_emitted_plus_refused_partitions_candidates(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs,
                   limits=EmissionLimits(max_artifact_bytes=1))
        assert rep.emitted + rep.refused == len(res.candidates)
        assert rep.emitted == 0 and rep.refused == 2


class TestByteAccounting:
    def test_artifact_bytes_are_exact_compact_bytes(
            self, tmp_path, packs) -> None:
        """Enforcement prices what it writes: the accounted bytes
        equal the compact serialized size of the emitted results."""
        from core.json import dumps_artifact
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs)
        recomputed = sum(
            len(dumps_artifact(r, indent=None,
                               ensure_ascii=True).encode("ascii"))
            for r in rep.sarif["runs"][0]["results"])
        assert rep.artifact_bytes == recomputed

    def test_file_bytes_track_the_accounted_budget(
            self, tmp_path, packs) -> None:
        """The whole-file overhead beyond the accounted records is a
        small envelope (driver, rules, separators) — the enforced
        budget approximates real file size, not an abstract number."""
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs)
        envelope = len(sarif_bytes(rep)) - rep.artifact_bytes
        assert 0 < envelope < 4096

    def test_upstream_estimate_rides_beside_the_actual(
            self, tmp_path, packs) -> None:
        """The engine's flag-only measurement arrives in the emission
        stats next to the enforced actual, same order of magnitude on
        the ordinary shape (the upstream signal is a magnitude
        indicator for the to_dict shape, not the SARIF shape)."""
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        upstream = rep.stats["artifact_bytes_estimate_upstream"]
        actual = rep.stats["artifact_bytes_emitted"]
        assert upstream > 0 and actual > 0
        assert 0.2 < actual / upstream < 5.0


class TestFrontierRail:
    def test_frontier_fields_bounded_with_markers(self, packs) -> None:
        """Frontier records carry unbounded target-derived names —
        the twin block bounds them per field like every emitted
        record (capped with the elision marker, never dropped)."""
        limits = EmissionLimits(max_name_field_chars=24)
        long_callee = "z" * 100
        rep = emit(_result(frontier=(_frontier(long_callee),)), packs,
                   limits=limits)
        assert len(rep.frontier) == 1
        record = rep.frontier[0]
        assert record["callee"] == ("z" * 24) + "...[+76 chars]"
        assert record["function"] == "a.py::f@1"
        assert record["derived_from_target"] is True
        assert rep.stats["name_fields_capped"] >= 1

    def test_frontier_bytes_join_the_artifact_accounting(
            self, packs) -> None:
        """The block is priced at exact compact bytes into the SAME
        budget the findings use — accounted, never free."""
        c = _candidate()
        rep_no = emit(_result(c), packs)
        rep = emit(_result(c, frontier=(_frontier(), _frontier(line=9))),
                   packs)
        assert len(rep.frontier) == 2
        fb = rep.stats["frontier_bytes_emitted"]
        assert fb > 0
        assert rep.artifact_bytes == rep_no.artifact_bytes + fb
        from core.json import dumps_artifact
        recomputed = sum(
            len(dumps_artifact(r, indent=None,
                               ensure_ascii=True).encode("ascii"))
            for r in rep.frontier)
        assert fb == recomputed

    def test_frontier_refused_past_budget_counted_marked(
            self, packs) -> None:
        """±1: a budget that exactly fits the finding refuses the
        whole frontier tail — counted + marked, findings intact."""
        c = _candidate()
        finding_bytes = _record_size(c, packs)
        rep = emit(
            _result(c, frontier=(_frontier(), _frontier(line=9))),
            packs,
            limits=EmissionLimits(max_artifact_bytes=finding_bytes))
        assert rep.emitted == 1  # the finding always wins the budget
        assert rep.frontier == []
        assert rep.stats["frontier_refused_budget"] == 2
        assert "artifact_budget" in rep.caps_hit
        assert rep.stats["frontier_bytes_emitted"] == 0

    def test_frontier_budget_exact_fit_boundary(self, packs) -> None:
        c = _candidate()
        base = emit(_result(c, frontier=(_frontier(),)), packs)
        need = base.artifact_bytes
        fits = emit(_result(c, frontier=(_frontier(),)), packs,
                    limits=EmissionLimits(max_artifact_bytes=need))
        assert len(fits.frontier) == 1
        assert "frontier_refused_budget" not in fits.stats
        short = emit(_result(c, frontier=(_frontier(),)), packs,
                     limits=EmissionLimits(max_artifact_bytes=need - 1))
        assert short.frontier == []
        assert short.stats["frontier_refused_budget"] == 1

    def test_frontier_never_displaces_a_finding(self, packs) -> None:
        """Findings are priced FIRST: a frontier flood can only cap
        its own block."""
        c = _candidate()
        finding_bytes = _record_size(c, packs)
        flood = tuple(_frontier(f"callee_{i}", line=i + 1)
                      for i in range(200))
        rep = emit(_result(c, frontier=flood), packs,
                   limits=EmissionLimits(
                       max_artifact_bytes=finding_bytes + 512))
        assert rep.emitted == 1 and rep.refused == 0
        assert rep.stats["frontier_refused_budget"] > 0
        assert len(rep.frontier) + rep.stats[
            "frontier_refused_budget"] == 200


class TestKilledOriginsRail:
    def _origins(self, n: int) -> tuple:
        return tuple(
            KilledOrigin(sink_class=f"class-{i}", step=0,
                         sanitizers=(f"san_{i}",))
            for i in range(n))

    def test_origins_at_cap_unchanged(self, packs) -> None:
        limits = EmissionLimits(max_list_items=2)
        c = _candidate(killed_origins=self._origins(2))
        rep = emit(_result(c), packs, limits=limits)
        origins = (rep.sarif["runs"][0]["results"][0]["properties"]
                   ["killed_origins"])
        assert len(origins) == 2
        assert all(isinstance(o, dict) for o in origins)
        assert "list_fields_capped" not in rep.stats

    def test_origins_one_over_cap_get_marker_entry(self, packs) -> None:
        """The one list that shipped uncapped — now under the same
        item cap as every sibling."""
        limits = EmissionLimits(max_list_items=2)
        c = _candidate(killed_origins=self._origins(3))
        rep = emit(_result(c), packs, limits=limits)
        origins = (rep.sarif["runs"][0]["results"][0]["properties"]
                   ["killed_origins"])
        assert len(origins) == 3
        assert origins[2] == "...[+1 more]"
        assert rep.stats["list_fields_capped"] >= 1


class TestPrimaryLocationGuard:
    def test_zero_sink_line_omits_region(self, tmp_path, packs) -> None:
        """SARIF startLine must be >= 1 — a zero line ships the
        location without a region (mirrors the flow-location guard),
        never a fabricated span."""
        c = _candidate(sink_line=0, steps=())
        rep = emit(_result(c), packs)
        location = rep.sarif["runs"][0]["results"][0]["locations"][0]
        assert "region" not in location["physicalLocation"]
        out = tmp_path / "zero.sarif"
        out.write_bytes(sarif_bytes(rep))
        parsed = parse_sarif_findings(out)
        assert parsed[0]["startLine"] is None
        assert rep.findings[0]["startLine"] is None

    def test_real_sink_line_keeps_region(self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        rep = emit(res, packs)
        region = (rep.sarif["runs"][0]["results"][0]["locations"][0]
                  ["physicalLocation"]["region"])
        assert region["startLine"] == 4


# ── honesty surface ──────────────────────────────────────────────────


class TestHonestySurface:
    def test_no_refutation_vocabulary_in_emitted_keys(
            self, tmp_path, packs) -> None:
        """The no-refutation pin extended to the emission boundary:
        neither the SARIF document nor the scan-shaped findings spell
        an absence claim in any key."""
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs)
        forbidden = ("refut", "disproven", "suppress", "clean",
                     "no_flow", "not_vulnerable", "is_dead",
                     "ruled_out", "safe", "false_positive",
                     "baselinestate", "justification")

        def walk_keys(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield k
                    yield from walk_keys(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from walk_keys(v)

        for doc in (rep.sarif, {"findings": rep.findings},
                    {"frontier": rep.frontier}):
            for key in walk_keys(doc):
                for bad in forbidden:
                    assert bad not in key.lower(), key

    def test_no_suppression_fields_on_any_result(
            self, tmp_path, packs) -> None:
        """Zero-suppression-surface pin: results carry no
        suppressions member (SARIF's own suppression channel stays
        untouched) and the detection tier is always candidate."""
        res = _run(tmp_path, _TWO_SINKS, packs)
        rep = emit(res, packs)
        for result in rep.sarif["runs"][0]["results"]:
            assert "suppressions" not in result
            # SARIF's own absence-claim channels stay unused: no
            # baselineState (absent/updated claims), no result-level
            # kind (whose non-"fail" values grade the result), no
            # justification member.
            assert "baselineState" not in result
            assert "kind" not in result
            assert "justification" not in result
            assert result["properties"]["detection_tier"] == "candidate"
        assert "suppressions" not in rep.sarif["runs"][0]
        for f in rep.findings:
            assert f["metadata"]["detection_tier"] == "candidate"

    def test_killed_annotations_stay_annotations(self, packs) -> None:
        """Killed-class provenance is VISIBLE (per-step and on the
        result) but never a verdict: the candidate still emits at
        full level with its flows."""
        ko = KilledOrigin(sink_class="sql-injection", step=0,
                          sanitizers=("shlex.quote",))
        steps = (
            _step("a.py::f@1", "a.py", 1, kind="seed",
                  killed=("sql-injection",)),
            _step("a.py::f@1", "a.py", 9, kind="sink"),
        )
        c = _candidate(steps=steps, killed_origins=(ko,))
        rep = emit(_result(c), packs)
        result = rep.sarif["runs"][0]["results"][0]
        assert result["level"] == "warning"
        assert result["properties"]["killed_origins"] == [{
            "sink_class": "sql-injection", "step": 0,
            "sanitizers": ["shlex.quote"],
        }]
        assert "codeFlows" in result

    def test_sarif_bytes_are_pure_ascii(self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        data = sarif_bytes(emit(res, packs))
        assert all(b < 128 for b in data)
        json.loads(data)

    def test_report_defaults_are_empty_not_none(self) -> None:
        rep = EmissionReport()
        assert rep.findings == [] and rep.stats == {}
        assert rep.emitted == 0 and rep.refused == 0
