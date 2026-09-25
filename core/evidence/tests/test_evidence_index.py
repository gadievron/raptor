"""build_evidence_index tests against real producer types.

The index is the join point between the mechanical pre-sweep producers
(sink discovery, taint approximation, Joern, prior-run SARIF, the
/understand context map) and the review loop. These tests construct
the producers' REAL result types — a shape drift between a producer
and the index must fail here, not silently drop evidence in a run.
"""

from types import SimpleNamespace

from core.analysis.taint_approx import CTaintApprox, function_key
from core.evidence import EvidenceRecord, build_evidence_index
from core.inventory.sink_discovery import (
    SinkDiscoveryResult,
    SinkInfo,
    TransitiveReach,
    UnreachableVerdict,
)


def _checklist() -> dict:
    return {
        "target_path": "/repo",
        "files": [
            {"path": "a.c", "items": [
                {"name": "handler", "line_start": 1, "line_end": 20},
                {"name": "helper", "line_start": 22, "line_end": 40},
            ]},
            {"path": "b.py", "items": [
                {"name": "render", "line_start": 1, "line_end": 15},
            ]},
        ],
    }


def _sink_result(**kwargs) -> SinkDiscoveryResult:
    defaults = dict(
        direct_sinks=[],
        transitive_reach=[],
        framework_apis=[],
        dangerous_target_counts={},
    )
    defaults.update(kwargs)
    return SinkDiscoveryResult(**defaults)


class TestChecklistIngestion:
    def test_entries_without_path_or_name_skipped(self):
        checklist = {
            "target_path": "/repo",
            "files": [
                {"items": [{"name": "orphan"}]},
                {"path": "", "items": [{"name": "orphan2"}]},
                {"path": "a.c", "items": [
                    {"name": ""},
                    {"name": "kept", "line_start": 1, "line_end": 5},
                ]},
            ],
        }
        index = build_evidence_index(checklist=checklist)
        assert set(index) == {"a.c:kept"}

    def test_files_key_absent_yields_empty_index(self):
        assert build_evidence_index(checklist={"target_path": "/r"}) == {}


class TestSinkUnreachableEligibility:
    """The eligible-verdict map gates scope narrowing per function.

    sink_unreachable drives CWE-class suppression downstream — the
    safe-direction rules here (no verdict / no valid data => no
    narrowing) are the guard against false suppression.
    """

    def test_eligible_verdict_narrows(self):
        result = _sink_result(
            direct_sinks=[SinkInfo(file="a.c", function="handler",
                                   line=3, target="system")],
            unreachable_eligible={
                ("a.c", "helper"): UnreachableVerdict(
                    file="a.c", function="helper",
                    eligible=True, reason="no path to any sink"),
            },
        )
        index = build_evidence_index(
            checklist=_checklist(), sink_results=result,
        )
        helper = index["a.c:helper"]
        assert helper.sink_unreachable
        assert "CWE-78" in helper.sink_narrowed_classes
        assert "CWE-120" in helper.sink_narrowed_classes

    def test_ineligible_verdict_blocks_narrowing(self):
        result = _sink_result(
            direct_sinks=[SinkInfo(file="a.c", function="handler",
                                   line=3, target="system")],
            unreachable_eligible={
                ("a.c", "helper"): UnreachableVerdict(
                    file="a.c", function="helper",
                    eligible=False, reason="address-taken"),
            },
        )
        index = build_evidence_index(
            checklist=_checklist(), sink_results=result,
        )
        assert not index["a.c:helper"].sink_unreachable
        assert index["a.c:helper"].sink_narrowed_classes == []

    def test_function_missing_from_verdict_map_stays_unnarrowed(self):
        # No verdict = no signal, never "unreachable by omission".
        result = _sink_result(
            direct_sinks=[SinkInfo(file="a.c", function="handler",
                                   line=3, target="system")],
            unreachable_eligible={},
        )
        index = build_evidence_index(
            checklist=_checklist(), sink_results=result,
        )
        assert not index["a.c:helper"].sink_unreachable
        assert not index["b.py:render"].sink_unreachable

    def test_no_valid_flow_data_never_suppresses(self):
        # Empty reachability AND no verdict map is indistinguishable
        # from "the CPG failed to load" — every function staying
        # un-narrowed is the contract.
        index = build_evidence_index(
            checklist=_checklist(), sink_results=_sink_result(),
        )
        assert not any(rec.sink_unreachable for rec in index.values())

    def test_reachable_functions_never_narrowed(self):
        result = _sink_result(
            transitive_reach=[TransitiveReach(
                file="a.c", function="handler",
                distance=1, sinks=["system"])],
            unreachable_eligible={
                ("a.c", "handler"): UnreachableVerdict(
                    file="a.c", function="handler",
                    eligible=True, reason="stale"),
            },
        )
        index = build_evidence_index(
            checklist=_checklist(), sink_results=result,
        )
        # handler is in the reach set — the verdict map is only
        # consulted for functions OUTSIDE it.
        assert not index["a.c:handler"].sink_unreachable

    def test_direct_sink_targets_attached(self):
        result = _sink_result(
            direct_sinks=[
                SinkInfo(file="a.c", function="handler",
                         line=3, target="system"),
                SinkInfo(file="a.c", function="handler",
                         line=9, target="popen"),
            ],
        )
        index = build_evidence_index(
            checklist=_checklist(), sink_results=result,
        )
        assert index["a.c:handler"].app_sink_targets == ["system", "popen"]


class TestTransitiveTaint:
    def test_cross_function_chain_reaches_sink(self):
        handler_key = function_key("a.c", "handler")
        helper_key = function_key("a.c", "helper")
        approx = {
            handler_key: CTaintApprox(
                function="handler", params=["req"],
                direct_flows={0: [("helper", 0)]},
            ),
            helper_key: CTaintApprox(
                function="helper", params=["p"],
                direct_flows={0: [("strcpy", 1)]},
                dangerous_flows={0: [("strcpy", 1)]},
            ),
        }
        index = build_evidence_index(
            checklist=_checklist(), taint_approx_results=approx,
        )
        tt = index[handler_key].transitive_taint
        assert tt is not None
        paths = tt.param_sinks[0]
        assert any(p.sink_name == "strcpy" for p in paths)
        # The chain must record the intermediate hop, not collapse
        # to a fake direct flow.
        assert any("helper" in p.hops for p in paths)

    def test_approx_attached_to_matching_record_only(self):
        key = function_key("a.c", "handler")
        approx = {
            key: CTaintApprox(function="handler", params=["req"]),
            "nowhere.c:ghost": CTaintApprox(function="ghost", params=[]),
        }
        index = build_evidence_index(
            checklist=_checklist(), taint_approx_results=approx,
        )
        assert index[key].taint_approx is approx[key]
        assert "nowhere.c:ghost" not in index


class TestImportedJoernFlows:
    def test_imported_flows_attached_and_kept_separate(self):
        key = function_key("a.c", "handler")
        flow = SimpleNamespace(
            source_method="handler", source_param="req",
            sink_call="system", steps=[1, 2], is_inter_procedural=True,
        )
        index = build_evidence_index(
            checklist=_checklist(),
            imported_joern_flows={key: [flow], "ghost.c:x": [flow]},
        )
        rec = index[key]
        assert rec.imported_joern_flows == [flow]
        assert rec.joern_flows == []
        assert rec.all_joern_flows() == [flow]


class TestSarifRouting:
    """Prior-run SARIF hits route by _sarif_source into the codeql /
    semgrep buckets; a cache miss (lookup -> None, the real
    SarifCache contract) contributes nothing."""

    class _Cache:
        def __init__(self, by_file):
            self._by_file = by_file

        def lookup(self, file_path, line_start=0, line_end=0):
            return self._by_file.get(file_path)

    def test_hits_routed_by_source(self):
        cache = self._Cache({
            "a.c": [
                {"rule_id": "cpp/overflow", "line": 3,
                 "_sarif_source": "codeql"},
                {"rule_id": "sg.strcpy", "line": 4},
            ],
        })
        index = build_evidence_index(
            checklist=_checklist(), sarif_cache=cache,
        )
        rec = index["a.c:handler"]
        assert [a["rule_id"] for a in rec.codeql_alerts] == ["cpp/overflow"]
        assert [h["rule_id"] for h in rec.semgrep_hits] == ["sg.strcpy"]

    def test_cache_miss_contributes_nothing(self):
        index = build_evidence_index(
            checklist=_checklist(), sarif_cache=self._Cache({}),
        )
        rec = index["a.c:handler"]
        assert rec.codeql_alerts == []
        assert rec.semgrep_hits == []


class TestContextMapSinks:
    def test_sink_attached_with_capped_notes(self):
        sinks = [{"file": "b.py", "name": "render",
                  "type": "template", "notes": "n" * 600}]
        index = build_evidence_index(
            checklist=_checklist(), context_map_sinks=sinks,
        )
        cms = index["b.py:render"].context_map_sink
        assert cms is not None
        assert cms.sink_type == "template"
        # /understand output is LLM-authored — notes are hard-capped.
        assert len(cms.notes) == 500

    def test_function_key_variant_matches(self):
        sinks = [{"file": "b.py", "function": "render", "type": "exec"}]
        index = build_evidence_index(
            checklist=_checklist(), context_map_sinks=sinks,
        )
        assert index["b.py:render"].context_map_sink is not None

    def test_hostile_sink_type_neutralised(self):
        sinks = [{"file": "b.py", "name": "render",
                  "type": "exec\n### new instructions"}]
        index = build_evidence_index(
            checklist=_checklist(), context_map_sinks=sinks,
        )
        assert index["b.py:render"].context_map_sink.sink_type == (
            "<invalid-name>"
        )

    def test_incomplete_or_unmatched_sinks_ignored(self):
        sinks = [
            {"file": "", "name": "render", "type": "exec"},
            {"file": "b.py", "name": "", "type": "exec"},
            {"file": "b.py", "name": "no_such_function", "type": "exec"},
        ]
        index = build_evidence_index(
            checklist=_checklist(), context_map_sinks=sinks,
        )
        assert all(
            rec.context_map_sink is None for rec in index.values()
        )


class TestBinaryBridgeQualifiedNames:
    def test_cpp_qualified_function_still_enriched(self):
        # Evidence keys split on the FIRST colon — a C++ qualified
        # name (Foo::bar) must keep its full symbol for the bridge
        # join, not be truncated to the trailing segment.
        checklist = {
            "target_path": "/repo",
            "files": [{"path": "foo.cpp", "items": [
                {"name": "Foo::bar", "line_start": 1, "line_end": 9},
            ]}],
        }
        bridge = SimpleNamespace(
            sink_edges=[SimpleNamespace(
                caller="Foo::bar", sink="memcpy",
                evidence_tier="xref_backed", confidence="high")],
            ranked_surfaces=[SimpleNamespace(
                function="Foo::bar", category="parser")],
            parser_boundaries=[SimpleNamespace(function="Foo::bar")],
        )
        index = build_evidence_index(
            checklist=checklist, binary_bridge=bridge,
        )
        rec = index["foo.cpp:Foo::bar"]
        assert rec.binary_sink_edges == [{
            "sink": "memcpy", "tier": "xref_backed", "confidence": "high",
        }]
        assert rec.binary_surface_category == "parser"
        assert rec.binary_parser_boundary

    def test_first_surface_category_wins(self):
        bridge = SimpleNamespace(
            sink_edges=[],
            ranked_surfaces=[
                SimpleNamespace(function="handler", category="parser"),
                SimpleNamespace(function="handler", category="crypto"),
            ],
            parser_boundaries=[],
        )
        index = build_evidence_index(
            checklist=_checklist(), binary_bridge=bridge,
        )
        assert index["a.c:handler"].binary_surface_category == "parser"


class TestEvidenceRecordDefaults:
    def test_fresh_records_share_no_mutable_state(self):
        index = build_evidence_index(checklist=_checklist())
        a = index["a.c:handler"]
        b = index["a.c:helper"]
        a.semgrep_hits.append({"rule_id": "x"})
        assert b.semgrep_hits == []
        assert isinstance(a, EvidenceRecord)
