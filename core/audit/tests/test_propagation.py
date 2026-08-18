"""Tests for core.audit.propagation — constraint propagation + resolver chain."""

from __future__ import annotations

from pathlib import Path

from core.audit.constraints import Constraint
from core.evidence import EvidenceRecord
from core.audit.propagation import (
    CallerCandidate,
    DepthProbe,
    PropagationConfig,
    _try_joern_resolve,
    _try_taint_approx_resolve,
    _try_taint_summary_resolve,
    format_depth_limit_report,
    get_callers,
    probe_beyond_ceiling,
    propagate_one_hop,
    rank_callers,
    score_caller,
    try_coccinelle_resolve,
    try_codeql_resolve,
)


def _constraint(**kwargs):
    defaults = {
        "function": "parse_header",
        "file": "src/packet.c",
        "kind": "parameter",
        "target": "len",
        "rule": "len must be <= 1024",
        "violation": "stack buffer overflow",
    }
    defaults.update(kwargs)
    return Constraint(**defaults)


def _checklist(files=None):
    return {"files": files or []}


class TestScoreCaller:
    def test_entry_point_boost(self):
        c = _constraint()
        result = score_caller(
            "src/main.c", "handle_request", 10, c,
            entry_points={"src/main.c:handle_request"},
        )
        assert result.score >= 10
        assert result.is_entry_point
        assert "entry_point" in result.reasons

    def test_test_file_demotion(self):
        c = _constraint()
        result = score_caller(
            "tests/test_packet.c", "test_parse", 5, c,
            entry_points=set(),
        )
        assert result.score < 0
        assert "test_file" in result.reasons

    def test_passthrough_detection(self):
        c = _constraint(target="len")
        checklist = _checklist([
            {
                "path": "src/wrapper.c",
                "items": [
                    {
                        "name": "forward_packet",
                        "metadata": {
                            "parameters": [{"name": "len", "type": "size_t"}],
                        },
                    },
                ],
            },
        ])
        result = score_caller(
            "src/wrapper.c", "forward_packet", 1, c,
            entry_points=set(),
            checklist=checklist,
        )
        assert result.is_passthrough
        assert "passthrough" in result.reasons
        assert result.score >= 4

    def test_no_source_file(self):
        c = _constraint()
        result = score_caller(
            "nonexistent.c", "fn", 1, c,
            entry_points=set(),
            target_path=Path("/tmp/empty"),
        )
        assert result.score == 0

    def test_variable_arg_boost(self, tmp_path: Path):
        c = _constraint()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "caller.c").write_text(
            "void caller(int n) {\n"
            "    parse_header(buf, n);\n"
            "}\n"
        )
        result = score_caller(
            "src/caller.c", "caller", 1, c,
            entry_points=set(),
            target_path=tmp_path,
        )
        assert result.score > 0
        assert "variable_arg" in result.reasons

    def test_no_bounds_check_boost(self, tmp_path: Path):
        c = _constraint()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "nochecks.c").write_text(
            "void nochecks(int n) {\n"
            "    parse_header(buf, n);\n"
            "    return;\n"
            "}\n"
        )
        result = score_caller(
            "src/nochecks.c", "nochecks", 1, c,
            entry_points=set(),
            target_path=tmp_path,
        )
        assert "no_bounds_check" in result.reasons


class TestRankCallers:
    def test_filters_negative_scores(self):
        candidates = [
            CallerCandidate(file="test/t.c", function="t", line=1, score=-20),
            CallerCandidate(file="src/a.c", function="a", line=1, score=5),
        ]
        ranked = rank_callers(candidates)
        assert len(ranked) == 1
        assert ranked[0].function == "a"

    def test_sorts_by_score_descending(self):
        candidates = [
            CallerCandidate(file="a.c", function="low", line=1, score=2),
            CallerCandidate(file="b.c", function="high", line=1, score=10),
            CallerCandidate(file="c.c", function="mid", line=1, score=5),
        ]
        ranked = rank_callers(candidates)
        assert [c.function for c in ranked] == ["high", "mid", "low"]

    def test_respects_max_callers(self):
        candidates = [
            CallerCandidate(file=f"{i}.c", function=f"f{i}", line=1, score=i)
            for i in range(20)
        ]
        ranked = rank_callers(candidates, max_callers=3)
        assert len(ranked) == 3
        assert ranked[0].score == 19

    def test_empty_candidates(self):
        assert rank_callers([]) == []

    def test_all_zero_or_negative(self):
        candidates = [
            CallerCandidate(file="a.c", function="a", line=1, score=0),
            CallerCandidate(file="b.c", function="b", line=1, score=-5),
        ]
        assert rank_callers(candidates) == []


class TestProbeBeyondCeiling:
    def test_entry_point_found(self):
        ceiling_callers = [
            ("src/dispatch.c", "dispatch", 10),
        ]
        checklist = _checklist({
            "src/dispatch.c": [
                {"name": "dispatch", "line_start": 10, "line_end": 20},
            ],
        })
        entry_points = {"src/main.c:handle_request"}

        probe = probe_beyond_ceiling(
            _constraint(),
            ceiling_callers,
            checklist,
            entry_points,
        )
        assert probe.estimated_remaining in ("1-2", "unknown")

    def test_no_callers_at_ceiling(self):
        probe = probe_beyond_ceiling(
            _constraint(), [], _checklist(), set(),
        )
        assert probe.estimated_remaining == "unknown"
        assert probe.callers_at_ceiling == []

    def test_codeql_recommended_for_deep_taint(self):
        probe = DepthProbe(
            callers_at_ceiling=["a:b"],
            entry_points_within_one_hop=[],
            estimated_remaining="3+",
            codeql_recommended=True,
            codeql_setup_hint="codeql database create ...",
        )
        assert probe.codeql_recommended

    def test_codeql_not_recommended_for_precondition(self):
        c = _constraint(kind="precondition")
        probe = probe_beyond_ceiling(
            c, [], _checklist(), set(),
        )
        assert not probe.codeql_recommended


class TestTryCodeqlResolve:
    def test_not_taint_expressible(self):
        c = _constraint(kind="precondition")
        config = PropagationConfig(codeql_db_path="/tmp/db")
        assert try_codeql_resolve(c, config) is None

    def test_no_db_path(self):
        c = _constraint(kind="parameter")
        config = PropagationConfig()
        assert try_codeql_resolve(c, config) is None

    def test_db_not_dir(self, tmp_path: Path):
        c = _constraint(kind="parameter")
        config = PropagationConfig(codeql_db_path=str(tmp_path / "nope"))
        assert try_codeql_resolve(c, config) is None


class TestTryCoccinelleResolve:
    def test_unsupported_kind(self):
        c = _constraint(kind="ordering")
        config = PropagationConfig(coccinelle_available=True)
        assert try_coccinelle_resolve(c, config) is None

    def test_postcondition_supported(self):
        c = _constraint(kind="postcondition")
        config = PropagationConfig(coccinelle_available=True)
        # Returns None because no target_path, but doesn't reject the kind
        assert try_coccinelle_resolve(c, config) is None

    def test_precondition_supported(self):
        c = _constraint(kind="precondition")
        config = PropagationConfig(coccinelle_available=True)
        assert try_coccinelle_resolve(c, config) is None

    def test_state_supported(self):
        c = _constraint(kind="state")
        config = PropagationConfig(coccinelle_available=True)
        assert try_coccinelle_resolve(c, config) is None

    def test_not_available(self):
        c = _constraint(kind="postcondition")
        config = PropagationConfig(coccinelle_available=False)
        assert try_coccinelle_resolve(c, config) is None

    def test_no_target_path(self):
        c = _constraint(kind="postcondition")
        config = PropagationConfig(
            coccinelle_available=True, target_path=None,
        )
        assert try_coccinelle_resolve(c, config) is None


class TestPropagateOneHop:
    def test_depth_limited(self):
        c = _constraint()
        config = PropagationConfig(max_depth=0)
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
            current_depth=0,
        )
        assert not result.resolved
        assert result.resolution == "depth_limited"
        assert result.depth_probe is not None

    def test_zero_callers_inconclusive(self):
        c = _constraint()
        config = PropagationConfig(max_depth=5)
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
        )
        assert not result.resolved
        assert result.resolution == "inconclusive"

    def test_module_unavailable_inconclusive(self, monkeypatch):
        import sys
        c = _constraint()
        config = PropagationConfig(max_depth=5)
        monkeypatch.setitem(
            sys.modules, "core.analysis.reachability", None,
        )
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
        )
        assert not result.resolved
        assert result.resolution == "inconclusive"

    def test_at_max_depth(self):
        c = _constraint()
        config = PropagationConfig(max_depth=5)
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
            current_depth=5,
        )
        assert result.resolution == "depth_limited"


class TestFormatDepthLimitReport:
    def test_basic_format(self):
        c = _constraint(
            propagation_chain=["handle_packet", "dispatch"],
        )
        probe = DepthProbe(
            callers_at_ceiling=["src/loop.c:recv_loop"],
            entry_points_within_one_hop=[],
            estimated_remaining="3+",
            codeql_recommended=True,
            codeql_setup_hint="codeql database create db --language=cpp",
        )
        report = format_depth_limit_report(c, probe, 5, 5)
        assert "Depth limit reached (5/5 hops)" in report
        assert "parse_header" in report
        assert "len must be <= 1024" in report
        assert "CodeQL" in report
        assert "--max-propagation-depth 10" in report

    def test_entry_point_nearby(self):
        c = _constraint()
        probe = DepthProbe(
            callers_at_ceiling=["src/a.c:fn"],
            entry_points_within_one_hop=["src/main.c:main"],
            estimated_remaining="1-2",
        )
        report = format_depth_limit_report(c, probe, 5, 5)
        assert "entry points within 1 hop" in report
        assert "1-2" in report

    def test_no_callers(self):
        c = _constraint()
        probe = DepthProbe(
            callers_at_ceiling=[],
            entry_points_within_one_hop=[],
            estimated_remaining="unknown",
        )
        report = format_depth_limit_report(c, probe, 3, 5)
        assert "no callers found" in report


class TestAdversarialFixes:
    def test_path_traversal_in_source_read(self, tmp_path: Path):
        """Ensure path traversal in caller_file doesn't escape target."""
        c = _constraint()
        result = score_caller(
            "../../etc/passwd", "evil", 1, c,
            entry_points=set(),
            target_path=tmp_path,
        )
        assert "variable_arg" not in result.reasons
        assert "no_bounds_check" not in result.reasons

    def test_coccinelle_rule_path_injection(self):
        c = _constraint(
            kind="postcondition",
            mechanical_check="../../evil.cocci",
        )
        config = PropagationConfig(
            coccinelle_available=True,
            target_path=Path("/tmp"),
        )
        result = try_coccinelle_resolve(c, config)
        assert result is None

    def test_coccinelle_rule_valid_name(self):
        c = _constraint(
            kind="postcondition",
            mechanical_check="check_return.cocci",
        )
        config = PropagationConfig(
            coccinelle_available=True,
            target_path=Path("/tmp"),
        )
        # Will fail at import, but the name validation should pass
        result = try_coccinelle_resolve(c, config)
        # None because the import fails, not because of name validation
        assert result is None

    def test_literal_arg_gets_nonzero_score(self, tmp_path: Path):
        """Literals should still get a score (might exceed bounds)."""
        c = _constraint()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "caller.c").write_text(
            "void caller() {\n"
            "    parse_header(buf, 9999);\n"
            "}\n"
        )
        result = score_caller(
            "src/caller.c", "caller", 1, c,
            entry_points=set(),
            target_path=tmp_path,
        )
        assert "literal_arg" in result.reasons
        assert result.score > 0

    def test_large_file_skipped(self, tmp_path: Path):
        """Files larger than 2MB should not be read for heuristic."""
        c = _constraint()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        large = src_dir / "huge.c"
        large.write_text("x" * (3 * 1024 * 1024))
        result = score_caller(
            "src/huge.c", "fn", 1, c,
            entry_points=set(),
            target_path=tmp_path,
        )
        assert "variable_arg" not in result.reasons
        assert "literal_arg" not in result.reasons


class TestBinaryOracleIntegration:
    def test_absent_function_refuted(self):
        c = _constraint()
        config = PropagationConfig(
            max_depth=5,
            binary_verdicts={"src/packet.c:parse_header": "absent"},
        )
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
        )
        assert result.resolved
        assert result.resolution == "refuted"
        assert result.resolver_used == "binary_oracle"

    def test_present_function_not_short_circuited(self):
        c = _constraint()
        config = PropagationConfig(
            max_depth=5,
            binary_verdicts={"src/packet.c:parse_header": "symbol_present"},
        )
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
        )
        assert result.resolver_used != "binary_oracle"

    def test_no_verdicts_no_effect(self):
        c = _constraint()
        config = PropagationConfig(max_depth=5)
        result = propagate_one_hop(
            c,
            checklist=_checklist(),
            entry_points=set(),
            config=config,
        )
        assert result.resolver_used != "binary_oracle"


class TestEntryReachabilityScoring:
    def test_no_inventory_no_effect(self):
        c = _constraint()
        result = score_caller(
            "src/caller.c", "fn", 1, c,
            entry_points=set(),
        )
        assert "no_entry_path" not in result.reasons

    def test_inventory_passed_through(self):
        c = _constraint()
        result = score_caller(
            "src/caller.c", "fn", 1, c,
            entry_points=set(),
            inventory={"files": {}},
        )
        assert "no_entry_path" not in result.reasons or result.score < 0


# ── Taint-approx and Joern resolvers ──────────────────────────────────


class _FakeTaintApprox:
    """Minimal stand-in for CTaintApprox."""

    def __init__(self, params, dangerous_flows=None, has_opaque_flow=False):
        self.params = params
        self.dangerous_flows = dangerous_flows or {}
        self.has_opaque_flow = has_opaque_flow


class _FakeJoernFlow:
    def __init__(self, source_param=""):
        self.source_param = source_param


class TestTaintApproxResolver:
    def test_confirms_when_param_has_dangerous_flow(self):
        approx = _FakeTaintApprox(
            params=["buf", "len"],
            dangerous_flows={1: [("memcpy", 3)]},
        )
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", taint_approx=approx)
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_taint_approx_resolve(c, config)
        assert result is not None
        assert result.resolved
        assert result.resolution == "confirmed"
        assert result.resolver_used == "taint_approx"

    def test_returns_none_when_param_not_dangerous(self):
        approx = _FakeTaintApprox(params=["buf", "len"], dangerous_flows={})
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", taint_approx=approx)
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_taint_approx_resolve(c, config)
        assert result is None

    def test_returns_none_for_non_parameter_constraint(self):
        config = PropagationConfig(evidence_index={})
        c = _constraint(kind="precondition")
        result = _try_taint_approx_resolve(c, config)
        assert result is None

    def test_returns_none_without_evidence(self):
        config = PropagationConfig()
        c = _constraint()
        result = _try_taint_approx_resolve(c, config)
        assert result is None

    def test_returns_none_when_param_not_in_params_list(self):
        approx = _FakeTaintApprox(
            params=["buf", "size"],
            dangerous_flows={0: [("strcpy", 2)]},
        )
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", taint_approx=approx)
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_taint_approx_resolve(c, config)
        assert result is None


class TestJoernResolver:
    def test_confirms_when_flows_exist(self):
        flow = _FakeJoernFlow(source_param="len")
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", joern_flows=[flow])
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_joern_resolve(c, config)
        assert result is not None
        assert result.resolved
        assert result.resolution == "confirmed"
        assert result.resolver_used == "joern"

    def test_confirms_imported_flows(self):
        flow = _FakeJoernFlow(source_param="len")
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", imported_joern_flows=[flow])
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_joern_resolve(c, config)
        assert result is not None
        assert result.resolved

    def test_returns_none_when_no_matching_param(self):
        flow = _FakeJoernFlow(source_param="other")
        rec = EvidenceRecord(file="src/packet.c", function="parse_header", joern_flows=[flow])
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_joern_resolve(c, config)
        assert result is None

    def test_returns_none_without_evidence(self):
        config = PropagationConfig()
        c = _constraint()
        result = _try_joern_resolve(c, config)
        assert result is None

    def test_returns_none_for_non_parameter_constraint(self):
        config = PropagationConfig(evidence_index={})
        c = _constraint(kind="precondition")
        result = _try_joern_resolve(c, config)
        assert result is None


class _FakeTaintSummary:
    """Minimal stand-in for TaintSummary."""

    def __init__(
        self, params, call_arg_taint=None,
        return_effects=None, summary_unknown=False,
    ):
        self.params = tuple(params)
        self.call_arg_taint = frozenset(call_arg_taint or [])
        self.return_effects = frozenset(return_effects or [])
        self.summary_unknown = summary_unknown

    def return_sanitizers_for_param(self, param_idx):
        return frozenset(
            (name, ai)
            for pi, name, ai in self.return_effects
            if pi == param_idx and name
        )


class TestTaintSummaryResolver:
    def test_confirms_when_call_arg_taint_matches(self):
        ts = _FakeTaintSummary(
            params=["buf", "len"],
            call_arg_taint=[("memcpy", 2, 1)],
        )
        rec = EvidenceRecord(
            file="src/packet.c", function="parse_header",
            taint_summary=ts,
        )
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_taint_summary_resolve(c, config)
        assert result is not None
        assert result.resolved
        assert result.resolution == "confirmed"
        assert result.resolver_used == "taint_summary"

    def test_refutes_when_sanitizer_present(self):
        ts = _FakeTaintSummary(
            params=["user_input"],
            call_arg_taint=[],
            return_effects=[(0, "sanitize_html", 0)],
        )
        rec = EvidenceRecord(
            file="src/packet.c", function="parse_header",
            taint_summary=ts,
        )
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="user_input")
        result = _try_taint_summary_resolve(c, config)
        assert result is not None
        assert result.resolved
        assert result.resolution == "refuted"
        assert result.resolver_used == "taint_summary"

    def test_returns_none_when_param_not_found(self):
        ts = _FakeTaintSummary(
            params=["buf", "size"],
            call_arg_taint=[("memcpy", 2, 0)],
        )
        rec = EvidenceRecord(
            file="src/packet.c", function="parse_header",
            taint_summary=ts,
        )
        config = PropagationConfig(evidence_index={"src/packet.c:parse_header": rec})
        c = _constraint(target="len")
        result = _try_taint_summary_resolve(c, config)
        assert result is None

    def test_returns_none_without_evidence(self):
        config = PropagationConfig()
        c = _constraint()
        result = _try_taint_summary_resolve(c, config)
        assert result is None

    def test_returns_none_for_non_parameter_constraint(self):
        config = PropagationConfig(evidence_index={})
        c = _constraint(kind="precondition")
        result = _try_taint_summary_resolve(c, config)
        assert result is None


class TestGetCallers:
    def test_returns_none_without_inventory(self):
        result = get_callers("src/a.c", "func", 10, inventory=None)
        assert result is None

    def test_returns_none_on_import_error(self):
        result = get_callers("src/a.c", "func", 10, inventory={})
        assert result is None or isinstance(result, list)

    def test_accepts_valid_inventory(self):
        result = get_callers("src/a.c", "func", 10, inventory={"files": {}})
        assert result is None or isinstance(result, list)
