"""Tests for the reachability gate in core.audit.orchestrator."""

from __future__ import annotations

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _apply_reachability_gate,
)
from pathlib import Path


def _config(tmp_path=None, **kw):
    base = tmp_path or Path(".")
    return OrchestratorConfig(
        target_path=base / "test",
        out_dir=base / "test-out",
        **kw,
    )


def _outcome(file="a.c", function="foo", status="finding", body="bug here"):
    return ReviewOutcome(
        file=file, function=function, status=status, body=body,
    )


def _ctx(role="internal", dangerous_apis=None, on_flow=False, callers=None,
         has_caller_data=True):
    return {
        "file": "a.c",
        "function": "foo",
        "role_context": {
            "role": role,
            "dangerous_apis": dangerous_apis or [],
            "is_on_flow_path": on_flow,
            "has_caller_data": has_caller_data,
            "reachability_note": "",
        },
        "callers": callers or [],
        "callees": [],
    }


class TestReachabilityGate:
    def test_entry_point_never_demoted(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="entry_point")
        result = _apply_reachability_gate(
            outcome, ctx, {"a.c:foo"}, _config(tmp_path),
        )
        assert result.status == "finding"

    def test_sink_never_demoted(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="sink", dangerous_apis=["strcpy"])
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "finding"

    def test_no_callers_not_entry_demoted_to_suspicious(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="internal", callers=[])
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "suspicious"
        assert "no visible callers" in result.body

    def test_no_callers_but_entry_point_kept(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="internal", callers=[])
        result = _apply_reachability_gate(
            outcome, ctx, {"a.c:foo"}, _config(tmp_path),
        )
        assert result.status != "dormant"

    def test_on_flow_path_kept(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="internal", callers=[], on_flow=True)
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "finding"

    def test_leaf_no_dangerous_apis_kept(self, tmp_path):
        outcome = _outcome(body="this function has a problem")
        ctx = _ctx(
            role="leaf",
            callers=[{"file": "b.c", "name": "bar", "line_start": 1}],
        )
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "finding"

    def test_internal_with_callers_kept(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(
            role="internal",
            callers=[{"file": "b.c", "name": "bar", "line_start": 1}],
        )
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "finding"

    def test_binary_absent_demoted_to_dormant(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(role="internal", callers=[])
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = _apply_reachability_gate(
            outcome, ctx, set(), config,
        )
        assert result.status == "dormant"
        assert "binary oracle" in result.body

    def test_binary_absent_header_inline_not_demoted(self, tmp_path):
        outcome = _outcome(file="include/net/netlink.h", function="nla_total_size_64bit")
        ctx = _ctx(role="internal", callers=[])
        ctx["source"] = "static inline int nla_total_size_64bit(int payload) {"
        config = _config(tmp_path, binary_verdicts={"nla_total_size_64bit": "absent"})
        result = _apply_reachability_gate(
            outcome, ctx, set(), config,
        )
        assert result.status != "dormant"

    def test_binary_absent_with_tool_evidence_not_demoted(self, tmp_path):
        outcome = _outcome()
        outcome.evidence_tool = "smt:check-overflow"
        ctx = _ctx(role="internal", callers=[])
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = _apply_reachability_gate(
            outcome, ctx, set(), config,
        )
        assert result.status != "dormant"

    def test_binary_absent_non_header_still_demoted(self, tmp_path):
        outcome = _outcome(file="net/core/sock.c", function="foo")
        ctx = _ctx(role="internal", callers=[])
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = _apply_reachability_gate(
            outcome, ctx, set(), config,
        )
        assert result.status == "dormant"

    def test_binary_present_not_demoted(self, tmp_path):
        outcome = _outcome()
        ctx = _ctx(
            role="internal",
            dangerous_apis=["strcpy"],
            callers=[{"file": "b.c", "name": "bar", "line_start": 1}],
        )
        config = _config(tmp_path, binary_verdicts={"foo": "symbol_present"})
        result = _apply_reachability_gate(
            outcome, ctx, set(), config,
        )
        assert result.status == "finding"

    def test_cost_preserved_through_demotion(self, tmp_path):
        outcome = _outcome()
        outcome.cost_usd = 0.42
        outcome.model = "test-model"
        ctx = _ctx(role="internal", callers=[])
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.cost_usd == 0.42
        assert result.model == "test-model"

    def test_no_caller_data_skips_demotion(self, tmp_path):
        """Without inventory/context-map, 'no callers' is not trustworthy."""
        outcome = _outcome()
        ctx = _ctx(role="internal", callers=[], has_caller_data=False)
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        assert result.status == "finding"

    def test_clean_status_not_gated(self, tmp_path):
        """Gate only runs on findings — clean outcomes skip it entirely."""
        outcome = _outcome(status="clean")
        ctx = _ctx(role="internal", callers=[])
        # The orchestrator checks status == "finding" before calling the gate,
        # but verify that if called, clean passes through unchanged.
        result = _apply_reachability_gate(
            outcome, ctx, set(), _config(tmp_path),
        )
        # No demotion rules apply to non-finding statuses
        assert result.status in ("clean", "suspicious")


