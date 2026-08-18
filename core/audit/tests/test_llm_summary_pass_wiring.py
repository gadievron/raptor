"""End-to-end wiring test for the pre-loop LLM summary pass.

The pass (core.audit.llm_summaries) was unwired from the audit body in
the ensemble-pipeline rework and silently produced nothing for weeks.
This test pins the restored wiring at the integration level: a real
``run_orchestrator`` run over a tiny hermetic C target, with the LLM
stubbed at the client boundary, must

1. call the budget client under the ``summary`` call class for the
   connected-but-unsummarized functions,
2. deliver the extracted callee summary into the CALLER's review
   prompt (the "Callee CPG summaries" section rendered by
   ``format_context_for_prompt``),
3. book the pass's spend into the run's phase ledger (telemetry class
   ``summary`` → ``cost_tracker.phases["summary"]``), and
4. surface the pass's activity in the tier counters
   (``llm_summary``) so a dead pass is visible in tier diagnostics.

C is used deliberately: no mechanical taint summariser covers it, so
the callee is guaranteed to be connected-but-unsummarized — exactly
the population the pass exists for.  No network, no real LLM.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytestmark = pytest.mark.slow

# Distinctive sink name: appears in the callee summary's taint flow
# AND (as a call site) in the callee's own source — the summary pass
# source-grounds every extracted claim (``_ground_summary``), so a
# sink name absent from the source would be dropped as a potential
# injection. Delivery is proven by finding the marker inside the
# CALLER prompt's "Callee CPG summaries" section specifically: callee
# summaries are the only channel that renders sink names there.
_MARKER_SINK = "zz_llm_summary_marker_sink"

_SUMMARY_JSON = json.dumps({
    "preconditions": [
        {"parameter": "len", "assumption": "must be <= sizeof dst"},
    ],
    "taint_flows": [
        {"source_param": "src", "source_index": 0,
         "sink_call": _MARKER_SINK, "sink_arg_index": 1},
    ],
    "callees": [],
    "callers": [],
    "error_paths": ["return -1"],
    "state_transitions": [],
})

_CALLEE = """\
void zz_llm_summary_marker_sink(char *dst, const char *src, int len);

int parse_header(char *dst, const char *src, int len)
{
    int i;
    int n = 0;
    if (src == 0) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (src[i] == ':') {
            break;
        }
        dst[i] = src[i];
        n++;
    }
    dst[n] = 0;
    if (n == 0) {
        return -1;
    }
    if (n > 64) {
        zz_llm_summary_marker_sink(dst, src, len);
        return -1;
    }
    return n;
}
"""

_CALLER = """\
#include <string.h>

int handle_request(char *out, const char *pkt, int pkt_len)
{
    char header[128];
    int rc;
    int total = 0;
    if (pkt == 0) {
        return -1;
    }
    if (pkt_len <= 0) {
        return -1;
    }
    rc = parse_header(header, pkt, pkt_len);
    if (rc < 0) {
        return -1;
    }
    memcpy(out, header, (unsigned long)rc);
    while (total < rc) {
        total++;
    }
    out[total] = 0;
    return total;
}
"""


class _StubBudgetClient:
    """Budget-client stand-in: canned summary JSON for ``summary``
    calls, telemetry emitted like the real client so the end-of-run
    reconciliation has a class ledger to book."""

    recommended_max_workers = 1
    total_cost = 0.0

    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def is_budget_exhausted(self) -> bool:
        return False

    def generate(self, prompt, **kwargs):
        self.calls.append({"prompt": prompt, **kwargs})
        call_class = kwargs.get("call_class", "unclassified")
        self.total_cost += 0.02
        from core.llm import telemetry

        telemetry.emit(
            call_class=call_class, cost_usd=0.02, duration_s=0.01,
            tokens_in=100, tokens_out=50,
        )
        from types import SimpleNamespace

        return SimpleNamespace(
            content=_SUMMARY_JSON if call_class == "summary" else "{}",
            cost=0.02,
        )


class _CapturingReviewClient:
    """Review-client stand-in for make_review_fn: records every review
    prompt, returns a clean verdict."""

    def __init__(self):
        self.prompts: list[str] = []

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompts.append(prompt)
        from types import SimpleNamespace

        return SimpleNamespace(
            result={"status": "clean", "body": "stub review"},
            cost=0.01,
            model="stub-model",
        )


@pytest.fixture(scope="module")
def wired_run(tmp_path_factory):
    base = tmp_path_factory.mktemp("summary_wiring")
    target = base / "target"
    target.mkdir()
    # Single translation unit: the reachability index resolves
    # bare-name C calls same-file only, and ctx["callees"] (the
    # consumption side of the summary merge) comes from that index.
    (target / "net.c").write_text(_CALLEE + "\n" + _CALLER)
    out = base / "out"
    out.mkdir()

    from packages.exploitability_validation import build_checklist

    checklist = build_checklist(str(target), str(out))
    assert (out / "checklist.json").exists()

    # Candidate discovery needs the caller→callee edge to see the
    # functions as CONNECTED. With tree-sitter grammars installed the
    # inventory extractor supplies it, but the grammars are optional
    # (commented out in requirements.txt) — the regex fallback finds
    # no call edges, the pass sees two disconnected functions, and
    # this suite reports "unwired" on a wiring that is fine. Supply
    # the edge through the context map (the pass's other documented
    # edge source) so the guard tests the WIRING, not the grammar
    # install.
    (out / "context-map.json").write_text(json.dumps({
        "call_edges": [{
            "caller_file": "net.c", "caller": "handle_request",
            "callee": "parse_header", "callee_file": "net.c",
        }],
    }))

    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig, run_orchestrator

    budget_client = _StubBudgetClient()
    review_client = _CapturingReviewClient()

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        inventory=checklist,
        llm_budget_client=budget_client,
        force=True,
        resume=False,
        prefilter=False,
        validate=False,
        sweep_validate_findings=False,
        clean_check=False,
        deepen_suspicious=False,
        propagate_constraints=False,
        enable_session_context=False,
        on_demand_synthesis=False,
        verdict_reuse=False,
        include_stale=False,
        max_workers=1,
    )
    result = run_orchestrator(config, make_review_fn(review_client))
    return result, budget_client, review_client


class TestSummaryPassWiring:

    def test_budget_client_called_with_summary_class(self, wired_run):
        _, budget_client, _ = wired_run
        summary_calls = [
            c for c in budget_client.calls
            if c.get("call_class") == "summary"
        ]
        assert summary_calls, (
            "pre-loop summary pass never called the budget client — "
            "the pass is unwired again"
        )
        # Both functions are connected and unsummarized (C has no
        # mechanical summariser), so both are candidates.
        assert len(summary_calls) == 2

    def test_callee_summary_reaches_caller_review_prompt(self, wired_run):
        _, _, review_client = wired_run
        # The prompt header names the function under review (callee
        # prompts mention the caller too, so match the header).
        caller_prompts = [
            p for p in review_client.prompts
            if p.startswith("## net.c:handle_request")
        ]
        assert caller_prompts, "caller was never reviewed"
        prompt = caller_prompts[0]
        assert "Callee CPG summaries" in prompt, (
            "callee-summary section missing from the caller's review "
            "prompt — LLM summaries are not reaching reviews"
        )
        # Scope the marker check to the summaries SECTION: the marker
        # is also a call site in the callee's source (it must be, to
        # survive the pass's source-grounding), so a callee source
        # snippet elsewhere in the prompt could carry it vacuously.
        section = prompt.split("Callee CPG summaries", 1)[1]
        section = section.split("\n### ", 1)[0]
        assert _MARKER_SINK in section, (
            "the LLM-extracted callee summary content did not reach "
            "the caller's review prompt"
        )
        assert "parse_header" in prompt

    def test_spend_booked_into_phase_ledger(self, wired_run):
        result, _, _ = wired_run
        phases = result.cost_tracker.phases
        assert "summary" in phases, (
            "summary call class not booked into the phase ledger"
        )
        assert phases["summary"].cost_usd > 0
        assert phases["summary"].calls == 2

    def test_cost_breakdown_carries_summary_phase(self, wired_run):
        # The operator-facing cost-breakdown.json serialisation must
        # carry the booked class.
        result, _, _ = wired_run
        data = result.cost_tracker.to_dict()
        assert "summary" in data["phases"]
        assert data["phases"]["summary"]["cost_usd"] > 0

    def test_tier_counter_visible_in_diagnostics(self, wired_run):
        result, _, _ = wired_run
        tc = result.tier_counters.get("llm_summary")
        assert tc is not None, "llm_summary tier counter not registered"
        assert tc.confirmed == 2
        assert tc.errors == 0

    def test_summaries_merged_without_overwriting(self, wired_run):
        # Non-overwrite discipline: keys already summarized must be
        # left alone. Indirectly pinned by candidate count == 2 above;
        # here pin that a second run over the same shared dict would
        # be a no-op via the unit surface.
        from core.audit.llm_summaries import identify_summary_candidates

        workqueue = [
            {"file": "net.c", "name": "parse_header"},
            {"file": "net.c", "name": "handle_request"},
        ]
        edges = [{
            "caller_file": "net.c", "caller": "handle_request",
            "callee": "parse_header", "callee_file": "net.c",
        }]
        existing = {
            "net.c:parse_header": object(),
            "net.c:handle_request": object(),
        }
        assert identify_summary_candidates(
            workqueue, existing, None, call_edges=edges,
        ) == []
