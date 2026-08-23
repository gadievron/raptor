"""Tier-1 edge-contract review pass + tier-2 folded verdicts.

Zero LLM calls: the pass is driven with a stub client; journal /
fold semantics use real files under tmp_path. Covers validation
assertion 2 (an unverdicted tier-1 edge stays a gap across re-runs;
a journalled verdict clears it; drift in EITHER endpoint resurfaces
it) and the synthetic half of assertion 3 (prompt assembly + outcome
recording with a stubbed response). The real-CVE CopyFail/DirtyFrag
E2E remains an operator-gated dev-time validation before any
default-on flip.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.audit.edge_review import (
    EDGE_STRATEGY,
    build_edge_prompt,
    compute_edge_gaps,
    edge_callee_id,
    edge_source_hash,
    run_edge_pass,
)
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)

_CALLER_SRC = """\
int handle(const char *raw) {
    return run_query(raw);
}
"""

_CALLEE_SRC = """\
int run_query(const char *q) {
    return exec(q);
}
"""


def _target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "routes.c").write_text(_CALLER_SRC, encoding="utf-8")
    (target / "svc.c").write_text(_CALLEE_SRC, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [
            {"path": "routes.c", "language": "c",
             "call_graph": {"calls": [
                 {"line": 2, "chain": ["run_query"],
                  "caller": "handle"}]},
             "items": [
                {"name": "handle", "kind": "function",
                 "line_start": 1, "line_end": 3}]},
            {"path": "svc.c", "language": "c", "items": [
                {"name": "run_query", "kind": "function",
                 "line_start": 1, "line_end": 3}]},
        ],
    }


_REC = {
    "caller_file": "routes.c", "caller": "handle",
    "callee_file": "svc.c", "callee": "run_query",
    "call_line": 2, "reason": "boundary:socket", "touched": False,
}
_OBLIGATIONS = {"tier1": [dict(_REC)], "tier2": [], "blind_spots": [],
                "stats": {}}


def _edge_entry(target, **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "routes.c",
        "function": "handle",
        "verdict": "clean",
        "source_hash": edge_source_hash(
            target, "routes.c", (1, 3), "svc.c", (1, 3)),
        "line_start": 1,
        "line_end": 3,
        "strategies": [EDGE_STRATEGY],
        "edge_callee": edge_callee_id("svc.c", "run_query"),
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


class TestEdgeIdentity:
    def test_key_carries_edge_suffix(self, tmp_path):
        target = _target(tmp_path)
        entry = _edge_entry(target)
        assert entry.key == "routes.c:handle->svc.c:run_query"
        assert entry.key != "routes.c:handle"
        # Edge suffix precedes the span suffix in the index key.
        assert ":svc.c:run_query@" in entry.index_key

    def test_two_span_hash_covers_both_endpoints(self, tmp_path):
        target = _target(tmp_path)
        before = edge_source_hash(
            target, "routes.c", (1, 3), "svc.c", (1, 3))
        assert before
        (target / "svc.c").write_text(
            _CALLEE_SRC.replace("exec", "exec2"), encoding="utf-8")
        assert edge_source_hash(
            target, "routes.c", (1, 3), "svc.c", (1, 3)) != before


class TestEdgeGaps:
    def _gaps(self, target, run_dir):
        return compute_edge_gaps(
            _OBLIGATIONS, out_dir=run_dir, project_dir=None,
            target_path=target, checklist=_checklist(target),
        )

    def test_unverdicted_edge_stays_gap(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        assert len(self._gaps(target, run)) == 1

    def test_journalled_verdict_clears_gap(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _edge_entry(target))
        assert self._gaps(target, run) == []

    def test_error_verdict_never_clears(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _edge_entry(target, verdict="error"))
        assert len(self._gaps(target, run)) == 1

    def test_caller_drift_resurfaces(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _edge_entry(target))
        (target / "routes.c").write_text(
            _CALLER_SRC.replace("raw", "raw2"), encoding="utf-8")
        assert len(self._gaps(target, run)) == 1

    def test_callee_drift_resurfaces(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        append_entry(run, _edge_entry(target))
        (target / "svc.c").write_text(
            _CALLEE_SRC.replace("exec", "spawn"), encoding="utf-8")
        assert len(self._gaps(target, run)) == 1


class TestEdgeEntryFoldIsolation:
    def test_edge_entry_never_suppresses_caller_function_gap(self, tmp_path):
        # An edge review of handle->run_query is NOT a review of
        # handle: the caller must still surface as a function gap.
        from core.audit.gaps import compute_gaps
        target = _target(tmp_path)
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        append_entry(run, _edge_entry(target))
        from core.coverage.journal import merge_into_index
        merge_into_index(project, run)
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink={},
        )
        names = {f"{g['file']}:{g['name']}" for g in gaps}
        assert "routes.c:handle" in names


class _StubResponse(SimpleNamespace):
    pass


class _StubLLM:
    def __init__(self, result):
        self._result = result
        self.prompts: list[str] = []
        self.system_prompts: list[str] = []

    def generate_structured(self, prompt, schema, system_prompt=None, **kw):
        self.prompts.append(prompt)
        self.system_prompts.append(system_prompt or "")
        return _StubResponse(result=dict(self._result), cost=0.01,
                             model="stub-model", usage=None)

    def is_budget_exhausted(self, estimated_cost=0.1):
        return False


class TestRunEdgePass:
    def _config(self, target, run_dir, llm):
        return SimpleNamespace(
            out_dir=run_dir, target_path=target,
            llm_client=llm, llm_budget_client=llm,
        )

    def _context_map(self):
        return {
            "trust_boundaries": [
                {"boundary": "socket", "check": "routes.c:2"}],
            "entry_points": [{"id": "EP1", "file": "routes.c", "line": 1}],
            "sinks": [{"type": "exec", "location": "svc.c:2"}],
        }

    def test_stubbed_review_journals_edge_entry(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        llm = _StubLLM({
            "status": "finding",
            "body": "caller passes raw attacker input",
            "caller_assumptions": "assumes callee validates",
            "callee_assumptions": "assumes caller validated",
            "hypothesis": "unvalidated query string crosses the edge",
            "cwe": "CWE-89",
        })
        committed = []

        def commit_fn(config, outcome, gap):
            committed.append((outcome, gap))
            from core.audit.collector import append_journal_for_outcome
            append_journal_for_outcome(
                out_dir=run, target_path=target, run_id="run1",
                outcome=outcome, gap=gap,
            )

        summary, tier2 = run_edge_pass(
            self._config(target, run, llm),
            _checklist(target), self._context_map(),
            commit_fn=commit_fn,
        )
        assert summary["reviewed"] == 1
        # Spend accumulates for the caller to book into the phase
        # ledger — the pass runs during prep, before the AuditResult
        # exists; without this every edge review lands "unattributed".
        assert summary["cost_usd"] == pytest.approx(0.01)
        assert summary["wall_time_s"] > 0
        # The journal-write chokepoint enforces the tool-gated
        # promotion invariant: an LLM-only contract "finding" is
        # demoted to suspicious (edge findings need tool evidence
        # like every other finding). The claim survives in full in
        # the hypothesis/body for deepen//validate.
        assert summary["findings"] == 0
        assert summary["suspicious"] == 1
        assert tier2 == {}
        # Both endpoint bodies + the contract questions reached the prompt.
        assert "run_query" in llm.prompts[0]
        assert "handle" in llm.prompts[0]
        assert "assume about" in llm.prompts[0]
        entries = [e for e in load_entries(run) if e.edge_callee]
        assert len(entries) == 1
        entry = entries[0]
        assert entry.verdict == "suspicious"
        assert entry.edge_callee == "svc.c:run_query"
        assert entry.strategies == [EDGE_STRATEGY]
        # Two-span hash: matches a fresh recomputation.
        assert entry.source_hash == edge_source_hash(
            target, "routes.c", (1, 3), "svc.c", (1, 3))
        # Second pass: nothing left to review (assertion 2 clears).
        summary2, _ = run_edge_pass(
            self._config(target, run, llm),
            _checklist(target), self._context_map(),
            commit_fn=commit_fn,
        )
        assert summary2["reviewed"] == 0
        assert summary2["unreviewed_tier1"] == 0

    def test_domain_knowledge_reaches_tier1_prompt(self, tmp_path):
        """Tier-1 edge prompts inject domain-model knowledge scored
        against BOTH endpoint bodies — before this, the dedicated edge
        review carried no knowledge at all while the tier-2 fold
        (inside the function review) did."""
        import json as _json
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        (run / "domain-model.json").write_text(_json.dumps({
            "concepts": [], "contracts": [],
            "invariants": [{
                "id": "tf_query-never-raw",
                "statement": "Strings passed to run_query must never "
                             "carry raw user input.",
                "negation": "Injection through the query edge.",
                "description": "[threat-frame derived]",
                "confidence": "derived",
                "provenance": "llm_prior",
            }],
        }))
        llm = _StubLLM({"status": "clean", "body": "checked"})
        run_edge_pass(
            self._config(target, run, llm),
            _checklist(target), self._context_map(),
            commit_fn=lambda *a, **k: None,
        )
        assert llm.prompts, "edge pass made no LLM calls"
        assert "never carry raw user input" in llm.prompts[0]

    def test_no_llm_client_degrades_named(self, tmp_path):
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        summary, _ = run_edge_pass(
            SimpleNamespace(out_dir=run, target_path=target,
                            llm_client=None, llm_budget_client=None),
            _checklist(target), self._context_map(),
            commit_fn=lambda *a: None,
        )
        assert summary["degraded"] == "no-llm-client"
        assert summary["unreviewed_tier1"] == 1
        assert (run / "edge-obligations.json").is_file()


class TestTier2Folded:
    def _outcome(self):
        return SimpleNamespace(
            file="routes.c", function="handle", status="clean",
            body="fn body", hypothesis="", hypotheses=None,
            evidence_tool="", model="stub", cost_usd=0.0,
            duration_s=0.0, review_result={
                "edge_verdicts": [
                    {"callee": "run_query", "call_line": 2,
                     "verdict": "finding", "note": "no validation"},
                    {"callee": "invented_fn", "verdict": "finding"},
                    {"callee": "run_query", "verdict": "bogus-verdict"},
                ],
            },
            function_qualified="", tools_dispatched=None,
            context_reduced=False, reused=False, reused_from_run="",
        )

    def test_edge_verdicts_persist_filtered(self, tmp_path):
        from core.audit.collector import append_journal_for_outcome
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        gap = {
            "file": "routes.c", "name": "handle",
            "line_start": 1, "line_end": 3,
            "edge_contracts": [
                {"callee": "run_query", "callee_file": "svc.c",
                 "call_line": 2},
            ],
        }
        append_journal_for_outcome(
            out_dir=run, target_path=target, run_id="run1",
            outcome=self._outcome(), gap=gap,
        )
        entries = load_entries(run)
        assert len(entries) == 1
        evs = entries[0].edge_verdicts
        # Invented callee dropped; invalid verdict clamped out.
        assert evs == [{"callee": "run_query", "verdict": "finding",
                        "call_line": 2, "note": "no validation"}]
        assert entries[0].edge_callee is None

    def test_prompt_section_renders(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "routes.c", "function": "handle",
            "line_start": 1, "line_end": 3, "source": "int handle;",
            "edge_contracts": [
                {"callee": "run_query", "callee_file": "svc.c",
                 "call_line": 2, "contract": "q must be validated"},
            ],
        }
        prompt = format_context_for_prompt(ctx)
        assert "Edge contracts to verdict" in prompt
        assert "run_query" in prompt
        assert "q must be validated" in prompt


class TestEdgePrompt:
    def test_prompt_carries_reason_and_bodies(self):
        prompt = build_edge_prompt(dict(_REC), _CALLER_SRC, _CALLEE_SRC)
        assert "boundary:socket" in prompt
        assert "run_query(raw)" in prompt
        assert "exec(q)" in prompt
        assert "Verdict the CONTRACT" in prompt


class TestKnowledgeDegradationGate:
    """run_edge_pass states missing OR EMPTY domain models as degraded."""

    def _run(self, tmp_path, model_json=None):
        import json as _json

        from core.audit.edge_review import run_edge_pass
        target = _target(tmp_path)
        run = tmp_path / "run"
        run.mkdir(exist_ok=True)
        if model_json is not None:
            (run / "domain-model.json").write_text(_json.dumps(model_json))
        cfg = SimpleNamespace(out_dir=run, target_path=target,
                              llm_client=None, llm_budget_client=None)
        run_edge_pass(cfg, _checklist(target), None,
                      commit_fn=lambda *a, **k: None)
        return _json.loads(
            (run / "edge-obligations.json").read_text())["stats"]["degraded"]

    def test_absent_model_degrades(self, tmp_path):
        assert "no-domain-model" in self._run(tmp_path)

    def test_empty_model_degrades_like_absent(self, tmp_path):
        # The artifact a failed study run used to leave behind: parses
        # fine, contains nothing. Zero knowledge = degraded.
        degraded = self._run(tmp_path, model_json={
            "concepts": [], "invariants": [], "contracts": []})
        assert "no-domain-model" in degraded

    def test_populated_model_not_degraded(self, tmp_path):
        degraded = self._run(tmp_path, model_json={
            "concepts": [{"id": "c1", "description": "d"}],
            "invariants": [], "contracts": []})
        assert "no-domain-model" not in degraded
