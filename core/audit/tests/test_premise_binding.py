"""Premise binding for refuted/countered-hypothesis re-verification.

A function-local SAT/pattern confirm may not override an LLM
refutation that rests on a cross-function premise ("the caller
validates the level", "that helper caps the length") — the engine
never encoded the premise, so the confirm re-proves the lexical shape
the reviewer already saw and refuted.
"""

import json
from pathlib import Path

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _premise_blocks_confirm,
    _promote_clean_refuted,
    _refutation_scope_cross_function,
    _tool_sees_cross_function,
)

_CROSS_COUNTER = (
    "access_remote_vm caps the returned length at PAGE_SIZE and the "
    "name is written under mmap_write_lock, so the read cannot "
    "overrun the buffer."
)
_LOCAL_COUNTER = (
    "the loop condition i < n prevents the index from ever reaching "
    "the sentinel slot, so the write stays in bounds."
)


class TestToolScope:
    def test_function_local_families(self):
        for t in ("smt:check-overflow", "coccinelle:missing_bounds_check",
                  "semgrep:rule-1", "ptr_lifecycle:stale-alias",
                  "prefilter:sink"):
            assert not _tool_sees_cross_function(t)

    def test_cross_function_families(self):
        for t in ("joern:flow-42", "codeql:cpp/overflow",
                  "consistency:contract-witness",
                  "callsite_deviation:width"):
            assert _tool_sees_cross_function(t)


class TestRefutationScope:
    def test_structured_field_wins(self):
        assert _refutation_scope_cross_function(
            {"counter": _LOCAL_COUNTER, "counter_scope": "cross_function"},
        )
        assert not _refutation_scope_cross_function(
            {"counter": _CROSS_COUNTER, "counter_scope": "local"},
        )

    def test_fallback_symbol_plus_guarantee(self):
        assert _refutation_scope_cross_function({"counter": _CROSS_COUNTER})

    def test_fallback_caller_language(self):
        assert _refutation_scope_cross_function({
            "counter": "callers only invoke grow when the array is "
                       "already full, so the reallocation is safe",
        })

    def test_fallback_local_fact_stays_local(self):
        assert not _refutation_scope_cross_function(
            {"counter": _LOCAL_COUNTER},
        )

    def test_short_counter_ignored(self):
        assert not _refutation_scope_cross_function({"counter": "callers"})


class TestPremiseBlocksConfirm:
    def test_blocks_function_local_confirm(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert _premise_blocks_confirm(h, ["smt:check-overflow"])

    def test_cross_function_channel_allows(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert not _premise_blocks_confirm(
            h, ["smt:check-overflow", "joern:flow"],
        )

    def test_local_refutation_allows(self):
        h = {"counter": _LOCAL_COUNTER, "counter_scope": "local"}
        assert not _premise_blocks_confirm(h, ["smt:check-overflow"])

    def test_no_confirm_no_block(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert not _premise_blocks_confirm(h, [])


class TestCleanRefutedLaneIntegration:
    def _run(self, tmp_path: Path, counter_scope: str):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int n) { return n * 4; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="clean after refutation",
            hypothesis="",
            hypotheses=[{
                "mechanism": "integer overflow in size multiplication "
                             "reaches the allocation",
                "confidence": "refuted",
                "counter": _CROSS_COUNTER,
                "counter_scope": counter_scope,
            }],
            line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        return config, result, checklist

    def test_cross_function_premise_blocks_promotion(
        self, tmp_path, monkeypatch,
    ):
        config, result, checklist = self._run(tmp_path, "cross_function")
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda m: "check-overflow",
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached", lambda *a, **k: "unguarded",
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "clean"
        assert getattr(
            result.tier_counters["refuted_sweep"], "premise_blocked", 0,
        ) >= 1
        # The premise was parked on the reading list for the study loop.
        rl = json.loads((config.out_dir / "reading-list.json").read_text())
        questions = [it["question"] for it in rl["items"]]
        assert any("access_remote_vm" in q for q in questions)

    def test_local_premise_still_promotes(self, tmp_path, monkeypatch):
        config, result, checklist = self._run(tmp_path, "local")
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda m: "check-overflow",
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached", lambda *a, **k: "unguarded",
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "finding"


class TestSmtCleanEscalationPremiseGate:
    def _clean_with_refuted(self, counter_scope):
        o = ReviewOutcome(
            file="a.c", function="f", status="clean", body="clean",
            hypothesis="",
            hypotheses=[{
                "mechanism": "early release of the buffer before the "
                             "flush completes",
                "confidence": "refuted",
                "counter": _CROSS_COUNTER,
                "counter_scope": counter_scope,
            }],
            line=1,
        )
        return o

    def _run(self, outcome, tmp_path, monkeypatch):
        import core.audit.orchestrator as o
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "o"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        # Force one checker to hit.
        import core.audit.condition_smt as cs
        class _R:  # minimal result shim
            bypass_found = True
            witness = None
        monkeypatch.setattr(cs, "check_auth_bypass", lambda *a, **k: _R())
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "f", "line_start": 1, "line_end": 1}]}]}
        o._promote_smt_clean(result, config, checklist=checklist)
        return result

    def test_cross_function_refutation_blocks_escalation(
        self, tmp_path, monkeypatch,
    ):
        r = self._run(
            self._clean_with_refuted("cross_function"), tmp_path,
            monkeypatch,
        )
        assert r.outcomes[0].status == "clean"

    def test_local_refutation_still_escalates(self, tmp_path, monkeypatch):
        r = self._run(
            self._clean_with_refuted("local"), tmp_path, monkeypatch,
        )
        assert r.outcomes[0].status == "suspicious"


class TestSweepValidatePremiseGate:
    """G2-lane premise binding: a function-local confirm may not ground
    the LLM's own finding when the primary hypothesis's counter rests
    on a cross-function premise the engine cannot see."""

    def _finding(self, counter_scope):
        return ReviewOutcome(
            file="a.c", function="f", status="finding",
            body="finding",
            hypothesis="resource leak: the error path skips the free "
                       "of the allocated cipher",
            hypotheses=[{
                "mechanism": "resource leak: the error path skips the "
                             "free of the allocated cipher",
                "confidence": "high",
                "counter": _CROSS_COUNTER,
                "counter_scope": counter_scope,
            }],
            review_result={
                "hypothesis": "resource leak: the error path skips the "
                              "free of the allocated cipher",
            },
            line=1,
        )

    def _run(self, outcome, tmp_path, monkeypatch):
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "o"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)

        class _PF:
            hits = []

        monkeypatch.setattr(orch, "run_prefilter", lambda *a, **k: _PF())
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "smt"}],
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        tier_counters = orch._make_tier_counters()
        validated = orch._sweep_validate(
            outcome, config, tier_counters=tier_counters,
        )
        return validated, config, tier_counters

    def test_cross_function_premise_blocks_grounding(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.evidence_grade import is_tool_evidence

        validated, config, tiers = self._run(
            self._finding("cross_function"), tmp_path, monkeypatch,
        )
        assert not is_tool_evidence(validated.evidence_tool or "")
        blocked = (validated.review_result or {}).get(
            "premise_blocked_confirms",
        )
        assert blocked and blocked[0]["evidence_tool"] == (
            "smt:check-overflow"
        )
        assert getattr(
            tiers["sweep_validate"], "premise_blocked", 0,
        ) >= 1
        rl = json.loads(
            (config.out_dir / "reading-list.json").read_text(),
        )
        assert any(
            "access_remote_vm" in it["question"] for it in rl["items"]
        )

    def test_local_counter_still_grounds(self, tmp_path, monkeypatch):
        validated, _config, _tiers = self._run(
            self._finding("local"), tmp_path, monkeypatch,
        )
        assert validated.evidence_tool == "smt:check-overflow"

    def test_cross_function_channel_still_grounds(
        self, tmp_path, monkeypatch,
    ):
        outcome = self._finding("cross_function")
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "o"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)

        class _PF:
            hits = []

        monkeypatch.setattr(orch, "run_prefilter", lambda *a, **k: _PF())
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "joern"}],
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["joern:flow"],
        )
        validated = orch._sweep_validate(
            outcome, config, tier_counters=orch._make_tier_counters(),
        )
        assert validated.evidence_tool == "joern:flow"


class TestSeedingChannelCannotOverturnRefutation:
    """The fail-open channel's registry-grade confirm proves fallible
    callee + discarded return — the exact facts the model weighed when
    it refuted the (channel-seeded) hypothesis. It corroborates
    standing findings; it may not overturn a completed refutation."""

    def _run(self, tmp_path, monkeypatch, confirms):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.go").write_text("package a\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.go", function="Cancel", status="clean",
            body="clean after refutation",
            hypothesis="",
            hypotheses=[{
                "mechanism": "ignored error from the close call leaves "
                             "the failure unhandled",
                "confidence": "refuted",
                "counter": "cleanup path: the discard is deliberate and "
                           "idempotent",
                "counter_scope": "local",
            }],
            line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {
            "files": [{
                "path": "a.go",
                "items": [
                    {"name": "Cancel", "line_start": 1, "line_end": 1},
                ],
            }],
        }
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda m: None,
        )
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "fail_open", "config": {}}],
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain", lambda *a, **k: list(confirms),
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached",
            lambda *a, **k: "unguarded",
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        return result

    def test_fail_open_confirm_does_not_overturn(
        self, tmp_path, monkeypatch,
    ):
        result = self._run(
            tmp_path, monkeypatch, ["fail_open:ignored-return"],
        )
        assert result.outcomes[0].status == "clean"

    def test_independent_confirm_still_promotes(
        self, tmp_path, monkeypatch,
    ):
        result = self._run(
            tmp_path, monkeypatch, ["coccinelle:use_after_free"],
        )
        assert result.outcomes[0].status == "suspicious"


class TestPromoteSuspiciousPremiseGate:
    """Primary-hypothesis sweep premise binding: a local confirm may
    not promote suspicious → finding past a cross-function counter the
    reviewer dismissed without evidence."""

    def _suspicious(self, counter_scope):
        # A dismissive-worded counter keeps _has_refuting_counter False
        # (the sweep proceeds) while the premise scope still binds.
        return ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="suspicious",
            hypothesis="resource leak on the rejected-level error path",
            hypotheses=[{
                "mechanism": "resource leak on the rejected-level "
                             "error path",
                "confidence": "high",
                "counter": "no realistic path: callers validate the "
                           "level before this function runs, so the "
                           "default branch is unreachable",
                "counter_scope": counter_scope,
            }],
            review_result={
                "hypothesis": "resource leak on the rejected-level "
                              "error path",
                "hypotheses": [{
                    "mechanism": "resource leak on the rejected-level "
                                 "error path",
                    "confidence": "high",
                    "counter": "no realistic path: callers validate "
                               "the level before this function runs, "
                               "so the default branch is unreachable",
                    "counter_scope": counter_scope,
                }],
            },
            line=1,
        )

    def _run(self, outcome, tmp_path, monkeypatch):
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "o"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1

        class _PF:
            hits = []

        monkeypatch.setattr(orch, "run_prefilter", lambda *a, **k: _PF())
        monkeypatch.setattr(
            orch, "_correlated_mech_detector_tool", lambda *a, **k: None,
        )
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "smt"}],
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached",
            lambda *a, **k: "unguarded",
        )
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "f", "line_start": 1, "line_end": 1}]}]}
        orch._promote_suspicious(result, config, checklist=checklist)
        return result, config

    def test_cross_function_premise_blocks_promotion(
        self, tmp_path, monkeypatch,
    ):
        result, config = self._run(
            self._suspicious("cross_function"), tmp_path, monkeypatch,
        )
        assert result.outcomes[0].status == "suspicious"
        assert getattr(
            result.tier_counters["primary_sweep"], "premise_blocked", 0,
        ) >= 1
        rl = json.loads(
            (config.out_dir / "reading-list.json").read_text(),
        )
        assert any(
            "callers validate" in it["question"] for it in rl["items"]
        )

    def test_local_counter_still_promotes(self, tmp_path, monkeypatch):
        result, _config = self._run(
            self._suspicious("local"), tmp_path, monkeypatch,
        )
        assert result.outcomes[0].status == "finding"
