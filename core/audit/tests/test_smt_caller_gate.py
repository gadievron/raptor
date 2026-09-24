"""Caller-side gate on clean-refuted SMT promotions.

An SMT confirm in the clean-refuted lane is intra-procedural; the
gate adjudicates the receipt's own precondition (the callee parameter
the verb solved over) at the in-repo call sites before the receipt
may mint a finding.  Holds keep the receipt at suspicious; a concrete
violating call site promotes with the site cited; errors fail closed.
"""

import json
from pathlib import Path

import core.audit.orchestrator as orch
import core.audit.smt_promotion_gate as spg
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _promote_clean_refuted,
)
from core.audit.smt_promotion_gate import (
    evaluate_caller_gate,
    receipt_preconditions,
)

_CALLEE = (
    "int compute(unsigned int max_size, unsigned int count)\n"
    "{\n"
    "    return max_size * count;\n"
    "}\n"
)
_MECHANISM = "integer overflow: `max_size` * `count` can wrap"

_NULL_CALLEE = "int handle(struct req *r)\n{\n    return r->id;\n}\n"
_NULL_MECHANISM = "`r` is NULL from cleanup paths — NULL dereference of r"

_FIELD_CALLEE = "int fire(struct ctx *c, cb_t cb)\n{\n    return c->cb(c);\n}\n"


# ── precondition adapter ────────────────────────────────────────────


class TestReceiptPreconditions:
    def test_overflow_binds_parameter_operands(self):
        contracts = receipt_preconditions(
            "check-overflow", _MECHANISM,
            ["max_size", "count"], _CALLEE,
        )
        assert {c.param for c in contracts} == {"max_size", "count"}
        assert all(c.kind == "bounded" for c in contracts)

    def test_smt_prefixed_verb_accepted(self):
        contracts = receipt_preconditions(
            "smt:check-overflow", _MECHANISM,
            ["max_size", "count"], _CALLEE,
        )
        assert {c.param for c in contracts} == {"max_size", "count"}

    def test_non_parameter_operands_bind_nothing(self):
        # The wrap is driven by locals the caller cannot influence
        # by argument choice — no caller-checkable precondition.
        contracts = receipt_preconditions(
            "check-overflow", _MECHANISM, ["other_param"], _CALLEE,
        )
        assert contracts == []

    def test_null_deref_binds_pointer_parameter(self):
        contracts = receipt_preconditions(
            "check-null-deref", _NULL_MECHANISM, ["r"], _NULL_CALLEE,
        )
        assert len(contracts) == 1
        assert contracts[0].kind == "null"
        assert contracts[0].param == "r"

    def test_field_access_operand_never_binds_same_named_param(self):
        # ``c->cb`` names a field; a same-named parameter must not be
        # adjudicated in its place.
        contracts = receipt_preconditions(
            "check-null-deref",
            "`c->cb` is NULL until registration - NULL dereference",
            ["c", "cb"], _FIELD_CALLEE,
        )
        assert contracts == []

    def test_bare_operand_still_binds_next_to_member_mentions(self):
        # A bare mention anywhere in the mechanism keeps the binding
        # even when a member access of the same name also appears.
        contracts = receipt_preconditions(
            "check-null-deref",
            "`cb` is NULL (also reachable via c->cb) — NULL call",
            ["c", "cb"], _FIELD_CALLEE,
        )
        assert len(contracts) == 1
        assert contracts[0].param == "cb"

    def test_structural_verbs_bind_nothing(self):
        # Whole-function checks (lock discipline, narrowing, path
        # validation) range over no named operand.
        for verb in (
            "check-lock-discipline", "check-integer-narrowing",
            "validate-path",
        ):
            assert receipt_preconditions(
                verb, "lock not released on error path",
                ["max_size"], _CALLEE,
            ) == []

    def test_no_parameters_bind_nothing(self):
        assert receipt_preconditions(
            "check-overflow", _MECHANISM, [], _CALLEE,
        ) == []


# ── module-level evaluation ─────────────────────────────────────────


class TestEvaluateCallerGate:
    def _target(self, tmp_path: Path, files: dict) -> Path:
        target = tmp_path / "target"
        target.mkdir()
        for name, text in files.items():
            (target / name).write_text(text)
        return target

    def test_unbindable_receipt_holds_with_note(self, tmp_path):
        target = self._target(tmp_path, {"lib.c": _CALLEE})
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-lock-discipline", "lock not released",
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "unbindable"
        assert "binds no caller-checkable precondition" in decision.reason

    def test_sizeof_bounded_sites_uphold(self, tmp_path):
        # sizeof-valued arguments earn the structural uphold — the
        # channel-refuted branch, distinct from constant-pinned
        # inconclusive below.
        target = self._target(tmp_path, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use_a(void) "
                "{ return compute(sizeof(struct hdr), sizeof(int)); }\n"
            ),
        })
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "refuted"
        assert "all 1 call site(s) uphold the precondition" in decision.reason

    def test_constant_pinned_sites_decline_not_uphold(self, tmp_path):
        # A pinned literal is decidable in neither direction without
        # the numeric bound: the channel declines, and the prose says
        # what is actually known — never "uphold".
        target = self._target(tmp_path, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use_a(void) { return compute(64, 3); }\n"
                "int use_b(void) { return compute(128, 8); }\n"
            ),
        })
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "inconclusive"
        assert decision.site_count == 2
        assert (
            "2 call site(s) bind the operand to constants; no numeric "
            "bound available to adjudicate" in decision.reason
        )
        assert "uphold" not in decision.reason

    def test_huge_pinned_literal_never_claimed_upheld(self, tmp_path):
        # A literal that plainly reaches the wrap must not produce
        # caller-proof "uphold" prose.
        target = self._target(tmp_path, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use(void) "
                "{ return compute(4294967295u, 4294967295u); }\n"
            ),
        })
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "inconclusive"
        assert "uphold" not in decision.reason
        assert "no numeric bound available to adjudicate" in decision.reason

    def test_unguarded_site_promotes_with_citation(self, tmp_path):
        target = self._target(tmp_path, {
            "req.c": _NULL_CALLEE,
            "call.c": "int trigger(void)\n{\n    return handle(NULL);\n}\n",
        })
        decision = evaluate_caller_gate(
            target, "req.c", "handle",
            "check-null-deref", _NULL_MECHANISM,
            source="", def_span=(1, 4),
        )
        assert decision.action == "promote"
        assert "call.c:3" in decision.citation

    def test_non_null_variable_arg_never_confirms(self, tmp_path):
        # Only a literal NULL violates a null contract — a variable
        # argument (even one whose name contains a zero) must not
        # promote.
        target = self._target(tmp_path, {
            "req.c": _NULL_CALLEE,
            "call.c": (
                "int go(struct req *req0)\n"
                "{\n"
                "    return handle(req0);\n"
                "}\n"
            ),
        })
        decision = evaluate_caller_gate(
            target, "req.c", "handle",
            "check-null-deref", _NULL_MECHANISM,
            source="", def_span=(1, 4),
        )
        assert decision.action == "hold"

    def test_field_deref_same_named_param_holds_unbindable(self, tmp_path):
        # The mechanism claims a FIELD is NULL; adjudicating the
        # same-named parameter would cite fire(x, NULL) as proof
        # about the wrong variable.
        target = self._target(tmp_path, {
            "fire.c": _FIELD_CALLEE,
            "call.c": "int go(struct ctx *x) { return fire(x, NULL); }\n",
        })
        decision = evaluate_caller_gate(
            target, "fire.c", "fire",
            "check-null-deref",
            "`c->cb` is NULL until registration - NULL dereference",
            source=_FIELD_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "unbindable"

    def test_external_only_callers_hold(self, tmp_path):
        target = self._target(tmp_path, {"lib.c": _CALLEE})
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "inconclusive"
        assert "external-only callers" in decision.reason

    def test_evaluation_error_fails_closed(self, tmp_path, monkeypatch):
        target = self._target(tmp_path, {"lib.c": _CALLEE})

        def _boom(*a, **k):
            raise ValueError("evaluation crashed")

        monkeypatch.setattr(spg, "parse_param_names", _boom)
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        assert decision.action == "hold"
        assert decision.channel_outcome == "error"
        assert decision.error_class == "ValueError"
        assert "evaluation errored" in decision.reason


# ── lane integration (_promote_clean_refuted) ───────────────────────

_NO_KNOB = object()


class TestCleanRefutedCallerGate:
    """The validated caller-proof shapes hold at
    suspicious-with-receipt; a violating call site still promotes;
    the knob restores prior behavior; errors fail closed."""

    def _run(
        self,
        tmp_path,
        monkeypatch,
        files,
        mechanism,
        verb,
        *,
        gate=_NO_KNOB,
        file="lib.c",
        func="compute",
        line_end=4,
    ):
        target = tmp_path / "target"
        target.mkdir()
        for name, text in files.items():
            (target / name).write_text(text)
        out = tmp_path / "out"
        out.mkdir()
        kwargs = {}
        if gate is not _NO_KNOB:
            kwargs["smt_promotion_caller_gate"] = gate
        config = OrchestratorConfig(
            target_path=target, out_dir=out, **kwargs,
        )
        outcome = ReviewOutcome(
            file=file, function=func, status="clean",
            body="clean body", hypothesis="", line=1,
            hypotheses=[{"mechanism": mechanism, "confidence": "refuted"}],
        )
        outcome.review_result = {"hypotheses": outcome.hypotheses}
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {"files": [{
            "path": file,
            "items": [{"name": func, "line_start": 1, "line_end": line_end}],
        }]}
        monkeypatch.setattr(orch, "_hypothesis_to_smt_verb", lambda h: verb)
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain", lambda *a, **k: [f"smt:{verb}"],
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        return result, config

    def test_knob_defaults_on(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        assert config.smt_promotion_caller_gate is True

    def test_lane_gates_by_default_without_knob(self, tmp_path, monkeypatch):
        # No knob passed: the default must gate (flipping the default
        # must fail this test, not just the explicit-knob ones).
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }, _MECHANISM, "check-overflow")
        assert result.outcomes[0].status == "suspicious"
        assert result.findings == 0

    def test_entry_invariant_helper_holds(self, tmp_path, monkeypatch):
        # Every caller range-checks the parameter before the call —
        # lexical-grade guard receipts decline to refute, so the
        # channel is inconclusive and the gate holds.
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "entry.c": (
                "int entry(unsigned int max_size)\n"
                "{\n"
                "    if (max_size > 0x8000000) return -1;\n"
                "    return compute(max_size, 4);\n"
                "}\n"
            ),
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert outcome.evidence_tool == "clean-refuted:smt:check-overflow"
        assert outcome.body.startswith("[smt-caller-gate:")
        assert result.findings == 0
        assert result.refuted_rescued == 1

    def test_structurally_constrained_arguments_hold(
        self, tmp_path, monkeypatch,
    ):
        result, config = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use_a(void) { return compute(64, 3); }\n"
                "int use_b(void) { return compute(128, 8); }\n"
            ),
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert outcome.evidence_tool == "clean-refuted:smt:check-overflow"
        assert (
            "caller-contract gate: 2 call site(s) bind the operand to "
            "constants; no numeric bound available to adjudicate"
            in outcome.body
        )
        assert "uphold" not in outcome.body
        assert result.findings == 0
        assert result.clean == 0
        assert result.suspicious == 1
        gate_record = outcome.review_result["smt_caller_gate"]
        assert gate_record["action"] == "hold"
        assert gate_record["site_count"] == 2
        assert getattr(
            result.tier_counters["refuted_sweep"], "caller_gate_held", 0,
        ) == 1

    def test_sizeof_bounded_callers_uphold_prose(self, tmp_path, monkeypatch):
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use_a(void) "
                "{ return compute(sizeof(struct hdr), sizeof(int)); }\n"
            ),
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert "all 1 call site(s) uphold the precondition" in outcome.body

    def test_dominating_fatal_assert_holds(self, tmp_path, monkeypatch):
        # The assert lives in the callee; the caller passes a plain
        # variable, so no site is structurally decidable and the
        # channel declines — the gate holds rather than guessing.
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": (
                "int compute(unsigned int max_size, unsigned int count)\n"
                "{\n"
                "    assert(max_size <= 4096);\n"
                "    return max_size * count;\n"
                "}\n"
            ),
            "drive.c": (
                "int drive(unsigned int n)\n"
                "{\n"
                "    return compute(n, 2);\n"
                "}\n"
            ),
        }, _MECHANISM, "check-overflow", line_end=5)
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert outcome.evidence_tool == "clean-refuted:smt:check-overflow"
        assert result.findings == 0

    def test_unguarded_call_site_promotes_with_citation(
        self, tmp_path, monkeypatch,
    ):
        result, _ = self._run(tmp_path, monkeypatch, {
            "req.c": _NULL_CALLEE,
            "call.c": "int trigger(void)\n{\n    return handle(NULL);\n}\n",
        }, _NULL_MECHANISM, "check-null-deref", file="req.c", func="handle")
        outcome = result.outcomes[0]
        assert outcome.status == "finding"
        assert outcome.evidence_tool == "clean-refuted:smt:check-null-deref"
        assert "[smt-caller-gate:" in outcome.body
        assert "call.c:3" in outcome.body
        assert result.findings == 1
        assert result.sweep_promoted == 1

    def test_external_only_callers_hold(self, tmp_path, monkeypatch):
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert "external-only callers" in outcome.body
        assert result.findings == 0

    def test_knob_off_restores_promotion(self, tmp_path, monkeypatch):
        # Two-direction: the same fixture that holds under the gate
        # promotes when the knob is off.
        files = {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }
        result_on, _ = self._run(
            tmp_path, monkeypatch, files, _MECHANISM,
            "check-overflow", gate=True,
        )
        assert result_on.outcomes[0].status == "suspicious"

        off_dir = tmp_path / "off"
        off_dir.mkdir()
        result_off, _ = self._run(
            off_dir, monkeypatch, files,
            _MECHANISM, "check-overflow", gate=False,
        )
        assert result_off.outcomes[0].status == "finding"
        assert (
            result_off.outcomes[0].evidence_tool
            == "clean-refuted:smt:check-overflow"
        )
        assert result_off.sweep_promoted == 1

    def test_hold_writes_suppression_record(self, tmp_path, monkeypatch):
        _, config = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": (
                "int use_a(void) { return compute(64, 3); }\n"
                "int use_b(void) { return compute(128, 8); }\n"
            ),
        }, _MECHANISM, "check-overflow")
        records = [
            json.loads(line) for line in
            (config.out_dir / "suppressions.jsonl").read_text().splitlines()
        ]
        assert len(records) == 1
        rec = records[0]
        assert rec["dropped"] is False
        assert rec["verdict"] == "smt_promotion_caller_gate"
        assert "2 call site(s) bind the operand to constants" in rec["reason"]
        assert rec["site_count"] == 2
        assert rec["function"] == "compute"
        assert rec["rule_id"] == "clean-refuted:smt:check-overflow"

    def test_hold_writes_audit_log_entry(self, tmp_path, monkeypatch):
        _, config = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }, _MECHANISM, "check-overflow")
        entries = [
            json.loads(line) for line in
            (config.out_dir / ".audit-log.jsonl").read_text().splitlines()
        ]
        held = [
            e for e in entries
            if e.get("action") == "smt_promotion_caller_gate_held"
        ]
        assert len(held) == 1
        assert held[0]["status"] == "suspicious"
        assert held[0]["prior_status"] == "clean"

    def test_promote_writes_no_suppression_record(
        self, tmp_path, monkeypatch,
    ):
        _, config = self._run(tmp_path, monkeypatch, {
            "req.c": _NULL_CALLEE,
            "call.c": "int trigger(void)\n{\n    return handle(NULL);\n}\n",
        }, _NULL_MECHANISM, "check-null-deref", file="req.c", func="handle")
        assert not (config.out_dir / "suppressions.jsonl").exists()

    def test_gate_error_fails_closed_with_error_class(
        self, tmp_path, monkeypatch,
    ):
        # An errored consult must hold (fail-closed) AND be stamped —
        # never artifact-identical to a knob-off run or a normal hold.
        def _boom(*a, **k):
            raise RuntimeError("gate evaluation crashed")

        monkeypatch.setattr(spg, "evaluate_caller_gate", _boom)
        result, config = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert "evaluation errored" in outcome.body
        assert "RuntimeError" in outcome.body
        rec = json.loads(
            (config.out_dir / "suppressions.jsonl").read_text()
            .splitlines()[0]
        )
        assert rec["dropped"] is False
        assert rec["channel_outcome"] == "error"
        assert rec["error_class"] == "RuntimeError"
        gate_record = outcome.review_result["smt_caller_gate"]
        assert gate_record["channel_outcome"] == "error"
        assert gate_record["error_class"] == "RuntimeError"

    def test_gate_consult_after_premise_veto(self, tmp_path, monkeypatch):
        # Veto-order pin: a premise-blocked confirm must never reach
        # the gate — reordering the gate above the premise veto fails
        # this test.
        calls = []
        monkeypatch.setattr(
            spg, "evaluate_caller_gate",
            lambda *a, **k: calls.append(a) or None,
        )
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda h: "check-overflow",
        )
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain", lambda *a, **k: ["smt:check-overflow"],
        )
        target = tmp_path / "target"
        target.mkdir()
        (target / "lib.c").write_text(_CALLEE)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="lib.c", function="compute", status="clean",
            body="clean body", hypothesis="", line=1,
            hypotheses=[{
                "mechanism": _MECHANISM,
                "confidence": "refuted",
                "counter": (
                    "every caller routes through check_limits which "
                    "caps max_size below the wrap threshold"
                ),
                "counter_scope": "cross_function",
            }],
        )
        outcome.review_result = {"hypotheses": outcome.hypotheses}
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {"files": [{
            "path": "lib.c",
            "items": [{"name": "compute", "line_start": 1, "line_end": 4}],
        }]}
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "clean"
        assert calls == []

    def test_gate_consult_after_sink_guard_veto(self, tmp_path, monkeypatch):
        # Veto-order pin: a sink-guard-vetoed confirm must never reach
        # the gate.
        calls = []
        monkeypatch.setattr(
            spg, "evaluate_caller_gate",
            lambda *a, **k: calls.append(a) or None,
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached", lambda fn, js: "guarded",
        )
        result, _ = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }, _MECHANISM, "check-overflow")
        assert result.outcomes[0].status == "clean"
        assert calls == []

    def test_hold_does_not_short_circuit_later_hypotheses(
        self, tmp_path, monkeypatch,
    ):
        # A hold resolves only its own receipt: a later ranked
        # hypothesis carrying a caller-VIOLATING precondition still
        # promotes, and the verdict counters stay consistent across
        # the hold → promote sequence.
        target = tmp_path / "target"
        target.mkdir()
        (target / "req.c").write_text(_NULL_CALLEE)
        (target / "call.c").write_text(
            "int trigger(void)\n{\n    return handle(NULL);\n}\n",
        )
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        overflow_mech = (
            "integer overflow: `total_len` * `elem_cnt` can wrap "
            "(CWE-190 at line 12)"
        )
        outcome = ReviewOutcome(
            file="req.c", function="handle", status="clean",
            body="clean body", hypothesis="", line=1,
            hypotheses=[
                # Ranked first (higher mechanism specificity): holds
                # (its operands are not parameters of handle).
                {"mechanism": overflow_mech, "confidence": "refuted"},
                # Ranked second: promotes on the literal-NULL caller.
                {"mechanism": _NULL_MECHANISM, "confidence": "refuted"},
            ],
        )
        outcome.review_result = {"hypotheses": outcome.hypotheses}
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {"files": [{
            "path": "req.c",
            "items": [{"name": "handle", "line_start": 1, "line_end": 4}],
        }]}
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb",
            lambda h: "check-overflow" if "wrap" in h
            else "check-null-deref",
        )
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: (
                ["smt:check-overflow"]
                if "wrap" in k.get("hypothesis", "")
                else ["smt:check-null-deref"]
            ),
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "finding"
        assert (
            result.outcomes[0].evidence_tool
            == "clean-refuted:smt:check-null-deref"
        )
        assert result.clean == 0
        assert result.suspicious == 0
        assert result.findings == 1
        assert result.refuted_rescued == 1
        assert result.sweep_promoted == 1
        entries = [
            json.loads(line) for line in
            (config.out_dir / ".audit-log.jsonl").read_text().splitlines()
        ]
        actions = [e.get("action") for e in entries]
        assert "smt_promotion_caller_gate_held" in actions
        # The gate record must describe the PROMOTING decision — the
        # earlier hypothesis' hold record on a finding would
        # contradict the verdict for review_result consumers.
        gate_record = result.outcomes[0].review_result["smt_caller_gate"]
        assert gate_record["action"] == "promote"
        assert gate_record["channel_outcome"] == "confirmed"
        assert "call.c" in gate_record["reason"]

    def test_lane2_after_hold_preserves_verification_stamp(
        self, tmp_path, monkeypatch,
    ):
        # A cheap-channel rescue for a LATER hypothesis must not
        # displace the held verification-role clean-refuted stamp —
        # the stronger receipt keeps grading, the new channel is
        # provenance-appended.
        target = tmp_path / "target"
        target.mkdir()
        (target / "lib.c").write_text(_CALLEE)
        (target / "use.c").write_text(
            "int u(void) { return compute(sizeof(int), sizeof(long)); }\n",
        )
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="lib.c", function="compute", status="clean",
            body="clean body", hypothesis="", line=1,
            hypotheses=[
                # Ranked first: SMT confirm, gate holds (sizeof
                # callers uphold the bounded precondition).
                {"mechanism": _MECHANISM, "confidence": "refuted"},
                # Ranked second: cheap-channel (semgrep) confirm.
                {
                    "mechanism": "unchecked copy length into fixed buffer",
                    "confidence": "refuted",
                },
            ],
        )
        outcome.review_result = {"hypotheses": outcome.hypotheses}
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {"files": [{
            "path": "lib.c",
            "items": [{"name": "compute", "line_start": 1, "line_end": 4}],
        }]}
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb",
            lambda h: "check-overflow" if "wrap" in h else None,
        )
        monkeypatch.setattr(
            "core.audit.cwe_dispatch.smt_verb_for_cwe", lambda c: None,
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda chain, **k: (
                ["smt:" + chain[0]["config"]["verb"]]
                if chain and chain[0].get("type") == "smt"
                else ["semgrep:c-overflow-rule"]
            ),
        )
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda m, f, cwe=None, language=None: [{"type": "semgrep", "config": {}}],
        )
        monkeypatch.setattr(orch, "_is_detection_only", lambda t: False)
        _promote_clean_refuted(result, config, checklist=checklist)
        rescued = result.outcomes[0]
        assert rescued.status == "suspicious"
        assert rescued.evidence_tool == (
            "clean-refuted:smt:check-overflow+semgrep:c-overflow-rule"
        )
        assert "[refuted-hypothesis-confirmed via" in rescued.body
        assert "[smt-caller-gate:" in rescued.body
        assert result.clean == 0
        assert result.suspicious == 1
        assert result.refuted_rescued == 1

    def test_gate_module_import_failure_fails_closed(
        self, tmp_path, monkeypatch,
    ):
        # The crash handler constructs its hold from the module-top
        # import: even when the lazy import of the gate module is
        # itself the failure, the consult holds instead of taking
        # down the sweep-promotion phase.
        import sys

        monkeypatch.setitem(
            sys.modules, "core.audit.smt_promotion_gate", None,
        )
        result, config = self._run(tmp_path, monkeypatch, {
            "lib.c": _CALLEE,
            "use.c": "int use_a(void) { return compute(64, 3); }\n",
        }, _MECHANISM, "check-overflow")
        outcome = result.outcomes[0]
        assert outcome.status == "suspicious"
        assert "evaluation errored" in outcome.body
        assert "ModuleNotFoundError" in outcome.body
        rec = json.loads(
            (config.out_dir / "suppressions.jsonl").read_text()
            .splitlines()[0]
        )
        assert rec["dropped"] is False
        assert rec["verdict"] == "smt_promotion_caller_gate"
        assert rec["error_class"] == "ModuleNotFoundError"


class TestCallerGateContainment:
    """The defining-source read is contained: ``file_path`` arrives
    from receipt records (LLM-writable), so an absolute path or a
    ``../`` walk must never read a host file outside the target root
    into gate evidence — the pre-fix bare join did exactly that."""

    def _split_tree(self, tmp_path: Path) -> tuple[Path, Path]:
        target = tmp_path / "target"
        target.mkdir()
        (target / "use.c").write_text(
            "int use_a(void) { return compute(4u, 4u); }\n",
        )
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "callee.c"
        secret.write_text(_CALLEE)
        return target, secret

    def test_escaping_file_path_reads_nothing_and_holds_unbindable(
            self, tmp_path):
        import sys

        target, secret = self._split_tree(tmp_path)
        opened: list = []

        def hook(event, args):
            if event == "open" and args and str(secret) in str(args[0]):
                opened.append(args)

        sys.addaudithook(hook)
        for fp in (str(secret), "../outside/callee.c"):
            decision = evaluate_caller_gate(
                target, fp, "compute",
                "check-overflow", _MECHANISM,
                source=_CALLEE, def_span=(1, 4),
            )
            # No defining source -> no parameter operands -> the
            # receipt binds nothing. Pre-fix, the secret's params
            # bound contracts and the gate adjudicated on them.
            assert decision.action == "hold"
            assert decision.channel_outcome == "unbindable"
        assert opened == [], (
            "out-of-root defining file was opened by the caller gate"
        )

    def test_in_root_defining_source_still_binds(self, tmp_path):
        target, _ = self._split_tree(tmp_path)
        (target / "lib.c").write_text(_CALLEE)
        decision = evaluate_caller_gate(
            target, "lib.c", "compute",
            "check-overflow", _MECHANISM,
            source=_CALLEE, def_span=(1, 4),
        )
        # The contained read binds the parameters exactly as the raw
        # read did: the gate proceeds past unbindable.
        assert decision.channel_outcome != "unbindable"
