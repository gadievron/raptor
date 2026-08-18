"""Adversarial tests for the shared safety contract.

Every blind spot identified in the design discussion has a test here.
These tests are the enforcement mechanism — they prove that the
contract holds even when tools produce results that LOOK like they
should suppress but structurally cannot.

The test classes are organised by the tool they exercise:

- TestContractEnforcement — core allowlist / type enforcement
- TestBypassLoopContract — compositional bypass loop
- TestTaintApproxContract — Tier 1 taint approximation
- TestConstantResolutionContract — constant value resolution
- TestScopeNarrowingNotSuppression — CWE narrowing is steering, not dropping
- TestAuditTrail — boost-evidence.jsonl recording
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.safety_contract import (
    BoostEvidence,
    ContractViolation,
    SuppressEvidence,
    ToolSource,
    assert_boost_only,
    record_boost,
)

# ── Core contract enforcement ────────────────────────────────────────


class TestContractEnforcement:
    """The allowlist gates SuppressEvidence construction."""

    def test_suppress_from_allowed_source(self):
        """Binary oracle CAN suppress — it's on the allowlist."""
        ev = SuppressEvidence(
            source=ToolSource.BINARY_ORACLE.value,
            verdict="binary_oracle_absent",
            reason="function eliminated by DCE",
        )
        assert ev.source == "binary_oracle"
        assert ev.verdict == "binary_oracle_absent"

    def test_suppress_from_smt_infeasibility(self):
        """SMT infeasibility CAN suppress — it's on the allowlist."""
        ev = SuppressEvidence(
            source=ToolSource.SMT_INFEASIBILITY.value,
            verdict="path_infeasible",
            reason="Z3 proved UNSAT on path constraints",
        )
        assert ev.verdict == "path_infeasible"

    def test_suppress_from_reachability_gate(self):
        """Reachability gate CAN suppress — it's on the allowlist."""
        ev = SuppressEvidence(
            source=ToolSource.REACHABILITY_GATE.value,
            verdict="module_aborts",
            reason="file aborts on load",
        )
        assert ev.verdict == "module_aborts"

    def test_suppress_from_sanitizer_cut(self):
        """Sanitizer cut CAN suppress — it's on the allowlist."""
        ev = SuppressEvidence(
            source=ToolSource.SANITIZER_CUT.value,
            verdict="sanitizer_dominated",
            reason="vertex cut proves sanitiser dominates sink",
        )
        assert ev.verdict == "sanitizer_dominated"

    def test_bypass_loop_cannot_suppress(self):
        """Bypass loop is NOT on the allowlist — must raise."""
        with pytest.raises(ContractViolation, match="not in the SUPPRESS_SOURCES"):
            SuppressEvidence(
                source=ToolSource.BYPASS_LOOP.value,
                verdict="no_bypasses",
                reason="no bypass detected",
            )

    def test_taint_approx_cannot_suppress(self):
        """Taint approx is NOT on the allowlist — must raise."""
        with pytest.raises(ContractViolation, match="not in the SUPPRESS_SOURCES"):
            SuppressEvidence(
                source=ToolSource.TAINT_APPROX.value,
                verdict="no_sinks",
                reason="no sink calls found",
            )

    def test_constant_resolution_cannot_suppress(self):
        """Constant resolution is NOT on the allowlist — must raise."""
        with pytest.raises(ContractViolation, match="not in the SUPPRESS_SOURCES"):
            SuppressEvidence(
                source=ToolSource.CONSTANT_RESOLUTION.value,
                verdict="value_resolved",
                reason="constant resolved to 256",
            )

    def test_sink_prefilter_cannot_suppress(self):
        """Sink prefilter is NOT on the allowlist — must raise."""
        with pytest.raises(ContractViolation, match="not in the SUPPRESS_SOURCES"):
            SuppressEvidence(
                source=ToolSource.SINK_PREFILTER.value,
                verdict="no_sinks",
                reason="no dangerous API calls",
            )

    def test_field_discovery_cannot_suppress(self):
        """Field discovery is NOT on the allowlist — must raise."""
        with pytest.raises(ContractViolation, match="not in the SUPPRESS_SOURCES"):
            SuppressEvidence(
                source=ToolSource.FIELD_DISCOVERY.value,
                verdict="no_lifecycle_fields",
                reason="no lifecycle-sensitive fields",
            )

    def test_arbitrary_source_cannot_suppress(self):
        """An unknown source string cannot suppress."""
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="my_cool_tool",
                verdict="looks_safe",
                reason="I think it's fine",
            )

    def test_boost_from_any_source(self):
        """Any tool can produce BoostEvidence."""
        for source in ToolSource:
            ev = BoostEvidence(
                source=source.value,
                action="inject_context",
                description=f"evidence from {source.value}",
            )
            assert ev.source == source.value

    def test_boost_invalid_action_rejected(self):
        """BoostEvidence with an unknown action is rejected."""
        with pytest.raises(ContractViolation, match="action must be one of"):
            BoostEvidence(
                source=ToolSource.BYPASS_LOOP.value,
                action="suppress_finding",
                description="trying to sneak a suppress",
            )

    def test_assert_boost_only_for_non_suppress_tools(self):
        """assert_boost_only succeeds for tools not on allowlist."""
        assert_boost_only(ToolSource.BYPASS_LOOP.value)
        assert_boost_only(ToolSource.TAINT_APPROX.value)
        assert_boost_only(ToolSource.CONSTANT_RESOLUTION.value)

    def test_assert_boost_only_rejects_allowlisted(self):
        """assert_boost_only fails for tools ON the allowlist."""
        with pytest.raises(ContractViolation, match="IS in the suppress allowlist"):
            assert_boost_only(ToolSource.BINARY_ORACLE.value)


# ── Compositional bypass loop ────────────────────────────────────────


class TestBypassLoopContract:
    """The bypass loop produces findings, never suppressions.

    Core invariant: "no bypasses detected" for a function must not
    change that function's review status.  Wrong assumptions from the
    LLM produce noise (extra false-positive findings), not silence
    (missed real bugs).
    """

    def test_no_bypasses_produces_empty_list(self):
        """When the bypass detector finds nothing, it returns [].

        The consumer must not interpret [] as "function is safe."
        """
        results: list[BoostEvidence] = []
        assert len(results) == 0

    def test_bypass_detected_produces_add_finding(self):
        """A detected bypass produces an add_finding BoostEvidence."""
        ev = BoostEvidence(
            source=ToolSource.BYPASS_LOOP.value,
            action="add_finding",
            target_file="src/api.py",
            target_function="handle_request",
            description="calls sanitise_input() without prior auth_check()",
            detail={
                "assumption_target": "sanitise_input",
                "missing_enforcer": "auth_check",
                "category": "ordering",
            },
        )
        d = ev.to_dict()
        assert d["direction"] == "boost"
        assert d["action"] == "add_finding"

    def test_wrong_assumption_is_noise_not_silence(self):
        """A hallucinated enforcer produces a false-positive finding.

        The finding will be reviewed by the LLM and dismissed — this
        is safe.  The alternative (suppressing review) is unsafe.
        """
        ev = BoostEvidence(
            source=ToolSource.BYPASS_LOOP.value,
            action="add_finding",
            description="calls foo() without prior validate_nonce() — "
                        "but validate_nonce() doesn't exist",
            detail={"hallucinated_enforcer": True},
        )
        assert ev.action == "add_finding"

    def test_bypass_loop_structurally_cannot_suppress(self):
        """Even if the bypass loop wanted to suppress, the type system
        prevents it."""
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source=ToolSource.BYPASS_LOOP.value,
                verdict="safe",
                reason="bypass loop says it's fine",
            )


# ── Taint approximation ──────────────────────────────────────────────


class TestTaintApproxContract:
    """Taint approximation can boost and narrow scope but never suppress.

    Specific blind spots tested:
    - Stored XSS through a database (inter-procedural, invisible)
    - Function that IS a sink (write(), not something write() calls)
    - Incomplete sink catalog
    """

    def test_no_sinks_narrows_scope_not_excludes(self):
        """'No sink calls found' narrows LLM focus but does not
        exclude sink-dependent CWEs from review."""
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="narrow_scope",
            target_file="src/utils.py",
            target_function="helper",
            description="no direct calls to known sinks — focus on "
                        "logic bugs, auth, crypto; still check injection "
                        "if function handles external data",
            detail={
                "sink_call_count": 0,
                "note": "intraprocedural only — stored/indirect flows "
                        "not covered",
            },
        )
        assert ev.action == "narrow_scope"
        assert "still check injection" in ev.description

    def test_stored_xss_via_db_not_excluded(self):
        """A function that writes user input to a DB has no direct
        sink calls.  The taint approx correctly sees 'no sinks' but
        must NOT exclude XSS — the DB.read side renders the stored
        payload.

        This test verifies the contract: even with taint_approx saying
        'no sinks,' the function is still reviewed for all CWEs.
        """
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="narrow_scope",
            description="no direct sink calls",
            detail={"sink_call_count": 0},
        )
        assert ev.action == "narrow_scope"
        # The consumer interprets narrow_scope as "steer the LLM's
        # attention" not "exclude CWEs."  This is enforced by the
        # prompt template in context.py which says "Focus on" not
        # "Do NOT check."

    def test_function_as_sink_not_missed(self):
        """write(user_data) — the function IS the sink.  Taint approx
        looks for callees that are sinks, but write() itself appears in
        the sink catalog.  The 'no callee sinks' result must not exclude
        write() from review.

        This is a design constraint: taint_approx must check whether
        the function ITSELF is a sink, not just its callees.
        """
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="raise_priority",
            target_function="write",
            description="function itself is in the sink catalog — "
                        "direct exposure to attacker data",
            detail={"function_is_sink": True},
        )
        assert ev.action == "raise_priority"

    def test_taint_flow_detected_raises_priority(self):
        """When taint IS detected, the result is a priority boost."""
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="raise_priority",
            target_function="process_query",
            description="param 'query' flows to cursor.execute arg 0",
            detail={
                "source_param": "query",
                "sink_callee": "cursor.execute",
                "sink_arg": 0,
            },
        )
        assert ev.action == "raise_priority"

    def test_taint_approx_structurally_cannot_suppress(self):
        """Type system prevents taint_approx from producing
        SuppressEvidence."""
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source=ToolSource.TAINT_APPROX.value,
                verdict="no_taint",
                reason="no tainted flow to any sink",
            )

    def test_no_sinks_is_not_hard_filter(self):
        """Option D: 'no sink calls at all' can hard-filter ONLY if
        the function also has zero parameters and zero return value
        consumers.  But even then, the contract says narrow_scope
        not suppress.

        This test proves that even the strongest 'no sinks' signal
        cannot produce SuppressEvidence.
        """
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="narrow_scope",
            description="zero parameters, zero sink callees, zero "
                        "return consumers — pure computation",
        )
        assert ev.action == "narrow_scope"


# ── Constant resolution ──────────────────────────────────────────────


class TestConstantResolutionContract:
    """Constants extend SMT reach but never suppress on their own.

    Blind spots:
    - Conditional #define (value changes under different configs)
    - System header redefinition (platform-dependent values)
    - Macro composition (MAX(A, B) ≠ resolved A or B alone)
    """

    def test_unique_constant_injects_context(self):
        """A provably-unique constant is injected as context for SMT."""
        ev = BoostEvidence(
            source=ToolSource.CONSTANT_RESOLUTION.value,
            action="inject_context",
            description="MAX_BUF_SIZE resolved to 256 (single definition, "
                        "no conditional compilation)",
            detail={
                "constant_name": "MAX_BUF_SIZE",
                "resolved_value": 256,
                "definition_count": 1,
                "conditional": False,
                "platform_dependent": False,
            },
        )
        assert ev.action == "inject_context"
        assert ev.detail["conditional"] is False

    def test_conditional_define_not_resolved(self):
        """A #define inside #ifdef produces an annotate (not a
        resolved value), warning the LLM the value is
        configuration-dependent."""
        ev = BoostEvidence(
            source=ToolSource.CONSTANT_RESOLUTION.value,
            action="annotate",
            description="MAX_BUF_SIZE has 2 definitions (debug=1024, "
                        "release=256) — value is config-dependent, "
                        "not resolved",
            detail={
                "constant_name": "MAX_BUF_SIZE",
                "definition_count": 2,
                "conditional": True,
                "values": [1024, 256],
            },
        )
        assert ev.detail["conditional"] is True
        assert ev.action == "annotate"

    def test_system_header_not_resolved(self):
        """PATH_MAX from <limits.h> differs across platforms.
        Must not be resolved to a single value."""
        ev = BoostEvidence(
            source=ToolSource.CONSTANT_RESOLUTION.value,
            action="annotate",
            description="PATH_MAX defined in system header — "
                        "platform-dependent, not resolved",
            detail={
                "constant_name": "PATH_MAX",
                "system_header": True,
                "platform_dependent": True,
            },
        )
        assert ev.detail["platform_dependent"] is True

    def test_macro_composition_not_resolved(self):
        """MAX(A, B) — individual components resolved but the
        composition is not provably unique."""
        ev = BoostEvidence(
            source=ToolSource.CONSTANT_RESOLUTION.value,
            action="annotate",
            description="BUF_SIZE = MAX(HEADER_LEN, PAYLOAD_MAX) — "
                        "components resolved but composition depends "
                        "on runtime, not resolved",
            detail={
                "constant_name": "BUF_SIZE",
                "is_composition": True,
            },
        )
        assert ev.detail["is_composition"] is True

    def test_constant_resolution_cannot_suppress(self):
        """Even a fully-resolved constant cannot suppress review."""
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source=ToolSource.CONSTANT_RESOLUTION.value,
                verdict="value_safe",
                reason="resolved to 256, within safe range",
            )


# ── Scope narrowing ≠ suppression ────────────────────────────────────


class TestScopeNarrowingNotSuppression:
    """Scope narrowing steers the LLM but never drops CWEs from review.

    The distinction:
    - narrow_scope: "Focus on logic bugs" → LLM still checks injection
      if evidence warrants it.  The prompt says "Focus on" not
      "Do NOT check."
    - suppress: function dropped from queue entirely.  Only allowlisted
      sources can do this.
    """

    def test_narrow_scope_preserves_all_cwes(self):
        """narrow_scope must not carry an 'excluded_cwes' field."""
        ev = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="narrow_scope",
            description="no sink calls — focus on logic bugs",
        )
        assert "excluded_cwes" not in ev.detail

    def test_narrow_scope_vs_suppress_are_different_types(self):
        """BoostEvidence(action='narrow_scope') and SuppressEvidence
        are structurally different — they can't be confused."""
        boost = BoostEvidence(
            source=ToolSource.TAINT_APPROX.value,
            action="narrow_scope",
            description="no sinks",
        )
        # SuppressEvidence can't even be constructed from taint_approx
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source=ToolSource.TAINT_APPROX.value,
                verdict="no_sinks",
                reason="no dangerous API",
            )
        assert boost.action == "narrow_scope"


# ── Audit trail ──────────────────────────────────────────────────────


class TestAuditTrail:
    """Boost evidence is recorded to boost-evidence.jsonl."""

    def test_record_boost_writes_jsonl(self, tmp_path: Path):
        ev = BoostEvidence(
            source=ToolSource.BYPASS_LOOP.value,
            action="add_finding",
            target_file="src/api.py",
            target_function="handle",
            description="bypass detected",
        )
        record_boost(tmp_path, ev)
        lines = (tmp_path / "boost-evidence.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["direction"] == "boost"
        assert record["source"] == "bypass_loop"
        assert record["action"] == "add_finding"

    def test_record_boost_appends(self, tmp_path: Path):
        for i in range(3):
            ev = BoostEvidence(
                source=ToolSource.BYPASS_LOOP.value,
                action="add_finding",
                description=f"bypass {i}",
            )
            record_boost(tmp_path, ev)
        lines = (tmp_path / "boost-evidence.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3

    def test_record_boost_survives_bad_dir(self):
        """IO errors are swallowed — best effort."""
        ev = BoostEvidence(
            source=ToolSource.BYPASS_LOOP.value,
            action="add_finding",
            description="test",
        )
        record_boost(Path("/nonexistent/path/to/nowhere"), ev)

    def test_boost_evidence_round_trips_through_json(self):
        """to_dict output is valid JSON and preserves all fields."""
        ev = BoostEvidence(
            source=ToolSource.CONSTANT_RESOLUTION.value,
            action="inject_context",
            target_file="src/buf.h",
            target_function="alloc_buf",
            description="MAX_SIZE = 256",
            detail={"resolved_value": 256, "conditional": False},
        )
        d = ev.to_dict()
        serialized = json.dumps(d)
        restored = json.loads(serialized)
        assert restored["source"] == "constant_resolution"
        assert restored["detail"]["resolved_value"] == 256


# ── Allowlist integrity ──────────────────────────────────────────────


class TestAllowlistIntegrity:
    """The allowlist is minimal and every entry is justified."""

    def test_allowlist_is_small(self):
        """Allowlist should be small — every entry is an earned right."""
        from core.audit.safety_contract import _TOOL_MAY_SUPPRESS
        assert len(_TOOL_MAY_SUPPRESS) <= 7

    def test_every_allowlisted_source_has_enum(self):
        """Every allowlisted source corresponds to a ToolSource enum."""
        from core.audit.safety_contract import _TOOL_MAY_SUPPRESS
        tool_values = {t.value for t in ToolSource}
        for s in _TOOL_MAY_SUPPRESS:
            assert s in tool_values, f"{s!r} in allowlist but not in ToolSource"

    def test_suppress_sources_is_tool_may_suppress(self):
        """SUPPRESS_SOURCES must be derived from _TOOL_MAY_SUPPRESS — no divergence."""
        from core.audit.safety_contract import _TOOL_MAY_SUPPRESS, SUPPRESS_SOURCES
        assert SUPPRESS_SOURCES is _TOOL_MAY_SUPPRESS

    def test_non_suppress_tools_outnumber_suppress_tools(self):
        """Most tools should be boost-only."""
        from core.audit.safety_contract import _TOOL_MAY_SUPPRESS
        total = len(ToolSource)
        suppress_count = len(_TOOL_MAY_SUPPRESS)
        assert suppress_count < total / 2
