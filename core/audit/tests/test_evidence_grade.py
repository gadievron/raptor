"""Tests for core.audit.evidence_grade."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.audit.evidence_grade import (
    VALID_EVIDENCE_TOOLS,
    Confidence,
    EvidenceSource,
    default_confidence,
    finding_confidence,
    format_evidence_chain,
    grade_evidence,
    grade_evidence_record,
    grade_review_result,
    is_tool_evidence,
    sanitize_llm_evidence_tool,
)


class TestEvidenceSource:
    def test_mechanical_sources_are_high(self):
        mechanical = [
            EvidenceSource.TREE_SITTER,
            EvidenceSource.TAINT_APPROX,
            EvidenceSource.CALL_GRAPH,
            EvidenceSource.JOERN,
            EvidenceSource.SEMGREP,
            EvidenceSource.CODEQL,
        ]
        for src in mechanical:
            assert default_confidence(src) == Confidence.HIGH

    def test_llm_sources_are_low(self):
        assert default_confidence(EvidenceSource.LLM_INFERRED) == Confidence.LOW
        assert default_confidence(EvidenceSource.LLM_SPEC) == Confidence.LOW

    def test_dynamic_sources_are_high(self):
        assert default_confidence(EvidenceSource.DYNAMIC_SANITIZER) == Confidence.HIGH
        assert default_confidence(EvidenceSource.DYNAMIC_FRIDA) == Confidence.HIGH

    def test_dynamic_crash_is_medium(self):
        assert default_confidence(EvidenceSource.DYNAMIC_CRASH) == Confidence.MEDIUM

    def test_dark_verify_is_high(self):
        assert default_confidence(EvidenceSource.DARK_VERIFY) == Confidence.HIGH

    def test_compilation_is_medium(self):
        assert default_confidence(EvidenceSource.COMPILATION) == Confidence.MEDIUM

    def test_corroborated_llm_is_medium(self):
        assert default_confidence(EvidenceSource.LLM_CORROBORATED) == Confidence.MEDIUM


class TestGradeEvidence:
    def test_creates_graded_evidence(self):
        ge = grade_evidence(EvidenceSource.JOERN, "3 flows found")
        assert ge.source == EvidenceSource.JOERN
        assert ge.confidence == Confidence.HIGH
        assert ge.description == "3 flows found"

    def test_confidence_override(self):
        ge = grade_evidence(
            EvidenceSource.LLM_INFERRED, "hypothesis",
            confidence_override=Confidence.HIGH,
        )
        assert ge.confidence == Confidence.HIGH

    def test_to_dict(self):
        ge = grade_evidence(
            EvidenceSource.SEMGREP, "match",
            detail="rule: tainted-format-string",
        )
        d = ge.to_dict()
        assert d["source"] == "mechanical:semgrep"
        assert d["confidence"] == "high"
        assert d["description"] == "match"
        assert d["detail"] == "rule: tainted-format-string"

    def test_to_dict_no_detail(self):
        ge = grade_evidence(EvidenceSource.JOERN, "flow")
        d = ge.to_dict()
        assert "detail" not in d

    def test_priority_ordering(self):
        high = grade_evidence(EvidenceSource.JOERN, "x")
        med = grade_evidence(EvidenceSource.NEGATIVE_SPACE, "y")
        low = grade_evidence(EvidenceSource.LLM_INFERRED, "z")
        assert high.priority < med.priority < low.priority


class TestFindingConfidence:
    def test_empty_chain_is_low(self):
        assert finding_confidence([]) == Confidence.LOW

    def test_single_high(self):
        chain = [grade_evidence(EvidenceSource.JOERN, "flow")]
        assert finding_confidence(chain) == Confidence.HIGH

    def test_single_low(self):
        chain = [grade_evidence(EvidenceSource.LLM_INFERRED, "guess")]
        assert finding_confidence(chain) == Confidence.LOW

    def test_mechanical_plus_llm_upgrades(self):
        chain = [
            grade_evidence(EvidenceSource.JOERN, "flow"),
            grade_evidence(EvidenceSource.LLM_INFERRED, "hypothesis"),
        ]
        conf = finding_confidence(chain)
        assert conf == Confidence.HIGH

    def test_multiple_low_stays_low(self):
        chain = [
            grade_evidence(EvidenceSource.LLM_INFERRED, "a"),
            grade_evidence(EvidenceSource.LLM_SPEC, "b"),
        ]
        assert finding_confidence(chain) == Confidence.LOW

    def test_dynamic_is_high(self):
        chain = [grade_evidence(EvidenceSource.DYNAMIC_SANITIZER, "crash")]
        assert finding_confidence(chain) == Confidence.HIGH


@dataclass
class FakeEvidenceRecord:
    file: str = "a.c"
    function: str = "f"
    sink_unreachable: bool = False
    taint_approx: Any | None = None
    taint_summary: Any | None = None
    joern_flows: list[Any] = field(default_factory=list)
    imported_joern_flows: list[Any] = field(default_factory=list)
    joern_unguarded_sinks: list[Any] = field(default_factory=list)
    codeql_alerts: list[Any] = field(default_factory=list)
    semgrep_hits: list[Any] = field(default_factory=list)
    negative_space: list[Any] = field(default_factory=list)
    binary_sink_edges: list[Any] = field(default_factory=list)


@dataclass
class FakeTaintApprox:
    dangerous_flows: dict[int, list] = field(default_factory=dict)
    has_opaque_flow: bool = False
    params: list = field(default_factory=list)


class TestGradeEvidenceRecord:
    def test_empty_record(self):
        rec = FakeEvidenceRecord()
        items = grade_evidence_record(rec)
        assert items == []

    def test_taint_approx(self):
        rec = FakeEvidenceRecord(
            taint_approx=FakeTaintApprox(
                dangerous_flows={0: [("sink", 0)]},
                params=["buf"],
            ),
        )
        items = grade_evidence_record(rec)
        assert len(items) == 1
        assert items[0].source == EvidenceSource.TAINT_APPROX

    def test_joern_flows(self):
        rec = FakeEvidenceRecord(joern_flows=[{"flow": 1}, {"flow": 2}])
        items = grade_evidence_record(rec)
        assert any(e.source == EvidenceSource.JOERN for e in items)
        assert "2 Joern CPG flows" in items[0].description

    def test_multiple_sources(self):
        rec = FakeEvidenceRecord(
            joern_flows=[{"f": 1}],
            semgrep_hits=[{"h": 1}],
            negative_space=[{"n": 1}],
        )
        items = grade_evidence_record(rec)
        sources = {e.source for e in items}
        assert EvidenceSource.JOERN in sources
        assert EvidenceSource.SEMGREP in sources
        assert EvidenceSource.NEGATIVE_SPACE in sources

    def test_sink_unreachable(self):
        rec = FakeEvidenceRecord(sink_unreachable=True)
        items = grade_evidence_record(rec)
        assert len(items) == 1
        assert items[0].source == EvidenceSource.CALL_GRAPH

    def test_binary_edges(self):
        rec = FakeEvidenceRecord(
            binary_sink_edges=[{"edge": 1}],
        )
        items = grade_evidence_record(rec)
        assert items[0].source == EvidenceSource.BINARY_ORACLE


class TestGradeReviewResult:
    def test_empty_result(self):
        assert grade_review_result(None) == []
        assert grade_review_result({}) == []

    def test_hypothesis(self):
        items = grade_review_result({"hypothesis": "buffer overflow"})
        assert len(items) == 1
        assert items[0].source == EvidenceSource.LLM_INFERRED

    def test_spec_deviation(self):
        items = grade_review_result({
            "spec_deviation": {
                "deviation": "missing length check",
                "expected": "check len",
                "actual": "no check",
            },
        })
        assert any(e.source == EvidenceSource.LLM_SPEC for e in items)

    def test_typestate_confirmed_without_context_is_llm_inferred(self):
        # ``typestate_violation`` is parsed model JSON. Without the
        # pipeline confirming typestate context was injected for this
        # function, a fabricated ``confirmed: true`` must not mint a
        # ``mechanical:`` namespace item nor HIGH confidence.
        items = grade_review_result({
            "typestate_violation": {
                "confirmed": True,
                "violation_kind": "double_free",
                "type_name": "malloc/free",
            },
        })
        assert not any(e.source == EvidenceSource.TYPESTATE for e in items)
        assert not any(e.confidence == Confidence.HIGH for e in items)
        ts = [e for e in items if "double_free" in e.description]
        assert len(ts) == 1
        assert ts[0].source == EvidenceSource.LLM_INFERRED

    def test_typestate_confirmed_with_matching_context_corroborated(self):
        ctx = [SimpleNamespace(
            type_name="malloc/free", violation_kind="double_free",
        )]
        items = grade_review_result(
            {
                "typestate_violation": {
                    "confirmed": True,
                    "violation_kind": "double_free",
                    "type_name": "malloc/free",
                },
            },
            typestate_context=ctx,
        )
        ts = [e for e in items if "double_free" in e.description]
        assert len(ts) == 1
        assert ts[0].source == EvidenceSource.LLM_CORROBORATED
        assert ts[0].confidence == Confidence.MEDIUM

    def test_typestate_confirmed_type_mismatch_not_corroborated(self):
        # Context was injected, but for a DIFFERENT resource type than
        # the model's claim names — no corroboration.
        ctx = [SimpleNamespace(
            type_name="fopen/fclose", violation_kind="missing_cleanup",
        )]
        items = grade_review_result(
            {
                "typestate_violation": {
                    "confirmed": True,
                    "violation_kind": "double_free",
                    "type_name": "malloc/free",
                },
            },
            typestate_context=ctx,
        )
        ts = [e for e in items if "double_free" in e.description]
        assert len(ts) == 1
        assert ts[0].source == EvidenceSource.LLM_INFERRED

    def test_typestate_unconfirmed_skipped(self):
        items = grade_review_result({
            "typestate_violation": {
                "confirmed": False,
                "violation_kind": "double_free",
            },
        })
        ts = [e for e in items if e.source == EvidenceSource.TYPESTATE]
        assert len(ts) == 0

    def test_evidence_tool_dynamic(self):
        items = grade_review_result({}, evidence_tool="dynamic:sanitizer")
        assert any(e.source == EvidenceSource.DYNAMIC_SANITIZER for e in items)

    def test_evidence_tool_dynamic_crash(self):
        items = grade_review_result({}, evidence_tool="dynamic:crash")
        crash = [e for e in items if e.source == EvidenceSource.DYNAMIC_CRASH]
        assert len(crash) == 1
        assert crash[0].confidence == Confidence.MEDIUM

    def test_evidence_tool_joern(self):
        items = grade_review_result({}, evidence_tool="joern")
        assert any(e.source == EvidenceSource.JOERN for e in items)

    def test_evidence_tool_semgrep(self):
        items = grade_review_result({}, evidence_tool="semgrep")
        assert any(e.source == EvidenceSource.SEMGREP for e in items)

    def test_evidence_tool_codeql(self):
        items = grade_review_result({}, evidence_tool="codeql")
        assert any(e.source == EvidenceSource.CODEQL for e in items)

    def test_evidence_tool_coccinelle(self):
        items = grade_review_result({}, evidence_tool="coccinelle")
        assert any(e.source == EvidenceSource.COCCINELLE for e in items)

    def test_evidence_tool_smt(self):
        items = grade_review_result({}, evidence_tool="smt")
        assert any(e.source == EvidenceSource.SMT for e in items)

    def test_evidence_tool_dark_verify_confirmed(self):
        items = grade_review_result({}, evidence_tool="dark_verify:confirmed")
        assert any(e.source == EvidenceSource.DARK_VERIFY for e in items)

    def test_evidence_tool_dark_verify_refuted(self):
        items = grade_review_result({}, evidence_tool="dark_verify:refuted")
        dv = [e for e in items if e.source == EvidenceSource.DARK_VERIFY]
        assert len(dv) == 1
        assert "refuted" in dv[0].description

    def test_evidence_tool_compilation(self):
        items = grade_review_result({}, evidence_tool="compilation")
        assert any(e.source == EvidenceSource.COMPILATION for e in items)

    def test_evidence_tool_plus_joined(self):
        items = grade_review_result({}, evidence_tool="semgrep+joern")
        sources = {e.source for e in items}
        assert EvidenceSource.SEMGREP in sources
        assert EvidenceSource.JOERN in sources

    def test_evidence_tool_plus_joined_no_duplicates(self):
        items = grade_review_result({}, evidence_tool="semgrep+semgrep")
        semgrep = [e for e in items if e.source == EvidenceSource.SEMGREP]
        assert len(semgrep) == 1

    def test_malformed_plus_stamp_not_graded(self):
        assert grade_review_result({}, evidence_tool="semgrep+") == []
        assert grade_review_result({}, evidence_tool="+joern") == []
        assert grade_review_result({}, evidence_tool="semgrep++joern") == []

    def test_cli_namespaced_stamps_grade(self):
        for bare in ("joern", "semgrep", "codeql", "coccinelle", "smt"):
            cli = f"{bare}:cli"
            assert is_tool_evidence(cli), cli
            items = grade_review_result({}, evidence_tool=cli)
            assert len(items) > 0, f"{cli} should grade"

    def test_cli_namespaced_stamps_leave_namespaced_unchanged(self):
        for ns in ("dynamic:sanitizer", "dark_verify:confirmed", "frida:runtime"):
            assert ":" in ns
            assert is_tool_evidence(ns)


class TestFormatEvidenceChain:
    def test_empty_chain(self):
        assert format_evidence_chain([]) == ""

    def test_renders_sorted_by_priority(self):
        chain = [
            grade_evidence(EvidenceSource.LLM_INFERRED, "guess"),
            grade_evidence(EvidenceSource.JOERN, "flow"),
        ]
        text = format_evidence_chain(chain)
        joern_pos = text.index("joern")
        llm_pos = text.index("inferred")
        assert joern_pos < llm_pos

    def test_includes_confidence_tag(self):
        chain = [grade_evidence(EvidenceSource.SEMGREP, "match")]
        text = format_evidence_chain(chain)
        assert "[HIGH]" in text
        assert "semgrep" in text


class TestIsToolEvidence:
    """is_tool_evidence rejects LLM-hallucinated stamps."""

    def test_canonical_stamps_accepted(self):
        for stamp in VALID_EVIDENCE_TOOLS:
            assert is_tool_evidence(stamp), stamp

    def test_namespaced_composites_accepted(self):
        assert is_tool_evidence("semgrep:rule-123")
        assert is_tool_evidence("critique:prefilter:rule-id")
        assert is_tool_evidence("smt:path_feasibility")
        assert is_tool_evidence("sarif_cache:hit")
        assert is_tool_evidence("dynamic:sanitizer")
        assert is_tool_evidence("frida:runtime")
        assert is_tool_evidence("dark_verify:confirmed")

    def test_llm_hallucinations_rejected(self):
        assert not is_tool_evidence("Semgrep")
        assert not is_tool_evidence("CodeQL")
        assert not is_tool_evidence("llm")
        assert not is_tool_evidence("llm-claimed:codeql")

    def test_triage_stamps_are_provenance_not_tool_evidence(self):
        # A 500-token batch glance (or the skip classifier) records
        # which shortcut produced the verdict — it never ran a tool.
        # Blessing it used to short-circuit refutation gates, the G2
        # finding gate, and the promotion alarm.
        assert not is_tool_evidence("triage:batch")
        assert not is_tool_evidence("triage:classifier")
        assert not is_tool_evidence("semgrep+triage:batch")

    def test_plus_joined_multi_tool_accepted(self):
        assert is_tool_evidence("semgrep+joern")
        assert is_tool_evidence("semgrep+joern+codeql")
        assert is_tool_evidence("semgrep:rule-123+joern")

    def test_plus_joined_with_hallucination_rejected(self):
        assert not is_tool_evidence("semgrep+llm")
        assert not is_tool_evidence("Semgrep+joern")

    def test_empty_and_none_rejected(self):
        assert not is_tool_evidence("")
        assert not is_tool_evidence("none")


class TestDetectionVariantFirewall:
    """Detection-grade rule-id variants are corroboration, never full
    tool evidence — for EVERY channel, as classified by the channel's
    own is_detection_rule_id."""

    def test_naming_variants_are_not_tool_evidence(self):
        # fail_open / ptr_lifecycle / lock_region previously slipped
        # the firewall: a lone -naming stamp passed as full evidence.
        for stamp in (
            "fail_open:handler-outcome-naming",
            "fail_open:ignored-return-naming",
            "ptr_lifecycle:stale-alias-naming",
            "lock_region:callback-under-lock-naming",
            "resource_bounds:unbounded-accumulation-naming",
            "release_order:release-before-verify-naming",
        ):
            assert not is_tool_evidence(stamp), stamp

    def test_majority_and_unreceipted_variants_rejected(self):
        for stamp in (
            "consistency:return-check-majority",
            "protocol_state:invariant-violated-unreceipted",
            "protocol_state:dead-state-field",
            "protocol_state:unvalidated-peer-write",
        ):
            assert not is_tool_evidence(stamp), stamp

    def test_full_grade_channel_stamps_still_qualify(self):
        for stamp in (
            "fail_open:handler-outcome",
            "ptr_lifecycle:stale-alias",
            "lock_region:callback-under-lock",
            "consistency:return-check",
            "release_order:release-before-verify",
            "protocol_state:invariant-violated",
        ):
            assert is_tool_evidence(stamp), stamp

    def test_variant_riding_a_receipt_composite_qualifies(self):
        assert is_tool_evidence("smt+ptr_lifecycle:stale-alias-naming")
        assert is_tool_evidence("fail_open:handler-outcome-naming+coccinelle")

    def test_smt_detection_verbs_are_not_tool_evidence(self):
        # Incident regression (openssh instrumented corpus): these
        # stamps backed 88 exported tool_backed findings with 0
        # survivors through /validate — the channel's own role table
        # (sweep._SMT_VERB_ROLES) already classified them detection,
        # but the firewall never consulted it.
        for stamp in (
            "smt:check-toctou",
            "smt:check-null-propagation",
            "smt:check-auth-bypass",
            "smt:check-resource-leak",
            "smt:check-early-release",
            "smt:check-lock-domain",
            "smt:check-overflow-to-oob",
            "smt:check-negative-bypass",
            "smt:invariant-preservation",
        ):
            assert not is_tool_evidence(stamp), stamp

    def test_smt_verification_verbs_and_witnesses_qualify(self):
        # Verification-role verbs and concrete solver witnesses keep
        # their receipts; dead_path_smt is a real Z3 run that was
        # previously invisible to the firewall.
        for stamp in (
            "smt",
            "smt:check-overflow",
            "smt:check-oob",
            "smt:check-null-deref",
            "smt:validate-path",
            "smt:check-auth-bypass:witness",
            "dead_path_smt",
            "dead_path_smt:witness",
        ):
            assert is_tool_evidence(stamp), stamp

    def test_bare_joern_reachability_is_not_tool_evidence(self):
        # joern:live / joern:pre_sweep are guard-blind reachability —
        # detection-role at the promotion sites; grading them as
        # sustain-capable evidence here let the same receipt hold an
        # LLM-authored claim against demotion (the trap-flap shape
        # survived only through re-review dice).
        assert not is_tool_evidence("joern:live")
        assert not is_tool_evidence("joern:pre_sweep")

    def test_joern_verification_stamps_still_qualify(self):
        for stamp in (
            "joern",
            "joern:flow",
            "joern:guard-dominance",
            "joern:taint:parse_header->memcpy",
        ):
            assert is_tool_evidence(stamp), stamp

    def test_joern_live_riding_a_receipt_composite_qualifies(self):
        assert is_tool_evidence("semgrep:rule-1+joern:live")
        assert not is_tool_evidence("joern:live+joern:pre_sweep")

    def test_joern_firewall_matches_channel_classifier(self):
        from core.audit.evidence_grade import _is_detection_variant
        from core.audit.joern_verify import (
            DETECTION_STAMPS,
            is_detection_rule_id,
        )

        for stamp in sorted(DETECTION_STAMPS) + ["joern:flow", "joern"]:
            assert _is_detection_variant(stamp) == \
                is_detection_rule_id(stamp), stamp

    def test_referee_does_not_sustain_on_bare_joern_live(self):
        # The verdict-weight consumer: a prior journal entry whose only
        # receipt is bare reachability must not be graded tool-evidenced
        # (an LLM-only /validate ruling can then demote it).
        from core.audit.feedback import _prior_has_tool_evidence

        class _Entry:
            evidence_tools = ["joern:live"]

        assert _prior_has_tool_evidence(_Entry()) is False

    def test_matches_each_channel_classifier(self):
        """The firewall must agree with every channel's own contract."""
        import importlib

        from core.audit.evidence_grade import _is_detection_variant
        for namespace, mod_name in (
            ("consistency", "core.audit.peer_evidence"),
            ("fail_open", "core.audit.fail_open_verify"),
            ("lock_region", "core.audit.lock_region"),
            ("ptr_lifecycle", "core.audit.ptr_lifecycle"),
            ("release_order", "core.audit.release_order"),
            ("resource_bounds", "core.audit.resource_bounds"),
            ("protocol_state", "core.audit.protocol_state"),
        ):
            mod = importlib.import_module(mod_name)
            suffix = mod.DETECTION_VARIANT_SUFFIX
            variant = f"{namespace}:x{suffix}"
            assert _is_detection_variant(variant) == \
                mod.is_detection_rule_id(variant), variant


class TestSanitizeLlmEvidenceTool:
    """LLM-supplied evidence_tool values must not pass is_tool_evidence."""

    def test_exact_tool_names_namespaced(self):
        for name in ("semgrep", "joern", "codeql", "smt"):
            result = sanitize_llm_evidence_tool(name)
            assert result.startswith("llm-claimed:"), name
            assert not is_tool_evidence(result), name

    def test_llm_self_descriptions_collapsed(self):
        for val in ("llm", "manual review", "code review", "none", "n/a", ""):
            assert sanitize_llm_evidence_tool(val) == ""

    def test_already_prefixed_unchanged(self):
        assert sanitize_llm_evidence_tool("llm-claimed:joern") == "llm-claimed:joern"

    def test_none_input(self):
        assert sanitize_llm_evidence_tool(None) == ""

    def test_whitespace_stripped(self):
        assert sanitize_llm_evidence_tool("  semgrep  ").startswith("llm-claimed:")


class TestProvenanceWrappers:
    """``clean-refuted:<tool>`` wraps a real receipt in promotion
    provenance — the inner stamp decides, on its own merits."""

    def test_wrapped_tool_qualifies(self):
        assert is_tool_evidence("clean-refuted:smt")
        assert is_tool_evidence("clean-refuted:smt:check-overflow")
        assert is_tool_evidence("clean-refuted:semgrep+joern")

    def test_wrapper_alone_is_not_evidence(self):
        assert not is_tool_evidence("clean-refuted:")
        assert not is_tool_evidence("clean-refuted:llm-claimed:smt")

    def test_wrapped_detection_variant_still_may_not_convict(self):
        # Wrapping must not launder a detection-role stamp into
        # promoting evidence.
        assert not is_tool_evidence("clean-refuted:consistency:x-majority")

    def test_llm_claimed_namespacing_survives_wrapping(self):
        assert not is_tool_evidence(
            sanitize_llm_evidence_tool("clean-refuted:smt"),
        )


class TestLiveProducerNamespaces:
    """Producer namespaces the firewall was missing: genuine pipeline
    stamps (never reachable from raw model output — sanitization
    namespaces those under llm-claimed:) must grade as tool evidence
    instead of tripping the chokepoint demotion + CRITICAL alarm."""

    def test_live_producer_stamps_qualify(self):
        for stamp in (
            "lifecycle",                        # _proactive_validate
            "api_boundary:caller-contract",     # api_boundary.RULE_ID
            "integer_truncation:trunc-assign",  # binary-context sweeps
            "proto_length:len-mismatch",
            "struct_field:field-oob",
            "validate:observed_runtime",        # validate_bridge
            "validate:replayed_crash",
            "validate:confirmed-history",       # findings_export receipt
            "insufficient_guard_smt:witness",   # condition-SMT detectors
            "signed_mismatch_smt:witness",
        ):
            assert is_tool_evidence(stamp), stamp

    def test_llm_claimed_variants_still_rejected(self):
        for stamp in (
            "llm-claimed:lifecycle",
            "llm-claimed:validate:observed_runtime",
            "llm-claimed:insufficient_guard_smt:witness",
        ):
            assert not is_tool_evidence(stamp), stamp


class TestCompositePolicy:
    """'+'-composite judgment: known parts decide; model-authored
    parts poison; unknown pipeline producers are ignored."""

    def test_all_known_namespaces_accepted(self):
        assert is_tool_evidence("smt:path-feasible+lifecycle")
        assert is_tool_evidence(
            "api_boundary:caller-contract+integer_truncation:t1",
        )

    def test_mixed_unknown_part_judged_by_known_parts(self):
        # A producer namespace this table hasn't learned yet must not
        # veto the real receipt next to it (the CRITICAL-alarm-on-
        # legitimate-runs shape).
        assert is_tool_evidence("semgrep+future_producer:rule-1")
        assert is_tool_evidence("future_producer:rule-1+joern:flow")
        # ...but unknown parts alone still prove nothing.
        assert not is_tool_evidence("future_producer:rule-1")

    def test_llm_claimed_part_poisons_whole_composite(self):
        # sanitize prefixes the FULL raw model string, so the model
        # wrote "foo+semgrep" — the semgrep part is claim, not receipt.
        assert not is_tool_evidence("llm-claimed:foo+semgrep")
        assert not is_tool_evidence("semgrep+llm-claimed:foo")
        assert not is_tool_evidence("llm-claimed:foo+dynamic:crash")

    def test_miscased_tool_name_poisons(self):
        # Pipeline stamps are lowercase by construction; a miscased
        # spelling is model-authored text.
        assert not is_tool_evidence("Semgrep+joern")
        assert not is_tool_evidence("joern+CodeQL:rule")

    def test_aggregation_shape_two_detection_namespaces_qualifies(self):
        # The Bayesian aggregation lane stamps "+".join(confirmed)
        # after >=2 independent detection channels cross the posterior
        # threshold — the chokepoint must accept its own receipt.
        assert is_tool_evidence(
            "consistency:return-check-majority"
            "+fail_open:handler-outcome-naming",
        )
        assert not is_tool_evidence("consistency:return-check-majority")
        # Two variants of ONE namespace are correlated, not
        # independent — never the aggregation shape.
        assert not is_tool_evidence(
            "consistency:return-check-majority"
            "+consistency:flag-mode-majority",
        )


class TestProducerStampClosure:
    """Mechanical closure of pipeline evidence_tool producers against
    the evidence-grade firewall.

    Every stamp a pipeline producer can commit on a ``finding``-status
    outcome must satisfy ``is_tool_evidence`` — a producer outside the
    registry fires the CRITICAL promotion alarm on legitimate runs and
    is demoted at export (the same enumeration-boundary shape has now
    produced firewall gaps twice). The sweep enumerates the real
    producers from source: constructor keywords, promotion/stamp
    helpers, and attribute assignments, resolving function-local
    constant bindings (including paired ``status, stamp = ...`` tuple
    assigns, so a stamp only ever committed with a non-``finding``
    status is not a violation)."""

    _AUDIT_ROOT = Path(__file__).resolve().parents[1]

    # Stamps a producer deliberately commits only on demotable /
    # non-finding outcomes. Additions require a behavioral test
    # proving the stamp never rides a "finding" status.
    _DELIBERATELY_DEMOTABLE: frozenset = frozenset()

    @classmethod
    def _modules(cls):
        import ast as _ast

        for path in sorted(cls._AUDIT_ROOT.rglob("*.py")):
            parts = path.relative_to(cls._AUDIT_ROOT).parts
            if "tests" in parts or "scripts" in parts:
                continue
            yield path, _ast.parse(path.read_text())

    @staticmethod
    def _scopes(tree):
        """Yield (scope_node, body_statements) for the module and each
        function, so constant resolution stays function-local."""
        import ast as _ast

        yield tree, tree.body
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                yield node, node.body

    @staticmethod
    def _local_bindings(scope_node):
        """name -> set of str constants assigned in this scope, plus
        the list of paired tuple-assign bindings ({name: const|None})."""
        import ast as _ast

        consts: dict = {}
        pairs: list = []
        for node in _ast.walk(scope_node):
            if isinstance(node, _ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, _ast.Tuple)
                        and isinstance(node.value, _ast.Tuple)
                        and len(target.elts) == len(node.value.elts)
                        and all(isinstance(t, _ast.Name) for t in target.elts)
                    ):
                        pair = {}
                        for t, v in zip(target.elts, node.value.elts):
                            val = (
                                v.value
                                if isinstance(v, _ast.Constant)
                                and isinstance(v.value, str) else None
                            )
                            pair[t.id] = val
                            if val is not None:
                                consts.setdefault(t.id, set()).add(val)
                        pairs.append(pair)
                    elif isinstance(target, _ast.Name) and isinstance(
                        node.value, _ast.Constant,
                    ) and isinstance(node.value.value, str):
                        consts.setdefault(target.id, set()).add(
                            node.value.value,
                        )
            elif isinstance(node, _ast.AnnAssign) and isinstance(
                node.target, _ast.Name,
            ) and isinstance(node.value, _ast.Constant) and isinstance(
                node.value.value, str,
            ):
                consts.setdefault(node.target.id, set()).add(
                    node.value.value,
                )
        return consts, pairs

    @classmethod
    def _finding_stamps(cls):
        """Enumerate (location, stamp) for every constant-resolvable
        stamp a producer can commit alongside status="finding"."""
        import ast as _ast

        found: list = []
        call_sites = 0
        for path, tree in cls._modules():
            rel = path.relative_to(cls._AUDIT_ROOT)
            for scope, _body in cls._scopes(tree):
                consts, pairs = cls._local_bindings(scope)
                for node in _ast.walk(scope):
                    if not isinstance(node, _ast.Call):
                        continue
                    kw = {k.arg: k.value for k in node.keywords if k.arg}
                    fn = node.func
                    fn_name = (
                        fn.id if isinstance(fn, _ast.Name)
                        else fn.attr if isinstance(fn, _ast.Attribute)
                        else ""
                    )
                    # Promotion / stamping helpers: the tool argument
                    # becomes the receipt of a finding-status outcome.
                    if fn_name in ("_promote_outcome", "_stamp_evidence"):
                        args = list(node.args)
                        tool = args[1] if len(args) > 1 else kw.get("tool")
                        if isinstance(tool, _ast.Constant) and isinstance(
                            tool.value, str,
                        ):
                            found.append((f"{rel}:{node.lineno}", tool.value))
                        elif isinstance(tool, _ast.JoinedStr) and tool.values:
                            first = tool.values[0]
                            if isinstance(first, _ast.Constant):
                                # A prefixed receipt: the prefix must be
                                # a known namespace or a provenance
                                # wrapper (judged at runtime on the
                                # wrapped receipt).
                                found.append((
                                    f"{rel}:{node.lineno}",
                                    ("prefix", str(first.value)),
                                ))
                        continue
                    if "evidence_tool" not in kw or "status" not in kw:
                        continue
                    call_sites += 1
                    status_node, ev_node = kw["status"], kw["evidence_tool"]

                    def _resolve(n):
                        if isinstance(n, _ast.Constant) and isinstance(
                            n.value, str,
                        ):
                            return {n.value}, None
                        if isinstance(n, _ast.Name):
                            return set(consts.get(n.id, ())), n.id
                        return set(), None

                    status_vals, status_name = _resolve(status_node)
                    ev_vals, ev_name = _resolve(ev_node)
                    if "finding" not in status_vals:
                        continue
                    if status_name and ev_name:
                        # Paired tuple assigns bind status and stamp
                        # together — only stamps paired with "finding"
                        # are commitments the firewall must accept.
                        paired = [
                            p for p in pairs
                            if status_name in p and ev_name in p
                        ]
                        if paired:
                            for p in paired:
                                if p[status_name] == "finding" and p[
                                    ev_name
                                ] is not None:
                                    found.append((
                                        f"{rel}:{node.lineno}", p[ev_name],
                                    ))
                            continue
                    for stamp in ev_vals:
                        found.append((f"{rel}:{node.lineno}", stamp))
        return found, call_sites

    # Full AST parse + producer-site walk of every core/audit runtime
    # module with function-local constant resolution — genuinely heavy;
    # over the fast tier's budget. The attribute-writer sibling keeps a
    # sweep of the same closure in the default tier.
    @pytest.mark.slow
    def test_every_finding_producer_stamp_passes_the_firewall(self):
        from core.audit.evidence_grade import (
            _PROVENANCE_WRAPPERS,
            _TOOL_NAMESPACES,
        )

        found, call_sites = self._finding_stamps()
        # Non-vacuity: the sweep must actually see the producer
        # surface (helper literals and constructor sites both exist).
        assert call_sites >= 3, "sweep no longer sees producer calls"
        assert len(found) >= 2, "sweep no longer resolves any stamps"
        violations = []
        for loc, stamp in found:
            if isinstance(stamp, tuple):  # ("prefix", value)
                prefix = stamp[1]
                ns = prefix.split(":", 1)[0]
                if ns not in _TOOL_NAMESPACES and not any(
                    prefix.startswith(w) or w.startswith(prefix)
                    for w in _PROVENANCE_WRAPPERS
                ):
                    violations.append((loc, prefix))
                continue
            if stamp in self._DELIBERATELY_DEMOTABLE:
                continue
            if not is_tool_evidence(stamp):
                violations.append((loc, stamp))
        assert not violations, (
            "finding-status producers commit stamps the evidence-grade "
            f"firewall rejects (CRITICAL-alarm + export demotion): "
            f"{violations}"
        )

    def test_attribute_stamp_writers_pass_the_firewall(self):
        """Promotion paths that stamp via ``outcome.evidence_tool = X``
        (dynamic sweep, dark-verify) — every constant they can write
        must be firewall-known or deliberately demotable."""
        import ast as _ast

        found = []
        for path, tree in self._modules():
            rel = path.relative_to(self._AUDIT_ROOT)
            for node in _ast.walk(tree):
                if not isinstance(node, _ast.Assign):
                    continue
                for target in node.targets:
                    if (
                        isinstance(target, _ast.Attribute)
                        and target.attr == "evidence_tool"
                        and isinstance(node.value, _ast.Constant)
                        and isinstance(node.value.value, str)
                        and node.value.value
                    ):
                        found.append(
                            (f"{rel}:{node.lineno}", node.value.value),
                        )
        assert found, "sweep no longer sees attribute stamp writers"
        violations = [
            (loc, stamp) for loc, stamp in found
            if stamp not in self._DELIBERATELY_DEMOTABLE
            and not is_tool_evidence(stamp)
        ]
        assert not violations, (
            "attribute stamp writers emit firewall-rejected stamps: "
            f"{violations}"
        )
