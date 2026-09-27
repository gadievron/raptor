"""Exact-spelling registry: enumerated admission, fail-closed unknowns.

Verification-grade admission lives in ONE module-level table
(``core.audit.evidence_grade``): the exact-spelling registry for
namespaces that admit per enumerated spelling, the channel
classifiers for the census channels, and the hoisted
``is_verification_evidence`` predicate that ``core.audit.pipeline``'s
merge tie-break delegates to.

Two directions per the receipt discipline:

* fail-closed — an unknown spelling (an unlisted variant under a
  registry-owned namespace, or an unknown variant under a
  classifier-owned namespace whose channel module is unavailable)
  is NOT verification-grade, however plausible it looks; namespace
  membership alone buys nothing for these namespaces.
* non-poisonous / quiet-alarm — the same unknown spelling riding in a
  ``+``-composite next to a known receipt is ignored, never a
  rejection: known receipts keep their grade and the alarm channel
  stays quiet on legitimate runs.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from core.audit import evidence_grade as eg
from core.audit.pipeline import _is_verification_evidence


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A synthetic registry-owned namespace, also present in
    ``_TOOL_NAMESPACES`` — proving the registry OVERRIDES the
    namespace-root admission for its namespaces rather than relying
    on the namespace staying unregistered elsewhere."""
    monkeypatch.setattr(eg, "_EXACT_SPELLING_REGISTRY", {
        "regtool": {
            "regtool:confirmed": eg._ROLE_VERIFICATION,
            "regtool:relation-violation": eg._ROLE_DETECTION,
        },
    })
    monkeypatch.setattr(
        eg, "_TOOL_NAMESPACES",
        frozenset(eg._TOOL_NAMESPACES | {"regtool"}),
    )
    yield


class TestRegistryAdmission:
    """Registry-owned namespaces admit per enumerated spelling only."""

    def test_listed_verification_spelling_qualifies(
        self, registry: None,
    ) -> None:
        assert eg.is_tool_evidence("regtool:confirmed")
        assert eg.is_verification_evidence("regtool:confirmed")

    def test_listed_detection_spelling_never_convicts_alone(
        self, registry: None,
    ) -> None:
        assert not eg.is_tool_evidence("regtool:relation-violation")
        assert not eg.is_verification_evidence("regtool:relation-violation")

    def test_listed_detection_spelling_aggregates(
        self, registry: None,
    ) -> None:
        # Two DISTINCT detection-role namespaces agreeing is the
        # Bayesian aggregation-promotion receipt — the registry's
        # detection spellings participate like channel-classified ones.
        stamp = "regtool:relation-violation+fail_open:handler-outcome-naming"
        assert eg.is_tool_evidence(stamp)
        assert eg.is_verification_evidence(stamp)

    def test_unlisted_spelling_fails_closed(self, registry: None) -> None:
        assert not eg.is_tool_evidence("regtool:novel-variant")
        assert not eg.is_verification_evidence("regtool:novel-variant")

    def test_bare_root_grants_nothing(self, registry: None) -> None:
        # The namespace also sits in _TOOL_NAMESPACES (see fixture):
        # without the registry override the root check would admit it.
        assert not eg.is_tool_evidence("regtool")
        assert not eg.is_verification_evidence("regtool")

    def test_unlisted_spelling_is_non_poisonous(
        self, registry: None,
    ) -> None:
        # Quiet-alarm preservation: an unknown spelling next to a
        # known receipt is ignored — the known receipt keeps its
        # grade, so legitimate runs never trip the CRITICAL
        # promotion-without-tool-evidence alarm over a lane the
        # registry has not learned yet.
        assert eg.is_tool_evidence("semgrep+regtool:novel-variant")
        assert eg.is_verification_evidence(
            "semgrep:rule-123+regtool:novel-variant",
        )

    def test_unlisted_spelling_never_counts_toward_aggregation(
        self, registry: None,
    ) -> None:
        # Ignored means IGNORED: no role, so it cannot be one of the
        # two distinct detection namespaces either.
        assert not eg.is_tool_evidence(
            "regtool:novel-variant+fail_open:handler-outcome-naming",
        )


class TestClassifierUnavailableFailClosed:
    """Unknown variants under a classifier-owned namespace fail closed
    when the channel module is unavailable, instead of riding the
    namespace-root prefix admission."""

    @pytest.fixture(autouse=True)
    def _no_channel_classifiers(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            eg, "_channel_detection_classifier", lambda ns: None,
        )

    @pytest.mark.parametrize("stamp", [
        # Unknown variants: previously admitted by the namespace-root
        # check the moment the channel classifier could not veto them.
        "smt:brand-new-verb",
        "joern:novel-variant",
        # Whole-namespace detection channels enumerate no verification
        # spellings at all — nothing under them may convict alone.
        "sanwit",
        "sanwit:brand-new:ctx",
        "gadget_oracle:novel",
        # Guard-blind symbolic reachability is detection-role even
        # with the channel classifier gone (heuristic mirror).
        "symbolic:symbolic-reach",
    ])
    def test_unknown_variant_not_tool_evidence(self, stamp: str) -> None:
        assert not eg.is_tool_evidence(stamp), stamp
        assert not eg.is_verification_evidence(stamp), stamp

    @pytest.mark.parametrize("stamp", [
        # Enumerated verification spellings survive the fallback
        # byte-identical to the classifier-present grading.
        "smt",
        "smt:check-overflow",
        "smt:check-integer-narrowing:witness",
        # A concrete solver model keeps its receipt on detection
        # verbs too (mirrors sweep.is_detection_rule_id).
        "smt:check-toctou:witness",
        "smt:disproof:sat",
        "joern",
        "joern:flow",
        "joern:guard-dominance",
        # Pipeline-minted dynamic-tail family (sweep.py's
        # joern:taint:<function>-><sink>).
        "joern:taint:parse_frame->memcpy",
        "symbolic",
        "symbolic:symbolic-pc-hijack",
        "symbolic:symbolic-reach-crash",
        "consistency:guard-presence",
        "fail_open:tristate",
        "ptr_lifecycle:stale-alias",
        "lock_region:callback-under-lock",
        "resource_bounds:unbounded-accumulation",
        "release_order:release-before-verify",
        "protocol_state:invariant-violated",
    ])
    def test_enumerated_spelling_preserved(self, stamp: str) -> None:
        assert eg.is_tool_evidence(stamp), stamp

    @pytest.mark.parametrize("stamp", [
        # Known detection variants keep their heuristic grading —
        # aggregation-eligible, never convict alone.
        "joern:live",
        "joern:pre_sweep",
        "smt:check-toctou",
        "smt:check-encoding-residual:witness",
        "consistency:cwe190-majority",
        "fail_open:handler-outcome-naming",
    ])
    def test_known_detection_variant_still_detection(
        self, stamp: str,
    ) -> None:
        assert eg._is_detection_variant(stamp), stamp
        assert not eg.is_tool_evidence(stamp), stamp

    def test_unknown_variant_is_non_poisonous(self) -> None:
        # The composite policy ignores the ungradable part; the known
        # receipt next to it keeps the stamp's grade.
        assert eg.is_tool_evidence("semgrep:rule-123+smt:brand-new-verb")

    def test_channel_authority_unchanged_when_available(self) -> None:
        # Discriminating counterpart for the fallback gate: this test
        # class stubs the classifiers OUT; the module-level default
        # (classifier importable) keeps namespace-grading with the
        # channel as the authority — pinned by the allowlist suite
        # (test_verification_evidence_allowlist) running unstubbed.
        assert eg._channel_detection_classifier("smt") is None  # stubbed


class TestCodeqlLlmEntry:
    """The LIVE ``codeql-llm`` registry entry: CodeQL dataflow verdicts
    whose query predicates were LLM-authored mint
    ``codeql-llm:dataflow`` (packages.llm_analysis.verification_tier.
    mechanical_receipt) — enumerated DETECTION role, so the receipt
    corroborates and aggregates but never convicts, skips, or breaks a
    merge tie alone. The mechanical ``codeql`` namespace stays
    UNOWNED: its pack-query producer mints open-ended
    ``codeql:<query-stem>`` spellings that enumeration would
    fail-close."""

    def test_spelling_is_detection_role(self) -> None:
        assert eg.registry_owns("codeql-llm:dataflow")
        assert eg.registered_spelling_role("codeql-llm:dataflow") == (
            eg._ROLE_DETECTION
        )
        assert not eg.is_tool_evidence("codeql-llm:dataflow")
        assert not eg.is_verification_evidence("codeql-llm:dataflow")

    def test_spelling_aggregates_with_a_second_namespace(self) -> None:
        stamp = "codeql-llm:dataflow+joern:live"
        assert eg.is_tool_evidence(stamp)
        assert eg.is_verification_evidence(stamp)

    def test_unlisted_spelling_fails_closed_non_poisonous(self) -> None:
        assert not eg.is_tool_evidence("codeql-llm:novel")
        assert not eg.is_verification_evidence("codeql-llm:novel")
        assert not eg.is_tool_evidence("codeql-llm")
        # Quiet alarm: ignored next to a known receipt.
        assert eg.is_tool_evidence("semgrep+codeql-llm:novel")

    def test_mechanical_codeql_namespace_stays_unowned(self) -> None:
        # The open-ended pack-query lane keeps its grade byte-for-byte
        # — ownership of the mechanical namespace would demote every
        # codeql:<query-stem> receipt the audit sweep mints.
        assert not eg.registry_owns("codeql:dataflow")
        assert eg.is_tool_evidence("codeql")
        assert eg.is_tool_evidence("codeql:dataflow")
        assert eg.is_tool_evidence("codeql:some-pack-query-stem")
        assert eg.is_verification_evidence("codeql:dataflow")


class TestDifferentialEntry:
    """The LIVE ``differential`` registry entry — the joint migration
    test. The differential-execution lane enumerates exactly two
    executed-witness spellings; this class proves (a) both survive
    into the registry byte-exact with full verification grade, and
    (b) the fail-closed posture holds: an unknown ``differential:*``
    spelling is NOT verification-grade, even when the namespace root
    is separately admitted in ``_TOOL_NAMESPACES`` (the producing
    lane's own namespace-root entry must not re-open prefix
    admission when both changes are present)."""

    _SPELLINGS = ("differential:confirmed",
                  "differential:relation-violation")

    def test_enumerated_spellings_survive_byte_exact(self) -> None:
        ns = eg._EXACT_SPELLING_REGISTRY["differential"]
        assert set(ns) == set(self._SPELLINGS)
        for spelling in self._SPELLINGS:
            assert eg.registry_owns(spelling)
            assert eg.registered_spelling_role(spelling) == (
                eg._ROLE_VERIFICATION
            )
            assert eg.is_tool_evidence(spelling)
            assert eg.is_verification_evidence(spelling)
            assert _is_verification_evidence(spelling)

    def test_unknown_spelling_not_verification_grade(self) -> None:
        for stamp in ("differential", "differential:agreement",
                      "differential:observed",
                      "differential:confirmed-variant"):
            assert not eg.is_tool_evidence(stamp), stamp
            assert not eg.is_verification_evidence(stamp), stamp
            assert not _is_verification_evidence(stamp), stamp

    def test_fail_closed_survives_namespace_root_admission(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Composition shape: the producing lane also lists the bare
        # root in _TOOL_NAMESPACES. Registry ownership must keep
        # overriding — unknown variants stay out of verification
        # grade, the enumerated pair keeps its grade.
        monkeypatch.setattr(
            eg, "_TOOL_NAMESPACES",
            frozenset(eg._TOOL_NAMESPACES | {"differential"}),
        )
        assert not eg.is_tool_evidence("differential")
        assert not eg.is_tool_evidence("differential:agreement")
        assert not eg.is_verification_evidence("differential:agreement")
        for spelling in self._SPELLINGS:
            assert eg.is_verification_evidence(spelling)

    def test_unknown_spelling_is_non_poisonous(self) -> None:
        # Quiet alarm: the unknown variant riding next to a known
        # receipt is ignored, never a rejection.
        assert eg.is_tool_evidence("semgrep+differential:agreement")
        assert eg.is_verification_evidence(
            "differential:confirmed+differential:agreement",
        )


class TestOrchestratorDetectionOnlyConsult:
    """The promotion surface's role table
    (``core.audit.orchestrator._is_detection_only``) consults the
    registry: enumerated roles decide, unlisted spellings under an
    owned namespace fail CLOSED (detection role, no promotion)."""

    def test_live_entry_is_detection_only(self) -> None:
        from core.audit.orchestrator import (
            _is_detection_only,
            _promotion_grade_receipt,
        )
        assert _is_detection_only("codeql-llm:dataflow")
        assert not _promotion_grade_receipt("codeql-llm:dataflow")

    def test_unlisted_spelling_fails_closed(self) -> None:
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only("codeql-llm:novel")
        assert _is_detection_only("codeql-llm")

    def test_unowned_namespace_unchanged(self) -> None:
        from core.audit.orchestrator import _is_detection_only
        assert not _is_detection_only("codeql:dataflow")
        assert not _is_detection_only("codeql:some-pack-query-stem")

    def test_registered_verification_spelling_promotes(
        self, registry: None,
    ) -> None:
        from core.audit.orchestrator import _is_detection_only
        assert not _is_detection_only("regtool:confirmed")
        assert _is_detection_only("regtool:relation-violation")
        assert _is_detection_only("regtool:novel-variant")


class TestPipelineDelegation:
    """pipeline._is_verification_evidence is a thin delegate — one
    admission authority, no drift."""

    @pytest.mark.parametrize("stamp", [
        "smt:check-integer-narrowing",
        "clean-refuted:smt",
        "smt:check-integer-narrowing+llm-claimed:smt",
        "consistency:cwe190-majority+fail_open:handler-outcome-naming",
        "",
        "futuretool:confirmed",
        "journal:recall:run-3",
        "smt:check-toctou",
        "llm-claimed:smt+joern",
        "prefilter:sink-scan+semgrep:rule",
        "smt:check-toctou+smt:check-auth-bypass",
    ])
    def test_delegate_matches_registry_predicate(self, stamp: str) -> None:
        assert _is_verification_evidence(stamp) == \
            eg.is_verification_evidence(stamp), stamp

    def test_registry_reaches_the_merge_tie_break(
        self, registry: None,
    ) -> None:
        # The delegation is live, not a copy: a registry entry
        # patched into evidence_grade changes the pipeline predicate.
        assert _is_verification_evidence("regtool:confirmed")
        assert not _is_verification_evidence("regtool:novel-variant")
