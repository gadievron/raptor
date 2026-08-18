"""Dispatch coverage for the second D1 long-tail wave (A5): CWE-908,
CWE-835, CWE-345.

The final comparison audit warned ``review emitted CWE-345 / CWE-908 /
CWE-835 but no tool-chain dispatch entry exists`` — notably the run's
one promoted finding was CWE-908, whose family had no channel (the
promotion went through generic precondition receipts). Each family is
wired to the channels that can actually adjudicate it; the
empty-dispatch warning must no longer fire for these, and families
that remain unmapped keep their synthesis seeding. Hermetic — no LLM,
no tool subprocesses.
"""

from __future__ import annotations

from core.audit.api_boundary import api_boundary_applicable
from core.audit.compiler_sweep import compiler_applicable
from core.audit.consistency_verify import consistency_applicable
from core.audit.cwe_dispatch import (
    infer_cwe_from_hypothesis,
    lookup,
    smt_verb_for_cwe,
)
from core.audit.fail_open_verify import fail_open_applicable
from core.audit.joern_verify import flow_chain_entry
from core.audit.orchestrator import (
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
)


class TestCwe908UninitialisedResource:
    """Wired to the channels that did the promoted finding's work:
    joern flows + consistency census (the precondition sweep runs from
    review preconditions and is CWE-independent)."""

    def test_dispatch_entry(self):
        entry = lookup("CWE-908")
        assert entry is not None
        assert entry["joern"] is True
        assert "memcpy" in entry["sinks"]
        assert entry["codeql"] == "cpp/uninitialized-local"

    def test_joern_flow_channel(self):
        flow = flow_chain_entry("CWE-908")
        assert flow and flow["type"] == "joern_flow"
        assert "memcpy" in flow["config"]["sinks"]

    def test_consistency_census_channel(self):
        assert consistency_applicable("CWE-908")

    def test_fallback_chain(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-908")}
        assert "joern" in types
        assert "joern_flow" in types
        assert "consistency" in types


class TestCwe835LoopBound:
    """Loop-bound family → smt (counter-wrap feasibility) + compiler
    (analyzer infinite-loop diagnostics, confirm-only)."""

    def test_dispatch_entry(self):
        assert lookup("CWE-835") is not None
        assert smt_verb_for_cwe("CWE-835") == "check-overflow"

    def test_compiler_channel_confirm_only(self):
        assert compiler_applicable("CWE-835")
        from core.audit.compiler_sweep import COMPILER_CWE_MAP
        spec = COMPILER_CWE_MAP["CWE-835"]
        assert spec.reliable is False  # silence never refutes
        assert "-Wanalyzer-infinite-loop" in spec.gcc_ids

    def test_fallback_chain(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-835")}
        assert types >= {"compiler", "smt"}


class TestCwe345Authenticity:
    """Authenticity family → the role-bound channels: fail_open
    (verification role x permissive outcome) + api_boundary (caller
    obligation at call sites)."""

    def test_dispatch_entry(self):
        assert lookup("CWE-345") is not None

    def test_role_channels(self):
        assert fail_open_applicable("CWE-345")
        assert api_boundary_applicable("CWE-345")

    def test_fallback_chain(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-345")}
        assert types >= {"fail_open", "api_boundary"}


class TestWarningAndSynthesisTail:
    def test_no_empty_dispatch_warning_for_new_families(self, monkeypatch):
        import core.audit.orchestrator as _orch

        warned = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in ("CWE-908", "CWE-835", "CWE-345"):
            chain = _hypothesis_to_tool_chain("", "a.c", cwe=cwe)
            assert chain, f"{cwe} must dispatch at least one channel"
        assert warned == []

    def test_unmapped_tail_still_warns_and_seeds_synthesis(
        self, monkeypatch,
    ):
        """Families outside every dispatch table keep the loud warning
        (whose message routes suspicious verdicts to on-demand checker
        synthesis)."""
        import core.audit.orchestrator as _orch

        warned = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        chain = _cwe_fallback_chain("CWE-1104")  # unmaintained 3p — no channel
        assert chain == []
        assert warned == ["CWE-1104"]

    def test_hypothesis_keyword_inference(self):
        # Uninitialised phrasings keep routing to CWE-457 (earlier
        # row, full dispatch entry) — CWE-908 dispatch fires from the
        # review's cwe field, not keyword fallback.
        assert infer_cwe_from_hypothesis(
            "uninitialized stack bytes copied out to the caller",
        ) == "CWE-457"
        assert infer_cwe_from_hypothesis(
            "attacker-controlled step causes an infinite loop: the "
            "exit condition is never reached",
        ) == "CWE-835"
        assert infer_cwe_from_hypothesis(
            "the payload's signature is not verified before the "
            "message is processed",
        ) == "CWE-345"

    def test_existing_first_match_behaviour_unchanged(self):
        # Pre-existing families keep winning on their keywords
        # (appended rows, first match wins).
        assert infer_cwe_from_hypothesis(
            "uninitialized variable used in comparison",
        ) == "CWE-457"
        assert infer_cwe_from_hypothesis(
            "authentication bypass via empty password",
        ) == "CWE-863"
