"""Gadget-oracle channel wiring: chain-builder hooks, evidence
grading, substrate registration, coverage discipline, the orchestrator
leg, and the audit-context prompt block.

Hermetic: the channel entry point is stubbed at the module seam — no
tree-sitter parse, no filesystem scan. The live flow matrix lives in
core/analysis/tests/test_gadget_oracle.py.
"""

from __future__ import annotations

import json

import pytest

from core.analysis.gadget_oracle import (
    GadgetOracleEvidence,
    RULE_ABSENCE,
    RULE_CHAIN,
)

_HYP = "POP chain: a __destruct gadget reaches unlink via property state"


class TestChainBuilders:
    def test_cwe_hook_appends_leg_on_php(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        chain = _cwe_fallback_chain(
            "CWE-502", "object injection via unserialize", "web/a.php")
        assert {"type": "gadget_oracle", "config": {}} in chain

    def test_cwe_hook_drops_leg_off_php(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        chain = _cwe_fallback_chain(
            "CWE-502", "object injection", "src/a.py")
        assert {"type": "gadget_oracle", "config": {}} not in chain

    def test_cwe_hook_fail_closed_without_file_context(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        chain = _cwe_fallback_chain("CWE-502", "object injection", "")
        assert {"type": "gadget_oracle", "config": {}} not in chain

    def test_other_cwe_grows_no_leg(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        chain = _cwe_fallback_chain("CWE-89", "sql injection", "a.php")
        assert {"type": "gadget_oracle", "config": {}} not in chain

    def test_keyword_hook_appends_leg(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(_HYP, "web/a.php")
        assert {"type": "gadget_oracle", "config": {}} in chain

    def test_keyword_hook_language_gated(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(_HYP, "src/a.c")
        assert {"type": "gadget_oracle", "config": {}} not in chain

    def test_non_gadget_hypothesis_grows_no_leg(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "buffer overflow in the parser", "web/a.php")
        assert {"type": "gadget_oracle", "config": {}} not in chain

    def test_cwe_and_keyword_dedup_to_one_leg(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            _HYP, "web/a.php", cwe="CWE-502")
        legs = [e for e in chain if e["type"] == "gadget_oracle"]
        assert len(legs) == 1


class TestEvidenceGrading:
    def test_stamp_never_qualifies_alone(self):
        from core.audit.evidence_grade import is_tool_evidence

        assert not is_tool_evidence(RULE_CHAIN)
        assert not is_tool_evidence(RULE_ABSENCE)

    def test_two_detection_namespaces_aggregate(self):
        from core.audit.evidence_grade import is_tool_evidence

        assert is_tool_evidence(f"{RULE_CHAIN}+joern:live")

    def test_not_promotion_grade(self):
        from core.audit.orchestrator import _promotion_grade_receipt

        assert not _promotion_grade_receipt(RULE_CHAIN)
        assert not _promotion_grade_receipt(RULE_ABSENCE)

    def test_detection_classifier_module_registered(self):
        from core.audit.evidence_grade import (
            _DETECTION_CLASSIFIER_MODULES,
        )

        assert (_DETECTION_CLASSIFIER_MODULES["gadget_oracle"]
                == "core.analysis.gadget_oracle")

    def test_receipt_map_prose_reaches_real_stamps(self):
        from core.audit.evidence_grade import _RECEIPT_MAP

        assert "gadget_oracle" in _RECEIPT_MAP
        # Lookup is exact-part-then-bare-namespace: the bare row is
        # the one that renders for the two-segment rule ids; a
        # namespaced row would be a dead key.
        for key in _RECEIPT_MAP:
            if key.startswith("gadget_oracle:"):
                raise AssertionError(
                    f"unreachable gadget_oracle receipt-map key "
                    f"{key!r} — only the bare namespace row renders"
                )

    def test_string_heuristic_fallback_matches_channel(self):
        # The evidence_grade string fallback (for hosts where the
        # channel module is unavailable) must mirror
        # is_detection_rule_id: the whole namespace is detection.
        from core.audit.evidence_grade import _is_detection_variant

        assert _is_detection_variant(RULE_CHAIN)
        assert _is_detection_variant(RULE_ABSENCE)


class TestSubstrateRegistration:
    def test_registered_file_scope(self):
        from core.audit.substrate import registered_scope

        assert registered_scope("gadget_oracle") == "file"

    def test_php_covered_others_not(self, tmp_path):
        from core.audit.substrate import file_substrate_coverage

        (tmp_path / "a.php").write_text("<?php\n")
        (tmp_path / "b.c").write_text("int main(void){}\n")
        cov = file_substrate_coverage(
            "gadget_oracle", target_path=tmp_path, file_path="a.php",
        )
        assert cov.covered is True
        cov = file_substrate_coverage(
            "gadget_oracle", target_path=tmp_path, file_path="b.c",
        )
        assert cov.covered is False


class TestCoverageDiscipline:
    def test_absent_from_silence_to_clean_map(self):
        """The channel must never license silence->clean: absence is
        hint-tier until corpus-earned, so a dispatched gadget_oracle
        row cannot resolve a class clean."""
        from core.audit.tool_coverage import _CWE_TOOL_MAP

        for tools in _CWE_TOOL_MAP.values():
            assert "gadget_oracle" not in tools

    def test_not_early_exit_skippable(self):
        from core.audit.orchestrator import _EARLY_EXIT_SKIPPABLE_TYPES

        assert "gadget_oracle" not in _EARLY_EXIT_SKIPPABLE_TYPES


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target, out_dir=None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = True


class TestOrchestratorLeg:
    def _canned(self, outcome, rule_id, reason="r"):
        return GadgetOracleEvidence(
            outcome=outcome, reason=reason, rule_id=rule_id,
            file_path="web/a.php", function_name="g",
        )

    def _dispatch(self, tmp_path, monkeypatch, result,
                  file_path="web/a.php"):
        import core.analysis.gadget_oracle as gadget_mod
        from core.audit.orchestrator import _run_tool_chain

        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text(
            "<?php function g(){}\n")
        (tmp_path / "web" / "b.c").write_text("int g(void){}\n")
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        calls = []

        def fake_check(*args, **kwargs):
            calls.append((args, kwargs))
            return result

        monkeypatch.setattr(
            gadget_mod, "run_gadget_oracle_check", fake_check)
        confirmed = _run_tool_chain(
            [{"type": "gadget_oracle", "config": {}}],
            config=_Cfg(tmp_path, out_dir),
            file_path=file_path,
            function_name="g",
            source="function g() {}",
            hypothesis=_HYP,
            line_start=1,
            cwe="CWE-502",
        )
        return confirmed, calls, out_dir

    def test_confirmed_receipt_and_audit_log(self, tmp_path, monkeypatch):
        result = self._canned("confirmed", RULE_CHAIN)
        result.chains = [{"class": "A", "magic_method": "__destruct"}]
        confirmed, calls, out_dir = self._dispatch(
            tmp_path, monkeypatch, result)
        assert confirmed == [RULE_CHAIN]
        assert len(calls) == 1
        log = (out_dir / ".audit-log.jsonl").read_text()
        rows = [json.loads(line) for line in log.splitlines()]
        receipt = next(
            r for r in rows if r.get("action") == "gadget_oracle_check")
        assert receipt["rule_id"] == RULE_CHAIN
        assert receipt["chains"][0]["class"] == "A"

    def test_absence_never_confirms(self, tmp_path, monkeypatch):
        confirmed, calls, _ = self._dispatch(
            tmp_path, monkeypatch,
            self._canned("inconclusive", RULE_ABSENCE,
                         "no-gadgets-complete-census"),
        )
        assert confirmed == []
        assert len(calls) == 1

    def test_skipped_lands_in_skip_record(self, tmp_path, monkeypatch):
        import core.analysis.gadget_oracle as gadget_mod
        from core.audit.orchestrator import _run_tool_chain

        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text(
            "<?php function g(){}\n")
        monkeypatch.setattr(
            gadget_mod, "run_gadget_oracle_check",
            lambda *a, **k: self._canned(
                "skipped", RULE_ABSENCE, "grammar-unavailable"),
        )
        skipped = set()
        confirmed = _run_tool_chain(
            [{"type": "gadget_oracle", "config": {}}],
            config=_Cfg(tmp_path),
            file_path="web/a.php",
            function_name="g",
            source="function g() {}",
            hypothesis=_HYP,
            line_start=1,
            skipped_types=skipped,
        )
        assert confirmed == []
        assert "gadget_oracle" in skipped

    def test_channel_exception_lands_in_errored(
            self, tmp_path, monkeypatch):
        import core.analysis.gadget_oracle as gadget_mod
        from core.audit.orchestrator import _run_tool_chain

        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text(
            "<?php function g(){}\n")

        def boom(*a, **k):
            raise RuntimeError("scan exploded")

        monkeypatch.setattr(
            gadget_mod, "run_gadget_oracle_check", boom)
        errored = set()
        confirmed = _run_tool_chain(
            [{"type": "gadget_oracle", "config": {}}],
            config=_Cfg(tmp_path),
            file_path="web/a.php",
            function_name="g",
            source="function g() {}",
            hypothesis=_HYP,
            line_start=1,
            errored_types=errored,
        )
        assert confirmed == []
        assert "gadget_oracle" in errored

    def test_substrate_gate_skips_non_php_pre_dispatch(
            self, tmp_path, monkeypatch):
        confirmed, calls, _ = self._dispatch(
            tmp_path, monkeypatch,
            self._canned("confirmed", RULE_CHAIN),
            file_path="web/b.c",
        )
        assert confirmed == []
        assert calls == []  # never dispatched — substrate skip


def _prompt_ctx(gadget_context):
    return {
        "file": "handler.php",
        "function": "interstitial:1-40",
        "line_start": 1,
        "source": "<?php $x = 1;",
        "metadata": {},
        "callers": [],
        "callees": [],
        "sinks": [],
        "existing_annotation": None,
        "threat_model": None,
        "include_context": None,
        "gadget_context": gadget_context,
    }


def _artifact(tmp_path, *, chains=(), sites=(), complete=True):
    report = {
        "tier": "hint",
        "target_path": str(tmp_path),
        "census": {"complete": complete, "php_files": 2,
                   "parsed_clean": 2 if complete else 1,
                   "incomplete_reasons": [] if complete
                   else ["parse-errors"]},
        "chains": list(chains),
        "unserialize_sites": list(sites),
    }
    (tmp_path / "gadget-chains.json").write_text(json.dumps(report))
    return report


_CHAIN_ROW = {
    "class": "TempLogger", "file": "lib/logger.php",
    "magic_method": "__destruct", "line": 4,
    "trigger": "unserialize", "steps": [],
    "property_path": "path",
    "sink": {"category": "file", "callee": "unlink", "line": 5,
             "excerpt": "unlink($this->path)"},
    "availability": "not_established",
}

_SITE_ROW = {"file": "handler.php", "line": 2,
             "request_derived": True, "excerpt": "($_COOKIE['s'])"}


class TestGadgetContextBlock:
    def test_facts_built_from_artifact(self, tmp_path):
        from core.audit.context import _build_gadget_context

        _artifact(tmp_path, chains=[_CHAIN_ROW], sites=[_SITE_ROW])
        facts = _build_gadget_context(tmp_path, "handler.php")
        assert facts is not None
        assert facts["tier"] == "hint"
        assert facts["chains_total"] == 1
        assert facts["unserialize_sites_in_file"][0]["line"] == 2
        assert facts["qualifier"]

    def test_absent_without_artifact(self, tmp_path):
        from core.audit.context import _build_gadget_context

        assert _build_gadget_context(tmp_path, "handler.php") is None
        assert _build_gadget_context(None, "handler.php") is None

    def test_renderer_hint_framing_and_census(self, tmp_path):
        from core.audit.context import (
            _build_gadget_context,
            format_context_for_prompt,
        )

        _artifact(tmp_path, chains=[_CHAIN_ROW], sites=[_SITE_ROW])
        facts = _build_gadget_context(tmp_path, "handler.php")
        out = format_context_for_prompt(_prompt_ctx(facts))
        assert "### PHP gadget surface (hint-tier)" in out
        assert "TempLogger" in out
        assert "verify against source" in out
        assert "availability: not_established" in out
        assert "unserialize() site in this file at line 2" in out
        assert "request data" in out
        assert "- Census: " in out
        assert "never treat as a verdict input" in out.lower()

    def test_renderer_absence_framing(self, tmp_path):
        from core.audit.context import (
            _build_gadget_context,
            format_context_for_prompt,
        )

        _artifact(tmp_path, chains=[], sites=[_SITE_ROW])
        facts = _build_gadget_context(tmp_path, "handler.php")
        out = format_context_for_prompt(_prompt_ctx(facts))
        assert "No magic-method gadget chains found" in out
        assert "never" in out.lower()

    def test_renderer_escapes_hostile_artifact_strings(self, tmp_path):
        from core.audit.context import (
            _build_gadget_context,
            format_context_for_prompt,
        )

        hostile = dict(_CHAIN_ROW)
        hostile["class"] = "Evil\x1b]0;pwn\x07"
        hostile["file"] = "handler.php"
        _artifact(tmp_path, chains=[hostile])
        facts = _build_gadget_context(tmp_path, "handler.php")
        out = format_context_for_prompt(_prompt_ctx(facts))
        assert "\x1b" not in out
        assert "\x07" not in out

    def test_no_block_without_facts(self):
        from core.audit.context import format_context_for_prompt

        out = format_context_for_prompt(_prompt_ctx(None))
        assert "PHP gadget surface" not in out


class TestCweDispatchEntryUnchanged:
    """The CWE-502 stock entry keeps its pre-oracle chain byte-for-
    byte — the oracle joins additively via the channel hook, never by
    editing the dispatch dict."""

    def test_stock_entry_keys(self):
        from core.audit.cwe_dispatch import lookup

        entry = lookup("CWE-502")
        assert entry is not None
        assert entry["joern"] is True
        assert entry["codeql"] == "py/unsafe-deserialization"
        assert entry["semgrep"] == "php/unserialize-taint.yaml"
        assert "gadget_oracle" not in entry


@pytest.mark.parametrize("stamp", [RULE_CHAIN, RULE_ABSENCE])
def test_journal_chokepoint_accepts_namespace(stamp):
    """A pipeline-minted gadget_oracle stamp must be a recognized
    namespace (aggregation-eligible), or the journal chokepoint
    force-demotes it and fires the injection alarm."""
    from core.audit.evidence_grade import _TOOL_NAMESPACES

    assert stamp.split(":", 1)[0] in _TOOL_NAMESPACES
