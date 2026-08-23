"""Dispatch routing for the observed empty-dispatch classes: CWE-829
gets a real chain; CWE-778 / CWE-1164 are not-tool-verifiable by
policy; placeholder classes (CWE-NOINFO / CWE-000 / CWE-Other) are
normalized into keyword re-classification; and the on-demand synthesis
lane requires a harm-stating hypothesis before it may attempt.

A long instrumented run emitted all four shapes; the ones without
dispatch entries fell to on-demand checker synthesis, which promoted
suspicious -> finding on self-referential pattern matches — including
two whose hypothesis prose explicitly refuted harm. Hermetic — no LLM,
no tool subprocesses.
"""

from __future__ import annotations

import json
import logging

from core.audit.checker_synthesis import (
    _KNOWN_IMPACT_PRIMITIVES,
    ondemand_synthesis_refusal_reason,
    synthesize_verification_rule,
)
from core.audit.cwe_dispatch import (
    infer_cwe_from_hypothesis,
    is_placeholder_cwe,
    joern_applicable,
    lookup,
    not_tool_verifiable_reason,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _cwe_fallback_chain,
    _effective_cwe,
    _hypothesis_to_tool_chain,
    _synthesize_unmapped_suspicious,
)

# A harm-free hypothesis naming no recognized mechanism — the shape
# the run's inverted promotions took (prose refuting harm, promoted to
# finding/high through a self-referential pattern match). Note the
# run's literal prose ("performs no dereference of li ... even if li
# is NULL") is deliberately NOT used for the placeholder tests: its
# "deref...null" substring matches the CWE-476 keyword row, so the
# machinery reclassifies it and the real null-propagation chain
# adjudicates — the correct outcome for that specimen (see
# test_observed_prose_reclassifies_to_real_chain).
_NO_HARM_HYPOTHESIS = (
    "Empty audit hook body: the stub performs no work and cannot "
    "misbehave."
)

_OBSERVED_RUN_PROSE = (
    "Empty function body performs no dereference of li, no arithmetic, "
    "no I/O — cannot cause memory unsafety even if li is NULL."
)


def _outcome(status="suspicious", hypothesis="h", cwe=""):
    o = ReviewOutcome(
        file="a.c", function="f", status=status,
        body="b", hypothesis=hypothesis, line=3,
    )
    o.review_result = {"hypothesis": hypothesis}
    if cwe:
        o.review_result["cwe"] = cwe
    return o


class TestCwe829UntrustedInclusion:
    """Untrusted-functionality inclusion → joern taint to the
    code-inclusion/loading sinks (CWE-90 precedent: joern+sinks-only
    entries are real chains)."""

    def test_dispatch_entry(self):
        entry = lookup("CWE-829")
        assert entry is not None
        assert entry["joern"] is True
        assert "include" in entry["sinks"]
        assert "dlopen" in entry["sinks"]

    def test_no_generic_load_sink(self):
        # The joern runner matches dotted sinks by trailing segment —
        # System.load would degrade to bare `load` and match
        # yaml.load/json.load/pickle.load in every frontend.
        sinks = lookup("CWE-829")["sinks"]
        assert "System.load" not in sinks
        assert "load" not in sinks
        assert all(s.split(".")[-1] != "load" for s in sinks)
        assert "System.loadLibrary" in sinks

    def test_joern_applicable(self):
        assert joern_applicable("CWE-829")

    def test_fallback_chain_nonempty(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-829")}
        assert "joern" in types

    def test_no_empty_dispatch_warning(self, monkeypatch):
        import core.audit.orchestrator as _orch

        warned = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        assert _hypothesis_to_tool_chain("", "a.c", cwe="CWE-829")
        assert warned == []

    def test_keyword_inference(self):
        assert infer_cwe_from_hypothesis(
            "the script includes functionality from an untrusted "
            "control sphere",
        ) == "CWE-829"
        assert infer_cwe_from_hypothesis(
            "loads a module from an untrusted url at runtime",
        ) == "CWE-829"

    def test_existing_first_match_behaviour_unchanged(self):
        assert infer_cwe_from_hypothesis(
            "command injection via unsanitized filename",
        ) == "CWE-78"
        assert infer_cwe_from_hypothesis(
            "use-after-free of the freed buffer",
        ) == "CWE-416"


class TestNotToolVerifiablePolicy:
    """CWE-778 / CWE-1164: quality/operational classes no deterministic
    tool can adjudicate — parked at hypothesis grade with the reason
    recorded, never synthesis candidates."""

    def test_policy_reasons_present(self):
        assert not_tool_verifiable_reason("CWE-778")
        assert not_tool_verifiable_reason("CWE-1164")
        assert not_tool_verifiable_reason("778")  # normalization
        assert not_tool_verifiable_reason("CWE-829") == ""
        assert not_tool_verifiable_reason("CWE-190") == ""
        assert not_tool_verifiable_reason("") == ""

    def test_no_dispatch_entry(self):
        assert lookup("CWE-778") is None
        assert lookup("CWE-1164") is None
        assert _cwe_fallback_chain("CWE-778") == []
        assert _cwe_fallback_chain("CWE-1164") == []

    def test_unmapped_log_states_policy_not_synthesis(self, caplog):
        import core.audit.orchestrator as _orch

        _orch._UNMAPPED_CWES_LOGGED.discard("CWE-778")
        with caplog.at_level(logging.INFO, logger="core.audit.orchestrator"):
            _orch._warn_unmapped_cwe("CWE-778")
        text = caplog.text
        assert "not tool-verifiable by policy" in text
        assert "checker-synthesis candidates" not in text

    def test_unmapped_tail_outside_policy_keeps_warning(self, caplog):
        import core.audit.orchestrator as _orch

        _orch._UNMAPPED_CWES_LOGGED.discard("CWE-1104")
        with caplog.at_level(
            logging.WARNING, logger="core.audit.orchestrator",
        ):
            _orch._warn_unmapped_cwe("CWE-1104")
        assert "checker-synthesis candidates" in caplog.text

    def test_refusal_reason_for_policy_classes(self):
        assert "not tool-verifiable by policy" in (
            ondemand_synthesis_refusal_reason("CWE-778", "any hypothesis")
        )
        assert "not tool-verifiable by policy" in (
            ondemand_synthesis_refusal_reason("CWE-1164", "any hypothesis")
        )


class TestPlaceholderCwe:
    def test_placeholders(self):
        assert is_placeholder_cwe("CWE-NOINFO")
        assert is_placeholder_cwe("CWE-noinfo")
        assert is_placeholder_cwe("CWE-000")
        assert is_placeholder_cwe("CWE-0")
        assert is_placeholder_cwe("CWE-Other")
        assert is_placeholder_cwe("CWE-UNKNOWN")

    def test_non_placeholders(self):
        assert not is_placeholder_cwe("")
        assert not is_placeholder_cwe("CWE-829")
        assert not is_placeholder_cwe("190")

    def test_effective_cwe_reclassifies_placeholder(self):
        o = _outcome(
            hypothesis="use-after-free of the freed connection object",
            cwe="CWE-NOINFO",
        )
        assert _effective_cwe(o) == "CWE-416"
        assert o.review_result["cwe_placeholder"] == "CWE-NOINFO"
        assert o.review_result["cwe_inferred"] == "CWE-416"

    def test_effective_cwe_placeholder_without_harm_is_empty(self):
        o = _outcome(hypothesis=_NO_HARM_HYPOTHESIS, cwe="CWE-noinfo")
        assert _effective_cwe(o) == ""
        assert o.review_result["cwe_placeholder"] == "CWE-noinfo"

    def test_effective_cwe_concrete_class_untouched(self):
        o = _outcome(hypothesis="anything", cwe="CWE-269")
        assert _effective_cwe(o) == "CWE-269"
        assert "cwe_placeholder" not in o.review_result

    def test_observed_prose_reclassifies_to_real_chain(self):
        # The run's inverted-promotion prose keyword-matches CWE-476
        # ("deref...null") — placeholder normalization hands it to the
        # real null-propagation chain instead of checker synthesis.
        o = _outcome(hypothesis=_OBSERVED_RUN_PROSE, cwe="CWE-778")
        # Policy class: kept verbatim (the policy park handles it).
        assert _effective_cwe(o) == "CWE-778"
        o2 = _outcome(hypothesis=_OBSERVED_RUN_PROSE, cwe="CWE-NOINFO")
        assert _effective_cwe(o2) == "CWE-476"
        assert _cwe_fallback_chain("CWE-476")


class TestSynthesisHarmGate:
    """Option (c): the on-demand lane requires a harm-stating
    hypothesis — a concrete non-policy class, or a hypothesis naming a
    recognized harm mechanism (structural reuse of the keyword table,
    no prose heuristics)."""

    def test_placeholder_plus_no_harm_refused(self):
        for cwe in ("", "CWE-NOINFO", "CWE-000", "CWE-Other"):
            reason = ondemand_synthesis_refusal_reason(
                cwe, _NO_HARM_HYPOTHESIS,
            )
            assert "no harm-stating hypothesis" in reason

    def test_concrete_unmapped_class_allowed(self):
        # CWE-269 (privilege management) has no dispatch entry but is a
        # concrete harm class — the lane stays open for it.
        assert ondemand_synthesis_refusal_reason(
            "CWE-269", _NO_HARM_HYPOTHESIS,
        ) == ""

    def test_harm_mechanism_backs_missing_class(self):
        assert ondemand_synthesis_refusal_reason(
            "", "double free of ctx on the error path",
        ) == ""

    def test_impact_primitive_backs_missing_class(self):
        # The review's structured impact object states what the
        # attacker gains — that is a harm statement even when the
        # class is a placeholder and the mechanism is unrecognized.
        review = {"impact": {"primitive": "dos"}}
        assert ondemand_synthesis_refusal_reason(
            "CWE-NOINFO", "novel mechanism the keyword table misses",
            review,
        ) == ""
        assert "no harm-stating hypothesis" in (
            ondemand_synthesis_refusal_reason(
                "CWE-NOINFO", "novel mechanism the keyword table misses",
                {"impact": {}},
            )
        )

    def test_policy_class_refused_despite_impact(self):
        # Policy classes are refused unconditionally — an impact stamp
        # does not make "insufficient logging" tool-verifiable.
        assert "not tool-verifiable by policy" in (
            ondemand_synthesis_refusal_reason(
                "CWE-778", "h", {"impact": {"primitive": "dos"}},
            )
        )

    def test_non_enum_primitive_does_not_open_lane(self):
        # LLM drift emits "none"/"n/a"/garbage — those state no harm
        # and must not satisfy the gate (validated against the review
        # schema enum, not mere non-emptiness).
        for primitive in ("none", "n/a", "unknown", "  ", "None"):
            reason = ondemand_synthesis_refusal_reason(
                "CWE-NOINFO", _NO_HARM_HYPOTHESIS,
                {"impact": {"primitive": primitive}},
            )
            assert "no harm-stating hypothesis" in reason, primitive

    def test_enum_primitives_accepted_case_insensitive(self):
        for primitive in sorted(_KNOWN_IMPACT_PRIMITIVES) + ["DoS"]:
            assert ondemand_synthesis_refusal_reason(
                "CWE-NOINFO", _NO_HARM_HYPOTHESIS,
                {"impact": {"primitive": primitive}},
            ) == "", primitive

    def test_known_primitives_pin_review_schema_enum(self):
        from core.audit.llm_review import REVIEW_SCHEMA
        enum = REVIEW_SCHEMA["properties"]["impact"]["properties"][
            "primitive"
        ]["enum"]
        assert _KNOWN_IMPACT_PRIMITIVES == frozenset(enum)

    def test_verification_rule_refuses_before_llm(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(
            "core.audit.checker_synthesis._build_llm_callable",
            lambda config: (_ for _ in ()).throw(
                AssertionError("LLM must not be built for refused class"),
            ),
        )
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        assert synthesize_verification_rule(
            _outcome(hypothesis=_NO_HARM_HYPOTHESIS),
            config, cwe="CWE-778",
        ) is None
        assert synthesize_verification_rule(
            _outcome(hypothesis=_NO_HARM_HYPOTHESIS),
            config, cwe="CWE-NOINFO",
        ) is None


class TestOrchestratorRefusalRecording:
    """The parking is never silent: a suppressions.jsonl record
    (dropped=false, the durable surface — the journal entry is written
    pre-sweep and cannot carry it), skip in tier telemetry, and the
    in-memory review_result stamp; synthesis substrate never invoked."""

    def _run(self, tmp_path, monkeypatch, cwe, hypothesis):
        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            lambda *a, **kw: (_ for _ in ()).throw(
                AssertionError("synthesis must not run for refused class"),
            ),
        )
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        outcome = _outcome(hypothesis=hypothesis, cwe=cwe)
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _synthesize_unmapped_suspicious(
            result, config, 0, outcome, hypothesis, cwe, "src",
        )
        return result, outcome

    @staticmethod
    def _suppression_records(tmp_path):
        path = tmp_path / "out" / "suppressions.jsonl"
        if not path.is_file():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_policy_class_recorded(self, tmp_path, monkeypatch):
        result, outcome = self._run(
            tmp_path, monkeypatch, "CWE-778", _NO_HARM_HYPOTHESIS,
        )
        assert outcome.status == "suspicious"
        assert "not tool-verifiable by policy" in (
            outcome.review_result["synthesis_refused"]
        )
        assert result.tier_counters["synthesis_on_demand"].skipped == 1
        assert result.ondemand_synthesized == 0
        assert result.findings == 0
        recs = self._suppression_records(tmp_path)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == "synthesis_policy_refused"
        assert rec["dropped"] is False  # outcome SURVIVES at suspicious
        assert rec["file_path"] == "a.c"
        assert rec["function"] == "f"
        assert rec["rule_id"] == "audit:synthesis-policy"
        assert rec["cwe"] == "CWE-778"
        assert "not tool-verifiable by policy" in rec["reason"]

    def test_placeholder_no_harm_recorded(self, tmp_path, monkeypatch):
        result, outcome = self._run(
            tmp_path, monkeypatch, "", _NO_HARM_HYPOTHESIS,
        )
        assert outcome.status == "suspicious"
        assert "no harm-stating hypothesis" in (
            outcome.review_result["synthesis_refused"]
        )
        assert result.tier_counters["synthesis_on_demand"].skipped == 1
        recs = self._suppression_records(tmp_path)
        assert len(recs) == 1
        assert recs[0]["verdict"] == "synthesis_policy_refused"
        assert recs[0]["dropped"] is False
        assert "no harm-stating hypothesis" in recs[0]["reason"]
