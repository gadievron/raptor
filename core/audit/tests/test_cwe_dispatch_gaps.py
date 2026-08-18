"""Dispatch coverage for the CWE families a real run emitted with no
tool-chain entry (CWE-121, CWE-195, CWE-130, CWE-843), plus the
synthesis-candidate routing for families that stay unmapped.

The run warned three times: ``review emitted CWE-121|195|130 but no
tool-chain dispatch entry exists`` and post-loop CWE-843 type-punning
findings had no channel; on-demand synthesis ran 0 of its 10-attempt
cap. Hermetic — no LLM, no tool subprocesses.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.compiler_sweep import compiler_applicable
from core.audit.cwe_dispatch import (
    CWE_TO_TOOL_DISPATCH,
    cocci_rule_for_cwe,
    infer_cwe_from_hypothesis,
    lookup,
    smt_verb_for_cwe,
)
from core.audit.joern_verify import flow_chain_entry, guard_chain_entry
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
    _promote_suspicious,
)

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "coccinelle" / "rules"
)


class TestNewDispatchEntries:
    def test_cwe_121_maps_to_buffer_family(self):
        entry = lookup("CWE-121")
        assert entry is not None
        assert entry["smt"] == "check-oob"
        assert entry["joern"] is True
        assert "memcpy" in entry["sinks"]

    def test_cwe_195_maps_to_signedness_family(self):
        assert smt_verb_for_cwe("CWE-195") == "check-integer-narrowing"
        assert cocci_rule_for_cwe("CWE-195") == "sign_extension_widen.cocci"

    def test_cwe_130_maps_to_length_param_family(self):
        entry = lookup("CWE-130")
        assert entry is not None
        assert entry["smt"] == "check-oob"
        assert "recv" in entry["sinks"]
        assert cocci_rule_for_cwe("CWE-130") == "missing_bounds_check.cocci"

    def test_cwe_843_gets_compiler_channel(self):
        assert lookup("CWE-843") is not None
        assert compiler_applicable("CWE-843")

    def test_fallback_chain_nonempty_for_all_four(self):
        for cwe in ("CWE-121", "CWE-195", "CWE-130", "CWE-843"):
            chain = _cwe_fallback_chain(cwe)
            assert chain, f"{cwe} fallback chain must not be empty"

    def test_hypothesis_chain_nonempty_no_warning(self, monkeypatch):
        import core.audit.orchestrator as _orch

        warned = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in ("CWE-121", "CWE-195", "CWE-130", "CWE-843"):
            chain = _hypothesis_to_tool_chain("", "a.c", cwe=cwe)
            assert chain, f"{cwe} must dispatch at least one channel"
        assert warned == []

    def test_joern_channels_for_121_and_130(self):
        guard = guard_chain_entry("CWE-121")
        assert guard and guard["type"] == "joern_guard"
        assert guard["config"]["sinks"]
        flow = flow_chain_entry("CWE-130")
        assert flow and flow["type"] == "joern_flow"
        assert "recv" in flow["config"]["sinks"]

    def test_hypothesis_keyword_inference(self):
        assert infer_cwe_from_hypothesis(
            "type confusion via punned pointer cast",
        ) == "CWE-843"
        assert infer_cwe_from_hypothesis(
            "length field inconsistency: header length exceeds "
            "received bytes",
        ) == "CWE-130"

    def test_every_cocci_rule_reference_exists_on_disk(self):
        for cwe, entry in CWE_TO_TOOL_DISPATCH.items():
            rule = entry.get("cocci")
            if rule:
                assert (_RULES_DIR / rule).is_file(), (
                    f"{cwe} references missing cocci rule {rule}"
                )


def _suspicious_outcome(cwe: str, counter: str) -> ReviewOutcome:
    return ReviewOutcome(
        file="a.c",
        function="f",
        status="suspicious",
        body="suspicious body",
        hypothesis="the length header is attacker controlled",
        review_result={
            "cwe": cwe,
            "hypothesis": "the length header is attacker controlled",
            "hypotheses": [{
                "mechanism": "attacker controls the length",
                "confidence": "medium",
                "counter": counter,
            }],
        },
    )


class TestUnmappedFamiliesSeedSynthesis:
    _COUNTER = (
        "callers in other translation units always clamp the length "
        "before invoking this function"
    )

    def _run(self, monkeypatch, cwe: str, tmp_path):
        import core.audit.orchestrator as _orch

        synth_calls = []
        monkeypatch.setattr(
            _orch, "_synthesize_unmapped_suspicious",
            lambda *a, **kw: synth_calls.append(a[3]),
        )
        # Keep the sweep fully mechanical-free for the test.
        monkeypatch.setattr(
            _orch, "_read_raw_source", lambda *a, **kw: "int f(void){}",
        )

        result = OrchestratorResult()
        outcome = _suspicious_outcome(cwe, self._COUNTER)
        result.outcomes.append(outcome)
        result.suspicious = 1
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        _promote_suspicious(result, config, checklist={"files": []})
        return synth_calls

    def test_unmapped_family_with_counter_reaches_synthesis(
        self, monkeypatch, tmp_path,
    ):
        # CWE-1108 has no dispatch entry and the hypothesis text binds
        # no keyword channel: the only possible mechanical evidence is
        # a synthesized checker.
        calls = self._run(monkeypatch, "CWE-1108", tmp_path)
        assert len(calls) == 1, (
            "empty-dispatch families must become synthesis candidates "
            "even when a counter-hypothesis is present"
        )

    def test_mapped_family_with_counter_still_skips(
        self, monkeypatch, tmp_path,
    ):
        # CWE-130 now has channels: the counter-hypothesis skip keeps
        # its pre-existing semantics (no sweep, no synthesis).
        calls = self._run(monkeypatch, "CWE-130", tmp_path)
        assert calls == []
