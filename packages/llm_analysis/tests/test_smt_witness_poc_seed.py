"""Tests for SMT witness → /exploit PoC seed wiring.

Tier 4 SMT (packages/llm_analysis/dataflow_validation.py) attaches a
satisfying assignment to `analysis["smt_witness"]` when Z3 proves the
LLM-emitted path conditions are jointly satisfiable. The /exploit
prompt builder reads that field and surfaces it to the exploit-gen
LLM as a starter PoC — concrete trigger values that are guaranteed
to make the program take the dangerous code path, so the LLM doesn't
have to derive them from first principles (the hardest part of
integer-overflow / OOB / null-deref exploitation).

These tests cover the wiring at both ends:
  1. _tier4_smt_refine attaches a structured `smt_witness` field
     when the SMT outcome is sat (witness branch).
  2. build_exploit_prompt_bundle includes a dedicated `smt-witness`
     UntrustedBlock when the field is present, omits when absent.
  3. The block content is a parseable PoC seed (concrete values in
     decimal AND hex).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.prompts.exploit import (
    _format_smt_witness,
    build_exploit_prompt_bundle,
)


# -- _format_smt_witness ----------------------------------------------------

class TestFormatSmtWitness:
    """Witness rendering — concrete-value PoC seed for the LLM."""

    def test_empty_model_returns_empty_string(self):
        """Witness with no model is meaningless; render to empty so
        the caller can omit the block entirely."""
        assert _format_smt_witness({}) == ""
        assert _format_smt_witness({"model": {}}) == ""

    def test_model_renders_decimal_and_hex(self):
        """Exploit authors need hex for memory-layout reasoning;
        decimal for argv. Render both so the LLM doesn't have to
        convert."""
        out = _format_smt_witness({
            "model": {"count": 268435457},
            "path_conditions": ["count * 40 > 4294967295"],
            "path_profile": "uint32",
        })
        assert "count = 268435457" in out
        assert "0x10000001" in out  # hex form

    def test_includes_path_profile_for_context(self):
        out = _format_smt_witness({
            "model": {"x": 1},
            "path_profile": "uint32",
        })
        assert "uint32" in out

    def test_includes_path_conditions_for_context(self):
        out = _format_smt_witness({
            "model": {"x": 1},
            "path_conditions": ["x > 0"],
        })
        assert "x > 0" in out

    def test_emphasises_solver_guarantee(self):
        """The whole point of the witness is "Z3 has done this work
        for you, don't redo it." The framing must be unambiguous."""
        out = _format_smt_witness({
            "model": {"x": 1},
            "path_conditions": ["x > 0"],
        })
        # Must convey that the values are solver-verified, not
        # LLM-guessed. Look for any of: "guaranteed", "verified",
        # "solver", "Z3" — at least one must appear.
        assert any(w in out.lower() for w in ("guarantee", "verified", "solver", "z3")), (
            f"witness block should make it clear values are solver-verified; "
            f"got: {out[:200]}"
        )

    def test_non_int_value_renders_unchanged(self):
        """Defensive: if the model has a non-int (shouldn't happen
        but Z3 model values can be arbitrary), don't crash on the
        hex-format step."""
        out = _format_smt_witness({"model": {"name": "evil"}})
        assert "name = evil" in out

    def test_anon_var_decoded_when_mapping_present(self):
        """When anon_var_map records the substitution, the rendered
        line shows BOTH the placeholder and the original expression
        so the LLM can connect the value to a real input."""
        out = _format_smt_witness({
            "model": {"_anon_0": 32},
            "path_conditions": ["strlen(argv[1]) >= 16"],
            "path_profile": "uint64",
            "anon_var_map": {"_anon_0": "strlen(argv[1])"},
        })
        # Decoded form must appear — without it, gemini sees `_anon_0
        # = 32` and re-derives values from path_conditions instead of
        # using the witness (observed pre-fix on /tmp/smt-witness-test
        # 2026-05-10 — 0 occurrences of `32` in the generated PoC).
        assert "_anon_0 (= strlen(argv[1])) = 32" in out

    def test_anon_var_falls_back_to_bare_name_without_mapping(self):
        """No mapping (anon_var_map missing or empty) — fall back to
        the bare placeholder. Backwards-compatible with witnesses
        produced before the parser annotation landed; also the case
        for verb-path witnesses (smt_verbs.py allocates _anon_N too
        but doesn't track an expression for it)."""
        out = _format_smt_witness({
            "model": {"_anon_0": 32},
            "path_conditions": ["strlen(argv[1]) >= 16"],
        })
        assert "_anon_0 = 32" in out
        assert "(= strlen" not in out  # no decoration

    def test_named_local_unaffected_by_decoder(self):
        """Variables with non-`_anon_` names are unchanged — the
        decoder only kicks in for opaque placeholders."""
        out = _format_smt_witness({
            "model": {"count": 268435457},
            "path_conditions": ["count > 0x10000000"],
            "anon_var_map": {},  # explicitly empty
        })
        assert "count = 268435457" in out
        assert "(= " not in out  # no spurious decoration

    def test_partial_anon_mapping(self):
        """Some _anon_N decoded, others not (e.g. parser captured one
        but the second function-call hit a code path that didn't
        record). Each is decoded independently."""
        out = _format_smt_witness({
            "model": {"_anon_0": 32, "_anon_1": 7},
            "path_conditions": [
                "strlen(argv[1]) >= 16",
                "atoi(argv[2]) > 5",
            ],
            "anon_var_map": {"_anon_0": "strlen(argv[1])"},
        })
        assert "_anon_0 (= strlen(argv[1])) = 32" in out
        assert "_anon_1 = 7" in out
        # _anon_1 not decorated since it's not in the map
        lines = [l for l in out.split("\n") if "_anon_1" in l]
        assert all("(= " not in l for l in lines)


# -- build_exploit_prompt_bundle integration -------------------------------

class TestExploitPromptBundleSmtWitness:
    """The exploit prompt builder must surface the witness as a
    dedicated UntrustedBlock when present."""

    def _bundle_text(self, **kwargs):
        """Build the bundle and return all message text concatenated.
        PromptBundle has `messages` (tuple of MessagePart with role +
        content); we don't care about role-splitting for these
        assertions."""
        bundle = build_exploit_prompt_bundle(
            rule_id="r1",
            file_path="/x.c",
            start_line=42,
            level="warning",
            **kwargs,
        )
        return "\n".join(m.content for m in bundle.messages)

    def test_witness_renders_when_attached(self):
        analysis = {
            "is_exploitable": True,
            "smt_witness": {
                "model": {"count": 268435457},
                "path_conditions": ["count * 40 > 4294967295"],
                "path_profile": "uint32",
            },
        }
        text = self._bundle_text(analysis=analysis)
        # Should contain the witness's concrete value (decimal) and
        # the rendered hex.
        assert "268435457" in text
        assert "0x10000001" in text
        assert "uint32" in text

    def test_no_witness_block_when_absent(self):
        """No `smt_witness` field on the analysis ⇒ no smt-witness
        block in the prompt. Matches feasibility/etc behaviour."""
        analysis = {"is_exploitable": True}
        text = self._bundle_text(analysis=analysis)
        # The kind label "smt-witness" appears in block headers
        # only when the block is present.
        assert "smt-witness" not in text.lower()

    def test_empty_witness_block_when_model_empty(self):
        """smt_witness present but model empty ⇒ no block (the
        formatter returns empty, the caller skips)."""
        analysis = {
            "is_exploitable": True,
            "smt_witness": {"model": {}},
        }
        text = self._bundle_text(analysis=analysis)
        assert "smt-witness" not in text.lower()

    def test_witness_block_paired_with_existing_blocks(self):
        """Witness block should coexist with feasibility + code +
        analysis blocks; don't crowd them out."""
        analysis = {
            "is_exploitable": True,
            "smt_witness": {"model": {"x": 42}},
        }
        feasibility = {"chain_breaks": ["ASLR enabled"]}
        text = self._bundle_text(
            analysis=analysis,
            code="int main() { return 0; }",
            feasibility=feasibility,
        )
        # All four blocks present.
        assert "x = 42" in text  # witness
        assert "ASLR enabled" in text  # feasibility
        assert "int main()" in text  # code
        assert "is_exploitable" in text  # analysis


# -- Tier 4 attachment side -----------------------------------------------

class TestTier4AttachesSmtWitness:
    """_tier4_smt_refine must mutate the analysis dict to carry the
    structured witness when SMT outcome is sat (witness branch)."""

    def test_witness_branch_attaches_smt_witness_to_analysis(self):
        """Sat path conditions on a confirmed verdict → analysis
        dict gains an smt_witness field with model + path_conditions
        + path_profile."""
        from packages.llm_analysis.dataflow_validation import _tier4_smt_refine
        from packages.hypothesis_validation.result import ValidationResult

        analysis = {
            "path_conditions": ["x > 0"],
            "path_profile": "uint32",
        }
        finding = {"finding_id": "f1"}
        confirmed = ValidationResult(verdict="confirmed", evidence=[], iterations=1)

        # Mock validate_path to return a sat result with a model.
        with patch(
            "packages.exploit_feasibility.smt_path.validate_path"
        ) as mock_validate:
            mock_validate.return_value = {
                "feasible": True,
                "smt_available": True,
                "model": {"x": 7},
                "reasoning": "satisfiable",
                "satisfied": [],
                "unsatisfied": [],
                "unknown": [],
                "unknown_reasons": [],
            }
            refined, outcome = _tier4_smt_refine(confirmed, finding, analysis)

        assert outcome == "smt_witness"
        # The structured witness MUST be on analysis (not just in
        # the reasoning string).
        assert "smt_witness" in analysis
        assert analysis["smt_witness"]["model"] == {"x": 7}
        assert analysis["smt_witness"]["path_conditions"] == ["x > 0"]
        assert analysis["smt_witness"]["path_profile"] == "uint32"

    def test_refuted_branch_does_not_attach_witness(self):
        """Unsat conditions ⇒ no witness; analysis must be untouched
        on this axis (don't leak stale data from a prior call)."""
        from packages.llm_analysis.dataflow_validation import _tier4_smt_refine
        from packages.hypothesis_validation.result import ValidationResult

        analysis = {
            "path_conditions": ["x > 0", "x < 0"],  # mutually exclusive
            "path_profile": "uint32",
        }
        finding = {"finding_id": "f1"}
        inconclusive = ValidationResult(
            verdict="inconclusive", evidence=[], iterations=1,
        )

        with patch(
            "packages.exploit_feasibility.smt_path.validate_path"
        ) as mock_validate:
            mock_validate.return_value = {
                "feasible": False,
                "smt_available": True,
                "model": {},
                "reasoning": "unsatisfiable",
                "satisfied": [],
                "unsatisfied": ["x > 0", "x < 0"],
                "unknown": [],
                "unknown_reasons": [],
            }
            _, outcome = _tier4_smt_refine(inconclusive, finding, analysis)

        assert outcome == "smt_refuted"
        assert "smt_witness" not in analysis

    def test_no_check_branch_does_not_attach_witness(self):
        """No path_conditions ⇒ no SMT call ⇒ no witness."""
        from packages.llm_analysis.dataflow_validation import _tier4_smt_refine
        from packages.hypothesis_validation.result import ValidationResult

        analysis = {}  # no path_conditions
        finding = {"finding_id": "f1"}
        confirmed = ValidationResult(verdict="confirmed", evidence=[], iterations=1)

        _, outcome = _tier4_smt_refine(confirmed, finding, analysis)

        assert outcome == "no_check"
        assert "smt_witness" not in analysis

    def test_witness_includes_anon_var_map(self):
        """The mapping recorded by the SMT parser flows through the
        validate_path wrapper, _tier4_smt_refine, and lands on the
        analysis dict's smt_witness field. End-to-end propagation
        check — without it the renderer's anon-var decoding has
        nothing to consume."""
        from packages.llm_analysis.dataflow_validation import _tier4_smt_refine
        from packages.hypothesis_validation.result import ValidationResult

        analysis = {
            "path_conditions": ["strlen(argv[1]) >= 16"],
            "path_profile": "uint64",
        }
        finding = {"finding_id": "f1"}
        confirmed = ValidationResult(verdict="confirmed", evidence=[], iterations=1)

        with patch(
            "packages.exploit_feasibility.smt_path.validate_path"
        ) as mock_validate:
            mock_validate.return_value = {
                "feasible": True,
                "smt_available": True,
                "model": {"_anon_0": 32},
                "reasoning": "satisfiable",
                "satisfied": [],
                "unsatisfied": [],
                "unknown": [],
                "unknown_reasons": [],
                "anon_var_map": {"_anon_0": "strlen(argv[1])"},
            }
            _, outcome = _tier4_smt_refine(confirmed, finding, analysis)

        assert outcome == "smt_witness"
        sw = analysis["smt_witness"]
        assert sw["anon_var_map"] == {"_anon_0": "strlen(argv[1])"}


class TestSmtPathValidatorAnonMap:
    """The bottom of the propagation chain: the parser must populate
    PathSMTResult.anon_var_map for function-call substitutions. Tests
    here pin the parser-side behaviour so the mapping is correct
    when it bubbles up to /exploit."""

    def _check(self, condition_text):
        from packages.codeql.smt_path_validator import (
            check_path_feasibility, PathCondition,
        )
        from core.smt_solver.config import BV_C_UINT64
        return check_path_feasibility(
            [PathCondition(text=condition_text, step_index=0)],
            profile=BV_C_UINT64,
        )

    def test_function_call_substitution_recorded(self):
        r = self._check("strlen(argv[1]) >= 16")
        assert r.feasible is True
        assert r.anon_var_map == {"_anon_0": "strlen(argv[1])"}

    def test_named_local_no_substitution(self):
        r = self._check("count > 268435456")
        assert r.feasible is True
        assert r.anon_var_map == {}

    def test_two_distinct_calls_get_separate_anons(self):
        """Two textually-identical calls should each get their own
        placeholder (calls aren't assumed pure) — and both should
        be recorded separately."""
        r = self._check("strlen(input) > strlen(other)")
        # _anon_0 → strlen(input), _anon_1 → strlen(other)
        assert len(r.anon_var_map) == 2
        assert r.anon_var_map["_anon_0"] == "strlen(input)"
        assert r.anon_var_map["_anon_1"] == "strlen(other)"
