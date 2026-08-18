"""Wire-shape pins for the synthesis prompt — structure-only assertions.

These pin STRUCTURE: section presence, framing position, envelope
encoding state, schema keys, block labels.  They never assert full
rendered content, so they are hermetic (no LLM, no network) and
tolerant of wording iterations, while still catching the regressions
that matter to the wire:

  * the audit-purpose framing dropping off the front of the system
    text (the measured refusal trigger for the auxiliary classes);
  * the ask reverting from the verification shape to the
    generation-of-attack-patterns shape;
  * an accidental change to the per-model envelope defence state;
  * schema drift away from what the downstream parser expects.
"""

from __future__ import annotations

import re

from core.security.prompt_framing import (
    SECURITY_AUDIT_FRAMING,
    with_audit_framing,
)
from packages.checker_synthesis.models import SeedBug
from packages.checker_synthesis.prompts import (
    SYNTHESIS_SCHEMA,
    build_synthesis_prompt,
    build_triage_prompt,
)

_PARSER_FIELDS = {
    "rule_body", "rationale", "test_positive", "test_negative",
    "fix_patch",
}


def _seed() -> SeedBug:
    return SeedBug(
        file="src/demo.c",
        function="copy_name",
        line_start=10,
        line_end=14,
        cwe="CWE-120",
        reasoning="fixture: size of the destination is not checked",
        snippet="void copy_name(char *d, const char *s) { strcpy(d, s); }\n",
    )


class TestSchemaParserContract:
    def test_schema_keys_pinned_to_parser_fields(self):
        assert set(SYNTHESIS_SCHEMA["required"]) == _PARSER_FIELDS
        assert set(SYNTHESIS_SCHEMA["properties"]) == _PARSER_FIELDS


class TestSystemShape:
    def test_system_leads_with_audit_framing(self):
        _user, system = build_synthesis_prompt(_seed(), "semgrep")
        assert system.startswith(SECURITY_AUDIT_FRAMING)

    def test_boundary_framing_is_idempotent(self):
        # core.audit.checker_synthesis._build_llm_callable wraps the
        # system text with with_audit_framing at the call boundary; the
        # builder-level framing must make that a no-op, not a double
        # prefix.
        _user, system = build_synthesis_prompt(_seed(), "semgrep")
        assert with_audit_framing(system) == system

    def test_verification_ask_sections_present(self):
        _user, system = build_synthesis_prompt(_seed(), "semgrep")
        for marker in (
            "HYPOTHESIS TO VERIFY AS A MECHANICAL RULE",
            "EVIDENCE PROVENANCE",
            "TASK:",
            "Respond with JSON",
        ):
            assert marker in system, f"missing system section: {marker}"
        # The pre-fix generation-shaped header must not resurface.
        assert "BUG TO REPLICATE" not in system

    def test_retry_and_fp_sections_conditional(self):
        seed = _seed()
        _u, base_sys = build_synthesis_prompt(seed, "semgrep")
        assert "RETRY" not in base_sys
        assert "PRIOR FALSE POSITIVES" not in base_sys
        _u, retry_sys = build_synthesis_prompt(
            seed, "semgrep", retry_feedback="rule did not match the seed",
        )
        assert "RETRY" in retry_sys


class TestUntrustedBlockShape:
    def test_block_labels_are_provenance_quoted(self):
        user, _system = build_synthesis_prompt(_seed(), "semgrep")
        assert 'kind="review-hypothesis"' in user
        assert 'kind="quoted-evidence"' in user
        assert 'origin="src/demo.c:copy_name"' in user

    def test_payload_stays_out_of_system(self):
        seed = _seed()
        _user, system = build_synthesis_prompt(seed, "semgrep")
        assert seed.reasoning not in system
        assert seed.snippet.strip() not in system


class TestDefenseState:
    """Synthesis opts out of payload encoding (measured hard-refusal
    of the extraction ask over an encoded payload — operator-approved
    transparent_payload, mirroring the taint-summary/spec-inference
    classes); triage keeps the encoded envelope."""

    def test_synthesis_renders_plaintext_all_profiles(self):
        seed = _seed()
        for model_id in ("", "claude-opus-4-8", "anthropic.claude-mythos-5"):
            user, _system = build_synthesis_prompt(
                seed, "semgrep", model_id=model_id,
            )
            assert "strcpy" in user  # payload in the clear
            assert not re.search(r"[A-Za-z0-9+/=]{80,}", user)

    def test_synthesis_keeps_structural_defenses(self):
        seed = _seed()
        user, _system = build_synthesis_prompt(
            seed, "semgrep", model_id="claude-opus-4-8",
        )
        # nonce envelope + slot discipline survive the transparent
        # rendering; only the encoding is dropped.
        assert re.search(r"</untrusted-[0-9a-f]+>", user)
        assert '<slot name="seed_function"' in user

    def test_triage_still_encodes_payload(self):
        from packages.checker_synthesis.models import (
            Match,
            SynthesisedRule,
        )

        seed = _seed()
        rule = SynthesisedRule(
            rule_id="test-rule", engine="semgrep",
            body="rules: []", rationale="pinned fixture",
        )
        match = Match(
            file="src/x.c", line=10,
            snippet="strcpy(dst, src);", metavars={},
        )
        user, _system = build_triage_prompt(
            seed, rule, match, model_id="claude-opus-4-8",
        )
        assert re.search(r"[A-Za-z0-9+/=]{40,}", user)
