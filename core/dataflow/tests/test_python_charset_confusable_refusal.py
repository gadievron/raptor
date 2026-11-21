"""Non-ASCII confusable allowlists must not earn a Tier 0 proof.

The danger models are ASCII-only, so an allowlist disjointness proof
can only speak for ASCII alphabets: a charset admitting fullwidth
``．``/``／`` proves "excludes ``../``" while the admitted payload
NFKC-normalises to exactly ``../`` in any downstream normalising
consumer. The Java lane refuses its analogous unverified-translation
family (``test_java_unicode_proof_refusal.py``); this is the Python
lane's mirror.

Strip-style forbidden sets (``charset_sub``) stay admitted with
non-ASCII members — stripping extra chars only shrinks the admitted
language — but a confusable-spelled forbidden set still never proves,
because the inclusion check demands the ASCII danger chars themselves.
"""
import unicodedata

import pytest

from core.dataflow import smt_barrier as sb
from core.dataflow.smt_barrier import (
    _charset_alphabet_is_modeled,
    _charset_body_is_safe,
)
from core.smt_solver import z3_available

_requires_z3 = pytest.mark.skipif(
    not z3_available(), reason="z3-solver not installed",
)

FULLWIDTH_BODY = "a-z．／"          # a-z．／
FULLWIDTH_RANGE_BODY = "ａ-ｚ"      # ａ-ｚ


def test_attack_premise_holds():
    # The refusal exists because of this exact mapping; if Unicode
    # ever stopped normalising fullwidth solidus/full stop to ASCII
    # the gate could be revisited.
    assert unicodedata.normalize("NFKC", "．．／") == "../"


class TestAlphabetGate:
    def test_fullwidth_literals_not_modeled(self):
        assert _charset_alphabet_is_modeled(FULLWIDTH_BODY) is False

    def test_fullwidth_range_endpoints_not_modeled(self):
        assert _charset_alphabet_is_modeled(FULLWIDTH_RANGE_BODY) is False

    def test_any_nonascii_refused_not_just_confusables(self):
        # The modeled alphabet is ASCII; chars with no ASCII
        # normalisation are still outside what the proof covers.
        assert _charset_alphabet_is_modeled("a-zé") is False

    def test_ascii_bodies_modeled(self):
        assert _charset_alphabet_is_modeled("A-Za-z0-9_+-") is True

    def test_body_safety_gate_is_unchanged_by_the_alphabet_gate(self):
        # Tokenizer safety and alphabet coverage are separate
        # questions: a fullwidth body still tokenizes fine (strip
        # validators rely on that).
        assert _charset_body_is_safe(FULLWIDTH_BODY) is True


@_requires_z3
class TestProofRefusal:
    def test_fullwidth_allowlist_cannot_prove_pathtrav_sound(self):
        spec = sb.ValidatorSpec(
            "charset", "name", FULLWIDTH_BODY, "+...", 0,
        )
        v = sb.prove_neutralizes(spec, "pathtrav")
        assert v.sound is False
        assert "non-ASCII allowlist" in v.reasoning

    def test_extracted_fullwidth_guard_is_refused_at_the_proof(self):
        # Extraction itself still lifts the spec — the refusal lives
        # at the proof chokepoint shared by Tier 0, Tier 1b claims
        # and the injection prescreen.
        line = ("    if not re.match(r'^[a-z．／]+$', n): "
                "raise ValueError")
        spec = sb.extract_validator_from_line(line, "python")
        assert spec is not None
        v = sb.prove_neutralizes(spec, "pathtrav")
        assert v.sound is False
        assert "non-ASCII allowlist" in v.reasoning

    def test_confusable_forbidden_set_still_never_proves(self):
        # Strip direction: fullwidth ．／ in the forbidden set do not
        # count as stripping ASCII './' — inclusion fails.
        spec = sb.ValidatorSpec(
            "charset_sub", "name", "", "+...", forbidden="．／",
        )
        v = sb.prove_neutralizes(spec, "pathtrav")
        assert v.sound is False

    def test_ascii_allowlist_still_proves_sound(self):
        spec = sb.ValidatorSpec(
            "charset", "name", "A-Za-z0-9_+-", "+...", 0,
        )
        v = sb.prove_neutralizes(spec, "pathtrav")
        assert v.sound is True


class TestSliceDiagnosticMirror:
    def test_fullwidth_allowlist_declines_the_slice_model(self):
        from core.dataflow.string_slice_diagnostic import (
            diagnose_validator_slice,
        )

        spec = sb.ValidatorSpec(
            "charset", "n", FULLWIDTH_BODY, "+...", 0,
        )
        out = diagnose_validator_slice(
            "x = 1\n", 1, 1, spec, "pathtrav",
        )
        assert out is None
