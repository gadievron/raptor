"""Similarity-seam equivalence against the matcher's cascade.

The seam (packages.ghidra.similarity) is the SINGLE implementation of
the normalisation/hash/shingle/Jaccard primitives; the cross-version
matcher binds them under its historical private names. These tests
pin the equivalence in both forms:

* identity — the matcher's bound names ARE the seam functions, so a
  fork of either side (re-defining a private in match.py, or a
  behaviour change hidden behind the alias) fails here loudly;
* behaviour — the seam reproduces the matcher's tier-2 hash keys and
  tier-5 similarity scores on the same inputs, exercised through
  ``match_databases`` itself, so both consumers break together on
  drift instead of diverging silently.
"""

from __future__ import annotations

import packages.ghidra.match as match_mod
from packages.ghidra import similarity
from packages.ghidra.model import REDatabase, REFunction
from packages.ghidra.similarity import (
    MAX_SHINGLE_TOKENS,
    decomp_hash,
    decomp_hash_text,
    decomp_similarity,
    jaccard,
    mask_own_name,
    normalize_decomp,
    normalize_keep_constants,
    shingles,
    shingles_text,
    strip_nul,
)


def _func(name, addr, *, size=64, decomp=None, auto=False):
    return REFunction(
        name=name, address=addr, size=size,
        decompilation=decomp, is_auto_named=auto,
    )


def _db(funcs):
    return REDatabase(source_tool="test", functions=list(funcs))


_BODY = (
    "int parse_frame(char *p, int n) {\n"
    "  if (n < 0x10) return -1;\n"
    "  memcpy(buf, p, n);\n"
    "  return FUN_00401000(p, n);\n"
    "}"
)


class TestIdentityPins:
    """The matcher's private names are the seam's functions — not
    copies. A re-defined private in match.py fails here."""

    def test_matcher_binds_seam_functions(self):
        assert match_mod._decomp_hash is similarity.decomp_hash
        assert match_mod._shingles is similarity.shingles
        assert match_mod._jaccard is similarity.jaccard


class TestBehaviouralEquivalence:
    def test_decomp_hash_text_equals_function_hash(self):
        f = _func("parse_frame", 0x1000, decomp=_BODY)
        assert decomp_hash(f) == decomp_hash_text(_BODY)
        assert decomp_hash(f) is not None

    def test_shingles_text_equals_function_shingles(self):
        f = _func("parse_frame", 0x1000, decomp=_BODY)
        assert shingles(f) == shingles_text(_BODY)
        assert shingles(f)

    def test_tier2_match_key_is_the_seam_hash(self):
        """A tier-2 match happens exactly when the seam hashes the
        two decompilations equal (rebase-shifted constants masked)."""
        rebased = _BODY.replace("0x10", "0x10").replace(
            "FUN_00401000", "FUN_00501000")
        old = _db([_func("a", 0x1000, decomp=_BODY, auto=True)])
        new = _db([_func("FUN_9", 0x2000, decomp=rebased, auto=True)])
        assert decomp_hash_text(_BODY) == decomp_hash_text(rebased)
        result = match_mod.match_databases(old, new)
        assert result.stats.get("tier2_decomp_hash") == 1

    def test_tier5_score_is_the_seam_jaccard(self):
        """The matched pair's tier-5 score equals the seam's Jaccard
        of the two shingle sets — same inputs, same number."""
        # Structural delta (hex constants are masked, so a constant
        # change alone would tier-2 match): one added statement.
        body_new = _BODY.replace(
            "memcpy(buf, p, n);", "memcpy(buf, p, n);\n  total = n;")
        old = _db([_func("a", 0x1000, decomp=_BODY, auto=True)])
        new = _db([_func("b", 0x2000, decomp=body_new, auto=True)])
        # Force past tiers 1-4: auto names, distinct hashes, no
        # strings/imports, no matched neighbours.
        assert decomp_hash_text(_BODY) != decomp_hash_text(body_new)
        result = match_mod.match_databases(old, new)
        (pair,) = result.pairs
        assert pair.tier == 5
        expected = jaccard(shingles_text(_BODY), shingles_text(body_new))
        assert expected is not None
        assert abs(pair.score - expected) < 1e-9
        # And the convenience wrapper agrees with the composed form.
        assert decomp_similarity(_BODY, body_new) == expected


class TestPrimitiveContracts:
    def test_normalize_masks_constants_and_autonames(self):
        norm = normalize_decomp(_BODY)
        assert "0x10" not in norm
        assert "FUN_00401000" not in norm
        assert "parse_frame" in norm

    def test_keep_constants_keeps_them(self):
        norm = normalize_keep_constants(_BODY)
        assert "0x10" in norm
        assert "FUN_00401000" not in norm

    def test_nul_cannot_forge_a_mask_sentinel(self):
        forged = "if (\x00H\x00 < n) return -1; " + "x = y; " * 8
        honest = forged.replace("\x00", " ")
        assert decomp_hash_text(forged) == decomp_hash_text(honest)
        assert strip_nul("\x00H\x00") == " H "

    def test_own_name_mask_survives_the_pipeline(self):
        """The destruction path: masking OUTSIDE the seam and letting
        the seam re-strip dissolves the NUL sentinel into a bare
        ``F`` token — a literal identifier ``F`` in another function
        then forges clone equality. The own= entry keeps the mask
        inside the single strip→mask→normalize pipeline."""
        body = "int check_a(int n) { return check_a_helper(n) + F; }"
        clone = body.replace("check_a(", "check_b(")
        # Rename-aware equality through the own= pipeline.
        assert (decomp_hash_text(body, own="check_a")
                == decomp_hash_text(clone, own="check_b"))
        # Forgery probe: a function whose body spells the OTHER's
        # masked slot as the literal identifier F must NOT hash-equal
        # (the sentinel is unspellable; the destroyed-sentinel path
        # made it a bare F and forged Jaccard 1.0).
        imposter = body.replace("check_a(", "F(")
        assert (decomp_hash_text(imposter, own="F")
                != decomp_hash_text(
                    mask_own_name(strip_nul(body), "check_a")))
        assert (shingles_text(body, own="check_a")
                == shingles_text(clone, own="check_b"))
        assert (shingles_text(body, own="check_a")
                != shingles_text(body.replace("check_a", "F"), own=""))

    def test_shingles_token_capped(self):
        big = "x = a + b; " * 200_000
        assert len(shingles_text(big)) <= MAX_SHINGLE_TOKENS

    def test_jaccard_empty_side_is_no_evidence(self):
        assert jaccard(frozenset(), frozenset({"a b c"})) is None
        assert decomp_similarity("", _BODY) is None

    def test_short_stub_hash_refused(self):
        assert decomp_hash_text("ret") is None
