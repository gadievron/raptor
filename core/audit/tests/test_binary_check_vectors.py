"""Binary check-vector extraction + wiring into the real engine.

The extractor consumes persisted artifacts only (call substrates,
decoded compare evidence, decompiled text) and fills the SAME
``SiblingPath.properties`` intake every source-lane vector uses —
so the batteries here run the REAL ``find_asymmetries`` pass over
extracted vectors and assert the N-vs-K outlier surfaces (and that a
uniformly-weak cluster surfaces nothing).
"""

from __future__ import annotations

from core.audit.binary_check_vectors import (
    CHECKS_ARE_SYNTACTIC_NOTE,
    MAX_CALLEE_CHECKS,
    MAX_CONSTANT_CHECKS,
    extract_group_check_vectors,
)
from core.audit.sibling_analysis import (
    SiblingGroup,
    SiblingPath,
    find_asymmetries,
)

_FID = "a" * 16 + ":0x100"


def _group(names, group_id="binary_callee_sig:parse_a"):
    return SiblingGroup(
        group_id=group_id,
        sibling_type="shared_callee_signature",
        description="test group",
        siblings=[
            SiblingPath(label=n, file="binary:acmed", function=n)
            for n in names
        ],
    )


_DECOMP_CHECKED = (
    "int parse_a(char *p, uint n) { if (p == (char *)0x0) return -1; "
    "if (n < 0x100) { memcpy(dst, p, n); } return 0; }"
)
_DECOMP_UNCHECKED = (
    "int parse_c(char *p, uint n) { memcpy(dst, p, n); return 0; }"
)


class TestCalleePresence:
    def test_cluster_frequent_callee_becomes_column(self):
        group = _group(["parse_a", "parse_b", "parse_c"])
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={
                "parse_a": {"check_len", "emit"},
                "parse_b": {"check_len", "emit"},
                "parse_c": {"emit"},
            },
        )
        assert "calls:check_len" in vectors.check_keys
        by_fn = {m.function: m for m in vectors.members}
        assert by_fn["parse_a"].checks["calls:check_len"] is True
        assert by_fn["parse_c"].checks["calls:check_len"] is False
        assert by_fn["parse_c"].tiers["calls:check_len"] == "xref_backed"
        # The engine intake was filled too.
        assert group.siblings[2].properties["calls:check_len"] is False

    def test_callee_columns_key_on_fid_when_known(self):
        group = _group(["parse_a", "parse_b"])
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={
                "parse_a": {"check_len"},
                "parse_b": {"check_len"},
            },
            callee_fids={"check_len": _FID},
        )
        assert vectors.check_keys == [f"calls:{_FID}"]

    def test_single_member_callee_is_not_a_column(self):
        group = _group(["parse_a", "parse_b"])
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={"parse_a": {"only_mine"}},
        )
        assert all(not k.startswith("calls:only_mine")
                   for k in vectors.check_keys)

    def test_callee_column_cap_frequency_first(self):
        names = ["m1", "m2", "m3"]
        shared = {f"helper_{i:02d}" for i in range(MAX_CALLEE_CHECKS + 6)}
        group = _group(names)
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={n: set(shared) for n in names},
        )
        callee_cols = [k for k in vectors.check_keys
                       if k.startswith("calls:")]
        assert len(callee_cols) == MAX_CALLEE_CHECKS
        assert any("capped" in note for note in vectors.notes)

    def test_hostile_callee_name_escaped_in_column_key(self):
        group = _group(["parse_a", "parse_b"])
        hostile = "evil\x1b]0;pwn\x07helper"
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={
                "parse_a": {hostile}, "parse_b": {hostile},
            },
        )
        (key,) = vectors.check_keys
        assert "\x1b" not in key
        assert "\\x1b" in key


class TestCompareVectors:
    def test_decoded_evidence_wins_over_decomp(self):
        group = _group(["parse_a", "parse_b"])
        vectors = extract_group_check_vectors(
            group,
            decoded_compares={
                "parse_a": [{"operand": 0x100}, {"operand": 0}],
                "parse_b": [{"operand": "0x100"}],
            },
            decomp_texts={"parse_a": _DECOMP_UNCHECKED},
        )
        by_fn = {m.function: m for m in vectors.members}
        assert by_fn["parse_a"].compare_source == "decoded_instruction"
        assert "cmp:0x100" in vectors.check_keys
        assert by_fn["parse_a"].checks["cmp:0x100"] is True
        assert by_fn["parse_b"].checks["cmp:0x100"] is True
        assert by_fn["parse_a"].checks["null_check_present"] is True
        assert by_fn["parse_b"].checks["null_check_present"] is False
        assert by_fn["parse_a"].checks["length_cap_present"] is True

    def test_decomp_fallback_is_tier_labelled(self):
        group = _group(["parse_a", "parse_c"])
        vectors = extract_group_check_vectors(
            group,
            decomp_texts={
                "parse_a": _DECOMP_CHECKED,
                "parse_c": _DECOMP_UNCHECKED,
            },
        )
        by_fn = {m.function: m for m in vectors.members}
        assert by_fn["parse_a"].compare_source == "decompiler_inferred"
        assert by_fn["parse_a"].checks["null_check_present"] is True
        assert by_fn["parse_a"].checks["length_cap_present"] is True
        assert by_fn["parse_c"].checks["length_cap_present"] is False
        assert (by_fn["parse_a"].tiers["null_check_present"]
                == "decompiler_inferred")

    def test_absent_evidence_withheld_not_false(self):
        """A member with NO evidence in a family contributes NO
        properties of that family — absence of evidence is not
        absence of the check, for compares AND for calls (a member
        outside the call substrate must not become a false outlier
        wearing the xref_backed label)."""
        group = _group(["parse_a", "parse_b", "parse_dark"])
        vectors = extract_group_check_vectors(
            group,
            callees_by_function={
                # parse_dark has NO substrate record at all — not an
                # empty callee set, which would be real evidence.
                "parse_a": {"check_len", "emit"},
                "parse_b": {"check_len", "emit"},
            },
            decomp_texts={
                "parse_a": _DECOMP_CHECKED,
                "parse_b": _DECOMP_CHECKED.replace("parse_a", "parse_b"),
            },
        )
        by_fn = {m.function: m for m in vectors.members}
        dark = by_fn["parse_dark"]
        assert dark.compare_source == "no_evidence"
        # The dark member's row is fully withheld: no compare AND no
        # calls checks.
        assert dark.checks == {}
        dark_sib = next(s for s in group.siblings
                        if s.function == "parse_dark")
        assert dark_sib.properties == {}
        # And the engine never counts the dark member — no asymmetry
        # row of ANY property names it (the members with evidence
        # agree, so there is no asymmetry at all).
        for asym in find_asymmetries(group):
            assert "parse_dark" not in asym.minority_siblings
        assert find_asymmetries(group) == []

    def test_constant_column_cap(self):
        group = _group(["m1", "m2"])
        consts = [{"operand": i + 2} for i in range(
            MAX_CONSTANT_CHECKS + 9)]
        vectors = extract_group_check_vectors(
            group,
            decoded_compares={"m1": consts, "m2": consts},
        )
        cmp_cols = [k for k in vectors.check_keys if k.startswith("cmp:")]
        assert len(cmp_cols) == MAX_CONSTANT_CHECKS
        assert any("capped" in note for note in vectors.notes)

    def test_junk_decoded_records_fall_back_to_decomp(self):
        group = _group(["parse_a", "parse_b"])
        vectors = extract_group_check_vectors(
            group,
            decoded_compares={"parse_a": ["junk", {"operand": "zz"}]},
            decomp_texts={
                "parse_a": _DECOMP_CHECKED,
                "parse_b": _DECOMP_CHECKED.replace("parse_a", "parse_b"),
            },
        )
        by_fn = {m.function: m for m in vectors.members}
        assert by_fn["parse_a"].compare_source == "decompiler_inferred"

    def test_shift_operators_are_not_compares(self):
        """Two directions: ``x << 2`` (and compound shifts) must not
        mint compare constants or a length cap; ``x < 2`` must."""
        group = _group(["shifty_a", "shifty_b"])
        shift_body = (
            "int {n}(uint x) {{ x <<= 2; return (x << 4) | (x >> 3) "
            "| (x >>= 1); }}"
        )
        vectors = extract_group_check_vectors(
            group,
            decomp_texts={
                "shifty_a": shift_body.format(n="shifty_a"),
                "shifty_b": shift_body.format(n="shifty_b"),
            },
        )
        for member in vectors.members:
            assert member.checks.get("length_cap_present") is False
        assert not [k for k in vectors.check_keys
                    if k.startswith("cmp:")]
        # The compare direction still fires.
        group2 = _group(["cmp_a", "cmp_b"])
        vectors2 = extract_group_check_vectors(
            group2,
            decomp_texts={
                "cmp_a": "int cmp_a(uint x) { if (x < 2) return 1; return 0; }",
                "cmp_b": "int cmp_b(uint x) { if (x < 2) return 1; return 0; }",
            },
        )
        by_fn = {m.function: m for m in vectors2.members}
        assert by_fn["cmp_a"].checks["length_cap_present"] is True
        assert "cmp:0x2" in vectors2.check_keys

    def test_callee_columns_are_frequency_first_under_mixed_flood(self):
        """Anti-flood pin: a flood of low-frequency decoy callees
        whose names SORT FIRST must not displace the higher-frequency
        real columns (a name-sort mutant fails here)."""
        names = ["m1", "m2", "m3", "m4"]
        group = _group(names)
        real = [f"zz_real_{i}" for i in range(4)]     # freq 4, late names
        decoys = [f"aa_decoy_{i:02d}" for i in range(
            MAX_CALLEE_CHECKS + 8)]                    # freq 2, early names
        callees = {
            "m1": set(real) | set(decoys),
            "m2": set(real) | set(decoys),
            "m3": set(real),
            "m4": set(real),
        }
        vectors = extract_group_check_vectors(
            group, callees_by_function=callees,
        )
        kept = [k for k in vectors.check_keys if k.startswith("calls:")]
        assert len(kept) == MAX_CALLEE_CHECKS
        for callee in real:
            assert f"calls:{callee}" in kept

    def test_syntactic_note_always_present(self):
        vectors = extract_group_check_vectors(_group(["a", "b"]))
        assert CHECKS_ARE_SYNTACTIC_NOTE in vectors.notes


class TestEngineWiring:
    """The extracted vectors drive the REAL find_asymmetries pass."""

    def _extract(self, group):
        return extract_group_check_vectors(
            group,
            callees_by_function={
                "parse_a": {"check_len", "emit"},
                "parse_b": {"check_len", "emit"},
                "parse_c": {"check_len", "emit"},
                "parse_d": {"emit"},
            },
            decomp_texts={
                "parse_a": _DECOMP_CHECKED,
                "parse_b": _DECOMP_CHECKED.replace("parse_a", "parse_b"),
                "parse_c": _DECOMP_CHECKED.replace("parse_a", "parse_c"),
                "parse_d": _DECOMP_UNCHECKED.replace("parse_c", "parse_d"),
            },
        )

    def test_missing_check_member_is_the_outlier(self):
        group = _group(["parse_a", "parse_b", "parse_c", "parse_d"])
        self._extract(group)
        asymmetries = find_asymmetries(group)
        outliers = {
            (a.property_name, tuple(a.minority_siblings))
            for a in asymmetries
        }
        assert ("calls:check_len", ("parse_d",)) in outliers
        assert ("length_cap_present", ("parse_d",)) in outliers
        for a in asymmetries:
            assert a.minority_count < a.majority_count

    def test_uniform_weakness_flags_no_outlier(self):
        """Every member skips the check → no asymmetry. The consumer
        must render this as UNEXAMINED, never as safe."""
        group = _group(["parse_a", "parse_b", "parse_c"])
        extract_group_check_vectors(
            group,
            callees_by_function={
                n: {"emit"} for n in
                ("parse_a", "parse_b", "parse_c")
            },
            decomp_texts={
                n: _DECOMP_UNCHECKED.replace("parse_c", n)
                for n in ("parse_a", "parse_b", "parse_c")
            },
        )
        assert find_asymmetries(group) == []
