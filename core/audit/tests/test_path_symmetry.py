"""Path-symmetry census: 1:1 verb pairing, per-side cohort votes,
learned-vocabulary extension, and the enumerated inconclusives."""

from __future__ import annotations

import pytest

from core.audit.path_symmetry import (
    DIMENSION_PATH_SYMMETRY,
    REASON_ASYMMETRY_BY_CONTRACT,
    REASON_PAIRING_UNRESOLVED,
    detect_path_symmetry_deviations,
    verb_pair_vocabulary,
)
from core.testing import requires_ts

pytestmark = requires_ts("c")


def _setter(name: str, slot: str, checked: bool = True) -> str:
    guard = f"    if (v < 0) return -1;\n" if checked else ""
    return (
        f"int set_{name}(int v)\n"
        "{\n"
        f"{guard}"
        f"    {slot} = v;\n"
        "    return 0;\n"
        "}\n"
    )


def _getter(name: str, slot: str) -> str:
    return (
        f"int get_{name}(void)\n"
        "{\n"
        f"    return {slot};\n"
        "}\n"
    )


def _family(deviant: str | None = "gain") -> str:
    src = ""
    for name in ("gain", "rate", "mode", "level"):
        src += _getter(name, f"g_{name}")
        src += _setter(name, f"g_{name}", checked=(name != deviant))
    return src


def _detect(src: str, **kwargs):
    return detect_path_symmetry_deviations(
        {"pairs.c": src}, seed=b"pin", **kwargs,
    )


class TestCohortVote:
    def test_unchecked_write_side_flags_the_deviant(self):
        devs, stats = _detect(_family("gain"))
        assert devs, stats
        assert {d.enclosing_function for d in devs} == {"set_gain"}
        d = devs[0]
        assert d.side == "write"
        assert d.property_name == "error_handling"
        assert (d.n, d.conforming) == (4, 3)
        assert d.counterpart == "get_gain"
        assert d.counterpart_has is False
        pe = d.peer_evidence
        assert pe is not None
        assert pe.dimension == DIMENSION_PATH_SYMMETRY
        assert pe.rule_id == "consistency:path-symmetry-majority"
        assert stats["pairs"] == 4
        assert stats["families"] == 1
        assert stats["vote_ops"] > 0

    def test_uniform_cohort_is_clean(self):
        devs, _stats = _detect(_family(deviant=None))
        assert devs == []

    def test_below_min_pairs_no_vote(self):
        src = (
            _getter("gain", "g_gain") + _setter("gain", "g_gain")
            + _getter("rate", "g_rate")
            + _setter("rate", "g_rate", checked=False)
        )
        devs, stats = _detect(src)
        assert devs == []
        assert stats["families"] == 0

    def test_read_side_votes_too(self):
        # Cohort of getters that null-guard a lookup; one does not.
        def getter(name: str, guarded: bool) -> str:
            guard = (
                "    if (!p) return -1;\n" if guarded else ""
            )
            return (
                f"int get_{name}(struct s *p)\n"
                "{\n"
                f"{guard}"
                f"    return p->{name};\n"
                "}\n"
            )
        def setter(name: str) -> str:
            return (
                f"int set_{name}(struct s *p, int v)\n"
                "{\n"
                "    if (!p) return -1;\n"
                f"    p->{name} = v;\n"
                "    return 0;\n"
                "}\n"
            )
        src = "".join(
            getter(n, n != "mode") + setter(n)
            for n in ("gain", "rate", "mode", "level")
        )
        devs, _stats = _detect(src)
        read_devs = [d for d in devs if d.side == "read"]
        assert {d.enclosing_function for d in read_devs} == {
            "get_mode",
        }
        assert all(d.counterpart_has for d in read_devs)


class TestPairing:
    def test_duplicate_definition_is_pairing_unresolved(self):
        # A second definition of set_gain (per-platform variant):
        # the stem join must refuse rather than pick one.
        devs, stats = _detect(_family("gain") + (
            "int set_gain(long v)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        ))
        assert stats["inconclusive_reasons"].get(
            REASON_PAIRING_UNRESOLVED,
        )
        assert all(d.enclosing_function != "set_gain" for d in devs)

    def test_camel_and_snake_styles_never_cross_join(self):
        src = (
            _getter("gain", "g_gain")
            + "int setGain(int v)\n{\n    g_gain = v;\n    return 0;\n}\n"
        )
        _devs, stats = _detect(src)
        assert stats["pairs"] == 0


class TestContractsAndVocabulary:
    def test_contract_covered_deviant_is_withheld(self):
        devs, stats = _detect(
            _family("gain"),
            domain_model={
                "contracts": [{"function": "set_gain"}],
            },
        )
        assert all(
            d.enclosing_function != "set_gain" for d in devs
        )
        assert stats["inconclusive_reasons"].get(
            REASON_ASYMMETRY_BY_CONTRACT,
        )

    def test_learned_verb_pairs_extend_the_seed(self):
        vocab = verb_pair_vocabulary({
            "paired_operations": [
                {"acquire": "fetch_row", "release": "stash_row",
                 "kind": "transform"},
            ],
        })
        assert ("fetch", "stash") in vocab
        assert ("get", "set") in vocab

    def test_suffix_verb_pairs_resolve_too(self):
        vocab = verb_pair_vocabulary({
            "paired_operations": [
                {"acquire": "dev_open", "release": "dev_close",
                 "kind": "alloc_free"},
            ],
        })
        assert ("open", "close") in vocab

    def test_hostile_vocabulary_is_capped_and_validated(self):
        entries = [
            {"acquire": f"v{i}_x", "release": f"w{i}_x"}
            for i in range(100)
        ]
        entries.append({"acquire": "GET$_x", "release": "put_x"})
        vocab = verb_pair_vocabulary({"paired_operations": entries})
        from core.audit.path_symmetry import MAX_VERB_PAIRS
        assert len(vocab) <= MAX_VERB_PAIRS
        assert all(
            a.isidentifier() and b.isidentifier() for a, b in vocab
        )


class TestDeterminism:
    def test_seeded_runs_are_reproducible(self):
        a = _detect(_family("gain"))
        b = _detect(_family("gain"))
        assert [d.to_dict() for d in a[0]] == [
            d.to_dict() for d in b[0]
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
