"""Reproduction pins for the stratified lead ranking.

The ranking chain (contract strength → security relevance → ratio)
and the cap discipline are pinned against the pre-score behaviour;
the lead-strength score may take effect ONLY inside what used to be
the arbitrary file/line tie order among chain-equal leads of one
(dimension × formation) stratum."""

from __future__ import annotations

from core.audit.consistency_prepass import (
    MAX_CONSISTENCY_LEADS,
    MAX_LEADS_PER_FILE,
    _rank_leads,
    run_consistency_prepass,
)
from core.audit.consistency_stats import lead_strength_score


def _legacy_rank(leads):
    """The pre-score ranking (chain + file/line), reproduced here as
    the pin's oracle."""
    return sorted(
        leads,
        key=lambda ld: (
            ld.get("contract_source", "none") == "majority",
            not ld.get("security_relevant", False),
            -float(ld.get("ratio") or 0.0),
            ld.get("file", ""),
            ld.get("line", 0),
        ),
    )


def _lead(i: int, **kw):
    base = {
        "dimension": "return-check",
        "formation": "same_callee",
        "callee": f"callee_{i}",
        "file": f"src/f{i}.c",
        "line": 10 + i,
        "contract_source": "majority",
        "security_relevant": bool(i % 2),
        "n": 10 + i,
        "conforming": 5 + i,
        "ratio": round(0.5 + 0.03 * i, 3),
        "score": round(lead_strength_score(5 + i, 10 + i), 4),
    }
    base.update(kw)
    return base


class TestOrderingReproduction:
    def test_chain_distinct_leads_keep_the_legacy_order(self):
        # No two leads tie on (contract, security, ratio): the new
        # ranking must byte-reproduce the legacy one.
        leads = [_lead(i) for i in range(12)]
        leads[0]["contract_source"] = "wur"
        leads[3]["contract_source"] = "annotation"
        assert _rank_leads(leads) == _legacy_rank(leads)

    def test_caps_unchanged(self):
        # Chain-distinct leads across many files: the run cap and the
        # per-file cap select exactly the legacy set, in order.
        leads = [
            _lead(i, file=f"src/f{i % 9}.c", ratio=round(1 - i * 0.001, 3))
            for i in range(60)
        ]
        ranked = _rank_leads(leads)
        assert len(ranked) <= MAX_CONSISTENCY_LEADS
        per_file: dict[str, int] = {}
        for ld in ranked:
            per_file[ld["file"]] = per_file.get(ld["file"], 0) + 1
        assert all(v <= MAX_LEADS_PER_FILE for v in per_file.values())
        # Same selection as the legacy ranking under the same caps.
        legacy = _legacy_rank(leads)
        expected: list[dict] = []
        counts: dict[str, int] = {}
        for ld in legacy:
            if len(expected) >= MAX_CONSISTENCY_LEADS:
                break
            if counts.get(ld["file"], 0) >= MAX_LEADS_PER_FILE:
                continue
            counts[ld["file"]] = counts.get(ld["file"], 0) + 1
            expected.append(ld)
        assert ranked == expected

    def test_score_breaks_chain_ties_within_a_stratum(self):
        # Two chain-equal leads in one stratum: the larger family
        # wins the tie although its file sorts later — the one place
        # the score is allowed to differ from the legacy order.
        small = _lead(
            0, file="src/a.c", ratio=0.9, n=10, conforming=9,
            security_relevant=True,
            score=round(lead_strength_score(9, 10), 4),
        )
        large = _lead(
            1, file="src/z.c", ratio=0.9, n=20, conforming=18,
            security_relevant=True,
            score=round(lead_strength_score(18, 20), 4),
        )
        ranked = _rank_leads([small, large])
        assert ranked == [large, small]
        assert _legacy_rank([small, large]) == [small, large]
        # The capped SET is unchanged either way — only the order
        # within the tie moved.
        assert {ld["callee"] for ld in ranked} == {
            ld["callee"] for ld in _legacy_rank([small, large])
        }

    def test_strata_do_not_interleave_by_score(self):
        # Chain-equal leads from two strata: ordered by stratum id;
        # the low-score lead of the earlier stratum precedes the
        # high-score lead of the later one.
        flag = _lead(
            0, dimension="flag-mode", file="src/z.c", ratio=0.9,
            security_relevant=True, n=4, conforming=3,
            score=round(lead_strength_score(3, 4), 4),
        )
        ret = _lead(
            1, dimension="return-check", file="src/a.c", ratio=0.9,
            security_relevant=True, n=40, conforming=36,
            score=round(lead_strength_score(36, 40), 4),
        )
        assert ret["score"] > flag["score"]
        assert _rank_leads([ret, flag]) == [flag, ret]

    def test_equal_scores_fall_back_to_file_line(self):
        a = _lead(0, file="src/a.c", ratio=0.9, n=10, conforming=9,
                  security_relevant=True,
                  score=round(lead_strength_score(9, 10), 4))
        b = _lead(1, file="src/b.c", ratio=0.9, n=10, conforming=9,
                  security_relevant=True,
                  score=round(lead_strength_score(9, 10), 4))
        assert _rank_leads([b, a]) == [a, b]


def _tie_corpus() -> dict[str, str]:
    """Three same-ratio (0.9) majority families of different sizes:
    verify_sig 9/10, check_token 9/10, check_nonce 18/20."""
    texts: dict[str, str] = {}

    def family(fname: str, callee: str, checks: int, discards: int):
        src = f"int {callee}(int x);\n"
        for i in range(checks):
            src += (
                f"int {callee[:2]}{i}(void) "
                f"{{ if ({callee}({i})) return 1; return 0; }}\n"
            )
        for i in range(discards):
            src += f"void {callee[:2]}d{i}(void) {{ {callee}({i}); }}\n"
        texts[fname] = src

    family("major.c", "verify_sig", 9, 1)
    family("tie_a.c", "check_token", 9, 1)
    family("tie_b.c", "check_nonce", 18, 2)
    return texts


class TestPrepassEndToEnd:
    def test_leads_carry_score_and_formation(self, tmp_path):
        result = run_consistency_prepass(
            _tie_corpus(), out_dir=tmp_path,
        )
        assert result["leads"]
        for lead in result["leads"]:
            assert lead["formation"] == "same_callee"
            assert lead["score"] == round(
                lead_strength_score(lead["conforming"], lead["n"]), 4,
            )
            assert lead["score"] < lead["ratio"]

    def test_same_lead_set_larger_family_first_within_the_tie(
        self, tmp_path,
    ):
        result = run_consistency_prepass(
            _tie_corpus(), out_dir=tmp_path,
        )
        leads = result["leads"]
        # Same lead SET as the legacy ranking would select.
        assert {(ld["callee"], ld["file"], ld["line"]) for ld in leads} \
            == {
                (ld["callee"], ld["file"], ld["line"])
                for ld in _legacy_rank(leads)
            }
        # All three families tie the chain at ratio 0.9; the n=20
        # family's deviants outrank both n=10 families, which keep
        # their file order (equal scores).
        callee_order = []
        for ld in leads:
            if ld["callee"] not in callee_order:
                callee_order.append(ld["callee"])
        assert callee_order == [
            "check_nonce", "verify_sig", "check_token",
        ]
