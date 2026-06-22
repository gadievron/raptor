"""Tests for the path-homology validation harness (Phase 4).

Covers the pure statistics core (cross-tab, bounds, separation /
decompiler reports, the suggested gate decision, goto counting) — r2-free.
The record-extraction layer needs radare2 and is exercised by an operator
corpus run, not here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.inventory.path_homology_precision import (  # noqa: E402
    FunctionRecord,
    count_gotos,
    cross_tab,
    decompiler_report,
    gate_decision,
    rule_of_three_ub,
    separation_report,
)


def _rec(name, betti, label=None, goto=None):
    return FunctionRecord(
        binary="b", function=name, address=0,
        betti=betti, decompiler_low_confidence=(len(betti) > 2 and betti[2] > 0),
        label=label, goto_count=goto)


class TestPrimitives:
    def test_rule_of_three(self):
        assert rule_of_three_ub(0) is None
        assert rule_of_three_ub(100) == 0.03

    def test_irreducible_property(self):
        assert _rec("a", [1, 0, 1]).irreducible is True
        assert _rec("b", [1, 2, 0]).irreducible is False
        assert _rec("c", [1, 1]).irreducible is False  # no β_2 computed

    def test_count_gotos(self):
        assert count_gotos("if (x) goto L1; ... goto L2;") == 2
        assert count_gotos("no jumps here") == 0
        assert count_gotos("") == 0
        assert count_gotos(None) == 0
        # word-boundary: "gotoh" must not match.
        assert count_gotos("gotoh(); algotos;") == 0

    def test_cross_tab_skips_none_col(self):
        recs = [_rec("a", [1, 0, 1], label="vulnerable"),
                _rec("b", [1, 0, 0], label=None)]
        t = cross_tab(recs,
                      row_key=lambda r: "irr" if r.irreducible else "red",
                      col_key=lambda r: r.label)
        assert t == {"irr": {"vulnerable": 1}}


class TestSeparation:
    def test_perfect_separation(self):
        recs = [
            _rec("v1", [1, 0, 1], label="vulnerable"),
            _rec("v2", [1, 0, 1], label="vulnerable"),
            _rec("b1", [1, 0, 0], label="benign"),
            _rec("b2", [1, 1, 0], label="benign"),
        ]
        sep = separation_report(recs)
        assert sep["p_irreducible_given_vulnerable"] == 1.0
        assert sep["p_irreducible_given_benign"] == 0.0
        assert sep["risk_ratio"] == float("inf")
        assert sep["cross_tab"]["irreducible"]["vulnerable"] == 2

    def test_no_separation(self):
        recs = [_rec("v", [1, 0, 0], label="vulnerable"),
                _rec("b", [1, 0, 0], label="benign")]
        sep = separation_report(recs)
        assert sep["risk_ratio"] is None  # 0/0


class TestDecompiler:
    def test_goto_correlates_with_irreducible(self):
        recs = [
            _rec("i1", [1, 0, 1], goto=3),
            _rec("i2", [1, 0, 1], goto=1),
            _rec("r1", [1, 1, 0], goto=0),
            _rec("r2", [1, 0, 0], goto=0),
        ]
        dec = decompiler_report(recs)
        assert dec["p_goto_given_irreducible"] == 1.0
        assert dec["p_goto_given_reducible"] == 0.0
        assert dec["risk_ratio"] == float("inf")

    def test_skips_undecompiled(self):
        recs = [_rec("i", [1, 0, 1], goto=None), _rec("r", [1, 0, 0], goto=0)]
        dec = decompiler_report(recs)
        assert dec["n_decompiled"] == 1  # the None one is excluded


class TestGate:
    def test_vacuous_signal_is_no_go(self):
        # Nothing irreducible anywhere ⇒ hard no-go ("absent").
        recs = [_rec("a", [1, 0, 0], label="vulnerable", goto=0),
                _rec("b", [1, 1, 0], label="benign", goto=0)]
        d = gate_decision(recs)
        assert d["suggested_pass"] is False
        assert "absent" in d["reason"]

    def test_separation_passes_gate(self):
        recs = [
            _rec("v1", [1, 0, 1], label="vulnerable", goto=2),
            _rec("v2", [1, 0, 1], label="vulnerable", goto=1),
            _rec("b1", [1, 0, 0], label="benign", goto=0),
            _rec("b2", [1, 0, 0], label="benign", goto=0),
            _rec("b3", [1, 0, 0], label="benign", goto=0),
        ]
        d = gate_decision(recs)
        assert d["suggested_pass"] is True
        assert d["separation_pass"] is True

    def test_decompiler_only_passes_gate(self):
        # No labels, but β_2>0 strongly predicts goto ⇒ go via claim (b).
        recs = [
            _rec("i1", [1, 0, 1], goto=4),
            _rec("i2", [1, 0, 1], goto=2),
            _rec("r1", [1, 1, 0], goto=0),
            _rec("r2", [1, 0, 0], goto=0),
            _rec("r3", [1, 0, 0], goto=0),
        ]
        d = gate_decision(recs)
        assert d["decompiler_pass"] is True
        assert d["suggested_pass"] is True
